import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { run, commandExists } from '../util/exec.js';

/**
 * LLM access layer.
 *
 * The deterministic half of Sentinel never calls a model. This layer is strictly
 * additive: it triages scanner noise, reviews the files the collectors flagged,
 * and drafts fix plans. If no provider is reachable the scan completes anyway
 * and every artefact states that the model pass did not run — the one failure
 * mode a security report must not have is quietly producing less while looking
 * the same.
 */

export type ProviderKind = 'bandit-cli' | 'anthropic' | 'openai' | 'ollama' | 'none';

/** What `--provider` accepts. `auto` keeps the detection order below. */
export type ProviderChoice = 'auto' | 'bandit' | 'anthropic' | 'openai' | 'ollama';
export const PROVIDER_CHOICES: readonly ProviderChoice[] = ['auto', 'bandit', 'anthropic', 'openai', 'ollama'];
export function isProviderChoice(v: string): v is ProviderChoice {
  return (PROVIDER_CHOICES as readonly string[]).includes(v);
}

/**
 * `mode` is load-bearing, not cosmetic.
 *
 * Review passes run `read-only`, so an analysis pass can never edit the
 * repository it is describing. `sentinel fix` runs `write`, because its whole
 * job is to change files — and that is safe only because the caller has already
 * put it on a fresh branch in a clean tree with the repository's tests as the
 * gate. Defaulting to read-only means a new call site cannot accidentally get
 * write access.
 */
export type LlmMode = 'read-only' | 'write';

export interface LlmCompleteOptions {
  timeoutMs?: number;
  maxTokens?: number;
  mode?: LlmMode;
  /** Directory the agent should treat as its working tree. */
  cwd?: string;
}

export interface LlmProvider {
  kind: ProviderKind;
  label: string;
  available: boolean;
  note: string;
  complete(prompt: string, opts?: LlmCompleteOptions): Promise<LlmResponse>;
}

export interface LlmResponse {
  ok: boolean;
  text: string;
  error?: string;
  durationMs: number;
}

export interface ProviderOptions {
  /** Explicit path to the Bandit CLI entrypoint. */
  banditCli?: string;
  /** Disable the LLM pass entirely. */
  disabled?: boolean;
  model?: string;
  timeoutMs?: number;
  /** Which provider to use; `auto` (default) detects. */
  provider?: ProviderChoice;
  /**
   * `--offline`: prompts carry the audited source, so the model pass may only
   * reach a loopback or private-network endpoint. Hosted APIs are refused, and
   * `auto` picks nothing, because Sentinel cannot see where the Bandit CLI
   * sends a prompt.
   */
  offline?: boolean;
}

/**
 * Loopback, RFC 1918, unique-local IPv6 and `*.localhost`/`*.local` names:
 * endpoints on the operator's own machine or network.
 */
export function isLocalEndpoint(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return false;
  }
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host === 'host.docker.internal') return true;
  if (host === '::1' || /^f[cd][0-9a-f]{2}:/.test(host)) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** `OLLAMA_HOST` is often a bare `host:port`; Ollama itself accepts that. */
export function ollamaBaseUrl(env: string | undefined = process.env.OLLAMA_HOST): string {
  const raw = (env ?? '').trim() || 'http://127.0.0.1:11434';
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  return withScheme.replace(/\/$/, '');
}

/**
 * Where to look for an agent entrypoint, in order.
 *
 * Deliberately no machine-specific paths: `--bandit-cli` or
 * `SENTINEL_BANDIT_CLI` is the supported way to point at a checkout, and a
 * sibling-checkout guess is included because that is a layout anyone can verify
 * by looking, rather than one baked in from whoever wrote this file.
 */
const BANDIT_CLI_CANDIDATES = (): string[] => {
  const out: string[] = [];
  if (process.env.SENTINEL_BANDIT_CLI) out.push(process.env.SENTINEL_BANDIT_CLI);
  const home = process.env.HOME ?? '';
  if (home) out.push(join(home, '.bandit', 'bin', 'cli.js'));
  const sibling = join('..', 'bandit-agent-framework', 'apps', 'bandit-cli', 'dist', 'cli.js');
  out.push(join(process.cwd(), sibling), join(process.cwd(), '..', sibling));
  return out;
};

export function detectProvider(options: ProviderOptions = {}): LlmProvider {
  if (options.disabled) {
    return nullProvider('the model pass was disabled for this run (--no-llm)');
  }
  const choice = options.provider ?? 'auto';

  if (options.offline) {
    if (choice === 'anthropic') {
      return nullProvider('--offline keeps the audited source on this network, so the hosted Anthropic API was not called. Use --provider ollama for an offline model pass.');
    }
    if (choice === 'auto') {
      return nullProvider('--offline with no --provider: the model pass ran nowhere rather than guess where a prompt would go. Pass --provider ollama (or openai with a local OPENAI_BASE_URL) for an offline model pass.');
    }
    if (choice === 'openai') {
      const base = process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1';
      if (!isLocalEndpoint(base)) {
        return nullProvider(`--offline refuses the OpenAI-compatible endpoint ${base}: it is not on loopback or a private network. Point OPENAI_BASE_URL at a local server, or use --provider ollama.`);
      }
    }
    if (choice === 'ollama' && !isLocalEndpoint(ollamaBaseUrl())) {
      return nullProvider(`--offline refuses OLLAMA_HOST ${ollamaBaseUrl()}: it is not on loopback or a private network.`);
    }
  }

  switch (choice) {
    case 'ollama':
      return ollamaProvider(options);
    case 'anthropic':
      return process.env.ANTHROPIC_API_KEY ? anthropicProvider(options) : nullProvider('--provider anthropic needs ANTHROPIC_API_KEY.');
    case 'openai':
      return process.env.OPENAI_API_KEY || process.env.OPENAI_BASE_URL
        ? openAiProvider(options)
        : nullProvider('--provider openai needs OPENAI_API_KEY, or OPENAI_BASE_URL for a keyless local server.');
    case 'bandit': {
      const candidates = options.banditCli ? [options.banditCli, ...BANDIT_CLI_CANDIDATES()] : BANDIT_CLI_CANDIDATES();
      const found = candidates.find((p) => p && existsSync(p));
      if (found) return banditCliProvider(found, options);
      if (commandExists('bandit')) return banditBinaryProvider(options);
      return nullProvider('--provider bandit: no Bandit CLI was found (--bandit-cli, SENTINEL_BANDIT_CLI, ~/.bandit/bin/cli.js, or `bandit` on PATH).');
    }
    case 'auto':
      break;
  }

  // 1. Bandit CLI — preferred, because it runs against whatever provider the
  //    operator already configured (including a local model) and needs no key here.
  const explicit = options.banditCli;
  const candidates = explicit ? [explicit, ...BANDIT_CLI_CANDIDATES()] : BANDIT_CLI_CANDIDATES();
  const cliPath = candidates.find((p) => p && existsSync(p));
  if (cliPath) return banditCliProvider(cliPath, options);
  if (commandExists('bandit')) return banditBinaryProvider(options);

  // 2. Direct API keys.
  if (process.env.ANTHROPIC_API_KEY) return anthropicProvider(options);
  if (process.env.OPENAI_API_KEY) return openAiProvider(options);

  return nullProvider(
    'no model provider was reachable: the Bandit CLI was not found and neither ANTHROPIC_API_KEY nor OPENAI_API_KEY is set. The scan ran deterministic-only.',
  );
}

function nullProvider(note: string): LlmProvider {
  return {
    kind: 'none',
    label: 'none',
    available: false,
    note,
    complete: async () => ({ ok: false, text: '', error: note, durationMs: 0 }),
  };
}

function banditCliProvider(cliPath: string, options: ProviderOptions): LlmProvider {
  return {
    kind: 'bandit-cli',
    label: `bandit-cli (${cliPath})`,
    available: true,
    note: `model pass ran through the Bandit CLI at ${cliPath}, using whatever provider that CLI is configured for`,
    async complete(prompt, opts) {
      const started = Date.now();
      const res = run(process.execPath, [cliPath, prompt], {
        timeoutMs: opts?.timeoutMs ?? options.timeoutMs ?? 300_000,
        env: { ...process.env, NO_COLOR: '1', BANDIT_INK_INPUT: '0', ...permissionEnv(opts?.mode) },
        cwd: opts?.cwd ?? process.cwd(),
      });
      return {
        ok: res.stdout.trim().length > 0,
        text: stripAnsi(res.stdout),
        error: res.stdout.trim().length === 0 ? `bandit cli produced no output (exit ${res.code}): ${res.stderr.slice(0, 300)}` : undefined,
        durationMs: Date.now() - started,
      };
    },
  };
}

function banditBinaryProvider(options: ProviderOptions): LlmProvider {
  return {
    kind: 'bandit-cli',
    label: 'bandit (on PATH)',
    available: true,
    note: 'model pass ran through the `bandit` binary found on PATH',
    async complete(prompt, opts) {
      const started = Date.now();
      const res = run('bandit', [prompt], {
        timeoutMs: opts?.timeoutMs ?? options.timeoutMs ?? 300_000,
        env: { ...process.env, NO_COLOR: '1', BANDIT_INK_INPUT: '0', ...permissionEnv(opts?.mode) },
        cwd: opts?.cwd ?? process.cwd(),
      });
      return {
        ok: res.stdout.trim().length > 0,
        text: stripAnsi(res.stdout),
        error: res.stdout.trim().length === 0 ? `bandit produced no output (exit ${res.code})` : undefined,
        durationMs: Date.now() - started,
      };
    },
  };
}

function anthropicProvider(options: ProviderOptions): LlmProvider {
  const model = options.model ?? process.env.SENTINEL_MODEL ?? 'claude-sonnet-4-5';
  return {
    kind: 'anthropic',
    label: `anthropic (${model})`,
    available: true,
    note: `model pass used the Anthropic Messages API with model ${model}`,
    async complete(prompt, opts) {
      const started = Date.now();
      try {
        const res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-api-key': process.env.ANTHROPIC_API_KEY ?? '',
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model,
            max_tokens: opts?.maxTokens ?? 4096,
            messages: [{ role: 'user', content: prompt }],
          }),
          signal: AbortSignal.timeout(opts?.timeoutMs ?? 180_000),
        });
        if (!res.ok) {
          return { ok: false, text: '', error: `anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`, durationMs: Date.now() - started };
        }
        const doc = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
        const text = (doc.content ?? []).filter((c) => c.type === 'text').map((c) => c.text ?? '').join('\n');
        return { ok: text.length > 0, text, durationMs: Date.now() - started };
      } catch (err) {
        return { ok: false, text: '', error: err instanceof Error ? err.message : String(err), durationMs: Date.now() - started };
      }
    },
  };
}

function openAiProvider(options: ProviderOptions): LlmProvider {
  const base = process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1';
  const model = options.model ?? process.env.SENTINEL_MODEL ?? process.env.OPENAI_MODEL ?? 'gpt-4o-mini';
  return {
    kind: 'openai',
    label: `openai-compatible (${model} @ ${base})`,
    available: true,
    note: `model pass used an OpenAI-compatible endpoint at ${base} with model ${model}`,
    async complete(prompt, opts) {
      const started = Date.now();
      try {
        const res = await fetch(`${base.replace(/\/$/, '')}/chat/completions`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${process.env.OPENAI_API_KEY ?? ''}`,
          },
          body: JSON.stringify({
            model,
            max_tokens: opts?.maxTokens ?? 4096,
            messages: [{ role: 'user', content: prompt }],
          }),
          signal: AbortSignal.timeout(opts?.timeoutMs ?? 180_000),
        });
        if (!res.ok) {
          return { ok: false, text: '', error: `openai ${res.status}: ${(await res.text()).slice(0, 300)}`, durationMs: Date.now() - started };
        }
        const doc = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
        const text = doc.choices?.[0]?.message?.content ?? '';
        return { ok: text.length > 0, text, durationMs: Date.now() - started };
      } catch (err) {
        return { ok: false, text: '', error: err instanceof Error ? err.message : String(err), durationMs: Date.now() - started };
      }
    },
  };
}

/**
 * Ollama's native chat API. With no `--model`, the first installed *local*
 * model is used and named in the report, so a bare `--provider ollama` works on
 * a machine that has pulled anything at all.
 *
 * Ollama also lists cloud models (`kimi-k3:cloud`, carrying `remote_host`) that
 * it proxies to ollama.com. Those are never picked by default, and `--offline`
 * refuses one even when named: the prompt carries the audited source.
 */
export function isRemoteOllamaModel(m: { name?: string; remote_host?: string }): boolean {
  return Boolean(m.remote_host) || /[:-]cloud$/i.test(m.name ?? '');
}

function ollamaProvider(options: ProviderOptions): LlmProvider {
  const base = ollamaBaseUrl();
  let model = options.model ?? process.env.SENTINEL_MODEL ?? process.env.OLLAMA_MODEL ?? '';
  let checked = false;
  const where = isLocalEndpoint(base) ? 'this machine or network' : base;
  const provider: LlmProvider = {
    kind: 'ollama',
    label: `ollama (${model || 'first local model'} @ ${base})`,
    available: true,
    note: `model pass used Ollama at ${base}${model ? ` with model ${model}` : ''}`,
    async complete(prompt, opts) {
      const started = Date.now();
      const timeoutMs = opts?.timeoutMs ?? options.timeoutMs ?? 300_000;
      const fail = (error: string): LlmResponse => ({ ok: false, text: '', error, durationMs: Date.now() - started });
      try {
        if (!checked) {
          const tags = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(10_000) });
          const installed = ((await tags.json()) as { models?: Array<{ name?: string; remote_host?: string }> }).models ?? [];
          if (!model) {
            model = installed.find((m) => m.name && !isRemoteOllamaModel(m))?.name ?? '';
            if (!model) return fail(`ollama at ${base} has no local models installed (ollama pull <model>); cloud models are not picked by default`);
          }
          const entry = installed.find((m) => m.name === model || m.name === `${model}:latest`);
          const remote = isRemoteOllamaModel(entry ?? { name: model });
          if (remote && options.offline) {
            return fail(`--offline refuses ${model}: Ollama proxies it to ${entry?.remote_host ?? 'ollama.com'}, so the audited source would leave this network`);
          }
          checked = true;
          provider.label = `ollama (${model} @ ${base})`;
          provider.note = remote
            ? `model pass used Ollama cloud model ${model} via ${base}; prompts went to ${entry?.remote_host ?? 'ollama.com'}`
            : `model pass used Ollama at ${base} with local model ${model}${options.model ? '' : ' (the first installed; pass --model to choose)'}; no prompt left ${where}`;
        }
        const res = await fetch(`${base}/api/chat`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            model,
            stream: false,
            messages: [{ role: 'user', content: prompt }],
            options: { num_predict: opts?.maxTokens ?? 4096 },
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) return fail(`ollama ${res.status}: ${(await res.text()).slice(0, 300)}`);
        const doc = (await res.json()) as { message?: { content?: string } };
        const text = doc.message?.content ?? '';
        return { ok: text.length > 0, text, durationMs: Date.now() - started };
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }
    },
  };
  return provider;
}

/**
 * Read-only is the default: a call site that forgets to ask for write access
 * gets an agent that cannot modify anything.
 */
function permissionEnv(mode: LlmMode | undefined): NodeJS.ProcessEnv {
  if (mode === 'write') {
    // Non-interactive by necessity — `sentinel fix` has no terminal to prompt
    // at. The containment is the fresh branch, the clean-tree precondition and
    // the test gate, not an interactive confirmation.
    return { BANDIT_PERMISSION_MODE: 'dangerous', BANDIT_DANGEROUSLY_APPROVE_ALL: '1' };
  }
  return { BANDIT_PERMISSION_MODE: 'plan', BANDIT_DANGEROUSLY_APPROVE_ALL: '' };
}

/**
 * Did the provider fail to answer, as opposed to answering badly?
 *
 * These two need different remedies — "retry in a minute" versus "fix the
 * prompt" — so they must not both surface as "returned no parseable JSON". That
 * message sent us looking for a parser bug when the model behind the agent was
 * simply cold.
 */
const PROVIDER_UNAVAILABLE =
  /\bfatal:|didn't answer in \d+s|did not answer in \d+s|warming up the model — retry 3 of 3|rate limit|429|503|502|ECONNREFUSED|ETIMEDOUT|context (?:length|window) exceeded|model not found/i;

export function providerFailureReason(text: string, error: string | undefined): string | null {
  const haystack = `${error ?? ''}\n${text}`;
  const m = PROVIDER_UNAVAILABLE.exec(haystack);
  if (!m) return null;
  const line = haystack
    .split('\n')
    .map((l) => l.trim())
    .find((l) => PROVIDER_UNAVAILABLE.test(l));
  return line ? line.slice(0, 300) : m[0];
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\[[0-9;]*[A-Za-z]/g, '');
}

/**
 * Pull the last JSON object or array out of a model response.
 *
 * Models wrap JSON in fences, prefix it with prose, and occasionally emit two
 * candidates. Taking the *last* well-formed value is the behaviour that survives
 * all three.
 */
export function extractJson<T>(text: string): T | null {
  const fenced = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1] ?? '');
  for (const candidate of fenced.reverse()) {
    const parsed = tryParseBalanced<T>(candidate);
    if (parsed !== null) return parsed;
  }
  return scanForJson<T>(text);
}

function tryParseBalanced<T>(text: string): T | null {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return scanForJson<T>(trimmed);
  }
}

/**
 * Find the last well-formed JSON array or object anywhere in the text.
 *
 * The naive version of this — slice from the first `[` to the last `]` — is
 * wrong in a way that silently costs you the whole model pass. Agent output
 * routinely contains prose that happens to use brackets ("SEC-001
 * [High/confirmed]"), so the first bracket belongs to a sentence and the slice
 * spans from mid-sentence to the end of the real payload. It never parses, the
 * pass reports "no parseable JSON", and the scan quietly degrades to
 * deterministic-only while looking like it ran.
 *
 * So: try every opening bracket as a candidate start, match brackets properly
 * (skipping string literals and escapes), and keep the last one that parses.
 */
function scanForJson<T>(text: string): T | null {
  let best: T | null = null;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch !== '[' && ch !== '{') continue;
    const end = matchBracket(text, i);
    if (end < 0) continue;
    try {
      best = JSON.parse(text.slice(i, end + 1)) as T;
      // Skip past what we just consumed: a nested value cannot be a better
      // candidate than the structure containing it.
      i = end;
    } catch {
      continue;
    }
  }
  return best;
}

/** Index of the bracket closing the one at `start`, or -1. String-aware. */
function matchBracket(text: string, start: number): number {
  const open = text[start];
  const close = open === '[' ? ']' : '}';
  let depth = 0;
  let inString = false;
  let quote = '';
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i]!;
    if (inString) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) inString = false;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      quote = ch;
      continue;
    }
    if (ch === '[' || ch === '{') depth += 1;
    else if (ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return ch === close ? i : -1;
    }
  }
  return -1;
}
