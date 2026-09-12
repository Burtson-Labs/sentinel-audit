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

export type ProviderKind = 'bandit-cli' | 'anthropic' | 'openai' | 'none';

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
  const candidates = [...fenced.reverse(), text];
  for (const candidate of candidates) {
    const parsed = tryParseBalanced<T>(candidate);
    if (parsed !== null) return parsed;
  }
  return null;
}

function tryParseBalanced<T>(text: string): T | null {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    // fall through to balanced extraction
  }
  for (const [open, close] of [
    ['[', ']'],
    ['{', '}'],
  ] as const) {
    const start = trimmed.indexOf(open);
    const end = trimmed.lastIndexOf(close);
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(trimmed.slice(start, end + 1)) as T;
      } catch {
        continue;
      }
    }
  }
  return null;
}
