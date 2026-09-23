import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { extractJson, detectProvider, isLocalEndpoint, ollamaBaseUrl } from '../src/llm/client.js';
import { applyLlmResults, type LlmPassResult } from '../src/llm/passes.js';
import type { Finding } from '../src/types.js';

describe('extractJson', () => {
  it('reads a bare JSON array', () => {
    expect(extractJson('[{"a":1}]')).toEqual([{ a: 1 }]);
  });

  it('reads a fenced block', () => {
    expect(extractJson('Here you go:\n```json\n[{"a":1}]\n```\nhope that helps')).toEqual([{ a: 1 }]);
  });

  it('takes the last fenced block when a model emits two', () => {
    expect(extractJson('```json\n[{"a":1}]\n```\nactually:\n```json\n[{"a":2}]\n```')).toEqual([{ a: 2 }]);
  });

  it('survives prose that uses brackets before the payload', () => {
    // The regression that cost an entire model pass: slicing from the first
    // bracket to the last spans from mid-sentence into the real payload.
    const out = [
      'reasoning',
      'The finding SEC-001 [High/confirmed] should be kept because [reasons].',
      '',
      '[{"id":"SEC-001","verdict":"keep","reason":"x","evidence":"src/a.ts:1"}]',
    ].join('\n');
    expect(extractJson<Array<{ id: string }>>(out)?.[0]?.id).toBe('SEC-001');
  });

  it('ignores brackets inside string literals when matching', () => {
    expect(extractJson('[{"note":"contains ] and } characters"}]')).toEqual([{ note: 'contains ] and } characters' }]);
  });

  it('handles escaped quotes inside the payload', () => {
    expect(extractJson('[{"note":"a \\"quoted\\" word"}]')).toEqual([{ note: 'a "quoted" word' }]);
  });

  it('prefers the containing structure over a nested one', () => {
    const parsed = extractJson<Array<{ inner: { a: number } }>>('noise [{"inner":{"a":1}}] more noise');
    expect(parsed?.[0]?.inner?.a).toBe(1);
  });

  it('returns null when there is no JSON at all', () => {
    expect(extractJson('I could not complete that request.')).toBeNull();
  });

  it('never fabricates a closing bracket for a truncated structure', () => {
    // The inner object is well-formed and is returned; the truncated array is
    // not reconstructed. Callers check Array.isArray, so a truncated array
    // still reads as "no usable payload" rather than as a one-element result.
    const parsed = extractJson('[{"a":1}');
    expect(Array.isArray(parsed)).toBe(false);
    expect(parsed).toEqual({ a: 1 });
  });

  it('returns null when a truncated object has nothing parseable inside', () => {
    expect(extractJson('[{"a":')).toBeNull();
  });
});

describe('detectProvider', () => {
  it('reports unavailability with a reason when disabled', () => {
    const p = detectProvider({ disabled: true });
    expect(p.available).toBe(false);
    expect(p.note).toMatch(/disabled/);
  });

  it('a null provider still answers, with an error rather than a throw', async () => {
    const res = await detectProvider({ disabled: true }).complete('anything');
    expect(res.ok).toBe(false);
    expect(res.error).toBeTruthy();
  });
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'SEC-001',
    title: 'x',
    type: 'Security',
    severity: 'High',
    suggestedLabels: [],
    affectedArea: 'UI',
    evidence: 'src/a.ts:1 — x',
    whyThisMatters: 'y',
    recommendation: 'z',
    acceptanceCriteria: ['a'],
    effortEstimate: 'M',
    dependenciesRelated: [],
    provenance: {
      repoUrl: 'u', branch: 'main', commitSha: 's', reviewDate: '2026-01-01',
      tool: 'sentinel-audit', toolVersion: '0.1.0', profile: 'owasp-asvs', llmPass: 'ran',
    },
    standardMapping: 'm',
    status: 'plausible',
    verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'n' },
    locations: [{ file: 'src/a.ts', startLine: 1 }],
    standards: { profile: 'owasp-asvs', controls: [], cwe: [], owasp: [] },
    fixPlan: { agentExecutable: false, strategy: 's', files: [], acceptanceTests: [], risk: 'low', estimatedDiffSize: 'd', notAgentExecutableReason: 'r' },
    source: 'rule',
    confidence: 0.5,
    fingerprint: 'f',
    ...overrides,
  };
}

const emptyPass = (): LlmPassResult => ({ triage: [], proposals: [], fixPlans: [], calls: 0, failures: 0, notes: [] });

describe('applyLlmResults', () => {
  it('applies a cited dismissal', () => {
    const f = finding();
    const pass = emptyPass();
    pass.triage.push({ id: 'SEC-001', verdict: 'dismiss', reason: 'the guard is in the wrapper', evidence: 'src/b.ts:20' });
    applyLlmResults([f], pass);
    expect(f.status).toBe('triaged-out');
    expect(f.triage?.by).toBe('llm');
    expect(f.triage?.evidenceCited).toBe('src/b.ts:20');
  });

  it('applies a downgrade and records why in the notes', () => {
    const f = finding();
    const pass = emptyPass();
    pass.triage.push({ id: 'SEC-001', verdict: 'downgrade', reason: 'only reachable in dev', evidence: 'src/a.ts:1', severity: 'Low' });
    applyLlmResults([f], pass);
    expect(f.severity).toBe('Low');
    expect(f.notes?.join(' ')).toMatch(/only reachable in dev/);
  });

  it('refuses to let a model opinion overturn an executed proof', () => {
    const f = finding({
      status: 'confirmed',
      verification: {
        method: 'proof-executed',
        claimType: 'behavioral',
        performed: true,
        result: 'confirmed',
        checks: [],
        proof: { path: 'p', command: 'node p', exitCode: 0, durationMs: 1, predicted: 'p', observed: 'o', verdict: 'vulnerable', stdoutExcerpt: '', stderrExcerpt: '' },
        notes: 'proof ran',
      },
    });
    const pass = emptyPass();
    pass.triage.push({ id: 'SEC-001', verdict: 'dismiss', reason: 'I think it is fine', evidence: 'src/a.ts:1' });
    const res = applyLlmResults([f], pass);
    expect(f.status).toBe('confirmed');
    expect(res.rejected).toBe(1);
    expect(f.notes?.join(' ')).toMatch(/does not overturn a proof/);
  });

  it('can only narrow agent-executability, never widen it', () => {
    const f = finding({ fixPlan: { ...finding().fixPlan, agentExecutable: false } });
    const pass = emptyPass();
    pass.fixPlans.push({ id: 'SEC-001', agentPrompt: 'do the thing', agentExecutable: true, rationale: 'easy' });
    applyLlmResults([f], pass);
    expect(f.fixPlan.agentExecutable).toBe(false);
  });
});

describe('dedupeProposals', () => {
  it('collapses the same defect reported at several lines in one file', async () => {
    const { dedupeProposals } = await import('../src/llm/passes.js');
    const base = {
      title: 'Unescaped interpolation',
      severity: 'High' as const,
      type: 'Security' as const,
      file: 'src/links.js',
      evidence: 'src/links.js:2 — interpolated',
      whyThisMatters: 'x',
      recommendation: 'y',
      confidenceSelfReported: 'high',
    };
    const out = dedupeProposals([
      { ...base, line: 2 },
      { ...base, line: 6, evidence: 'src/links.js:6 — interpolated' },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]!.line).toBe(2);
    expect(out[0]!.evidence).toMatch(/also at src\/links\.js:6/);
  });

  it('keeps genuinely different defects apart', async () => {
    const { dedupeProposals } = await import('../src/llm/passes.js');
    const mk = (title: string, file: string) => ({
      title, severity: 'High' as const, type: 'Security' as const, file, line: 1,
      evidence: `${file}:1 — x`, whyThisMatters: 'x', recommendation: 'y', confidenceSelfReported: 'high',
    });
    expect(dedupeProposals([mk('A', 'src/a.ts'), mk('B', 'src/a.ts'), mk('A', 'src/b.ts')])).toHaveLength(3);
  });
});

describe('providerFailureReason', () => {
  it('distinguishes an unavailable provider from a bad answer', async () => {
    const { providerFailureReason } = await import('../src/llm/client.js');
    expect(providerFailureReason("fatal: The model took a moment to warm up and didn't answer in 120s", undefined)).toMatch(/didn't answer in 120s/);
    expect(providerFailureReason('', 'HTTP 429 rate limit exceeded')).toMatch(/rate limit/i);
    expect(providerFailureReason('Here is my analysis: the code looks fine.', undefined)).toBeNull();
  });

  it('treats an exhausted retry chain as unavailability', async () => {
    const { providerFailureReason } = await import('../src/llm/client.js');
    expect(providerFailureReason('warming up the model — retry 3 of 3 in 2s', undefined)).toBeTruthy();
  });
});

describe('offline model pass: the audited source stays on this network', () => {
  const withEnv = (env: Record<string, string | undefined>, fn: () => void): void => {
    const saved = { ...process.env };
    try {
      for (const [k, v] of Object.entries(env)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      fn();
    } finally {
      process.env = saved;
    }
  };

  it('classifies loopback and private-network endpoints as local, everything else as not', () => {
    for (const u of ['http://localhost:11434', 'http://127.0.0.1:1234/v1', 'http://[::1]:11434', 'http://10.0.0.5', 'http://172.20.1.1', 'http://192.168.1.51:11434', 'http://gpu.local', 'http://[fd12::1]/'])
      expect(isLocalEndpoint(u), u).toBe(true);
    for (const u of ['https://api.openai.com/v1', 'https://api.anthropic.com', 'http://172.32.0.1', 'http://8.8.8.8', 'http://localhost.evil.com', 'not a url'])
      expect(isLocalEndpoint(u), u).toBe(false);
  });

  it('accepts OLLAMA_HOST as a bare host:port', () => {
    expect(ollamaBaseUrl(undefined)).toBe('http://127.0.0.1:11434');
    expect(ollamaBaseUrl('0.0.0.0:11434')).toBe('http://0.0.0.0:11434');
    expect(ollamaBaseUrl('https://gpu.example/')).toBe('https://gpu.example');
  });

  it('refuses hosted APIs and never auto-detects when offline', () => {
    withEnv({ ANTHROPIC_API_KEY: 'k', OPENAI_API_KEY: 'k', OPENAI_BASE_URL: undefined, SENTINEL_BANDIT_CLI: undefined }, () => {
      expect(detectProvider({ offline: true }).available).toBe(false);
      expect(detectProvider({ offline: true, provider: 'anthropic' }).available).toBe(false);
      expect(detectProvider({ offline: true, provider: 'openai' }).available).toBe(false);
    });
    withEnv({ OPENAI_BASE_URL: 'http://127.0.0.1:1234/v1', OPENAI_API_KEY: undefined }, () => {
      expect(detectProvider({ offline: true, provider: 'openai' }).available).toBe(true);
    });
    withEnv({ OLLAMA_HOST: 'https://ollama.example.com' }, () => {
      expect(detectProvider({ offline: true, provider: 'ollama' }).available).toBe(false);
    });
    withEnv({ OLLAMA_HOST: undefined }, () => {
      expect(detectProvider({ offline: true, provider: 'ollama' }).kind).toBe('ollama');
    });
  });
});

describe('ollama provider', () => {
  let server: Server;
  let base = '';
  const bodies: unknown[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        res.setHeader('content-type', 'application/json');
        if (req.url === '/api/tags') return res.end(JSON.stringify({ models: [{ name: 'kimi-k3:cloud', remote_host: 'https://ollama.com' }, { name: 'qwen3-coder:30b' }, { name: 'gemma4:e4b' }] }));
        if (req.url === '/api/chat') {
          bodies.push(JSON.parse(data));
          return res.end(JSON.stringify({ message: { role: 'assistant', content: '[{"ok":true}]' } }));
        }
        res.statusCode = 404;
        res.end('{}');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const addr = server.address();
    base = `127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
  });

  afterAll(() => {
    server.close();
  });

  it('uses the first installed model when none is named, and says so', async () => {
    const saved = process.env.OLLAMA_HOST;
    process.env.OLLAMA_HOST = base;
    try {
      const p = detectProvider({ provider: 'ollama', offline: true });
      const r = await p.complete('hello', { maxTokens: 64 });
      expect(r.ok).toBe(true);
      expect(r.text).toBe('[{"ok":true}]');
      expect(bodies.at(-1)).toMatchObject({ model: 'qwen3-coder:30b', stream: false, options: { num_predict: 64 } });
      expect(p.label).toContain('qwen3-coder:30b');
      expect(p.note).toMatch(/first installed/);
      expect(bodies.some((b) => (b as { model: string }).model.endsWith(':cloud'))).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.OLLAMA_HOST;
      else process.env.OLLAMA_HOST = saved;
    }
  });

  it('refuses a named cloud model offline, before any prompt is sent', async () => {
    const saved = process.env.OLLAMA_HOST;
    process.env.OLLAMA_HOST = base;
    try {
      const sent = bodies.length;
      const r = await detectProvider({ provider: 'ollama', model: 'kimi-k3:cloud', offline: true }).complete('secret source');
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/--offline refuses kimi-k3:cloud/);
      expect(bodies.length).toBe(sent);
    } finally {
      if (saved === undefined) delete process.env.OLLAMA_HOST;
      else process.env.OLLAMA_HOST = saved;
    }
  });

  it('uses --model when given', async () => {
    const saved = process.env.OLLAMA_HOST;
    process.env.OLLAMA_HOST = base;
    try {
      await detectProvider({ provider: 'ollama', model: 'gemma4:e4b' }).complete('hi');
      expect(bodies.at(-1)).toMatchObject({ model: 'gemma4:e4b' });
    } finally {
      if (saved === undefined) delete process.env.OLLAMA_HOST;
      else process.env.OLLAMA_HOST = saved;
    }
  });
});
