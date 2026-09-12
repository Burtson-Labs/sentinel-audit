import { describe, it, expect } from 'vitest';
import { maskSource } from '../src/util/lex.js';
import { ALL_RULES, ruleById, isVendoredArtifact } from '../src/rules/index.js';
import type { RuleFileContext, RuleRepoContext } from '../src/rules/types.js';
import type { RepoFile } from '../src/util/fsx.js';

function fileCtx(path: string, src: string, isTest = false): RuleFileContext {
  const file: RepoFile = {
    path,
    absolute: `/repo/${path}`,
    bytes: src.length,
    ext: `.${path.split('.').pop()}`,
    binary: false,
  };
  return { file, src, masked: maskSource(src), isTest, root: '/repo' };
}

function repoCtx(files: Record<string, string>): RuleRepoContext {
  const texts = new Map(Object.entries(files));
  const masked = new Map([...texts].map(([p, t]) => [p, maskSource(t)] as const));
  return {
    root: '/repo',
    files: [...texts.keys()].map((p) => ({ path: p, absolute: `/repo/${p}`, bytes: 0, ext: `.${p.split('.').pop()}`, binary: false })),
    texts,
    masked,
    isTest: (p) => /\.(test|spec)\./.test(p),
  };
}

const scan = (id: string, path: string, src: string, isTest = false) => {
  const rule = ruleById(id);
  if (!rule?.scan) throw new Error(`no per-file rule ${id}`);
  return rule.scan(fileCtx(path, src, isTest));
};

const aggregate = (id: string, files: Record<string, string>) => {
  const rule = ruleById(id);
  if (!rule?.aggregate) throw new Error(`no aggregate rule ${id}`);
  return rule.aggregate(repoCtx(files));
};

describe('rule registry', () => {
  it('has unique rule ids', () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every rule a claim type, a why, and acceptance criteria', () => {
    for (const r of ALL_RULES) {
      expect(['factual', 'behavioral']).toContain(r.claimType);
      expect(r.why.length).toBeGreaterThan(40);
      expect(r.acceptance.length).toBeGreaterThan(0);
      expect(r.recommendation.length).toBeGreaterThan(20);
    }
  });

  it('gives every rule a fix plan that explains itself', () => {
    for (const r of ALL_RULES) {
      const plan = r.fixPlan([{ ruleId: r.id, file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm' }], repoCtx({}));
      expect(plan.strategy.length).toBeGreaterThan(20);
      if (plan.agentExecutable) expect(plan.agentPrompt, `${r.id} claims agent-executable`).toBeTruthy();
      else expect(plan.notAgentExecutableReason, `${r.id} must say why not`).toBeTruthy();
    }
  });

  it('declares every rule as per-file or aggregate, never neither', () => {
    for (const r of ALL_RULES) expect(Boolean(r.scan || r.aggregate), r.id).toBe(true);
  });
});

describe('SEC-XSS-DANGEROUS-HTML', () => {
  it('flags innerHTML assigned a call result', () => {
    const hits = scan('SEC-XSS-DANGEROUS-HTML', 'src/a.ts', 'el.innerHTML = render(input);\n');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(1);
  });

  it('ignores a constant string literal', () => {
    expect(scan('SEC-XSS-DANGEROUS-HTML', 'src/a.ts', "el.innerHTML = '';\n")).toHaveLength(0);
  });

  it('ignores an occurrence inside a comment', () => {
    expect(scan('SEC-XSS-DANGEROUS-HTML', 'src/a.ts', '// el.innerHTML = render(x);\nconst a = 1;\n')).toHaveLength(0);
  });

  it('flags dangerouslySetInnerHTML with a dynamic value', () => {
    const hits = scan('SEC-XSS-DANGEROUS-HTML', 'src/a.tsx', '<div dangerouslySetInnerHTML={{ __html: body }} />\n');
    expect(hits).toHaveLength(1);
  });

  it('notes when a sanitiser name appears on the same line', () => {
    const hits = scan('SEC-XSS-DANGEROUS-HTML', 'src/a.ts', 'el.innerHTML = DOMPurify.sanitize(x);\n');
    expect(hits[0]!.meta?.sanitiserNearby).toBe(true);
  });
});

describe('SEC-TOKEN-WEBSTORAGE', () => {
  it('flags a credential-shaped key', () => {
    const hits = scan('SEC-TOKEN-WEBSTORAGE', 'src/a.ts', "localStorage.setItem('auth.token', t);\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.longLived).toBe(true);
    expect(hits[0]!.meta?.isWrite).toBe(true);
  });

  it('does not match the store name itself — sessionStorage is not a credential', () => {
    expect(scan('SEC-TOKEN-WEBSTORAGE', 'src/a.ts', "sessionStorage.setItem(makeKey(id), JSON.stringify(events));\n")).toHaveLength(0);
  });

  it('ignores UI preference keys', () => {
    expect(scan('SEC-TOKEN-WEBSTORAGE', 'src/a.ts', "localStorage.setItem('theme', 'dark');\n")).toHaveLength(0);
  });

  it('marks short-lived protocol values as such rather than as credentials', () => {
    const hits = scan('SEC-TOKEN-WEBSTORAGE', 'src/a.ts', "sessionStorage.setItem('oidc.verifier', v);\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.protocolValue).toBe(true);
    expect(hits[0]!.meta?.longLived).toBe(false);
    expect(hits[0]!.message).toMatch(/short-lived protocol value/);
  });

  it('picks up a computed key via the identifier name', () => {
    const hits = scan('SEC-TOKEN-WEBSTORAGE', 'src/a.ts', 'localStorage.setItem(TOKEN_KEY, token);\n');
    expect(hits).toHaveLength(1);
  });
});

describe('SEC-CHILD-PROCESS-SHELL', () => {
  it('flags an interpolated exec', () => {
    const hits = scan('SEC-CHILD-PROCESS-SHELL', 'src/a.ts', 'exec(`git checkout ${branch}`);\n');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.interpolated).toBe(true);
  });

  it('flags spawn with shell:true', () => {
    const hits = scan('SEC-CHILD-PROCESS-SHELL', 'src/a.ts', "spawn(cmd, args, { shell: true });\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.shellTrue).toBe(true);
  });

  it('leaves an argv-form execFile alone', () => {
    expect(scan('SEC-CHILD-PROCESS-SHELL', 'src/a.ts', "execFile('git', ['status']);\n")).toHaveLength(0);
  });

  it('downgrades severity when no call carries an influenced value', () => {
    const rule = ruleById('SEC-CHILD-PROCESS-SHELL')!;
    const constant = [{ ruleId: rule.id, file: 'a.ts', line: 1, excerpt: '', message: '', meta: { interpolated: false, shellTrue: false } }];
    const risky = [{ ruleId: rule.id, file: 'a.ts', line: 1, excerpt: '', message: '', meta: { interpolated: true } }];
    expect(rule.severityFor!(constant)).toBe('Low');
    expect(rule.severityFor!(risky)).toBe('High');
  });
});

describe('SEC-WEAK-CRYPTO', () => {
  it('flags md5', () => {
    const hits = scan('SEC-WEAK-CRYPTO', 'src/a.ts', "createHash('md5').update(x);\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('hash');
  });

  it('ignores Math.random for a UI value', () => {
    expect(scan('SEC-WEAK-CRYPTO', 'src/a.ts', 'const id = Math.random().toString(36);\n')).toHaveLength(0);
  });

  it('flags Math.random in a token context', () => {
    const hits = scan('SEC-WEAK-CRYPTO', 'src/a.ts', 'const token = Math.random().toString(36);\n');
    expect(hits).toHaveLength(1);
  });

  it('recognises a CSPRNG fallback branch and downgrades it', () => {
    const src = [
      'const c = globalThis.crypto;',
      'if (c?.getRandomValues) c.getRandomValues(arr);',
      'else for (let i = 0; i < n; i += 1) arr[i] = Math.floor(Math.random() * 256);',
      '',
    ].join('\n');
    const hits = scan('SEC-WEAK-CRYPTO', 'src/a.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.csprngFallback).toBe(true);
    expect(ruleById('SEC-WEAK-CRYPTO')!.severityFor!(hits)).toBe('Low');
  });
});

describe('SEC-HTTP-ENDPOINT', () => {
  it('flags a routable plaintext host', () => {
    const hits = scan('SEC-HTTP-ENDPOINT', 'src/a.ts', "const api = 'http://api.production.io/v1';\n");
    expect(hits).toHaveLength(1);
  });

  it('ignores loopback and reserved TLDs', () => {
    const src = [
      "const a = 'http://localhost:3000';",
      "const b = 'http://127.0.0.1:8080';",
      "const c = 'http://service.local';",
      "const d = 'http://api.example.com';",
      '',
    ].join('\n');
    expect(scan('SEC-HTTP-ENDPOINT', 'src/a.ts', src)).toHaveLength(0);
  });

  it('ignores RFC1918 LAN addresses', () => {
    expect(scan('SEC-HTTP-ENDPOINT', 'src/a.ts', "const nas = 'http://10.0.0.5:9000';\n")).toHaveLength(0);
  });

  it('ignores a namespace URI', () => {
    expect(scan('SEC-HTTP-ENDPOINT', 'src/a.ts', "const SCHEMA = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';\n")).toHaveLength(0);
  });

  it('ignores a URL mentioned only in a comment', () => {
    expect(scan('SEC-HTTP-ENDPOINT', 'src/a.ts', '// "README.md" became http://readme.md (Moldova)\nconst a = 1;\n')).toHaveLength(0);
  });

  it('does not apply to licence or markdown files', () => {
    const rule = ruleById('SEC-HTTP-ENDPOINT')!;
    const mk = (path: string): RepoFile => ({ path, absolute: `/repo/${path}`, bytes: 1, ext: `.${path.split('.').pop()}`, binary: false });
    expect(rule.appliesTo!(mk('LICENSE'))).toBe(false);
    expect(rule.appliesTo!(mk('docs/guide.md'))).toBe(false);
    expect(rule.appliesTo!(mk('src/a.ts'))).toBe(true);
  });
});

describe('SEC-SECRET-IN-CLIENT-BUNDLE', () => {
  it('flags a credential-shaped public build variable', () => {
    const hits = scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'src/a.ts', 'const t = import.meta.env.VITE_OTLP_TOKEN;\n');
    expect(hits).toHaveLength(1);
  });

  it('ignores a locator even when it contains a credential word', () => {
    expect(scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'src/a.ts', 'const u = import.meta.env.VITE_OIDC_TOKEN_URL;\n')).toHaveLength(0);
  });

  it('notes a publishable key rather than treating it as a leak', () => {
    const hits = scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'src/a.ts', 'const k = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY;\n');
    expect(hits[0]!.meta?.benign).toBe(true);
  });
});

describe('SEC-UNAUTH-HANDLER', () => {
  it('flags a route with no auth in the chain', () => {
    const hits = scan('SEC-UNAUTH-HANDLER', 'src/server.ts', "app.post('/v1/turns', handler);\n");
    expect(hits).toHaveLength(1);
  });

  it('stays silent when the route carries an auth middleware', () => {
    expect(scan('SEC-UNAUTH-HANDLER', 'src/server.ts', "app.post('/v1/turns', requireAuth, handler);\n")).toHaveLength(0);
  });

  it('stays silent when a global guard is mounted earlier in the file', () => {
    const src = "app.use(authenticate);\napp.post('/v1/turns', handler);\n";
    expect(scan('SEC-UNAUTH-HANDLER', 'src/server.ts', src)).toHaveLength(0);
  });

  it('marks conventionally public paths', () => {
    const hits = scan('SEC-UNAUTH-HANDLER', 'src/server.ts', "app.get('/healthz', handler);\n");
    expect(hits[0]!.meta?.publicByDesign).toBe(true);
  });

  it('skips test files entirely', () => {
    expect(scan('SEC-UNAUTH-HANDLER', 'src/server.test.ts', "app.post('/x', h);\n", true)).toHaveLength(0);
  });
});

describe('SEC-POSTMESSAGE-ORIGIN', () => {
  it('flags a listener with no origin check', () => {
    const hits = scan('SEC-POSTMESSAGE-ORIGIN', 'src/a.ts', "window.addEventListener('message', (e) => handle(e.data));\n");
    expect(hits).toHaveLength(1);
  });

  it('stays silent when origin is checked', () => {
    const src = "window.addEventListener('message', (e) => { if (e.origin !== expected) return; handle(e.data); });\n";
    expect(scan('SEC-POSTMESSAGE-ORIGIN', 'src/a.ts', src)).toHaveLength(0);
  });

  it('flags a wildcard target origin', () => {
    const hits = scan('SEC-POSTMESSAGE-ORIGIN', 'src/a.ts', "frame.postMessage(payload, '*');\n");
    expect(hits.some((h) => h.meta?.kind === 'send')).toBe(true);
  });
});

describe('aggregate rules', () => {
  it('QUA-SWALLOWED-CATCH finds an empty catch and an explained one', () => {
    const hits = aggregate('QUA-SWALLOWED-CATCH', {
      'src/a.ts': 'try { x(); } catch {}\ntry { y(); } catch (e) { /* deliberate: best effort */ }\n',
    });
    expect(hits).toHaveLength(2);
    expect(hits.filter((h) => h.meta?.explained === true)).toHaveLength(1);
  });

  it('QUA-SWALLOWED-CATCH ignores a catch that handles the error', () => {
    const hits = aggregate('QUA-SWALLOWED-CATCH', { 'src/a.ts': 'try { x(); } catch (e) { log(e); }\n' });
    expect(hits).toHaveLength(0);
  });

  it('QUA-TEST-THINNESS fires when there are no tests', () => {
    const hits = aggregate('QUA-TEST-THINNESS', { 'src/a.ts': 'export const a = 1;\n', 'src/b.ts': 'export const b = 2;\n' });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.tests).toBe(0);
  });

  it('QUA-TEST-THINNESS stays silent at a healthy ratio', () => {
    const hits = aggregate('QUA-TEST-THINNESS', {
      'src/a.ts': 'export const a = 1;\n',
      'src/a.test.ts': 'it("works", () => {});\n',
    });
    expect(hits).toHaveLength(0);
  });

  it('SEC-CSP-MISSING fires for an HTML app with no policy', () => {
    const hits = aggregate('SEC-CSP-MISSING', { 'index.html': '<head><meta charset="utf-8"></head>\n' });
    expect(hits).toHaveLength(1);
  });

  it('SEC-CSP-MISSING stays silent when a meta policy exists', () => {
    const hits = aggregate('SEC-CSP-MISSING', {
      'index.html': `<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head>\n`,
    });
    expect(hits).toHaveLength(0);
  });

  it('SEC-CSP-MISSING does not fire for a non-web project', () => {
    expect(aggregate('SEC-CSP-MISSING', { 'src/index.ts': 'export const a = 1;\n' })).toHaveLength(0);
  });

  it('SEC-SOURCEMAP-PUBLISHED ignores a mode-gated setting', () => {
    const gated = aggregate('SEC-SOURCEMAP-PUBLISHED', { 'vite.config.ts': 'export default { build: { sourcemap: mode === "development" ? true : false } };\n' });
    expect(gated).toHaveLength(0);
  });

  it('SEC-SOURCEMAP-PUBLISHED flags an unconditional setting', () => {
    const hits = aggregate('SEC-SOURCEMAP-PUBLISHED', { 'vite.config.ts': 'export default { build: { sourcemap: true } };\n' });
    expect(hits).toHaveLength(1);
  });
});

describe('isVendoredArtifact', () => {
  it('detects a minified bundle by name', () => {
    expect(isVendoredArtifact('public/app.min.js', 'var a=1;')).toBe(true);
  });

  it('detects a build output directory', () => {
    expect(isVendoredArtifact('dist/index.js', 'export const a = 1;')).toBe(true);
  });

  it('detects a sourcemap comment', () => {
    expect(isVendoredArtifact('src/weird.js', 'var a=1;\n//# sourceMappingURL=weird.js.map')).toBe(true);
  });

  it('detects a generated-file banner', () => {
    expect(isVendoredArtifact('src/api.ts', '// @generated by openapi-codegen\nexport const x = 1;')).toBe(true);
  });

  it('detects a bundle by line length', () => {
    expect(isVendoredArtifact('src/thing.js', `var a=${'1,'.repeat(1200)}2;`)).toBe(true);
  });

  it('leaves hand-written source alone', () => {
    const src = Array.from({ length: 300 }, (_, i) => `const v${i} = ${i};`).join('\n');
    expect(isVendoredArtifact('public/exthost.cjs', src)).toBe(false);
  });
});

describe('SEC-WEAK-CRYPTO fix plan', () => {
  it('is not agent-executable when every site is a correct CSPRNG fallback', () => {
    const rule = ruleById('SEC-WEAK-CRYPTO')!;
    const fallbackOnly = [{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: '', message: '', meta: { kind: 'prng', csprngFallback: true } }];
    const plan = rule.fixPlan(fallbackOnly, repoCtx({}));
    expect(plan.agentExecutable).toBe(false);
    expect(plan.notAgentExecutableReason).toMatch(/fallback/);
  });

  it('is agent-executable for a genuinely broken primitive', () => {
    const rule = ruleById('SEC-WEAK-CRYPTO')!;
    const md5 = [{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: '', message: '', meta: { kind: 'hash' } }];
    const plan = rule.fixPlan(md5, repoCtx({}));
    expect(plan.agentExecutable).toBe(true);
    expect(plan.agentPrompt).toBeTruthy();
  });
});
