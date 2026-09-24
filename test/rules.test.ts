import { describe, it, expect } from 'vitest';
import { maskSource } from '../src/util/lex.js';
import { ALL_RULES, ruleById, isVendoredArtifact } from '../src/rules/index.js';
import { classifyOperand, negativePredicateName, sameFieldComparison, wordTokens } from '../src/rules/crypto.js';
import { declaresHeader, isEdgeConfigPath, SECURITY_HEADERS, surveyCsp, surveyEdgeConfig } from '../src/util/edge.js';
import { inSortComparator } from '../src/rules/security.js';
import { isPolicyDeclaration } from '../src/verify/index.js';
import type { RuleFileContext, RuleRepoContext } from '../src/rules/types.js';
import type { RepoFile } from '../src/util/fsx.js';

/** An ingress that sets the policy through a snippet annotation rather than a conf file. */
const INGRESS_WITH_CSP_SNIPPET = [
  'ingress:',
  '  enabled: true',
  '  annotations:',
  '    nginx.ingress.kubernetes.io/configuration-snippet: |',
  `      add_header Content-Security-Policy "default-src 'self'" always;`,
  '',
].join('\n');

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

  it('does not mistake RegExp.prototype.exec for child_process.exec', () => {
    const src = [
      "import { exec } from 'node:child_process';",
      'const TAG = /^\\$[A-Za-z_]*\\$/;',
      'export function scanSql(sql: string) {',
      '  const m = TAG.exec(sql);',
      '  return FORBIDDEN.exec(sql) ?? m;',
      '}',
      '',
    ].join('\n');
    expect(scan('SEC-CHILD-PROCESS-SHELL', 'src/postgres.ts', src)).toHaveLength(0);
  });

  it('stays silent for a regex-literal receiver', () => {
    const src = ['const FORBIDDEN = /DROP/i;', 'export const bad = (sql: string) => FORBIDDEN.exec(sql);', ''].join('\n');
    expect(scan('SEC-CHILD-PROCESS-SHELL', 'src/postgres.ts', src)).toHaveLength(0);
  });

  it('still flags a namespace-imported child_process call', () => {
    const src = ["import * as cp from 'node:child_process';", 'cp.exec(`git checkout ${branch}`);', ''].join('\n');
    const hits = scan('SEC-CHILD-PROCESS-SHELL', 'src/a.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.interpolated).toBe(true);
  });

  it('downgrades severity when no call carries an influenced value', () => {
    const rule = ruleById('SEC-CHILD-PROCESS-SHELL')!;
    const constant = [{ ruleId: rule.id, file: 'a.ts', line: 1, excerpt: '', message: '', meta: { interpolated: false, shellTrue: false } }];
    const risky = [{ ruleId: rule.id, file: 'a.ts', line: 1, excerpt: '', message: '', meta: { interpolated: true } }];
    expect(rule.severityFor!(constant)).toBe('Low');
    expect(rule.severityFor!(risky)).toBe('High');
  });
});

describe('SEC-SECRET-IN-CLIENT-BUNDLE', () => {
  it('flags a credential in a client-inlined build variable', () => {
    const hits = scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'src/api.ts', 'const key = import.meta.env.VITE_STRIPE_SECRET_KEY;\n');
    expect(hits).toHaveLength(1);
  });

  it('flags one declared in a .env file', () => {
    expect(scan('SEC-SECRET-IN-CLIENT-BUNDLE', '.env.production', 'NEXT_PUBLIC_API_TOKEN=abc123\n')).toHaveLength(1);
  });

  it('does not treat a module constant that starts with PUBLIC_ as a build variable', () => {
    const src = ["export const PRIVATE_KEY_FILE = 'audit-signing.key';", "export const PUBLIC_KEY_FILE = 'audit-signing.pub';", ''].join('\n');
    expect(scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'packages/runtime/src/keys.ts', src)).toHaveLength(0);
  });

  it('does not flag a re-export of such a constant', () => {
    expect(scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'packages/runtime/src/index.ts', 'export {\n  PRIVATE_KEY_FILE,\n  PUBLIC_KEY_FILE,\n} from "./keys.js";\n')).toHaveLength(0);
  });

  it('ignores a locator suffix', () => {
    expect(scan('SEC-SECRET-IN-CLIENT-BUNDLE', 'src/a.ts', 'const u = import.meta.env.VITE_OIDC_TOKEN_URL;\n')).toHaveLength(0);
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

  /** A finding whose own evidence says the code is correct must not ask the reader to act. */
  it('triages itself out when every site is a CSPRNG fallback branch', () => {
    const rule = ruleById('SEC-WEAK-CRYPTO')!;
    const fallback = { ruleId: rule.id, file: 'src/a.ts', line: 3, excerpt: 'x', message: 'm', meta: { kind: 'prng', csprngFallback: true } };
    expect(rule.triageFor!([fallback])?.reason).toMatch(/fallback branch of a CSPRNG check/);
    // one real site, and the finding stands
    const real = { ruleId: rule.id, file: 'src/b.ts', line: 9, excerpt: 'x', message: 'm', meta: { kind: 'prng' } };
    expect(rule.triageFor!([fallback, real])).toBeUndefined();
    // an observability id is a different claim, not a dismissal
    const trace = { ruleId: rule.id, file: 'src/c.ts', line: 2, excerpt: 'x', message: 'm', meta: { kind: 'prng', observabilityOnly: true } };
    expect(rule.triageFor!([trace])).toBeUndefined();
    // md5 is never dismissed by this path
    expect(rule.triageFor!([{ ...fallback, meta: { kind: 'hash' } }])).toBeUndefined();
  });
});

describe('SEC-TIMING-UNSAFE-COMPARE', () => {
  const hmacFile = (body: string): string => `import { createHmac } from 'node:crypto';\n${body}`;

  it('flags an HMAC compared with ===', () => {
    const src = hmacFile("const expectedSignature = createHmac('sha256', k).update(b).digest('hex');\nif (expectedSignature === header) accept();\n");
    const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'src/webhook.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.keyed).toBe(true);
    expect(hits[0]!.meta?.operand).toBe('expectedSignature');
  });

  it('flags an API key compared with ==', () => {
    const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', 'if (apiKey == supplied) ok();\n');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.operator).toBe('==');
  });

  it('flags Buffer.compare and Buffer.equals over a token', () => {
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', 'if (Buffer.compare(sessionToken, supplied) === 0) ok();\n')).toHaveLength(1);
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', 'if (storedSecret.equals(given)) ok();\n')).toHaveLength(1);
  });

  it('does not flag copied-token UI state', () => {
    const src = [
      'const [copiedToken, setCopiedToken] = useState<string | null>(null);',
      'const label = copiedToken === link.token ? "copied" : "copy";',
      'setTimeout(() => setCopiedToken((t) => (t === link.token ? null : t)), 1500);',
      '',
    ].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/Artifacts.tsx', src)).toHaveLength(0);
  });

  it('exempts the length guard that precedes timingSafeEqual', () => {
    const src = [
      "import { timingSafeEqual } from 'node:crypto';",
      'export function same(a: Buffer, givenToken: Buffer): boolean {',
      '  if (a.length !== givenToken.length) return false;',
      '  return timingSafeEqual(a, givenToken);',
      '}',
      '',
    ].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', src)).toHaveLength(0);
  });

  it('does not let an import of timingSafeEqual silence the rest of the module', () => {
    const src = [
      "import { timingSafeEqual } from 'node:crypto';",
      'export function safe(a: Buffer, givenToken: Buffer): boolean {',
      '  return timingSafeEqual(a, givenToken);',
      '}',
      'export function unsafe(apiKey: string, supplied: string): boolean {',
      '  return apiKey === supplied;',
      '}',
      '',
    ].join('\n');
    const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(6);
  });

  it('ignores an unkeyed content hash, which is not a timing oracle', () => {
    const src = ['const computedHash = await sha256Hex(content);', 'if (computedHash !== claimedHash) fail();', ''].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/verify.ts', src)).toHaveLength(0);
  });

  it('flags the same comparison once the digest is keyed', () => {
    const src = hmacFile(["const computedMac = createHmac('sha256', key).update(body).digest('hex');", 'if (computedMac !== claimedMac) fail();', ''].join('\n'));
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/verify.ts', src)).toHaveLength(1);
  });

  it('ignores public keys, lengths, null checks and typeof guards', () => {
    const src = [
      'if (embeddedPublicKey !== pinnedPublicKey) warn();',
      'if (claimedHash.length === 64) ok();',
      'if (privateKey !== undefined) use();',
      "if (typeof raw.hash === 'string') ok();",
      '',
    ].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', src)).toHaveLength(0);
  });

  it('ignores metadata about a secret rather than the secret', () => {
    const src = ['const selected = secret.id === selectedId;', 'const label = item.type === secret.type;', 'if (token.kind !== expectedKind) skip();', ''].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/SecretsPanel.tsx', src)).toHaveLength(0);
  });

  it('ignores a password compared against its own confirmation field', () => {
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/ResetPassword.tsx', 'if (password !== confirm) fail();\n')).toHaveLength(0);
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.tsx', 'if (confirmPassword !== password) fail();\n')).toHaveLength(0);
  });

  it('ignores a field-to-field config equality check', () => {
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/client.ts', 'return this.apiKey === options.apiKey;\n')).toHaveLength(0);
  });

  it('ignores "signature" used as a fingerprint in a file that does no crypto', () => {
    const src = ['const signature = buildDiagnosticsSignature(group);', 'if (signature !== previous) changed = true;', ''].join('\n');
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/autoHealer.ts', src)).toHaveLength(0);
  });

  it('downgrades to Low when every site is in a test', () => {
    const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'test/a.test.ts', 'expect(apiKey === supplied).toBe(true);\n', true);
    expect(hits).toHaveLength(1);
    expect(ruleById('SEC-TIMING-UNSAFE-COMPARE')!.severityFor!(hits)).toBe('Low');
  });

  it('ignores a construct that only appears in a comment', () => {
    expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/a.ts', '// never write `apiKey === supplied`\nconst x = 1;\n')).toHaveLength(0);
  });
});

describe('SEC-CRYPTO-IV-REUSE', () => {
  it('flags a module-level constant IV', () => {
    const src = ["const IV = Buffer.from('00112233445566778899aabb', 'hex');", "const c = createCipheriv('aes-256-gcm', key, IV);", ''].join('\n');
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('static');
  });

  it('flags a zero-filled IV passed inline', () => {
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', "const c = createCipheriv('aes-256-gcm', key, Buffer.alloc(12));\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('static');
  });

  it('flags a CSPRNG nonce drawn once at module scope and reused', () => {
    const src = ['const NONCE = randomBytes(12);', "function seal(p) { return createCipheriv('aes-256-gcm', key, NONCE); }", ''].join('\n');
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('module-scope');
  });

  it('flags a clock-derived nonce', () => {
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', "const c = createCipheriv('aes-256-gcm', key, Buffer.from(String(Date.now())));\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('predictable');
  });

  it('flags ECB from the cipher name', () => {
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', "const c = createCipheriv('aes-256-ecb', key, Buffer.alloc(0));\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('ecb');
  });

  it('flags a zero IV in a WebCrypto algorithm object', () => {
    const hits = scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', "await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, data);\n");
    expect(hits).toHaveLength(1);
  });

  it('accepts a per-call CSPRNG nonce', () => {
    const src = ['function seal(p) {', '  const iv = randomBytes(12);', "  return createCipheriv('aes-256-gcm', key, iv);", '}', ''].join('\n');
    expect(scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', src)).toHaveLength(0);
  });

  it('accepts an inline CSPRNG nonce in a WebCrypto call', () => {
    expect(scan('SEC-CRYPTO-IV-REUSE', 'src/crypt.ts', "await crypto.subtle.encrypt({ name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) }, key, data);\n")).toHaveLength(0);
  });

  it('ignores an iv property that belongs to no cipher', () => {
    expect(scan('SEC-CRYPTO-IV-REUSE', 'src/ui.ts', "const layout = { iv: 'auto', counter: 0 };\n")).toHaveLength(0);
  });

  it('never claims an automatable fix, because the ciphertext format changes', () => {
    const plan = ruleById('SEC-CRYPTO-IV-REUSE')!.fixPlan([{ ruleId: 'SEC-CRYPTO-IV-REUSE', file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm' }], repoCtx({}));
    expect(plan.agentExecutable).toBe(false);
    expect(plan.notAgentExecutableReason).toMatch(/undecryptable|data/i);
  });
});

describe('SEC-WEBCRYPTO-MISUSE', () => {
  it('flags an extractable private signing key', () => {
    const hits = scan('SEC-WEBCRYPTO-MISUSE', 'src/keys.ts', "await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('extractable-private-key');
  });

  it('accepts an extractable public verification key', () => {
    expect(scan('SEC-WEBCRYPTO-MISUSE', 'src/keys.ts', "await crypto.subtle.importKey('spki', der, { name: 'Ed25519' }, true, ['verify']);\n")).toHaveLength(0);
  });

  it('accepts a non-extractable private key', () => {
    expect(scan('SEC-WEBCRYPTO-MISUSE', 'src/keys.ts', "await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);\n")).toHaveLength(0);
  });

  it('flags SHA-1 named as an algorithm parameter', () => {
    const hits = scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', "await crypto.subtle.digest('SHA-1', bytes);\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.algorithm).toBe('SHA-1');
  });

  it('leaves createHash("md5") to SEC-WEAK-CRYPTO rather than double-reporting it', () => {
    expect(scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', "crypto.createHash('md5').update(name).digest('hex');\n")).toHaveLength(0);
    expect(scan('SEC-WEAK-CRYPTO', 'src/a.ts', "crypto.createHash('md5').update(name).digest('hex');\n")).toHaveLength(1);
  });

  it('flags a PBKDF2 cost below the floor and accepts one above it', () => {
    const weak = scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', "await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, base, 256);\n");
    expect(weak.filter((h) => h.meta?.kind === 'weak-kdf')).toHaveLength(1);
    expect(scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', "await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);\n")).toHaveLength(0);
  });

  it('ignores an iteration count that has nothing to do with a KDF', () => {
    expect(scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', 'const opts = { iterations: 3, backoffMs: 200 };\n')).toHaveLength(0);
  });

  it('flags a truncated AES-GCM tag', () => {
    const hits = scan('SEC-WEBCRYPTO-MISUSE', 'src/a.ts', "await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 32 }, key, data);\n");
    expect(hits.filter((h) => h.meta?.kind === 'short-tag')).toHaveLength(1);
  });

  it('refuses to automate a digest or KDF change, because stored values depend on it', () => {
    const rule = ruleById('SEC-WEBCRYPTO-MISUSE')!;
    const kdf = rule.fixPlan([{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm', meta: { kind: 'weak-kdf' } }], repoCtx({}));
    expect(kdf.agentExecutable).toBe(false);
    const flag = rule.fixPlan([{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm', meta: { kind: 'extractable-private-key' } }], repoCtx({}));
    expect(flag.agentExecutable).toBe(true);
    expect(flag.agentPrompt).toBeTruthy();
  });
});

describe('SEC-SIGNATURE-VERIFY-DISCARDED', () => {
  it('flags a verification call used as a bare statement', () => {
    const src = ['async function ingest(log, key, sig) {', '  await verifySignature(log, key, sig);', '  accept(log);', '}', ''].join('\n');
    const hits = scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/ingest.ts', src);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('result-discarded');
    expect(ruleById('SEC-SIGNATURE-VERIFY-DISCARDED')!.severityFor!(hits)).toBe('Blocker');
  });

  it('accepts a verification result that is used', () => {
    const src = [
      'const ok = await verifyLog(content, { publicKey });',
      'if (!(await verifySignature(a, b, c))) throw new Error("bad signature");',
      'return timingSafeEqual(a, b);',
      '',
    ].join('\n');
    expect(scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/a.ts', src)).toHaveLength(0);
  });

  it('accepts a callback-style verify, which reports through its callback', () => {
    expect(scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/a.ts', 'jwt.verify(token, secret, (err, decoded) => done(err, decoded));\n')).toHaveLength(0);
  });

  it('flags a catch that turns failed verification into success', () => {
    const src = [
      'async function checkSig(log, key, sig) {',
      '  try {',
      "    return await crypto.subtle.verify('Ed25519', key, sig, log);",
      '  } catch {',
      '    return true;',
      '  }',
      '}',
      '',
    ].join('\n');
    const hits = scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/a.ts', src);
    expect(hits.filter((h) => h.meta?.kind === 'fail-open-catch')).toHaveLength(1);
  });

  it('accepts a negative predicate whose catch returns true to fail closed', () => {
    const src = [
      'function isTokenExpired(token: string): boolean {',
      '  try {',
      '    const decoded = this.parseJwtClaims(token);',
      '    if (!decoded) return true;',
      '    return decoded.exp * 1000 < Date.now();',
      '  } catch {',
      '    return true;',
      '  }',
      '}',
      '',
    ].join('\n');
    expect(scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/auth.ts', src)).toHaveLength(0);
  });

  it('flags a runtime switch that can turn verification off, once per line', () => {
    const hits = scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/a.ts', "export const SKIP_SIGNATURE_VERIFICATION = process.env.SKIP_SIGNATURE_VERIFICATION === '1';\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.kind).toBe('bypass-switch');
    expect(ruleById('SEC-SIGNATURE-VERIFY-DISCARDED')!.severityFor!(hits)).toBe('High');
  });

  it('flags the none algorithm being accepted', () => {
    const hits = scan('SEC-SIGNATURE-VERIFY-DISCARDED', 'src/a.ts', "jwt.verify(t, k, { algorithms: ['none'] });\n");
    expect(hits.filter((h) => h.meta?.kind === 'alg-none')).toHaveLength(1);
  });

  it('treats a bypass switch as advisory and everything else as automatable', () => {
    const rule = ruleById('SEC-SIGNATURE-VERIFY-DISCARDED')!;
    const onlySwitch = rule.fixPlan([{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm', meta: { kind: 'bypass-switch' } }], repoCtx({}));
    expect(onlySwitch.agentExecutable).toBe(false);
    const discarded = rule.fixPlan([{ ruleId: rule.id, file: 'src/a.ts', line: 1, excerpt: 'x', message: 'm', meta: { kind: 'result-discarded' } }], repoCtx({}));
    expect(discarded.agentExecutable).toBe(true);
  });
});

describe('crypto rule helpers', () => {
  it('splits identifiers into words without catching lookalikes', () => {
    expect(wordTokens('claimedSig')).toEqual(['claimed', 'sig']);
    expect(wordTokens('raw.prevHash')).toEqual(['raw', 'prev', 'hash']);
    expect(wordTokens('AUTH_TAG')).toEqual(['auth', 'tag']);
    expect(classifyOperand('signal')).toBeNull();
    expect(classifyOperand('macOsVersion')).toBeNull();
  });

  it('treats public key material as public', () => {
    expect(classifyOperand('embeddedPublicKey')).toBeNull();
    expect(classifyOperand('pubkey')).toBeNull();
  });

  it('requires a crypto context before believing "signature" means a signature', () => {
    expect(classifyOperand('signature', false)).toBeNull();
    expect(classifyOperand('signature', true)).toBe('keyed');
    expect(classifyOperand('apiKey', false)).toBe('keyed');
  });

  /**
   * Regression suite for six identical wrong High findings: the stale-async-result
   * idiom compares an integer sequence number called `token`, in files that do no
   * crypto at all.
   */
  describe('"token" has to earn the authenticator classification', () => {
    const STALE_GUARD = [
      'import { useRef } from "react";',
      'export function useSearch() {',
      '  const tokenRef = useRef(0);',
      '  const run = async (q: string) => {',
      '    const token = ++tokenRef.current;',
      '    const rows = await search(q);',
      '    if (token !== tokenRef.current) return;',
      '    setRows(rows);',
      '  };',
      '  return run;',
      '}',
      '',
    ].join('\n');

    const CLASS_COUNTER = [
      'export class Player {',
      '  private token = 0;',
      '  async load(src: string) {',
      '    const myToken = ++this.token;',
      '    const buf = await fetchAudio(src);',
      '    if (myToken !== this.token) return;',
      '    this.play(buf);',
      '  }',
      '}',
      '',
    ].join('\n');

    it('does not report a counter named token in a file with no crypto', () => {
      expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/useSearch.ts', STALE_GUARD)).toHaveLength(0);
      expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/player.ts', CLASS_COUNTER)).toHaveLength(0);
    });

    it('disqualifies a counter-valued operand even inside a crypto module', () => {
      const src = [
        'import { createHmac } from "node:crypto";',
        'export function sign(body: string, key: string) {',
        '  const token = ++counterRef.current;',
        '  const mac = createHmac("sha256", key).update(body).digest("hex");',
        '  if (token !== counterRef.current) return null;',
        '  return mac;',
        '}',
        '',
      ].join('\n');
      expect(scan('SEC-TIMING-UNSAFE-COMPARE', 'src/sign.ts', src)).toHaveLength(0);
    });

    it('still reports a real token comparison in a file that does crypto', () => {
      const src = [
        'import { createHmac } from "node:crypto";',
        'const SECRET_TOKEN = process.env.SECRET_TOKEN ?? "";',
        'export function authorise(providedToken: string, body: string) {',
        '  if (providedToken !== SECRET_TOKEN) throw new Error("denied");',
        '  return createHmac("sha256", SECRET_TOKEN).update(body).digest("hex");',
        '}',
        '',
      ].join('\n');
      const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'src/authorise.ts', src);
      expect(hits).toHaveLength(1);
      expect(hits[0]!.meta?.keyed).toBe(true);
      expect(ruleById('SEC-TIMING-UNSAFE-COMPARE')!.severityFor!(hits)).toBe('High');
    });

    it('still reports a bearer token from a request header in a file with no crypto primitives', () => {
      const src = [
        'export function guard(req: Request) {',
        '  const suppliedToken = req.headers.get("x-api-token") ?? "";',
        '  const expectedToken = process.env.API_TOKEN ?? "";',
        '  if (suppliedToken !== expectedToken) return deny();',
        '  return next();',
        '}',
        '',
      ].join('\n');
      const hits = scan('SEC-TIMING-UNSAFE-COMPARE', 'src/guard.ts', src);
      expect(hits).toHaveLength(1);
      expect(hits[0]!.meta?.keyed).toBe(true);
    });

    it('classifies the operand from its assignment, not only its name', () => {
      expect(classifyOperand('token', false, 'const token = ++tokenRef.current;')).toBeNull();
      expect(classifyOperand('token', false, 'const token = Date.now();')).toBeNull();
      expect(classifyOperand('tokenRef.current', false, 'const tokenRef = useRef(0);')).toBeNull();
      expect(classifyOperand('token', false, 'const token = process.env.API_TOKEN;')).toBe('keyed');
      expect(classifyOperand('token', true, 'const token = req.headers.authorization;')).toBe('keyed');
      // a ref that holds a token rather than a counter is still an authenticator
      expect(classifyOperand('tokenRef.current', false, 'const tokenRef = useRef<string | null>(null);\nconst tokenRef: string = "";')).toBe('keyed');
    });

    it('leaves the unambiguous credential words unconditional', () => {
      expect(classifyOperand('apiKey', false)).toBe('keyed');
      expect(classifyOperand('storedPassword', false)).toBe('keyed');
      expect(classifyOperand('clientSecret', false)).toBe('keyed');
      expect(classifyOperand('csrf', false)).toBe('keyed');
    });
  });

  it('recognises a field-to-field comparison', () => {
    expect(sameFieldComparison('this.apiKey', 'options.apiKey')).toBe(true);
    expect(sameFieldComparison('expectedSignature', 'header')).toBe(false);
    expect(sameFieldComparison('a.token', 'b.supplied')).toBe(false);
  });

  it('only exempts a catch inside a negative predicate', () => {
    expect(negativePredicateName('function isTokenExpired(token: string): boolean {')).toBe(true);
    expect(negativePredicateName('function verifySignature(log, key, sig) {')).toBe(false);
    expect(negativePredicateName('no function here')).toBe(false);
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

/**
 * Regression suite for four wrong findings in a chat application: `role` there
 * names the author of a message, and one of the four was a sort comparator.
 */
describe('SEC-CLIENT-SIDE-AUTHZ', () => {
  it('still reports a real authorisation role check', () => {
    const hits = scan('SEC-CLIENT-SIDE-AUTHZ', 'src/Nav.tsx', "if (user.role === 'admin') return <AdminPanel />;\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta?.predicate).toBe('role===');
  });

  it('still reports the permission and capability predicates', () => {
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.tsx', 'if (isAdmin) showDangerZone();\n')).toHaveLength(1);
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.tsx', "if (permissions.includes('billing:write')) enable();\n")).toHaveLength(1);
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.tsx', "if (user.role === 'owner' || hasRole('editor')) edit();\n")).toHaveLength(1);
  });

  it('does not report a chat message-author role', () => {
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/hooks/useConversation.ts', "if (role === 'assistant' && typeof content === 'string') render(content);\n")).toHaveLength(0);
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/hooks/useConversation.ts', "if (role === 'user' && typeof content === 'string') render(content);\n")).toHaveLength(0);
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/local/turnLog.ts', "if (ev.role === 'user' || ev.role === 'assistant') push(ev);\n")).toHaveLength(0);
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.ts', "if (m.role === 'system') return null;\nif (m.role === 'tool') return toolView(m);\n")).toHaveLength(0);
  });

  it('keeps firing when an authorisation role shares the line with a chat role', () => {
    const hits = scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.tsx', "if (user.role === 'admin' && message.role === 'user') allow();\n");
    expect(hits).toHaveLength(1);
  });

  it('does not report a sort comparator', () => {
    const src = [
      'keys.sort((a, b) => {',
      '  if (!!a.isAdmin !== !!b.isAdmin) return a.isAdmin ? -1 : 1;',
      '  return (b.credits ?? 0) - (a.credits ?? 0);',
      '});',
      '',
    ].join('\n');
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/services/auth/resolveKeySession.ts', src)).toHaveLength(0);
  });

  it('requires all three comparator signals before excusing a predicate', () => {
    // a sort call nearby is not on its own enough to excuse a real guard
    const src = ['items.sort((x, y) => x.name.localeCompare(y.name));', "if (user.isAdmin) showDangerZone();", ''].join('\n');
    expect(scan('SEC-CLIENT-SIDE-AUTHZ', 'src/a.tsx', src)).toHaveLength(1);
    expect(inSortComparator('list.sort((a, b) => {', 'return a.isAdmin ? -1 : 1;')).toBe(true);
    expect(inSortComparator('list.map((a) => {', 'return a.isAdmin ? -1 : 1;')).toBe(false);
    expect(inSortComparator('list.sort((a, b) => {', 'return user.isAdmin;')).toBe(false);
  });
});

describe('SEC-TARGET-BLANK', () => {
  it('accepts rel="noopener"', () => {
    expect(scan('SEC-TARGET-BLANK', 'src/a.tsx', '<a href={url} target="_blank" rel="noopener">docs</a>\n')).toHaveLength(0);
  });

  /** noreferrer implies noopener per spec, so demanding the literal token is advice that changes nothing. */
  it('accepts rel="noreferrer" on its own', () => {
    expect(scan('SEC-TARGET-BLANK', 'src/a.tsx', '<a href={url} target="_blank" rel="noreferrer">docs</a>\n')).toHaveLength(0);
    expect(scan('SEC-TARGET-BLANK', 'index.html', '<a href="/docs" target="_blank" rel="noreferrer">docs</a>\n')).toHaveLength(0);
    expect(scan('SEC-TARGET-BLANK', 'src/a.tsx', '<a href={url} target="_blank" rel="noopener noreferrer">docs</a>\n')).toHaveLength(0);
  });

  it('still flags an anchor with no rel at all', () => {
    const hits = scan('SEC-TARGET-BLANK', 'src/a.tsx', '<a href={url} target="_blank">docs</a>\n');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.message).toMatch(/noreferrer/);
  });

  it('still flags a rel that carries neither token', () => {
    expect(scan('SEC-TARGET-BLANK', 'src/a.tsx', '<a href={url} target="_blank" rel="nofollow">docs</a>\n')).toHaveLength(1);
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

  it('SEC-CSP-MISSING stays silent when the policy is only in an ingress snippet annotation', () => {
    const hits = aggregate('SEC-CSP-MISSING', {
      'index.html': '<head><meta charset="utf-8"></head>\n',
      'charts/app/values.yaml': INGRESS_WITH_CSP_SNIPPET,
    });
    expect(hits).toHaveLength(0);
  });
});

/**
 * Regression suite for the false *negative* that shipped with the first version
 * of this rule: `/add_header\s+Content-Security-Policy/` also matches
 * `Content-Security-Policy-Report-Only`, so an application whose policy blocked
 * nothing was reported as having a CSP. The tool reassured its reader about the
 * one header it was asked to check.
 */
describe('CSP enforcing vs report-only', () => {
  const HTML = '<head><meta charset="utf-8"></head>\n';
  const REPORT_ONLY_CONF = `add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self'" always;\n`;
  const ENFORCING_CONF = `add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;\n`;

  it('classifies a report-only header as enforcing nothing', () => {
    const survey = surveyCsp([['nginx/headers.conf', REPORT_ONLY_CONF]]);
    expect(survey.posture).toBe('report-only');
    expect(survey.enforcing).toHaveLength(0);
    expect(survey.reportOnly).toHaveLength(1);
  });

  it('classifies an enforcing header as enforcing', () => {
    expect(surveyCsp([['nginx/headers.conf', ENFORCING_CONF]]).posture).toBe('enforcing');
  });

  it('lets the enforcing header win when both are served', () => {
    expect(surveyCsp([['nginx/headers.conf', `${REPORT_ONLY_CONF}${ENFORCING_CONF}`]]).posture).toBe('enforcing');
  });

  it('reads a report-only meta tag and a report-only header configuration', () => {
    expect(surveyCsp([['index.html', `<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'">`]]).posture).toBe('report-only');
    expect(surveyCsp([['public/_headers', "  Content-Security-Policy-Report-Only: default-src 'self'\n"]]).posture).toBe('report-only');
  });

  it('treats helmet reportOnly:true as report-only and the plain option as enforcing', () => {
    expect(surveyCsp([['server.ts', "helmet({ contentSecurityPolicy: { reportOnly: true, directives: { defaultSrc: [\"'self'\"] } } })"]]).posture).toBe('report-only');
    expect(surveyCsp([['server.ts', "helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } })"]]).posture).toBe('enforcing');
  });

  it('does not report a missing CSP when one is enforced', () => {
    expect(aggregate('SEC-CSP-MISSING', { 'index.html': HTML, 'nginx/headers.conf': ENFORCING_CONF })).toHaveLength(0);
    expect(aggregate('SEC-CSP-REPORT-ONLY', { 'index.html': HTML, 'nginx/headers.conf': ENFORCING_CONF })).toHaveLength(0);
  });

  it('reports report-only as its own finding, not as a policy that exists', () => {
    const reportOnly = aggregate('SEC-CSP-REPORT-ONLY', { 'index.html': HTML, 'nginx/headers.conf': REPORT_ONLY_CONF });
    expect(reportOnly).toHaveLength(1);
    expect(reportOnly[0]!.message).toContain('report-only');
    expect(reportOnly[0]!.message).toMatch(/blocks nothing/);
    expect(reportOnly[0]!.file).toBe('nginx/headers.conf');
    expect(reportOnly[0]!.line).toBe(1);
    // and the two CSP rules never both fire: this one replaces the absence claim
    expect(aggregate('SEC-CSP-MISSING', { 'index.html': HTML, 'nginx/headers.conf': REPORT_ONLY_CONF })).toHaveLength(0);
  });

  it('still reports the absent policy when neither header exists', () => {
    expect(aggregate('SEC-CSP-MISSING', { 'index.html': HTML, 'nginx/headers.conf': 'add_header X-Frame-Options "DENY" always;\n' })).toHaveLength(1);
    expect(aggregate('SEC-CSP-REPORT-ONLY', { 'index.html': HTML, 'nginx/headers.conf': 'add_header X-Frame-Options "DENY" always;\n' })).toHaveLength(0);
  });

  it('keeps both CSP rules silent for a project with no HTML entry document', () => {
    expect(aggregate('SEC-CSP-REPORT-ONLY', { 'nginx/headers.conf': REPORT_ONLY_CONF })).toHaveLength(0);
  });

  it('does not let a report-only policy refute the missing-CSP finding at verification', () => {
    expect(isPolicyDeclaration(REPORT_ONLY_CONF)).toBe(false);
    expect(isPolicyDeclaration(ENFORCING_CONF)).toBe(true);
    // both present: the enforcing one is the answer, whichever comes first
    expect(isPolicyDeclaration(`${REPORT_ONLY_CONF}${ENFORCING_CONF}`)).toBe(true);
    expect(isPolicyDeclaration('# we should add a Content-Security-Policy one day\n')).toBe(false);
  });
});

/**
 * Regression suite for the false positive that prompted util/edge.ts: HSTS
 * reported absent for an application that sets it at the Kubernetes ingress.
 */
describe('security headers at the edge', () => {
  const CHART_VALUES_WITH_HSTS = [
    'ingress:',
    '  enabled: true',
    '  className: nginx',
    '  annotations:',
    '    kubernetes.io/ingress.class: nginx',
    '    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"',
    '    nginx.ingress.kubernetes.io/hsts: "true"',
    '    nginx.ingress.kubernetes.io/hsts-include-subdomains: "true"',
    '    nginx.ingress.kubernetes.io/hsts-max-age: "31536000"',
    '',
  ].join('\n');

  const hstsSpec = SECURITY_HEADERS.find((h) => h.name === 'Strict-Transport-Security')!;

  it('sees HSTS configured only by ingress annotations', () => {
    expect(declaresHeader(hstsSpec, CHART_VALUES_WITH_HSTS)).toBe(true);
  });

  it('sees HSTS configured only by a Traefik middleware', () => {
    const middleware = ['kind: Middleware', 'spec:', '  headers:', '    stsSeconds: 31536000', '    stsIncludeSubdomains: true', ''].join('\n');
    expect(declaresHeader(hstsSpec, middleware)).toBe(true);
  });

  it('still reports HSTS absent when nothing anywhere sets it', () => {
    const values = ['ingress:', '  enabled: true', '  className: nginx', '  annotations:', '    kubernetes.io/ingress.class: nginx', ''].join('\n');
    expect(declaresHeader(hstsSpec, values)).toBe(false);
  });

  it('treats a Helm chart values file as an edge surface', () => {
    expect(isEdgeConfigPath('charts/web-frontend/values.yaml')).toBe(true);
    expect(isEdgeConfigPath('charts/app/templates/ingress.yaml')).toBe(true);
    expect(isEdgeConfigPath('k8s/ingress.yaml')).toBe(true);
    expect(isEdgeConfigPath('nginx/security-headers.conf')).toBe(true);
    expect(isEdgeConfigPath('src/components/Button.tsx')).toBe(false);
  });

  it('drops the whole finding when every header is set only at the ingress', () => {
    const hits = aggregate('SEC-CSP-MISSING', {
      'index.html': '<head><meta charset="utf-8"></head>\n',
      'charts/app/values.yaml': `${CHART_VALUES_WITH_HSTS}\n`,
      'nginx/security-headers.conf': "add_header Content-Security-Policy \"default-src 'self'\" always;\n",
    });
    expect(hits).toHaveLength(0);
  });

  it('names the edge surfaces it checked when the headers really are absent', () => {
    const hits = aggregate('SEC-CSP-MISSING', {
      'index.html': '<head><meta charset="utf-8"></head>\n',
      'charts/app/values.yaml': 'ingress:\n  enabled: true\n  className: nginx\n',
    });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.message).toMatch(/Strict-Transport-Security/);
    expect(Number(hits[0]!.meta?.edgeSurfaces)).toBeGreaterThan(1);
  });

  it('reports an unresolvable edge surface instead of asserting absence', () => {
    const survey = surveyEdgeConfig([
      ['charts/app/templates/ingress.yaml', 'metadata:\n  annotations:\n    {{- toYaml .Values.ingress.annotations | nindent 4 }}\n'],
    ]);
    expect(survey.surfaces).toHaveLength(1);
    expect(survey.unresolved).toHaveLength(1);
    expect(survey.unresolved[0]).toMatch(/values file that is not in this repository/);
  });

  it('resolves the same template when the chart ships its values file', () => {
    const survey = surveyEdgeConfig([
      ['charts/app/templates/ingress.yaml', 'metadata:\n  annotations:\n    {{- toYaml .Values.ingress.annotations | nindent 4 }}\n'],
      ['charts/app/values.yaml', CHART_VALUES_WITH_HSTS],
    ]);
    expect(survey.unresolved).toHaveLength(0);
  });

  it('does not care which order the chart files are walked in', () => {
    const template: [string, string] = ['charts/app/templates/ingress.yaml', 'metadata:\n  annotations:\n    {{- toYaml .Values.ingress.annotations | nindent 4 }}\n'];
    const values: [string, string] = ['charts/app/values.yaml', CHART_VALUES_WITH_HSTS];
    expect(surveyEdgeConfig([template, values]).unresolved).toEqual(surveyEdgeConfig([values, template]).unresolved);
  });

  it('flags a Traefik middleware reference that is not defined here', () => {
    const survey = surveyEdgeConfig([
      ['k8s/ingress.yaml', 'metadata:\n  annotations:\n    traefik.ingress.kubernetes.io/router.middlewares: "prod-secure-headers@kubernetescrd"\n'],
    ]);
    expect(survey.unresolved).toHaveLength(1);
    expect(survey.unresolved[0]).toMatch(/secure-headers/);
  });

  it('accepts a Traefik middleware reference that resolves in-repo', () => {
    const survey = surveyEdgeConfig([
      ['k8s/ingress.yaml', 'metadata:\n  annotations:\n    traefik.ingress.kubernetes.io/router.middlewares: "prod-secure-headers@kubernetescrd"\n'],
      ['k8s/middleware.yaml', 'kind: Middleware\nmetadata:\n  name: secure-headers\nspec:\n  headers:\n    stsSeconds: 31536000\n'],
    ]);
    expect(survey.unresolved).toHaveLength(0);
  });

  it('flags a templated ingress snippet as uninspectable', () => {
    const survey = surveyEdgeConfig([
      ['charts/app/values.yaml', 'ingress:\n  annotations:\n    nginx.ingress.kubernetes.io/configuration-snippet: {{ .Values.snippet }}\n'],
    ]);
    expect(survey.unresolved.some((u) => /template expression/.test(u))).toBe(true);
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

describe('a rule does not report its own description', () => {
  // The self-scan reported four Highs/Mediums against src/rules/*.ts, every one
  // of them a sentence *about* the construct — a rule's `why`, `acceptance` or
  // agent instructions — living in a string literal. The same words are a
  // finding when they are code or a short value, so both directions are pinned.
  const RULE_PROSE = [
    'export const rules = {',
    "  acceptance: ['no rejectUnauthorized:false and no NODE_TLS_REJECT_UNAUTHORIZED=0 in shipped code', 'internal CAs trusted via the certificate store'],",
    "  detail: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate validation process-wide',",
    "  fix: 'Replace each flagged weak primitive. createHash(\"md5\"|\"sha1\") becomes createHash(\"sha256\") unless the value is a cache key, in which case add a comment saying the hash is non-cryptographic and leave it.',",
    "  why: 'A `message` listener that does not check `event.origin` accepts instructions from any frame or window that can reach it, and `postMessage(data, \"*\")` broadcasts the payload to whatever currently occupies the target.',",
    "  webcrypto: 'WebCrypto takes its parameters as data, so its misuses are invisible to a type checker and silent at runtime: `digest(\"SHA-1\", …)` returns a digest, `importKey(…, true, [\"sign\"])` returns a key.',",
    '};',
    '',
  ].join('\n');

  for (const id of ['SEC-TLS-DISABLED', 'SEC-WEAK-CRYPTO', 'SEC-POSTMESSAGE-ORIGIN', 'SEC-WEBCRYPTO-MISUSE']) {
    it(`${id} is silent on a file of rule prose`, () => {
      const rule = ruleById(id)!;
      expect(rule.scan!(fileCtx('src/rules/security.ts', RULE_PROSE))).toEqual([]);
    });
  }

  it('SEC-TLS-DISABLED still reports the option in code and the env override in a shell string', () => {
    const hits = ruleById('SEC-TLS-DISABLED')!.scan!(
      fileCtx('src/http.ts', "const agent = new Agent({ rejectUnauthorized: false });\nexecSync('NODE_TLS_REJECT_UNAUTHORIZED=0 node dist/server.js');\n"),
    );
    expect(hits.map((h) => h.line)).toEqual([1, 2]);
  });

  it('SEC-WEAK-CRYPTO still reports a real md5 in a signing path', () => {
    const hits = ruleById('SEC-WEAK-CRYPTO')!.scan!(
      fileCtx('src/sign.ts', "import { createHash } from 'node:crypto';\nexport function sign(secret: string): string {\n  return createHash('md5').update(secret).digest('hex');\n}\n"),
    );
    expect(hits.length).toBeGreaterThan(0);
  });

  it('SEC-POSTMESSAGE-ORIGIN still reports a wildcard target in code', () => {
    const hits = ruleById('SEC-POSTMESSAGE-ORIGIN')!.scan!(fileCtx('src/embed.ts', "parent.postMessage({ token }, '*');\n"));
    expect(hits.length).toBeGreaterThan(0);
  });

  it('SEC-WEBCRYPTO-MISUSE still reports a SHA-1 digest passed as a value', () => {
    const hits = ruleById('SEC-WEBCRYPTO-MISUSE')!.scan!(fileCtx('src/digest.ts', "export const d = (data: Uint8Array) => crypto.subtle.digest('SHA-1', data);\n"));
    expect(hits.length).toBeGreaterThan(0);
  });
});

describe('three shapes real scans got wrong', () => {
  it('excludes lockfiles from the code rules — a licence URL in package-lock.json is not an endpoint', () => {
    expect(isVendoredArtifact('package-lock.json', '{ "license": "http://geraintluff.github.io/tv4/LICENSE.txt" }')).toBe(true);
    expect(isVendoredArtifact('pnpm-lock.yaml', 'lockfileVersion: 9')).toBe(true);
    expect(isVendoredArtifact('src/lock.ts', 'export const lock = 1;')).toBe(false);
  });

  it('does not report two properties of one object as an authenticator comparison', () => {
    expect(sameFieldComparison('authCtx.apiKey', 'authCtx.token')).toBe(true);
    expect(sameFieldComparison('req.headers.authorization', 'config.apiToken')).toBe(false);
    expect(sameFieldComparison('supplied', 'stored')).toBe(false);
    const hits = ruleById('SEC-TIMING-UNSAFE-COMPARE')!.scan!(
      fileCtx('src/authGateway.ts', "import { createHmac } from 'node:crypto';\nexport function same(authCtx: { apiKey: string; token: string }): boolean {\n  return authCtx.apiKey === authCtx.token || false;\n}\n"),
    );
    expect(hits).toEqual([]);
  });

  it('does not report Array.prototype.join as path construction, but still reports path.join and a bare join', () => {
    const arrayJoin = ruleById('SEC-PATH-TRAVERSAL')!.scan!(
      fileCtx('src/git.ts', "export function ignored(root: string, paths: string[], filePath: string): string {\n  return run('git', ['-C', root, 'check-ignore', '--stdin'], { input: `${paths.slice(0, 5000).join('\\n')}\\n` }).stdout + filePath;\n}\n"),
    );
    expect(arrayJoin).toEqual([]);
    const pathJoin = ruleById('SEC-PATH-TRAVERSAL')!.scan!(fileCtx('src/files.ts', "import path from 'node:path';\nexport const target = (root: string, filePath: string) => path.join(root, filePath);\n"));
    expect(pathJoin.length).toBe(1);
    const bareJoin = ruleById('SEC-PATH-TRAVERSAL')!.scan!(fileCtx('src/files.ts', "import { join } from 'node:path';\nexport const target = (root: string, filename: string) => join(root, filename);\n"));
    expect(bareJoin.length).toBe(1);
  });

  it('does not report the ESM entry-script check, but still reports argv used as a path', () => {
    const mainCheck = ruleById('SEC-PATH-TRAVERSAL')!.scan!(
      fileCtx('scripts/build.mjs', "import { resolve } from 'node:path';\nimport { fileURLToPath } from 'node:url';\nif (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();\n"),
    );
    expect(mainCheck).toEqual([]);
    const argvPath = ruleById('SEC-PATH-TRAVERSAL')!.scan!(
      fileCtx('scripts/read.mjs', "import { resolve } from 'node:path';\nimport { readFileSync } from 'node:fs';\nconst file = resolve(process.argv[2]);\nreadFileSync(file);\n"),
    );
    expect(argvPath.length).toBe(1);
  });
});
