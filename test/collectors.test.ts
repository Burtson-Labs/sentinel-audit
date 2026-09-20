import { describe, it, expect } from 'vitest';
import { parseAuditJson, copyleftDependencies } from '../src/collectors/dependencies.js';
import { scanText, triageCandidate, documentationLoopbackHost, looksLikeSentence, SECRET_RULES } from '../src/collectors/secrets.js';
import { summariseWorkflow, gateSatisfied } from '../src/collectors/ci.js';
import { redactRepoUrl } from '../src/collectors/recon.js';
import { candidatesFromLicenses } from '../src/analyze.js';
import type { ScanContext } from '../src/types.js';
import { analyseDockerfile } from '../src/collectors/docker.js';
import { parseYaml, tryParseYaml } from '../src/util/yaml.js';
import { satisfies, compare, parse as parseSemver } from '../src/util/semver.js';
import { shannonEntropy, maskSecret } from '../src/util/hash.js';
import type { SecretCandidate, CiResult } from '../src/types.js';

describe('parseAuditJson', () => {
  it('reads the npm v7+ report shape', () => {
    const doc = {
      auditReportVersion: 2,
      vulnerabilities: {
        axios: {
          name: 'axios',
          severity: 'high',
          isDirect: true,
          range: '<1.12.0',
          via: [{ name: 'axios', severity: 'high', title: 'Proxy reuse', url: 'https://example.org/a', range: '<1.12.0', cwe: ['CWE-918'] }],
          fixAvailable: true,
        },
      },
    };
    const records = parseAuditJson(JSON.stringify(doc));
    expect(records).not.toBeNull();
    expect(records).toHaveLength(1);
    expect(records![0]!.module).toBe('axios');
    expect(records![0]!.severity).toBe('high');
    expect(records![0]!.path).toBe('direct');
    expect(records![0]!.cwe).toContain('CWE-918');
  });

  it('reads the npm v6 / advisories shape', () => {
    const doc = {
      advisories: {
        '1234': { module_name: 'lodash', severity: 'critical', title: 'Prototype pollution', url: 'u', vulnerable_versions: '<4.17.21', cwe: 'CWE-1321' },
      },
    };
    const records = parseAuditJson(JSON.stringify(doc));
    expect(records![0]!.module).toBe('lodash');
    expect(records![0]!.severity).toBe('critical');
  });

  it('reads newline-delimited advisory objects', () => {
    const ndjson = [
      JSON.stringify({ advisory: { module_name: 'a', severity: 'moderate', title: 'x', vulnerable_versions: '<1' } }),
      JSON.stringify({ advisory: { module_name: 'b', severity: 'low', title: 'y', vulnerable_versions: '<2' } }),
    ].join('\n');
    const records = parseAuditJson(ndjson);
    expect(records).toHaveLength(2);
  });

  it('sorts by severity, worst first', () => {
    const doc = {
      advisories: {
        '1': { module_name: 'low-one', severity: 'low', title: 'l' },
        '2': { module_name: 'crit-one', severity: 'critical', title: 'c' },
      },
    };
    const records = parseAuditJson(JSON.stringify(doc))!;
    expect(records[0]!.severity).toBe('critical');
  });

  it('returns null for output it cannot read, so the caller reports a gap', () => {
    expect(parseAuditJson('not json at all')).toBeNull();
  });

  it('de-duplicates identical advisories', () => {
    const doc = {
      advisories: {
        '1': { module_name: 'a', severity: 'high', title: 'same' },
        '2': { module_name: 'a', severity: 'high', title: 'same' },
      },
    };
    expect(parseAuditJson(JSON.stringify(doc))).toHaveLength(1);
  });
});

describe('copyleftDependencies', () => {
  it('finds strong-copyleft licences and ignores permissive ones', () => {
    const deps = [
      { name: 'a', version: '1', dev: false, license: 'MIT', direct: true },
      { name: 'b', version: '1', dev: false, license: 'AGPL-3.0', direct: true },
      { name: 'c', version: '1', dev: false, license: 'GPL-3.0-only', direct: true },
      { name: 'd', version: '1', dev: false, license: 'Apache-2.0', direct: true },
      { name: 'e', version: '1', dev: false, license: null, direct: true },
    ];
    const hits = copyleftDependencies(deps).map((d) => d.name);
    expect(hits).toEqual(['b', 'c']);
  });
});

describe('secret scanning', () => {
  const run = (path: string, text: string): SecretCandidate[] => {
    const out: SecretCandidate[] = [];
    scanText(path, text, out);
    return out;
  };

  it('finds a GitHub token and does not suppress it', () => {
    const hits = run('src/a.ts', `const t = 'ghp_${'a'.repeat(36)}';\n`);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.likelyFalsePositive).toBe(false);
  });

  it('never emits the raw value', () => {
    const secret = `ghp_${'b'.repeat(36)}`;
    const hits = run('src/a.ts', `const t = '${secret}';\n`);
    expect(hits[0]!.masked).not.toContain(secret);
    expect(hits[0]!.masked).toContain('*');
  });

  it('suppresses a URL whose credential is a variable reference', () => {
    const hits = run('.github/workflows/x.yml', 'git clone "https://x-access-token:${WEBSITE_TOKEN}@github.com/o/r.git"\n');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(hits[0]!.falsePositiveReason).toMatch(/variable reference/);
  });

  it('suppresses a storage-key name held in a *_KEY constant', () => {
    const hits = run('src/a.ts', "const TOKEN_KEY = 'app.authToken';\n");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(hits[0]!.falsePositiveReason).toMatch(/name|identifier/);
  });

  it('suppresses a value read from the environment', () => {
    const hits = run('src/a.ts', "const apiKey = process.env.API_KEY ?? 'unset-placeholder';\n");
    expect(hits.every((h) => h.likelyFalsePositive)).toBe(true);
  });

  it('always records a reason when it suppresses', () => {
    const hits = run('.env.example', "API_SECRET='your-secret-here'\n");
    for (const h of hits.filter((x) => x.likelyFalsePositive)) {
      expect(h.falsePositiveReason, 'a suppression without a reason is a bug').toBeTruthy();
    }
  });

  it('finds a private key block', () => {
    const hits = run('key.pem', '-----BEGIN RSA PRIVATE KEY-----\nabc\n');
    expect(hits.some((h) => h.ruleId === 'SECRET-private-key-block')).toBe(true);
  });

  it('finds a connection string with inline credentials', () => {
    const hits = run('src/a.ts', "const u = 'mongodb+srv://admin:R3alP4ssw0rd!@cluster.example.net/db';\n");
    expect(hits.some((h) => !h.likelyFalsePositive)).toBe(true);
  });

  it('keeps every rule regex anchored enough to have a capture group', () => {
    for (const r of SECRET_RULES) {
      expect(r.group, r.id).toBeGreaterThanOrEqual(1);
      expect(r.description.length, r.id).toBeGreaterThan(5);
    }
  });
});

describe('triageCandidate', () => {
  const rule = SECRET_RULES.find((r) => r.id === 'generic-assigned-secret')!;
  const base = { rule, lineText: '', entropy: 4.5, isExample: false, isFixture: false, path: 'src/a.ts' };

  it('suppresses placeholder words', () => {
    expect(triageCandidate({ ...base, value: 'your-token-here' }).suppress).toBe(true);
  });

  it('suppresses low-entropy generic matches', () => {
    expect(triageCandidate({ ...base, value: 'aaaaaaaaaaaaaa', entropy: 0.5 }).suppress).toBe(true);
  });

  it('keeps a high-entropy random value', () => {
    expect(triageCandidate({ ...base, value: 'xQ4$vB9#mL2@pR7!kT5%' }).suppress).toBe(false);
  });
});

/**
 * Regression suite for a High finding whose entire content was a README line
 * telling the reader how to point the tool at their own database. The
 * connection-string rule is `precise`, so every `!rule.precise` suppression was
 * skipped and the loopback host nobody could reach was reported as a leak.
 */
describe('documented loopback connection strings', () => {
  const run = (path: string, text: string): SecretCandidate[] => {
    const out: SecretCandidate[] = [];
    scanText(path, text, out);
    return out;
  };
  const README_LINE = 'export DATABASE_URL=postgres://readonly_user:secret@localhost:5432/appdb\n';

  it('dismisses a loopback connection string in a README', () => {
    const hits = run('examples/postgres-report/README.md', README_LINE);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(hits[0]!.falsePositiveReason).toMatch(/documentation example pointing at a loopback host/);
  });

  it('dismisses the other loopback and reserved spellings in documentation', () => {
    for (const url of [
      'mongodb://admin:pw1234@127.0.0.1:27017/db',
      'redis://default:pw1234@redis.local:6379',
      'postgres://u:pw1234@db.internal:5432/app',
      'https://user:pw1234@example.com/api',
      'amqps://guest:guest123@host.docker.internal:5672',
    ]) {
      const hits = run('docs/setup.md', `${url}\n`);
      expect(hits.length, url).toBeGreaterThan(0);
      expect(hits.every((h) => h.likelyFalsePositive), url).toBe(true);
    }
  });

  it('keeps a loopback credential in real source or configuration', () => {
    // a real-looking password: the literal word "secret" is a placeholder and
    // is dismissed on its own terms, whatever the host (see below)
    const inSource = run('src/db.ts', `const url = 'postgres://readonly_user:Hx7tQ2pL9sF4@localhost:5432/appdb';\n`);
    expect(inSource.some((h) => !h.likelyFalsePositive)).toBe(true);
    const inConfig = run('config/database.yml', `url: postgres://readonly_user:Hx7tQ2pL9sF4@localhost:5432/appdb\n`);
    expect(inConfig.some((h) => !h.likelyFalsePositive)).toBe(true);
  });

  it('keeps a routable connection string even in documentation', () => {
    const hits = run('docs/runbook.md', 'export DATABASE_URL=postgres://svc_reports:Hx7tQ2pL9sF4@db.production.io:5432/appdb\n');
    expect(hits.some((h) => !h.likelyFalsePositive)).toBe(true);
  });

  it('recognises the host only when the URL carries a credential', () => {
    expect(documentationLoopbackHost('postgres://user:pw@localhost:5432/db', 'README.md')).toBe('localhost');
    expect(documentationLoopbackHost('postgres://localhost:5432/db', 'README.md')).toBeUndefined();
    expect(documentationLoopbackHost('postgres://user:pw@db.production.io/db', 'README.md')).toBeUndefined();
    expect(documentationLoopbackHost('postgres://user:pw@localhost:5432/db', 'src/db.ts')).toBeUndefined();
    expect(documentationLoopbackHost('redis://user:pw@[::1]:6379', 'docs/a.md')).toBe('[::1]');
  });
});

describe('CI workflow analysis', () => {
  it('detects gates that actually gate', () => {
    const wf = `name: ci
on:
  pull_request:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: pnpm install
      - run: pnpm test
      - run: pnpm lint
`;
    const summary = summariseWorkflow('.github/workflows/ci.yml', wf);
    expect(summary.name).toBe('ci');
    expect(summary.triggers).toContain('pull_request');
    expect(summary.gates.test).toBe(true);
    expect(summary.gates.lint).toBe(true);
    expect(summary.gates.audit).toBe(false);
  });

  it('treats continue-on-error as not gating', () => {
    const wf = `name: ci
on: [pull_request]
jobs:
  build:
    steps:
      - run: pnpm test
        continue-on-error: true
`;
    expect(summariseWorkflow('.github/workflows/ci.yml', wf).gates.test).toBe(false);
  });

  it('treats "|| true" as not gating', () => {
    const wf = `name: ci
on: [pull_request]
jobs:
  build:
    steps:
      - run: pnpm audit || true
`;
    expect(summariseWorkflow('.github/workflows/ci.yml', wf).gates.audit).toBe(false);
  });

  it('recognises security scanners', () => {
    const wf = `name: sec
on: [pull_request]
jobs:
  s:
    steps:
      - uses: github/codeql-action/analyze@v3
      - run: gitleaks detect
`;
    const s = summariseWorkflow('.github/workflows/sec.yml', wf);
    expect(s.gates.sast).toBe(true);
    expect(s.gates.secrets).toBe(true);
  });

  it('falls back to text scanning when YAML parsing fails, rather than claiming no gates', () => {
    const broken = "name: ci\n\ton: bad\n      - run: pnpm test\n";
    const s = summariseWorkflow('.github/workflows/ci.yml', broken);
    expect(s.parseError).toBeTruthy();
    expect(s.gates.test).toBe(true);
  });

  it('gateSatisfied requires a PR-or-push trigger by default', () => {
    const ci: CiResult = {
      workflows: [
        {
          file: 'a.yml',
          name: 'release',
          triggers: ['release'],
          permissions: null,
          jobs: [],
          gates: { test: true, lint: false, typecheck: false, audit: false, sast: false, secrets: false },
        },
      ],
      hasRequiredStatusCheckHint: false,
      unpinnedActions: [],
      riskyTriggers: [],
    };
    expect(gateSatisfied(ci, 'test')).toBe(false);
    expect(gateSatisfied(ci, 'test', false)).toBe(true);
  });
});

describe('Dockerfile analysis', () => {
  it('reports root when no USER is set', () => {
    const d = analyseDockerfile('Dockerfile', 'FROM node:22\nCOPY . .\nCMD ["node","x.js"]\n');
    expect(d.runsAsRoot).toBe(true);
    expect(d.baseImages[0]!.pinned).toBe(false);
  });

  it('respects a USER in the final stage', () => {
    const d = analyseDockerfile('Dockerfile', 'FROM node:22\nUSER node\nCMD ["node","x.js"]\n');
    expect(d.runsAsRoot).toBe(false);
  });

  it('ignores a USER in an earlier build stage — the final stage decides', () => {
    const df = ['FROM node:22 AS builder', 'USER node', 'RUN npm ci', '', 'FROM nginx:alpine', 'COPY --from=builder /app /usr/share/nginx/html', ''].join('\n');
    const d = analyseDockerfile('Dockerfile', df);
    expect(d.runsAsRoot).toBe(true);
  });

  it('does not count a stage reference as an external base image', () => {
    const df = ['FROM node:22 AS builder', 'FROM builder AS test', ''].join('\n');
    const d = analyseDockerfile('Dockerfile', df);
    expect(d.baseImages).toHaveLength(1);
  });

  it('recognises digest pinning', () => {
    const d = analyseDockerfile('Dockerfile', 'FROM node@sha256:abc123\nUSER node\n');
    expect(d.baseImages[0]!.pinned).toBe(true);
  });

  it('flags credential-shaped build arguments', () => {
    const d = analyseDockerfile('Dockerfile', 'FROM node:22\nARG NPM_TOKEN\nENV API_SECRET=x\nUSER node\n');
    expect(d.secretsInArgs.map((s) => s.name)).toEqual(['NPM_TOKEN', 'API_SECRET']);
  });

  it('does not call public authentication endpoint variables secrets', () => {
    const d = analyseDockerfile('Dockerfile', 'FROM node:22\nARG VITE_OIDC_TOKEN_URL\nENV AUTH_ENDPOINT=https://auth.example.test\n');
    expect(d.secretsInArgs).toEqual([]);
  });
});

describe('yaml subset parser', () => {
  it('parses nested maps and sequences', () => {
    const doc = parseYaml('a:\n  b: 1\n  c:\n    - x\n    - y\n') as Record<string, unknown>;
    expect(doc.a).toEqual({ b: 1, c: ['x', 'y'] });
  });

  it('parses a sequence of maps', () => {
    const doc = parseYaml('steps:\n  - name: one\n    run: echo 1\n  - name: two\n    uses: a/b@v1\n') as { steps: unknown[] };
    expect(doc.steps).toHaveLength(2);
    expect(doc.steps[1]).toEqual({ name: 'two', uses: 'a/b@v1' });
  });

  it('parses inline flow sequences', () => {
    expect(parseYaml('on: [push, pull_request]\n')).toEqual({ on: ['push', 'pull_request'] });
  });

  it('parses block scalars', () => {
    const doc = parseYaml('run: |\n  line one\n  line two\n') as { run: string };
    expect(doc.run).toBe('line one\nline two');
  });

  it('strips comments outside quotes but not inside', () => {
    const doc = parseYaml('a: 1 # trailing\nb: "has # inside"\n') as Record<string, unknown>;
    expect(doc.a).toBe(1);
    expect(doc.b).toBe('has # inside');
  });

  it('coerces YAML 1.1 booleans', () => {
    expect(parseYaml('a: yes\nb: off\n')).toEqual({ a: true, b: false });
  });

  it('reports an error instead of guessing', () => {
    expect(tryParseYaml('\ta: 1\n').error).toBeTruthy();
  });
});

describe('semver subset', () => {
  it('compares versions including prereleases', () => {
    expect(compare(parseSemver('1.2.3')!, parseSemver('1.2.4')!)).toBe(-1);
    expect(compare(parseSemver('1.2.3')!, parseSemver('1.2.3')!)).toBe(0);
    expect(compare(parseSemver('1.2.3-rc.1')!, parseSemver('1.2.3')!)).toBe(-1);
    expect(compare(parseSemver('2.0.0')!, parseSemver('1.9.9')!)).toBe(1);
  });

  it('evaluates the comparator ranges npm audit emits', () => {
    expect(satisfies('1.11.0', '<1.12.0')).toBe(true);
    expect(satisfies('1.12.0', '<1.12.0')).toBe(false);
    expect(satisfies('1.5.0', '>=1.0.0 <1.6.0')).toBe(true);
    expect(satisfies('1.7.0', '>=1.0.0 <1.6.0')).toBe(false);
    expect(satisfies('2.0.0', '<1.0.0 || >=3.0.0')).toBe(false);
    expect(satisfies('3.1.0', '<1.0.0 || >=3.0.0')).toBe(true);
    expect(satisfies('1.0.0', '*')).toBe(true);
  });

  it('returns null for syntax it does not implement, so nothing is wrongly cleared', () => {
    expect(satisfies('1.2.3', '^1.0.0')).toBeNull();
    expect(satisfies('1.2.3', '~1.2.0')).toBeNull();
    expect(satisfies('1.2.3', '1.x')).toBeNull();
    expect(satisfies('not-a-version', '<2.0.0')).toBeNull();
  });
});

describe('entropy and masking', () => {
  it('scores random strings above repetitive ones', () => {
    expect(shannonEntropy('aaaaaaaa')).toBeLessThan(shannonEntropy('a8Fk2Lp9'));
  });

  it('masks while keeping a recognisable prefix and the length', () => {
    const masked = maskSecret('abcdefghijklmnopqrstuvwxyz');
    expect(masked.startsWith('abc')).toBe(true);
    expect(masked).toContain('len=26');
    expect(masked).not.toContain('defghij');
  });
});

/**
 * Relayed results have to go through the same triage as Sentinel's own matches.
 * A count with no path awareness is what let one report call the same fixture
 * Info in one finding and High in another.
 */
describe('external scanner results are triaged, not just counted', () => {
  const gitleaksJson = (rows: Array<Record<string, unknown>>): string => JSON.stringify(rows);

  it('parses gitleaks JSON into triaged hits with the path it reported', async () => {
    const { parseGitleaks } = await import('../src/collectors/secrets.js');
    const parsed = parseGitleaks(
      gitleaksJson([
        { Description: 'Generic API Key', File: 'src/server.ts', StartLine: 14, Secret: 'Jx9wQ2pL8sF4tB7+nE1vM5yH0cR6zKd3A=', RuleID: 'generic-api-key', Commit: 'deadbeefcafe' },
      ]),
    );
    expect(parsed.ok).toBe(true);
    expect(parsed.hits).toHaveLength(1);
    expect(parsed.hits[0]!.file).toBe('src/server.ts');
    expect(parsed.hits[0]!.line).toBe(14);
    expect(parsed.hits[0]!.commit).toBe('deadbeefcafe');
    expect(parsed.hits[0]!.likelyFalsePositive).toBe(false);
    // the raw secret never leaves the collector
    expect(parsed.hits[0]!.masked).not.toContain('Jx9wQ2pL8sF4tB7+nE1vM5yH0cR6zKd3A=');
  });

  it('dismisses identifier-shaped generic matches, the same as its own', async () => {
    const { parseGitleaks } = await import('../src/collectors/secrets.js');
    const parsed = parseGitleaks(
      gitleaksJson([
        { Description: 'Generic API Key', File: 'src/storage.ts', StartLine: 3, Secret: 'app.auth.accessToken', Match: "const TOKEN_KEY = 'app.auth.accessToken'", RuleID: 'generic-api-key' },
        { Description: 'Generic API Key', File: 'README.md', StartLine: 9, Secret: 'your-api-key-here', Match: 'export API_KEY=your-api-key-here', RuleID: 'generic-api-key' },
      ]),
    );
    expect(parsed.ok).toBe(true);
    expect(parsed.hits.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(parsed.hits[0]!.falsePositiveReason).toMatch(/identifier/);
  });

  it('marks a test-path hit without dismissing it', async () => {
    const { parseGitleaks } = await import('../src/collectors/secrets.js');
    const parsed = parseGitleaks(
      gitleaksJson([{ Description: 'GitHub PAT', File: 'test/fixtures/tokens.ts', StartLine: 2, Secret: `ghp_${'a'.repeat(36)}`, RuleID: 'github-pat' }]),
    );
    expect(parsed.hits[0]!.inTestPath).toBe(true);
    // a provider pattern is precise: a test path lowers its severity, it does not dismiss it
    expect(parsed.hits[0]!.likelyFalsePositive).toBe(false);
  });

  it('does not dismiss a real provider key just because it sits in a fixture', async () => {
    const { triageExternalHit } = await import('../src/collectors/secrets.js');
    const hit = triageExternalHit({
      ruleId: 'gitleaks:stripe-access-token',
      description: 'Stripe secret key',
      value: `sk_live_${'9'.repeat(24)}`,
      path: 'test/fixtures/payments.ts',
      line: 4,
    });
    expect(hit.likelyFalsePositive).toBe(false);
    expect(hit.inTestPath).toBe(true);
  });

  it('reports an unparseable report as untriageable rather than clean', async () => {
    const { parseGitleaks } = await import('../src/collectors/secrets.js');
    expect(parseGitleaks('gitleaks: fatal: not a git repository').ok).toBe(false);
    expect(parseGitleaks('[{"File":').ok).toBe(false);
    // an empty report is parsed successfully and has nothing to triage
    expect(parseGitleaks('[]')).toEqual({ ok: true, hits: [] });
  });

  it('relativises trufflehog absolute paths so the test-path check can see them', async () => {
    const { parseTrufflehog } = await import('../src/collectors/secrets.js');
    const line = JSON.stringify({
      DetectorName: 'Generic',
      Raw: 'Jx9wQ2pL8sF4tB7+nE1vM5yH0cR6zKd3A=',
      SourceMetadata: { Data: { Filesystem: { file: '/repo/test/fixtures/keys.ts', line: 5 } } },
    });
    const parsed = parseTrufflehog(line, '/repo');
    expect(parsed.hits[0]!.file).toBe('test/fixtures/keys.ts');
    expect(parsed.hits[0]!.inTestPath).toBe(true);
  });
});

describe('secret-scanning coverage statements are mutually exclusive', () => {
  it('never claims git history is both covered and unexamined', async () => {
    const { collectSecrets } = await import('../src/collectors/secrets.js');
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-secrets-'));
    writeFileSync(join(dir, 'a.ts'), 'export const a = 1;\n', 'utf8');
    const files = [{ path: 'a.ts', absolute: join(dir, 'a.ts'), bytes: 20, ext: '.ts', binary: false }];

    const out = collectSecrets(dir, files, { useExternalScanner: false });
    const notes = out.run.notExamined.join(' ');
    expect(out.secrets.externalScanner.available).toBe(false);
    expect(notes).toMatch(/only the working tree was scanned/);

    const withScanner = collectSecrets(dir, files, { useExternalScanner: true });
    const n2 = withScanner.run.notExamined.join(' ');
    if (withScanner.secrets.externalScanner.available) {
      expect(n2).not.toMatch(/only the working tree was scanned/);
      // Either wording is acceptable; what must hold is that the note says the
      // other scanner's detections are relayed rather than re-derived.
      expect(n2).toMatch(/not re-der\w+ (?:as Sentinel findings|the)|relayed and triaged/);
    }
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('shapes that are not credentials, wherever they appear', () => {
  const run = (path: string, text: string): SecretCandidate[] => {
    const out: SecretCandidate[] = [];
    scanText(path, text, out);
    return out;
  };
  // Sentinel's self-scan led its High secret finding with a *comment* quoting
  // `postgres://readonly_user:secret@localhost` and a gate description assigned
  // to `secrets:`; a real .NET scan led with a PEM header being stripped off a
  // key the code was given. None of the three is something to rotate.
  it('dismisses the placeholder word used as a connection-string password, on any host and path', () => {
    for (const [path, line] of [
      ['src/collectors/secrets.ts', '  // instruction: "export DATABASE_URL=postgres://readonly_user:secret@localhost:5432/appdb"'],
      ['src/util/hosts.ts', ' * `postgres://user:pass@localhost:5432/db` as a committed credential. The regex'],
      ['src/db.ts', "const url = 'mysql://app:password@db.internal:3306/app';"],
    ] as const) {
      const hits = run(path, `${line}\n`);
      expect(hits.length, line).toBeGreaterThan(0);
      expect(hits.every((h) => h.likelyFalsePositive), line).toBe(true);
      expect(hits[0]!.falsePositiveReason, line).toMatch(/placeholder word/);
    }
  });

  it('dismisses a credential written with an ellipsis, and the documentation word "token", for any rule', () => {
    // both lines are Sentinel's own: a changelog entry and a docblock explaining
    // why the remote URL is redacted before it is recorded
    for (const [path, line] of [
      ['CHANGELOG.md', '  artefacts. A remote configured as `https://x-access-token:ghp_…@github.com/…`,'],
      ['src/collectors/recon.ts', ' * `https://user:token@github.com/org/repo` is how many CI systems, credential'],
      ['docs/setup.md', 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."'],
    ] as const) {
      const hits = run(path, `${line}\n`);
      expect(hits.length, line).toBeGreaterThan(0);
      expect(hits.every((h) => h.likelyFalsePositive), line).toBe(true);
    }
    const real = run('src/ci.ts', "const remote = 'https://x-access-token:ghp_" + 'b'.repeat(36) + "@github.com/o/r.git';\n");
    expect(real.some((h) => !h.likelyFalsePositive)).toBe(true);
  });

  it('still reports a connection string whose password is not a placeholder, even on localhost in source', () => {
    const hits = run('src/db.ts', "const url = 'postgres://app:Hx7tQ2pL9sF4@localhost:5432/app';\n");
    expect(hits.some((h) => !h.likelyFalsePositive)).toBe(true);
  });

  it('dismisses a sentence assigned to a secret-shaped name', () => {
    const hits = run('src/report/markdown.ts', "    secrets: 'secret scanning over history, not just the working tree',\n");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(hits[0]!.falsePositiveReason).toMatch(/sentence/);
  });

  it('looksLikeSentence needs four spaced tokens, mostly words', () => {
    expect(looksLikeSentence('secret scanning over history, not just the working tree')).toBe(true);
    expect(looksLikeSentence('Hx7tQ2pL9sF4kT5vB9mL2pR7')).toBe(false);
    expect(looksLikeSentence('correct horse')).toBe(false);
    expect(looksLikeSentence('a1 b2 c3 d4 e5 f6')).toBe(false);
  });

  it('dismisses a PEM header used as a string token, but not one that opens a key', () => {
    const token = run('AuthApi/Services/OAuthService.cs', '                .Replace("-----BEGIN PRIVATE KEY-----", "")\n');
    expect(token.length).toBeGreaterThan(0);
    expect(token.every((h) => h.likelyFalsePositive)).toBe(true);
    expect(token[0]!.falsePositiveReason).toMatch(/string token/);

    const startsWith = run('src/keys.ts', "if (!pem.startsWith('-----BEGIN RSA PRIVATE KEY-----')) throw new Error('not a key');\n");
    expect(startsWith.every((h) => h.likelyFalsePositive)).toBe(true);

    const block = run('config/signing.pem', '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----\n');
    expect(block.some((h) => !h.likelyFalsePositive)).toBe(true);

    const literal = run('src/keys.ts', "const KEY = '-----BEGIN PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\\n-----END PRIVATE KEY-----';\n");
    expect(literal.some((h) => !h.likelyFalsePositive)).toBe(true);
  });
});

describe('the recorded repository URL never carries credentials', () => {
  // The URL is written into REPORT.md, CONFIDENCE.md, scan-context.json and the
  // SARIF repositoryUri, and those are uploaded as CI artefacts.
  it('strips a username, a username:token pair, and a bare token', () => {
    expect(redactRepoUrl('https://markymarkburt@github.com/Burtson-Labs/sentinel-audit.git')).toBe('https://github.com/Burtson-Labs/sentinel-audit.git');
    expect(redactRepoUrl('https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r.git')).toBe('https://github.com/o/r.git');
    expect(redactRepoUrl('https://oauth2:glpat-abc123@gitlab.com/o/r.git')).toBe('https://gitlab.com/o/r.git');
  });

  it('leaves ssh forms and credential-free URLs alone', () => {
    expect(redactRepoUrl('git@github.com:o/r.git')).toBe('git@github.com:o/r.git');
    expect(redactRepoUrl('ssh://git@github.com/o/r.git')).toBe('ssh://git@github.com/o/r.git');
    expect(redactRepoUrl('https://github.com/o/r.git')).toBe('https://github.com/o/r.git');
    expect(redactRepoUrl('unknown')).toBe('unknown');
  });
});

describe('a Sentinel scan on pull requests is an audit gate', () => {
  const wf = (run: string): string =>
    ['name: audit', 'on:', '  pull_request:', 'jobs:', '  audit:', '    runs-on: ubuntu-latest', '    steps:', '      - uses: actions/checkout@v4', `      - run: ${run}`, ''].join('\n');

  it('counts the shipped template invocation as sast and audit, not secrets', () => {
    const s = summariseWorkflow('.github/workflows/audit.yml', wf('npx --yes sentinel-audit scan . --profile owasp-asvs --no-llm'));
    expect(s.gates.sast).toBe(true);
    expect(s.gates.audit).toBe(true);
    expect(s.gates.secrets).toBe(false);
  });

  it('counts a global install, the scoped package, and the build-output invocation', () => {
    expect(summariseWorkflow('.github/workflows/audit.yml', wf('sentinel scan .')).gates.audit).toBe(true);
    expect(summariseWorkflow('.github/workflows/audit.yml', wf('npx --yes @burtson-labs/sentinel-audit scan . --no-llm')).gates.audit).toBe(true);
    expect(summariseWorkflow('.github/workflows/ci.yml', wf('node dist/cli.js scan . --format sarif')).gates.audit).toBe(true);
  });

  it('does not count --offline as an audit, because no advisories are fetched', () => {
    const s = summariseWorkflow('.github/workflows/audit.yml', wf('npx --yes sentinel-audit scan . --offline'));
    expect(s.gates.sast).toBe(true);
    expect(s.gates.audit).toBe(false);
  });

  it('does not count a soft-failed scan', () => {
    expect(summariseWorkflow('.github/workflows/audit.yml', wf('npx --yes sentinel-audit scan . || true')).gates.audit).toBe(false);
  });

  it('counts a continue-on-error scan whose recorded outcome a later step re-asserts — the template idiom', () => {
    const steps = [
      '      - uses: actions/checkout@v4',
      '      - name: Run sentinel',
      '        id: sentinel',
      '        continue-on-error: true',
      '        run: npx --yes sentinel-audit scan . --no-llm',
      '      - name: Upload SARIF',
      '        if: always()',
      '        uses: github/codeql-action/upload-sarif@v3',
    ];
    const enforce = ['      - name: Enforce the gate', '        if: always()', '        run: test "${{ steps.sentinel.outcome }}" = "success"'];
    const head = ['name: audit', 'on:', '  pull_request:', 'jobs:', '  audit:', '    runs-on: ubuntu-latest', '    steps:'];
    const withEnforce = summariseWorkflow('.github/workflows/audit.yml', [...head, ...steps, ...enforce, ''].join('\n'));
    expect(withEnforce.gates.audit).toBe(true);
    expect(withEnforce.gates.sast).toBe(true);

    const without = summariseWorkflow('.github/workflows/audit.yml', [...head, ...steps, ''].join('\n'));
    expect(without.gates.audit, 'a soft-failed step nobody re-asserts is not a gate').toBe(false);

    const expression = ['      - name: Enforce', "        if: steps.sentinel.outcome == 'success'", '        run: echo ok'];
    const viaIf = summariseWorkflow('.github/workflows/audit.yml', [...head, ...steps, ...expression, ''].join('\n'));
    expect(viaIf.gates.audit, 'an if-expression gates nothing — the job still succeeds').toBe(false);
  });
});

describe('licence findings cite the artefact they were read from', () => {
  it('evidence names package.json, so the finding passes the schema check it used to fail', () => {
    const ctx = {
      deps: { dependencies: [{ name: 'gpl-thing', version: '2.0.0', dev: false, license: 'GPL-3.0-only', direct: true }] },
    } as unknown as ScanContext;
    const [c] = candidatesFromLicenses(ctx);
    expect(c).toBeDefined();
    expect(c!.evidence).toMatch(/^package\.json/);
    expect(c!.evidence).toContain('gpl-thing@2.0.0 — GPL-3.0-only');
  });
});
