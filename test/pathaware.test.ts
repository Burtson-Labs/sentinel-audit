import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/scan.js';
import { validateFindings } from '../src/schema.js';
import { buildTestPathPredicate, isTestOrFixturePath, isCredentialSensitiveRule } from '../src/util/testpaths.js';
import { loadProfile, validateProfile, testPathPredicate } from '../src/profile.js';
import type { Finding } from '../src/types.js';

/**
 * Path-aware severity.
 *
 * The regression these tests pin down: Sentinel reported
 * `frontend/e2e-prod/admin-session-hygiene.spec.ts` as a **High** "Authentication
 * material written to web storage", citing a spec whose entire purpose is
 * exercising session hygiene. The line was real; the severity was not.
 *
 * The fix must be narrow in both directions, so both directions are tested:
 * credential/auth rules drop to Info in test paths, and everything else keeps
 * firing there.
 */

const dirs: string[] = [];

function tempRepo(files: Record<string, string>): string {
  const repo = mkdtempSync(join(tmpdir(), 'sentinel-paths-repo-'));
  dirs.push(repo);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(repo, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content, 'utf8');
  }
  // The secret verifier asks git whether a file is tracked, and an untracked
  // credential is a different (lesser) finding. Commit, so the test exercises
  // the severity path rather than the "never committed" path.
  const git = (...args: string[]): void => {
    execFileSync('git', ['-C', repo, '-c', 'user.email=t@example.org', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
      stdio: 'ignore',
    });
  };
  git('init', '-q');
  git('add', '-A');
  git('commit', '-qm', 'fixture');
  return repo;
}

const PKG = JSON.stringify({ name: 'fixture', version: '1.0.0', private: true, type: 'module', scripts: { test: 'node --test' } }, null, 2);

const SPEC_WITH_TOKEN_WRITE = [
  "import { test } from '@playwright/test';",
  '',
  "const MASTER = 'e2e-master-key';",
  '',
  "test('a stale api key is cleared on sign-out', async ({ page }) => {",
  "  await page.addInitScript((master) => localStorage.setItem('ov_api_key', master), MASTER);",
  '  await page.goto("/admin");',
  '});',
  '',
].join('\n');

const PROD_WITH_TOKEN_WRITE = [
  "const TOKEN_KEY = 'app.accessToken';",
  '',
  'export const authStore = {',
  '  setToken: (token: string) => {',
  '    localStorage.setItem(TOKEN_KEY, token);',
  '  },',
  '};',
  '',
].join('\n');

let mixed: Finding[];
let prodAndTest: Finding[];
let defaultProfile: Finding[];
let customProfile: Finding[];

beforeAll(async () => {
  // ---- repo 1: credential constructs and values live only in test paths ----
  const repo1 = tempRepo({
    'package.json': PKG,
    // the real-world case, directory name included
    'frontend/e2e-prod/admin-session-hygiene.spec.ts': SPEC_WITH_TOKEN_WRITE,
    // a credential-shaped *value* in a test path: still worth an Info
    'frontend/src/api/client.test.ts': [
      "export const REMOTE = 'https://admin:R3alP4ssw0rd!@cluster.internal.net';",
      '',
    ].join('\n'),
    // a real production credential: must stay High and must not be diluted
    'backend/config.py': [`GITHUB_TOKEN = "ghp_${'a'.repeat(36)}"`, ''].join('\n'),
    // a non-credential rule in a test path: must still be reported
    'frontend/src/api/retry.test.ts': ['export function attempt(fn: () => void): void {', '  try {', '    fn();', '  } catch {}', '}', ''].join('\n'),
  });
  const out1 = mkdtempSync(join(tmpdir(), 'sentinel-paths-out-'));
  dirs.push(out1);
  mixed = (await scan({ repo: repo1, outDir: out1, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true })).findings;

  // ---- repo 3: a credential construct in a directory only this repository
  // would call test code. Scanned twice — once with the builtin list (where it
  // is production code) and once with a profile that names it.
  const repo3 = tempRepo({
    'package.json': PKG,
    'checks/session-probe.ts': ["export function probe(key: string): void {", "  localStorage.setItem('probe_api_key', key);", '}', ''].join('\n'),
  });
  const out3 = mkdtempSync(join(tmpdir(), 'sentinel-paths-out3-'));
  dirs.push(out3);
  defaultProfile = (await scan({ repo: repo3, outDir: out3, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true })).findings;

  const profilePath = join(out3, 'custom-profile.json');
  const base = loadProfile('owasp-asvs') as unknown as Record<string, unknown>;
  writeFileSync(profilePath, JSON.stringify({ ...base, id: 'custom', testPaths: { mode: 'extend', patterns: ['(^|/)checks(/|$)'] } }, null, 2), 'utf8');
  const out3b = mkdtempSync(join(tmpdir(), 'sentinel-paths-out3b-'));
  dirs.push(out3b);
  customProfile = (await scan({ repo: repo3, outDir: out3b, profile: profilePath, formats: ['json'], noLlm: true, offline: true, noProofs: true })).findings;

  // ---- repo 2: the same construct in production *and* test code -----------
  const repo2 = tempRepo({
    'package.json': PKG,
    'src/auth.ts': PROD_WITH_TOKEN_WRITE,
    'src/auth.test.ts': SPEC_WITH_TOKEN_WRITE,
  });
  const out2 = mkdtempSync(join(tmpdir(), 'sentinel-paths-out2-'));
  dirs.push(out2);
  prodAndTest = (await scan({ repo: repo2, outDir: out2, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true })).findings;
}, 180_000);

afterAll(() => {
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // a leftover temp directory is not worth failing the suite over
    }
  }
});

const byRule = (findings: Finding[], ruleId: string): Finding | undefined => findings.find((f) => f.ruleId === ruleId);

describe('credential and auth rules in test paths', () => {
  it('does not report a session-hygiene spec as a High auth-storage finding', () => {
    const f = byRule(mixed, 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('Info');
    expect(f.evidence).toContain('admin-session-hygiene.spec.ts');
  });

  it('says "in test code" explicitly, in the title and in a note', () => {
    const f = byRule(mixed, 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.title).toMatch(/in test code only$/);
    expect(f.notes!.join(' ')).toMatch(/In test code: every cited location is a test, spec or fixture path/);
  });

  it('beats the profile severity floor, which would otherwise drag it back up', () => {
    // owasp-asvs sets `severityFloor: { Secret: "High" }`; the Info ceiling for
    // test paths is applied after the floor on purpose.
    const f = byRule(mixed, 'SEC-SECRET-IN-TEST')!;
    expect(f).toBeDefined();
    expect(loadProfile('owasp-asvs').severityFloor!.Secret).toBe('High');
    expect(f.severity).toBe('Info');
  });

  it('keeps High for the same construct in production code, and only notes the test matches', () => {
    const f = byRule(prodAndTest, 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.severity).toBe('High');
    expect(f.title).not.toMatch(/test code/);
    expect(f.evidence).toContain('src/auth.ts');
    expect(f.evidence).not.toContain('auth.test.ts');
    expect(f.notes!.join(' ')).toMatch(/match\(es\) in test paths were excluded/);
  });
});

describe('credential-shaped values in test paths', () => {
  it('reports them as a separate Info finding rather than dropping them', () => {
    const f = byRule(mixed, 'SEC-SECRET-IN-TEST')!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('Info');
    expect(f.evidence).toContain('client.test.ts');
    expect(f.whyThisMatters).toMatch(/still worth one Info line/);
  });

  it('still reports a production credential at High, undiluted by the test ones', () => {
    const f = byRule(mixed, 'SEC-SECRET-COMMITTED')!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('High');
    expect(f.evidence).toContain('backend/config.py');
    expect(f.evidence).not.toContain('client.test.ts');
    expect(f.title).toContain('1 credential-shaped value');
    expect(f.notes!.join(' ')).toMatch(/reported separately at Info/);
  });

  it('maps the new rule to a control in every builtin profile', () => {
    for (const id of ['owasp-asvs', 'cwe-top-25', 'generic-enterprise']) {
      const f = byRule(mixed, 'SEC-SECRET-IN-TEST')!;
      expect(f.standardMapping).not.toMatch(/no mapped control/);
      expect(loadProfile(id).controls['SEC-SECRET-IN-TEST']!.length).toBeGreaterThan(0);
    }
  });
});

describe('test paths are not excluded from every rule', () => {
  it('still reports a swallowed catch that only exists in a test file', () => {
    const f = byRule(mixed, 'QUA-SWALLOWED-CATCH');
    expect(f, 'a swallowed catch in a test is still a swallowed catch').toBeDefined();
    expect(f!.evidence).toContain('retry.test.ts');
    // the Info ceiling is for credential/auth rules only — this one keeps its own
    expect(f!.severity).not.toBe('Info');
  });

  it('only the credential/auth family gets the Info ceiling', () => {
    expect(isCredentialSensitiveRule('SEC-TOKEN-WEBSTORAGE')).toBe(true);
    expect(isCredentialSensitiveRule('SEC-SECRET-COMMITTED')).toBe(true);
    expect(isCredentialSensitiveRule('QUA-SWALLOWED-CATCH')).toBe(false);
    expect(isCredentialSensitiveRule('SEC-XSS-DANGEROUS-HTML')).toBe(false);
  });

  it('every finding still validates', () => {
    for (const set of [mixed, prodAndTest, defaultProfile, customProfile]) {
      expect(validateFindings(set).filter((i) => i.severity === 'error')).toEqual([]);
    }
  });
});

describe('a dismissal is not reported at a severity the profile floor invented', () => {
  it('keeps the triaged-out secret-noise finding at Info, not High', () => {
    const f = mixed.find((x) => x.ruleId === 'SEC-SECRET-TRIAGED');
    expect(f, 'the fixture has suppressed secret matches').toBeDefined();
    expect(f!.status).toBe('triaged-out');
    // owasp-asvs floors Secret at High; a finding we are dismissing must not be
    // raised by it, or a consumer counting High findings believes the dismissal
    expect(f!.severity).toBe('Info');
  });
});

describe('the test-path list is configurable in the profile', () => {
  it('an unusual directory is production code by default', () => {
    expect(isTestOrFixturePath('checks/session-probe.ts')).toBe(false);
    const f = byRule(defaultProfile, 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.evidence).toContain('checks/session-probe.ts');
    expect(f.severity).toBe('High');
  });

  it('becomes test code when the profile says so, and the finding drops to Info', () => {
    const f = byRule(customProfile, 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.severity).toBe('Info');
    expect(f.title).toMatch(/in test code only$/);
  });

  it('rejects a profile whose pattern is not a valid regular expression', () => {
    const problems = validateProfile({ ...loadProfile('owasp-asvs'), testPaths: { patterns: ['([unclosed'] } });
    expect(problems.join(' ')).toMatch(/not a valid regular expression/);
  });

  it('"replace" mode drops the built-ins entirely', () => {
    const only = buildTestPathPredicate({ mode: 'replace', patterns: ['(^|/)checks(/|$)'] });
    expect(only('checks/a.ts')).toBe(true);
    expect(only('src/a.test.ts')).toBe(false);
    // and an empty replace disables path-aware severity, which is a valid choice
    expect(buildTestPathPredicate({ mode: 'replace', patterns: [] })('src/a.test.ts')).toBe(false);
  });

  it('ignores an unusable extra pattern instead of taking the scan down', () => {
    const p = buildTestPathPredicate({ patterns: ['([unclosed'] });
    expect(p('src/a.test.ts')).toBe(true);
  });

  it('the profile predicate is the one the scan uses', () => {
    expect(testPathPredicate(loadProfile('owasp-asvs'))('src/a.spec.ts')).toBe(true);
  });
});

describe('the default test-path set covers how repositories actually spell it', () => {
  const yes = [
    'test/a.ts',
    'tests/a.ts',
    'spec/a.rb',
    'specs/a.ts',
    '__tests__/a.ts',
    '__mocks__/fetch.ts',
    '__fixtures__/payload.json',
    'e2e/login.ts',
    'frontend/e2e-prod/admin-session-hygiene.spec.ts',
    'packages/app/integration-tests/a.ts',
    'cypress/e2e/a.cy.ts',
    'playwright/a.ts',
    'fixtures/sample.json',
    'test-fixtures/sample.json',
    'mocks/server.ts',
    'testdata/input.json',
    'test_data/input.json',
    'stubs/client.ts',
    'src/api/client.test.ts',
    'src/api/client.spec.tsx',
    'src/api/client.fixture.ts',
    'src/api/server.mock.js',
    'pkg/handler_test.go',
    'app/test_views.py',
    'conftest.py',
    'src/AuthServiceTests.cs',
  ];
  const no = [
    'src/auth.ts',
    'src/latest/index.ts', // contains "test" as a substring, not a segment
    'src/contest/index.ts',
    'src/protest.ts',
    'backend/core/analytics.py',
    'src/components/Greatest.tsx',
  ];

  it('matches the shapes it should', () => {
    for (const p of yes) expect(isTestOrFixturePath(p), p).toBe(true);
  });

  it('does not match production paths that merely contain the letters', () => {
    for (const p of no) expect(isTestOrFixturePath(p), p).toBe(false);
  });
});
