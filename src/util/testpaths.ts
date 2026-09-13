/**
 * Which paths are test, fixture or mock code — and which rules must not shout
 * about what they find there.
 *
 * Why this is its own module: a credential-shaped construct inside a test is
 * usually the *subject* of the test. Sentinel once reported
 * `e2e/admin-session-hygiene.spec.ts` as a High "authentication material written
 * to web storage", citing a spec whose entire purpose is exercising session
 * hygiene. That finding is not wrong about the line — it is wrong about what the
 * line means, and at High severity it costs the reader trust in every other High
 * in the report.
 *
 * The correction is deliberately narrow. Test paths are *not* excluded from all
 * rules: a swallowed catch in a test is still a swallowed catch, and a hardcoded
 * production credential in a test file is still worth reporting. What changes is
 * that the credential/auth-storage/secret family reports at `Info` with an
 * explicit "in test code" note rather than at the rule's headline severity.
 */

/**
 * The built-in set. Regex sources rather than compiled patterns so a profile can
 * append to them.
 *
 * Covers: directory segments (`test`, `tests`, `__tests__`, `spec`, `specs`,
 * `e2e`, `e2e-prod`, `integration-tests`, `cypress`, `playwright`, `fixtures`,
 * `__fixtures__`, `mocks`, `__mocks__`, `testdata`, `test-data`, `stubs`),
 * filename suffixes (`*.test.ts`, `*.spec.tsx`, `*_test.go`, `FooTest.java`,
 * `*.fixture.ts`, `*.mock.js`), and conftest.py.
 */
export const DEFAULT_TEST_PATH_PATTERNS: readonly string[] = [
  // directory segments, including dash/underscore-suffixed variants such as
  // `e2e-prod` and `integration-tests`
  '(^|/)(__tests__|__fixtures__|__mocks__|__snapshots__)(/|$)',
  '(^|/)(tests?|specs?|e2e|cypress|playwright|fixtures?|mocks?|stubs?|testdata|test[-_]data|test[-_]fixtures?|test[-_]helpers?)(/|$)',
  '(^|/)[a-z0-9]+[-_](tests?|specs?|e2e|fixtures?|mocks?)(/|$)',
  '(^|/)(tests?|specs?|e2e|fixtures?|mocks?)[-_][a-z0-9-]+(/|$)',
  // filename suffixes
  '\\.(test|spec|fixture|fixtures|mock|mocks|stub|stubs)\\.[cm]?[jt]sx?$',
  '\\.(test|spec)\\.(py|rb|go|rs|java|kt|cs|php)$',
  '_test\\.(go|py|rb|rs)$',
  '(^|/)test_[^/]+\\.py$',
  '(^|/)conftest\\.py$',
  'Tests?\\.(cs|java|kt|swift)$',
  '(^|/)[Tt]est[A-Z][^/]*\\.(cs|java|kt)$',
];

export interface TestPathConfig {
  /** Extra regex sources. */
  patterns?: string[];
  /**
   * `extend` (default) appends to the built-in set; `replace` uses only the
   * supplied patterns. `replace` with an empty list disables path-aware
   * severity entirely, which is a legitimate choice for a repository that keeps
   * production code under a `test/` directory.
   */
  mode?: 'extend' | 'replace';
}

/**
 * Build the predicate. Invalid patterns are skipped rather than thrown: a typo
 * in a profile must not take a scan down, and the built-ins still apply.
 */
export function buildTestPathPredicate(config?: TestPathConfig): (path: string) => boolean {
  const sources =
    config?.mode === 'replace' ? (config.patterns ?? []) : [...DEFAULT_TEST_PATH_PATTERNS, ...(config?.patterns ?? [])];
  const compiled: RegExp[] = [];
  for (const src of sources) {
    try {
      compiled.push(new RegExp(src, 'i'));
    } catch {
      // an unusable pattern is ignored; the rest of the set still applies
    }
  }
  if (compiled.length === 0) return () => false;
  return (path: string) => compiled.some((re) => re.test(path));
}

/** The default predicate, for callers with no profile in hand. */
export const isTestOrFixturePath = buildTestPathPredicate();

/**
 * Rules whose whole subject is credential handling. A hit from one of these in
 * test code is reported at `Info`, because the construct is normally the thing
 * under test — while a hit anywhere else keeps the rule's own severity.
 *
 * Kept as an explicit list rather than inferred from labels: "which rules are
 * about credentials" is a judgement that should be reviewable in one place, not
 * an emergent property of tag spelling.
 */
export const CREDENTIAL_SENSITIVE_RULE_IDS: readonly string[] = [
  'SEC-TOKEN-WEBSTORAGE',
  'SEC-SECRET-COMMITTED',
  'SEC-SECRET-IN-TEST',
  'SEC-SECRET-IN-CLIENT-BUNDLE',
  'SEC-SECRET-HISTORY',
  'SEC-JWT-CLIENT-TRUST',
  'SEC-CLIENT-SIDE-AUTHZ',
  'DOCKER-SECRET-ARG',
];

export function isCredentialSensitiveRule(ruleId: string): boolean {
  return CREDENTIAL_SENSITIVE_RULE_IDS.includes(ruleId);
}

/** The note appended to a finding that only exists in test/fixture code. */
export function inTestCodeNote(paths: string[], ruleId: string): string {
  const shown = paths.slice(0, 3).join(', ');
  return `In test code: every cited location is a test, spec or fixture path (${shown}${paths.length > 3 ? `, +${paths.length - 3} more` : ''}). For ${ruleId} that is usually the construct under test rather than a production exposure, so this is reported at Info. It is not suppressed outright — a real production credential pasted into a test file is still a credential in the repository.`;
}
