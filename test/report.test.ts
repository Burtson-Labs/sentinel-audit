import { describe, it, expect } from 'vitest';
import { buildSarif } from '../src/report/sarif.js';
import { assessConfidence, band } from '../src/report/confidence.js';
import { buildCoverage } from '../src/report/coverage.js';
import { renderHtml } from '../src/report/html.js';
import { renderReport, renderConfidence, renderCoverage } from '../src/report/markdown.js';
import { loadProfile, listProfiles, validateProfile, controlsFor } from '../src/profile.js';
import { matchesFilter, detectTestCommand } from '../src/fix/index.js';
import type { Finding, ScanContext } from '../src/types.js';

function ctx(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    root: '/repo',
    outDir: '/out',
    profileId: 'owasp-asvs',
    recon: {
      root: '/repo',
      repoUrl: 'https://example.org/demo.git',
      branch: 'main',
      commitSha: 'a'.repeat(40),
      commitDate: '2026-01-01T00:00:00Z',
      packageManager: 'pnpm',
      languages: [{ language: 'TypeScript', files: 10, loc: 2000 }],
      totalFiles: 20,
      totalLoc: 3000,
      frameworks: ['React', 'Vite'],
      entrypoints: ['src/main.tsx'],
      sourceFileCount: 10,
      testFileCount: 1,
      testToSourceRatio: 0.1,
      largestFiles: [{ file: 'src/big.ts', loc: 1500 }],
      scripts: { test: 'vitest run' },
      hasTypeScript: true,
      tsStrict: true,
      workflows: ['.github/workflows/ci.yml'],
      dockerfiles: [],
      excluded: ['node_modules'],
    },
    deps: {
      manager: 'pnpm',
      lockfiles: ['pnpm-lock.yaml'],
      total: 50,
      direct: 10,
      dev: 4,
      advisories: [],
      auditAvailable: true,
      auditCommand: 'pnpm audit --json',
      dependencies: [],
      licenseSummary: { MIT: 40 },
      unknownLicenseCount: 0,
    },
    secrets: {
      candidates: [],
      filesScanned: 20,
      externalScanner: { name: 'gitleaks', available: false, findings: 0, note: 'not installed' },
    },
    ci: {
      workflows: [
        {
          file: '.github/workflows/ci.yml',
          name: 'ci',
          triggers: ['pull_request'],
          permissions: null,
          jobs: [],
          gates: { test: true, lint: false, typecheck: false, audit: false, sast: false, secrets: false },
        },
      ],
      hasRequiredStatusCheckHint: true,
      unpinnedActions: [],
      riskyTriggers: [],
    },
    docker: { files: [] },
    hits: [],
    runs: [{ name: 'recon', ok: true, durationMs: 5, note: 'ok', notExamined: ['binary assets'] }],
    llm: { provider: 'none', available: false, note: 'no provider reachable', calls: 0, failures: 0 },
    startedAt: '2026-01-01T00:00:00Z',
    finishedAt: '2026-01-01T00:00:05Z',
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'SEC-001',
    title: 'Token in web storage',
    type: 'Security',
    severity: 'High',
    suggestedLabels: ['security', 'auth'],
    affectedArea: 'UI',
    evidence: 'src/auth.ts:43 — localStorage.setItem with a credential key',
    whyThisMatters: 'readable by any script in the origin',
    recommendation: 'hold it in memory',
    acceptanceCriteria: ['no credential key in web storage'],
    effortEstimate: 'L',
    dependenciesRelated: [],
    provenance: {
      repoUrl: 'https://example.org/demo.git',
      branch: 'main',
      commitSha: 'a'.repeat(40),
      reviewDate: '2026-01-01',
      tool: 'sentinel-audit',
      toolVersion: '0.1.0',
      profile: 'owasp-asvs',
      llmPass: 'unavailable',
    },
    standardMapping: 'OWASP ASVS: 8.2.1',
    status: 'confirmed',
    verification: {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/auth.ts:43 — localStorage.setItem(...)' }],
      notes: 're-read from disk',
    },
    locations: [{ file: 'src/auth.ts', startLine: 43, excerpt: 'localStorage.setItem(TOKEN_KEY, t)' }],
    standards: { profile: 'owasp-asvs', controls: [{ id: 'ASVS 8.2.1', title: 'no sensitive data in browser storage' }], cwe: [], owasp: ['ASVS 8.2.1'] },
    fixPlan: {
      agentExecutable: false,
      strategy: 'move to an in-memory store',
      files: [{ path: 'src/auth.ts', change: 'use the accessor' }],
      acceptanceTests: [{ path: 'test/auth.test.ts', description: 'no token key written' }],
      risk: 'high',
      estimatedDiffSize: 'moderate',
      notAgentExecutableReason: 'needs a server-side cookie contract',
    },
    source: 'rule',
    ruleId: 'SEC-TOKEN-WEBSTORAGE',
    confidence: 0.9,
    fingerprint: 'abc123',
    ...overrides,
  };
}

describe('profiles', () => {
  it('loads every builtin profile and they all validate', () => {
    for (const id of listProfiles()) {
      const p = loadProfile(id);
      expect(validateProfile(p)).toEqual([]);
      expect(Object.keys(p.controls).length).toBeGreaterThan(10);
    }
  });

  it('maps a rule id to controls', () => {
    const asvs = loadProfile('owasp-asvs');
    expect(controlsFor(asvs, 'SEC-TOKEN-WEBSTORAGE').length).toBeGreaterThan(0);
  });

  it('falls back to the rule family prefix', () => {
    const cwe = loadProfile('cwe-top-25');
    const controls = controlsFor(cwe, 'DEP-ADVISORY-LODASH');
    expect(controls.some((c) => c.id.startsWith('CWE-'))).toBe(true);
  });

  it('returns no controls rather than inventing one', () => {
    expect(controlsFor(loadProfile('owasp-asvs'), 'NOT-A-RULE')).toEqual([]);
  });

  it('rejects a malformed profile', () => {
    expect(validateProfile({ id: 'x' }).length).toBeGreaterThan(0);
  });

  it('errors clearly for an unknown profile id', () => {
    expect(() => loadProfile('does-not-exist')).toThrow(/profile not found/);
  });

  it('the cwe profile supplies real CWE ids for the security rules', () => {
    const cwe = loadProfile('cwe-top-25');
    expect(controlsFor(cwe, 'SEC-XSS-DANGEROUS-HTML')[0]!.id).toBe('CWE-79');
    expect(controlsFor(cwe, 'SEC-CHILD-PROCESS-SHELL')[0]!.id).toBe('CWE-78');
  });
});

describe('buildSarif', () => {
  const sarif = (findings: Finding[]): Record<string, never> =>
    JSON.parse(buildSarif(ctx(), findings, { toolVersion: '0.1.0' }));

  it('emits a valid-shaped 2.1.0 document', () => {
    const doc = sarif([finding()]) as unknown as { version: string; runs: unknown[] };
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs).toHaveLength(1);
  });

  it('maps severity to a SARIF level', () => {
    const doc = sarif([finding({ severity: 'Blocker' }), finding({ id: 'SEC-002', severity: 'Low', ruleId: 'SEC-TARGET-BLANK' })]) as unknown as {
      runs: Array<{ results: Array<{ level: string }> }>;
    };
    expect(doc.runs[0]!.results[0]!.level).toBe('error');
    expect(doc.runs[0]!.results[1]!.level).toBe('note');
  });

  it('suppresses refuted findings instead of dropping them', () => {
    const refuted = finding({
      status: 'refuted',
      severity: 'Info',
      verification: {
        method: 'proof-executed',
        claimType: 'behavioral',
        performed: true,
        result: 'refuted',
        checks: [],
        notes: 'the sanitiser neutralised every payload',
      },
    });
    const doc = sarif([refuted]) as unknown as { runs: Array<{ results: Array<{ suppressions?: Array<{ justification: string }> }> }> };
    const result = doc.runs[0]!.results[0]!;
    expect(result.suppressions).toBeDefined();
    expect(result.suppressions![0]!.justification).toMatch(/Refuted/);
  });

  it('suppresses triaged-out findings with the cited reason', () => {
    const triaged = finding({
      status: 'triaged-out',
      triage: { suppressed: true, reason: 'value is an env reference', evidenceCited: 'src/a.ts:1', by: 'heuristic' },
    });
    const doc = sarif([triaged]) as unknown as { runs: Array<{ results: Array<{ suppressions?: Array<{ justification: string }> }> }> };
    expect(doc.runs[0]!.results[0]!.suppressions![0]!.justification).toMatch(/env reference/);
  });

  it('carries the verification record in properties so a consumer can filter on it', () => {
    const doc = sarif([finding()]) as unknown as {
      runs: Array<{ results: Array<{ properties: { sentinel: { status: string; verificationMethod: string } } }> }>;
    };
    const p = doc.runs[0]!.results[0]!.properties.sentinel;
    expect(p.status).toBe('confirmed');
    expect(p.verificationMethod).toBe('static-assertion');
  });

  it('sets a stable partial fingerprint', () => {
    const doc = sarif([finding()]) as unknown as { runs: Array<{ results: Array<{ partialFingerprints: { sentinelFingerprint: string } }> }> };
    expect(doc.runs[0]!.results[0]!.partialFingerprints.sentinelFingerprint).toBe('abc123');
  });

  it('records version-control provenance', () => {
    const doc = sarif([finding()]) as unknown as { runs: Array<{ versionControlProvenance: Array<{ revisionId: string }> }> };
    expect(doc.runs[0]!.versionControlProvenance[0]!.revisionId).toBe('a'.repeat(40));
  });

  it('declares each rule once even with many results', () => {
    const doc = sarif([finding(), finding({ id: 'SEC-002' }), finding({ id: 'SEC-003' })]) as unknown as {
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: unknown[] }>;
    };
    expect(doc.runs[0]!.tool.driver.rules).toHaveLength(1);
    expect(doc.runs[0]!.results).toHaveLength(3);
  });
});

describe('assessConfidence', () => {
  const profile = loadProfile('owasp-asvs');

  it('scores a clean repository high', () => {
    const c = assessConfidence(ctx(), [], profile);
    expect(c.overallScore).toBeGreaterThan(8);
    expect(c.gateDecision).toBe('pass');
  });

  it('blocks on a confirmed blocker', () => {
    const blocker = finding({ severity: 'Blocker', status: 'confirmed' });
    const c = assessConfidence(ctx(), [blocker], profile);
    expect(c.gateDecision).toBe('block');
    expect(c.bottomLine.join(' ')).toMatch(/block/i);
  });

  it('does not block on an unproven blocker, but passes with conditions', () => {
    const unproven = finding({
      severity: 'Blocker',
      status: 'plausible',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'reasoned' },
    });
    expect(assessConfidence(ctx(), [unproven], profile).gateDecision).toBe('pass-with-conditions');
  });

  it('saturates: a pile of Medium findings cannot outweigh a verified Blocker', () => {
    const mediums = Array.from({ length: 30 }, (_, i) => finding({ id: `SEC-${100 + i}`, severity: 'Medium' }));
    const blocker = [finding({ severity: 'Blocker' })];
    const mediumScore = assessConfidence(ctx(), mediums, profile).overallScore;
    const blockerScore = assessConfidence(ctx(), blocker, profile).overallScore;
    expect(blockerScore).toBeLessThan(mediumScore);
  });

  it('never leaves the 0..10 range', () => {
    const many = Array.from({ length: 60 }, (_, i) => finding({ id: `SEC-${100 + i}`, severity: 'Blocker' }));
    const c = assessConfidence(ctx(), many, profile);
    expect(c.overallScore).toBeGreaterThanOrEqual(0);
    expect(c.overallScore).toBeLessThanOrEqual(10);
  });

  it('reports the verified share of live findings', () => {
    const findings = [finding(), finding({ id: 'SEC-002', status: 'plausible', verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'x' } })];
    const c = assessConfidence(ctx(), findings, profile);
    expect(c.evidenceQuality.confirmed).toBe(1);
    expect(c.evidenceQuality.plausible).toBe(1);
    expect(c.evidenceQuality.verifiedShare).toBe(0.5);
  });

  it('credits refutations in the "why not lower" narrative', () => {
    const refuted = finding({
      status: 'refuted',
      severity: 'Info',
      verification: { method: 'proof-executed', claimType: 'behavioral', performed: true, result: 'refuted', checks: [], notes: 'safe' },
    });
    const c = assessConfidence(ctx(), [refuted], profile);
    expect(c.whyNotLower.join(' ')).toMatch(/refuted/i);
  });

  it('says so when the model pass did not run', () => {
    const c = assessConfidence(ctx(), [finding()], profile);
    expect(c.signals.some((s) => /model-assisted review pass did not run/i.test(s.signal))).toBe(true);
  });

  it('derives likelihood from verification strength', () => {
    const proven = finding({
      verification: {
        method: 'proof-executed',
        claimType: 'behavioral',
        performed: true,
        result: 'confirmed',
        checks: [],
        proof: { path: 'p', command: 'c', exitCode: 0, durationMs: 1, predicted: 'p', observed: 'o', verdict: 'vulnerable', stdoutExcerpt: '', stderrExcerpt: '' },
        notes: '',
      },
    });
    const guessed = finding({ id: 'SEC-002', status: 'plausible', confidence: 0.4, verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: '' } });
    const c = assessConfidence(ctx(), [proven, guessed], profile);
    expect(c.riskMatrix.find((r) => r.id === 'SEC-001')!.likelihood).toBe('High');
    expect(c.riskMatrix.find((r) => r.id === 'SEC-002')!.likelihood).toBe('Low');
  });

  it('band() labels the ranges', () => {
    expect(band(2)).toMatch(/critical/);
    expect(band(5)).toMatch(/concerning/);
    expect(band(7)).toMatch(/acceptable/);
    expect(band(9)).toMatch(/good/);
  });
});

describe('buildCoverage', () => {
  it('marks a missing external scanner as not covered', () => {
    const cov = buildCoverage(ctx(), [finding()]);
    const row = cov.sections[0]!.rows.find((r) => r.item.includes('git history'));
    expect(row!.status).toBe('not-covered');
  });

  it('always lists runtime behaviour as not examined', () => {
    const cov = buildCoverage(ctx(), []);
    expect(cov.notExamined.join(' ')).toMatch(/no application was started/);
  });

  it('propagates each collector\'s own gaps', () => {
    const cov = buildCoverage(ctx(), []);
    expect(cov.notExamined.some((n) => n.includes('binary assets'))).toBe(true);
  });

  it('separates verified findings from inferred ones', () => {
    const inferred = finding({
      id: 'SEC-002',
      status: 'plausible',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'reasoned only' },
    });
    const cov = buildCoverage(ctx(), [finding(), inferred]);
    expect(cov.verifiedDirectly.join(' ')).toContain('SEC-001');
    expect(cov.inferredOnly.join(' ')).toContain('SEC-002');
  });

  it('recommends confirming unproven high-severity findings before spending on them', () => {
    const unproven = finding({
      status: 'plausible',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'x' },
    });
    const cov = buildCoverage(ctx(), [unproven]);
    expect(cov.recommendedFollowUps.join(' ')).toMatch(/before committing remediation budget/);
  });
});

describe('renderers', () => {
  const profile = loadProfile('owasp-asvs');

  it('markdown report includes the verification block and the status', () => {
    const c = assessConfidence(ctx(), [finding()], profile);
    const md = renderReport(ctx(), [finding()], profile, c);
    expect(md).toContain('CONFIRMED');
    expect(md).toContain('**Verification**');
    expect(md).toContain('static-assertion');
    expect(md).toContain('Fix plan');
  });

  it('markdown report keeps a refuted section rather than hiding it', () => {
    const refuted = finding({
      status: 'refuted',
      severity: 'Info',
      verification: { method: 'proof-executed', claimType: 'behavioral', performed: true, result: 'refuted', checks: [], notes: 'safe' },
    });
    const c = assessConfidence(ctx(), [refuted], profile);
    const md = renderReport(ctx(), [refuted], profile, c);
    expect(md).toContain('# Refuted');
  });

  it('markdown report shows triaged-out items with their reasons', () => {
    const triaged = finding({
      status: 'triaged-out',
      triage: { suppressed: true, reason: 'value is an env reference', evidenceCited: 'src/a.ts:1', by: 'heuristic' },
    });
    const c = assessConfidence(ctx(), [triaged], profile);
    const md = renderReport(ctx(), [triaged], profile, c);
    expect(md).toContain('# Triaged out');
    expect(md).toContain('env reference');
  });

  it('confidence and coverage documents render', () => {
    const c = assessConfidence(ctx(), [finding()], profile);
    expect(renderConfidence(ctx(), c, profile)).toContain('Overall score');
    expect(renderCoverage(ctx(), buildCoverage(ctx(), [finding()]))).toContain('Explicitly not examined');
  });

  it('html report is self-contained: no external requests of any kind', () => {
    const c = assessConfidence(ctx(), [finding()], profile);
    const html = renderHtml(ctx(), [finding()], profile, c);
    expect(html).not.toMatch(/src\s*=\s*["']https?:/i);
    expect(html).not.toMatch(/<link[^>]+href\s*=\s*["']https?:/i);
    expect(html).not.toMatch(/@import\s+url\(/i);
    expect(html).not.toMatch(/\bfetch\s*\(/);
    expect(html).not.toMatch(/XMLHttpRequest|WebSocket|EventSource/);
  });

  it('html report styles both colour schemes', () => {
    const c = assessConfidence(ctx(), [finding()], profile);
    const html = renderHtml(ctx(), [finding()], profile, c);
    expect(html).toContain('prefers-color-scheme: dark');
    expect(html).toContain('data-theme="dark"');
    expect(html).toContain('data-theme="light"');
  });

  it('html report escapes finding text', () => {
    const nasty = finding({ title: '<script>alert(1)</script>' });
    const c = assessConfidence(ctx(), [nasty], profile);
    const html = renderHtml(ctx(), [nasty], profile, c);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

describe('fix helpers', () => {
  it('matches ids and prefixes', () => {
    expect(matchesFilter('SEC-001', undefined)).toBe(true);
    expect(matchesFilter('SEC-001', 'SEC-*')).toBe(true);
    expect(matchesFilter('QUA-001', 'SEC-*')).toBe(false);
    expect(matchesFilter('SEC-001', 'SEC-001,QUA-003')).toBe(true);
    expect(matchesFilter('SEC-002', 'SEC-001,QUA-003')).toBe(false);
    expect(matchesFilter('sec-001', 'SEC-001')).toBe(true);
  });

  it('returns null when the repository has no test command', () => {
    expect(detectTestCommand('/definitely/not/a/repo')).toBeNull();
  });
});

describe('report sections that make it actionable', () => {
  const profile = loadProfile('owasp-asvs');

  it('lists merge blockers with the finding\'s own acceptance criteria as sub-items', () => {
    const blocker = finding({ severity: 'Blocker', status: 'confirmed' });
    const md = renderReport(ctx(), [blocker], profile, assessConfidence(ctx(), [blocker], profile));
    expect(md).toContain('# Merge blockers');
    expect(md).toContain('- [ ] **SEC-001**');
    expect(md).toContain('  - [ ] no credential key in web storage');
  });

  it('says so plainly when there are no blockers, and names the unproven highs', () => {
    const unproven = finding({
      severity: 'High',
      status: 'plausible',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: 'x' },
    });
    const md = renderReport(ctx(), [unproven], profile, assessConfidence(ctx(), [unproven], profile));
    expect(md).toMatch(/# Merge blockers\n\nNone\./);
    expect(md).toContain('Confirm them before treating them as blockers');
  });

  it('keeps a debt register separate from security findings', () => {
    const debtItem = finding({ id: 'TD-001', type: 'Tech Debt', severity: 'Low', title: 'Oversized modules', ruleId: 'QUA-FILE-SIZE' });
    const md = renderReport(ctx(), [finding(), debtItem], profile, assessConfidence(ctx(), [finding(), debtItem], profile));
    expect(md).toContain('# Technical debt register');
    expect(md).toContain('TD-001');
  });

  it('recommends the missing gates in order and names the ones already present', () => {
    const md = renderReport(ctx(), [finding()], profile, assessConfidence(ctx(), [finding()], profile));
    expect(md).toContain('# Recommended quality gates');
    expect(md).toContain('Already enforced on a PR-triggered workflow: test');
    expect(md).toContain('**audit**');
    expect(md).toContain('sentinel init-workflow');
  });
});
