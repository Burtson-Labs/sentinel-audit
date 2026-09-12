import { describe, it, expect } from 'vitest';
import { validateFinding, validateFindings, scoreConfidence, statusFromVerification } from '../src/schema.js';
import type { Finding } from '../src/types.js';

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'SEC-001',
    title: 'Something is wrong',
    type: 'Security',
    severity: 'High',
    suggestedLabels: ['security'],
    affectedArea: 'API',
    evidence: 'src/app.ts:42 — the thing is there',
    whyThisMatters: 'because it matters',
    recommendation: 'fix it',
    acceptanceCriteria: ['it is fixed'],
    effortEstimate: 'M',
    dependenciesRelated: [],
    provenance: {
      repoUrl: 'https://example.org/repo.git',
      branch: 'main',
      commitSha: 'abc123',
      reviewDate: '2026-01-01',
      tool: 'sentinel-audit',
      toolVersion: '0.1.0',
      profile: 'owasp-asvs',
      llmPass: 'disabled',
    },
    standardMapping: 'Profile: CTRL-1 — a control',
    status: 'plausible',
    verification: {
      method: 'code-read',
      claimType: 'behavioral',
      performed: false,
      result: 'plausible',
      checks: [],
      notes: 'reasoned only',
    },
    locations: [{ file: 'src/app.ts', startLine: 42 }],
    standards: { profile: 'owasp-asvs', controls: [], cwe: [], owasp: [] },
    fixPlan: {
      agentExecutable: false,
      strategy: 'do the thing',
      files: [],
      acceptanceTests: [],
      risk: 'low',
      estimatedDiffSize: 'small',
      notAgentExecutableReason: 'needs a human',
    },
    source: 'rule',
    confidence: 0.5,
    fingerprint: 'deadbeef',
    ...overrides,
  };
}

const errors = (f: Partial<Finding>): string[] =>
  validateFinding(f).filter((i) => i.severity === 'error').map((i) => `${i.path}: ${i.message}`);

describe('validateFinding — structure', () => {
  it('accepts a well-formed finding', () => {
    expect(errors(baseFinding())).toEqual([]);
  });

  it('requires evidence to cite something concrete', () => {
    const issues = errors(baseFinding({ evidence: 'the codebase has problems' }));
    expect(issues.join()).toMatch(/evidence.*concrete/);
  });

  it('accepts a path-with-extension as evidence', () => {
    expect(errors(baseFinding({ evidence: 'vite.config.ts sets sourcemap unconditionally' }))).toEqual([]);
  });

  it('accepts a named tool artefact as evidence', () => {
    expect(errors(baseFinding({ evidence: '`pnpm audit` reports 3 advisories' }))).toEqual([]);
  });

  it('rejects an unknown severity', () => {
    expect(errors(baseFinding({ severity: 'Catastrophic' as Finding['severity'] })).join()).toMatch(/severity/);
  });

  it('requires at least one acceptance criterion', () => {
    expect(errors(baseFinding({ acceptanceCriteria: [] })).join()).toMatch(/acceptanceCriteria/);
  });

  it('requires an agent prompt when the plan claims to be agent-executable', () => {
    const f = baseFinding();
    f.fixPlan.agentExecutable = true;
    f.fixPlan.agentPrompt = undefined;
    expect(errors(f).join()).toMatch(/agentPrompt/);
  });
});

describe('validateFinding — the invariants that make the tool mean something', () => {
  it('forbids "confirmed" when nothing was executed', () => {
    const f = baseFinding({ status: 'confirmed' });
    expect(errors(f).join()).toMatch(/performed === true/);
  });

  it('forbids "confirmed" for a code-read verification', () => {
    const f = baseFinding({ status: 'confirmed' });
    f.verification.performed = true;
    f.verification.method = 'code-read';
    expect(errors(f).join()).toMatch(/not permitted with verification.method/);
  });

  it('forbids "confirmed" on a behavioural claim without an executed proof', () => {
    const f = baseFinding({ status: 'confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'the construct is present',
    };
    expect(errors(f).join()).toMatch(/requires an executed proof/);
  });

  it('allows "confirmed" on a factual claim verified by re-assertion', () => {
    const f = baseFinding({ status: 'confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'the construct is present',
    };
    expect(errors(f)).toEqual([]);
  });

  it('allows "confirmed" on a behavioural claim with a vulnerable proof verdict', () => {
    const f = baseFinding({ status: 'confirmed' });
    f.verification = {
      method: 'proof-executed',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      checks: [{ description: 'ran the proof', outcome: 'pass', detail: 'proofs/x.mjs' }],
      proof: {
        path: 'proofs/x.mjs',
        command: 'node proofs/x.mjs',
        exitCode: 0,
        durationMs: 10,
        predicted: 'a payload survives',
        observed: '1 of 15 survived',
        verdict: 'vulnerable',
        stdoutExcerpt: '',
        stderrExcerpt: '',
      },
      notes: 'proof ran',
    };
    expect(errors(f)).toEqual([]);
  });

  it('forbids "confirmed" when the attached proof says the code is safe', () => {
    const f = baseFinding({ status: 'confirmed' });
    f.verification = {
      method: 'proof-executed',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      checks: [{ description: 'ran the proof', outcome: 'fail', detail: 'proofs/x.mjs' }],
      proof: {
        path: 'proofs/x.mjs',
        command: 'node proofs/x.mjs',
        exitCode: 0,
        durationMs: 10,
        predicted: 'a payload survives',
        observed: 'none survived',
        verdict: 'safe',
        stdoutExcerpt: '',
        stderrExcerpt: '',
      },
      notes: 'proof ran',
    };
    expect(errors(f).join()).toMatch(/proof verdict of "vulnerable"/);
  });

  it('requires a cited location for a suppression', () => {
    const f = baseFinding({
      status: 'triaged-out',
      triage: { suppressed: true, reason: 'it is fine', evidenceCited: 'trust me', by: 'llm' },
    });
    expect(errors(f).join()).toMatch(/evidenceCited.*concrete/);
  });

  it('accepts a suppression that cites file:line', () => {
    const f = baseFinding({
      status: 'triaged-out',
      triage: { suppressed: true, reason: 'the value is an env reference', evidenceCited: 'src/app.ts:42', by: 'llm' },
    });
    expect(errors(f)).toEqual([]);
  });

  it('requires a refutation to have been executed', () => {
    const f = baseFinding({ status: 'refuted' });
    expect(errors(f).join()).toMatch(/requires an executed check/);
  });
});

describe('validateFindings — cross-finding checks', () => {
  it('flags duplicate ids', () => {
    const issues = validateFindings([baseFinding(), baseFinding()]);
    expect(issues.some((i) => /duplicate id/.test(i.message))).toBe(true);
  });

  it('warns about dangling related-finding references', () => {
    const issues = validateFindings([baseFinding({ dependenciesRelated: ['SEC-999'] })]);
    expect(issues.some((i) => /unknown finding/.test(i.message))).toBe(true);
  });
});

describe('scoreConfidence', () => {
  it('is highest for an executed proof that found the issue', () => {
    const score = scoreConfidence({
      status: 'confirmed',
      source: 'rule',
      verification: {
        method: 'proof-executed',
        claimType: 'behavioral',
        performed: true,
        result: 'confirmed',
        checks: [{ description: 'x', outcome: 'pass', detail: 'a:1' }],
        proof: {
          path: 'p',
          command: 'c',
          exitCode: 0,
          durationMs: 1,
          predicted: 'p',
          observed: 'o',
          verdict: 'vulnerable',
          stdoutExcerpt: '',
          stderrExcerpt: '',
        },
        notes: '',
      },
    });
    expect(score).toBeGreaterThan(0.95);
  });

  it('penalises a model-proposed, code-read finding', () => {
    const llm = scoreConfidence({
      status: 'plausible',
      source: 'llm',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: '' },
    });
    const rule = scoreConfidence({
      status: 'plausible',
      source: 'rule',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', checks: [], notes: '' },
    });
    expect(llm).toBeLessThan(rule);
  });

  it('is high for a refutation — we are confident the claim is false', () => {
    const score = scoreConfidence({
      status: 'refuted',
      source: 'rule',
      verification: { method: 'proof-executed', claimType: 'behavioral', performed: true, result: 'refuted', checks: [], notes: '' },
    });
    expect(score).toBeGreaterThan(0.9);
  });
});

describe('statusFromVerification', () => {
  it('caps a behavioural confirmation without a proof at plausible', () => {
    expect(statusFromVerification('behavioral', 'confirmed', 'static-assertion')).toBe('plausible');
  });

  it('allows a factual confirmation by re-assertion', () => {
    expect(statusFromVerification('factual', 'confirmed', 'static-assertion')).toBe('confirmed');
  });

  it('never promotes a code-read result', () => {
    expect(statusFromVerification('factual', 'confirmed', 'code-read')).toBe('plausible');
  });

  it('passes refutations through', () => {
    expect(statusFromVerification('behavioral', 'refuted', 'proof-executed')).toBe('refuted');
  });
});
