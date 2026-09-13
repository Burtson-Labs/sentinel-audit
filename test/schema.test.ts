import { describe, it, expect } from 'vitest';
import {
  validateFinding,
  validateFindings,
  scoreConfidence,
  statusFromVerification,
  statusClass,
  isConfirmed,
  isProofConfirmed,
} from '../src/schema.js';
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
      state: 'plausible',
      class: 'plausible',
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

const VULNERABLE_PROOF = {
  path: 'proofs/x.mjs',
  command: 'node proofs/x.mjs',
  exitCode: 0,
  durationMs: 10,
  predicted: 'a payload survives',
  observed: '1 of 15 survived',
  verdict: 'vulnerable' as const,
  stdoutExcerpt: '',
  stderrExcerpt: '',
};

describe('validateFinding — the invariants that make the tool mean something', () => {
  it('forbids a confirmed state when nothing was executed', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = { ...f.verification, state: 'pattern-confirmed', class: 'confirmed', claimType: 'factual' };
    expect(errors(f).join()).toMatch(/performed === true/);
  });

  it('forbids a confirmed state for a code-read verification', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = { ...f.verification, state: 'pattern-confirmed', class: 'confirmed', claimType: 'factual', performed: true, method: 'code-read' };
    expect(errors(f).join()).toMatch(/not permitted with verification.method/);
  });

  it('forbids "pattern-confirmed" on a behavioural claim — a re-matched regex is not exploitability', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      state: 'pattern-confirmed',
      class: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'the construct is present',
    };
    expect(errors(f).join()).toMatch(/not permitted on a behavioral claim/);
  });

  it('allows "pattern-confirmed" on a factual claim verified by re-assertion', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      state: 'pattern-confirmed',
      class: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'the construct is present',
    };
    expect(errors(f)).toEqual([]);
  });

  it('forbids "proof-confirmed" without an executed proof', () => {
    const f = baseFinding({ status: 'proof-confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      state: 'proof-confirmed',
      class: 'confirmed',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'the construct is present',
    };
    expect(errors(f).join()).toMatch(/requires verification.method "proof-executed"/);
  });

  it('allows "proof-confirmed" on a behavioural claim with a vulnerable proof verdict', () => {
    const f = baseFinding({ status: 'proof-confirmed' });
    f.verification = {
      method: 'proof-executed',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      state: 'proof-confirmed',
      class: 'confirmed',
      checks: [{ description: 'ran the proof', outcome: 'pass', detail: 'proofs/x.mjs' }],
      proof: VULNERABLE_PROOF,
      notes: 'proof ran',
    };
    expect(errors(f)).toEqual([]);
  });

  it('forbids "proof-confirmed" when the attached proof says the code is safe', () => {
    const f = baseFinding({ status: 'proof-confirmed' });
    f.verification = {
      method: 'proof-executed',
      claimType: 'behavioral',
      performed: true,
      result: 'confirmed',
      state: 'proof-confirmed',
      class: 'confirmed',
      checks: [{ description: 'ran the proof', outcome: 'fail', detail: 'proofs/x.mjs' }],
      proof: { ...VULNERABLE_PROOF, observed: 'none survived', verdict: 'safe' },
      notes: 'proof ran',
    };
    expect(errors(f).join()).toMatch(/verdict is "vulnerable"/);
  });

  it('forbids calling an executed vulnerable proof "pattern-confirmed" — it undersells, and the split must be exact', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = {
      method: 'proof-executed',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      state: 'pattern-confirmed',
      class: 'confirmed',
      checks: [{ description: 'ran the proof', outcome: 'pass', detail: 'proofs/x.mjs' }],
      proof: VULNERABLE_PROOF,
      notes: 'proof ran',
    };
    expect(errors(f).join()).toMatch(/is "proof-confirmed", not "pattern-confirmed"/);
  });

  it('rejects a verification.state that disagrees with status', () => {
    const f = baseFinding({ status: 'plausible' });
    f.verification = { ...f.verification, state: 'proof-confirmed', class: 'confirmed' };
    expect(errors(f).join()).toMatch(/verification.state: must equal status/);
  });

  it('rejects a verification.class that does not match its state', () => {
    const f = baseFinding({ status: 'pattern-confirmed' });
    f.verification = {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: 'confirmed',
      state: 'pattern-confirmed',
      class: 'plausible',
      checks: [{ description: 're-read the line', outcome: 'pass', detail: 'src/app.ts:42' }],
      notes: 'present',
    };
    expect(errors(f).join()).toMatch(/verification.class: must be "confirmed"/);
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
    f.verification = { ...f.verification, state: 'triaged-out', class: 'triaged-out' };
    expect(errors(f)).toEqual([]);
  });

  it('requires a refutation to have been executed', () => {
    const f = baseFinding({ status: 'refuted' });
    f.verification = { ...f.verification, state: 'refuted', class: 'refuted' };
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
  const proofScore = (): number =>
    scoreConfidence({
      status: 'proof-confirmed',
      source: 'rule',
      verification: {
        method: 'proof-executed',
        claimType: 'behavioral',
        performed: true,
        result: 'confirmed',
        state: 'proof-confirmed',
        class: 'confirmed',
        checks: [{ description: 'x', outcome: 'pass', detail: 'a:1' }],
        proof: VULNERABLE_PROOF,
        notes: '',
      },
    });

  const patternScore = (): number =>
    scoreConfidence({
      status: 'pattern-confirmed',
      source: 'rule',
      verification: {
        method: 'static-assertion',
        claimType: 'factual',
        performed: true,
        result: 'confirmed',
        state: 'pattern-confirmed',
        class: 'confirmed',
        checks: [{ description: 'x', outcome: 'pass', detail: 'a:1' }],
        notes: '',
      },
    });

  it('is highest for an executed proof that found the issue', () => {
    expect(proofScore()).toBeGreaterThan(0.95);
  });

  it('weights proof-confirmed clearly above pattern-confirmed', () => {
    // Not a hair's breadth: the gap has to be visible in the number, or the
    // column stops carrying the distinction the status names make.
    expect(patternScore()).toBeLessThan(proofScore() - 0.1);
  });

  it('penalises a model-proposed, code-read finding', () => {
    const llm = scoreConfidence({
      status: 'plausible',
      source: 'llm',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', state: 'plausible', class: 'plausible', checks: [], notes: '' },
    });
    const rule = scoreConfidence({
      status: 'plausible',
      source: 'rule',
      verification: { method: 'code-read', claimType: 'behavioral', performed: false, result: 'plausible', state: 'plausible', class: 'plausible', checks: [], notes: '' },
    });
    expect(llm).toBeLessThan(rule);
  });

  it('is high for a refutation — we are confident the claim is false', () => {
    const score = scoreConfidence({
      status: 'refuted',
      source: 'rule',
      verification: { method: 'proof-executed', claimType: 'behavioral', performed: true, result: 'refuted', state: 'refuted', class: 'refuted', checks: [], notes: '' },
    });
    expect(score).toBeGreaterThan(0.9);
  });
});

describe('statusClass', () => {
  it('folds both confirmed states onto the older coarse vocabulary', () => {
    expect(statusClass('proof-confirmed')).toBe('confirmed');
    expect(statusClass('pattern-confirmed')).toBe('confirmed');
  });

  it('leaves the other states alone', () => {
    expect(statusClass('plausible')).toBe('plausible');
    expect(statusClass('refuted')).toBe('refuted');
    expect(statusClass('triaged-out')).toBe('triaged-out');
  });

  it('isConfirmed accepts both, isProofConfirmed only the proven one', () => {
    expect(isConfirmed({ status: 'pattern-confirmed' })).toBe(true);
    expect(isConfirmed({ status: 'proof-confirmed' })).toBe(true);
    expect(isConfirmed({ status: 'plausible' })).toBe(false);
    expect(isProofConfirmed({ status: 'pattern-confirmed' })).toBe(false);
    expect(isProofConfirmed({ status: 'proof-confirmed' })).toBe(true);
  });
});

describe('statusFromVerification', () => {
  it('caps a behavioural confirmation without a proof at plausible', () => {
    expect(statusFromVerification('behavioral', 'confirmed', 'static-assertion')).toBe('plausible');
  });

  it('labels a factual re-assertion pattern-confirmed, never plain confirmed', () => {
    expect(statusFromVerification('factual', 'confirmed', 'static-assertion')).toBe('pattern-confirmed');
  });

  it('labels an executed proof with a vulnerable verdict proof-confirmed', () => {
    expect(statusFromVerification('behavioral', 'confirmed', 'proof-executed', 'vulnerable')).toBe('proof-confirmed');
    expect(statusFromVerification('factual', 'confirmed', 'proof-executed', 'vulnerable')).toBe('proof-confirmed');
  });

  it('does not hand the strong label to a proof that reached no verdict', () => {
    expect(statusFromVerification('behavioral', 'confirmed', 'proof-executed', 'inconclusive')).toBe('plausible');
    expect(statusFromVerification('factual', 'confirmed', 'proof-executed', 'inconclusive')).toBe('pattern-confirmed');
  });

  it('never promotes a code-read result', () => {
    expect(statusFromVerification('factual', 'confirmed', 'code-read')).toBe('plausible');
  });

  it('passes refutations through', () => {
    expect(statusFromVerification('behavioral', 'refuted', 'proof-executed')).toBe('refuted');
  });
});
