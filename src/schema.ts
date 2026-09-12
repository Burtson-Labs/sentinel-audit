import {
  SEVERITIES,
  FINDING_TYPES,
  EFFORTS,
  STATUSES,
  type Finding,
  type Severity,
  type FindingStatus,
} from './types.js';

/**
 * Hand-rolled validation instead of a schema library, for two reasons:
 *  1. zero runtime dependencies (see README "trust model");
 *  2. the interesting rules are *semantic*, not structural — "a `confirmed`
 *     behavioral finding must carry an executed proof" is the invariant that
 *     actually separates this tool from an LLM writing confident prose, and no
 *     off-the-shelf schema expresses it.
 */

export interface ValidationIssue {
  findingId: string;
  path: string;
  message: string;
  severity: 'error' | 'warning';
}

const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.trim().length > 0;
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');

/**
 * A concrete reference: file:line, a path with an extension, or a named
 * artefact/tool. The point of the check is that "the codebase has too much
 * `any`" is not evidence, while "src/foo.ts:12" is.
 */
const EVIDENCE_REF =
  /[\w./\\-]+:\d+|[\w./\\-]+\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts|json|ya?ml|conf|html?|toml|env|sh|lock)\b|\b(?:npm audit|pnpm audit|yarn npm audit|advisory|advisories|lockfile|workflow|Dockerfile|Containerfile|package\.json|node_modules|gitleaks|trufflehog|detect-secrets|semgrep|codeql|trivy|grype|osv-scanner)\b|(?:^|\s)\.git(?:\b|\/)/i;

export function validateFinding(f: Partial<Finding>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const id = isNonEmptyString(f.id) ? f.id : '<no-id>';
  const err = (path: string, message: string): void => {
    issues.push({ findingId: id, path, message, severity: 'error' });
  };
  const warn = (path: string, message: string): void => {
    issues.push({ findingId: id, path, message, severity: 'warning' });
  };

  // ---- structural: consultant-compatible surface ----
  if (!isNonEmptyString(f.id)) err('id', 'required');
  else if (!/^[A-Z]{2,6}-\d{3}$/.test(f.id)) warn('id', `expected FAMILY-NNN, got "${f.id}"`);
  if (!isNonEmptyString(f.title)) err('title', 'required');
  if (!f.type || !FINDING_TYPES.includes(f.type)) err('type', `must be one of ${FINDING_TYPES.join('|')}`);
  if (!f.severity || !SEVERITIES.includes(f.severity)) err('severity', `must be one of ${SEVERITIES.join('|')}`);
  if (!isStringArray(f.suggestedLabels)) err('suggestedLabels', 'must be string[]');
  if (!isNonEmptyString(f.affectedArea)) err('affectedArea', 'required');
  if (!isNonEmptyString(f.evidence)) err('evidence', 'required');
  else if (!EVIDENCE_REF.test(f.evidence)) {
    err('evidence', 'must cite a concrete reference (file:line or a named tool/artefact)');
  }
  if (!isNonEmptyString(f.whyThisMatters)) err('whyThisMatters', 'required');
  if (!isNonEmptyString(f.recommendation)) err('recommendation', 'required');
  if (!isStringArray(f.acceptanceCriteria) || f.acceptanceCriteria.length === 0) {
    err('acceptanceCriteria', 'at least one criterion required');
  }
  if (!f.effortEstimate || !EFFORTS.includes(f.effortEstimate)) err('effortEstimate', `must be one of ${EFFORTS.join('|')}`);
  if (!isStringArray(f.dependenciesRelated)) err('dependenciesRelated', 'must be string[]');
  if (!isNonEmptyString(f.standardMapping)) err('standardMapping', 'required');
  if (!f.provenance) err('provenance', 'required');
  else {
    for (const key of ['repoUrl', 'branch', 'commitSha', 'reviewDate', 'tool', 'toolVersion', 'profile'] as const) {
      if (!isNonEmptyString(f.provenance[key])) err(`provenance.${key}`, 'required');
    }
  }

  // ---- structural: sentinel additions ----
  if (!f.status || !STATUSES.includes(f.status)) err('status', `must be one of ${STATUSES.join('|')}`);
  if (typeof f.confidence !== 'number' || f.confidence < 0 || f.confidence > 1) {
    err('confidence', 'must be a number in [0,1]');
  }
  if (!isNonEmptyString(f.fingerprint)) err('fingerprint', 'required');
  if (!Array.isArray(f.locations)) err('locations', 'must be an array');
  if (!f.standards) err('standards', 'required');
  if (!f.fixPlan) err('fixPlan', 'required');
  else {
    if (!isNonEmptyString(f.fixPlan.strategy)) err('fixPlan.strategy', 'required');
    if (!Array.isArray(f.fixPlan.files)) err('fixPlan.files', 'must be an array');
    if (!Array.isArray(f.fixPlan.acceptanceTests)) err('fixPlan.acceptanceTests', 'must be an array');
    if (typeof f.fixPlan.agentExecutable !== 'boolean') err('fixPlan.agentExecutable', 'must be boolean');
    if (f.fixPlan.agentExecutable && !isNonEmptyString(f.fixPlan.agentPrompt)) {
      err('fixPlan.agentPrompt', 'required when agentExecutable is true');
    }
    if (f.fixPlan.agentExecutable === false && !isNonEmptyString(f.fixPlan.notAgentExecutableReason)) {
      warn('fixPlan.notAgentExecutableReason', 'should explain why an agent cannot do this');
    }
  }

  // ---- semantic invariants: the point of the tool ----
  const v = f.verification;
  if (!v) {
    err('verification', 'required — an unverified finding must say so explicitly');
    return issues;
  }
  if (typeof v.performed !== 'boolean') err('verification.performed', 'must be boolean');
  if (!isNonEmptyString(v.notes)) err('verification.notes', 'required');
  if (!Array.isArray(v.checks)) err('verification.checks', 'must be an array');
  else {
    for (const [i, c] of v.checks.entries()) {
      if (!isNonEmptyString(c.detail)) err(`verification.checks[${i}].detail`, 'required (file:line or a fact)');
    }
  }

  if (f.status === 'confirmed') {
    if (!v.performed) err('status', '"confirmed" requires verification.performed === true');
    if (v.method === 'code-read' || v.method === 'not-attempted') {
      err('status', `"confirmed" is not permitted with verification.method "${v.method}" — cap at "plausible"`);
    }
    if (v.claimType === 'behavioral' && v.method !== 'proof-executed') {
      err(
        'status',
        '"confirmed" on a behavioral claim requires an executed proof (verification.method "proof-executed")',
      );
    }
    if (v.claimType === 'behavioral' && v.proof?.verdict !== 'vulnerable') {
      err('verification.proof.verdict', 'a confirmed behavioral finding must have a proof verdict of "vulnerable"');
    }
    if (!v.checks.some((c) => c.outcome !== 'skip')) {
      err('verification.checks', '"confirmed" requires at least one executed check');
    }
  }

  if (f.status === 'refuted') {
    if (!v.performed) err('status', '"refuted" requires an executed check that disproved the claim');
    if (v.result !== 'refuted') err('verification.result', 'must be "refuted" when status is "refuted"');
  }

  if (f.status === 'triaged-out') {
    if (!f.triage) err('triage', 'required when status is "triaged-out"');
    else {
      if (!isNonEmptyString(f.triage.reason)) err('triage.reason', 'required — suppression without a reason is a bug');
      if (!isNonEmptyString(f.triage.evidenceCited)) {
        err('triage.evidenceCited', 'required — a dismissal must cite file:line or a tool field');
      } else if (!EVIDENCE_REF.test(f.triage.evidenceCited)) {
        err('triage.evidenceCited', 'must cite a concrete reference, not prose');
      }
    }
  }

  if (v.proof) {
    if (!isNonEmptyString(v.proof.command)) err('verification.proof.command', 'required');
    if (!isNonEmptyString(v.proof.predicted)) err('verification.proof.predicted', 'required');
    if (!isNonEmptyString(v.proof.observed)) err('verification.proof.observed', 'required');
    if (v.method !== 'proof-executed') {
      warn('verification.method', 'a proof is attached but method is not "proof-executed"');
    }
  }

  return issues;
}

export function validateFindings(findings: Array<Partial<Finding>>): ValidationIssue[] {
  const issues = findings.flatMap((f) => validateFinding(f));
  const seen = new Map<string, number>();
  for (const f of findings) {
    if (!isNonEmptyString(f.id)) continue;
    seen.set(f.id, (seen.get(f.id) ?? 0) + 1);
  }
  for (const [id, count] of seen) {
    if (count > 1) issues.push({ findingId: id, path: 'id', message: `duplicate id (${count}x)`, severity: 'error' });
  }
  const ids = new Set(findings.map((f) => f.id));
  for (const f of findings) {
    for (const dep of f.dependenciesRelated ?? []) {
      if (!ids.has(dep)) {
        issues.push({
          findingId: f.id ?? '<no-id>',
          path: 'dependenciesRelated',
          message: `references unknown finding "${dep}"`,
          severity: 'warning',
        });
      }
    }
  }
  return issues;
}

/**
 * Confidence is derived, never authored. This is what stops "the LLM felt
 * strongly about it" from becoming a number on a report.
 */
export function scoreConfidence(f: Pick<Finding, 'status' | 'verification' | 'source'>): number {
  const { verification: v, status } = f;
  if (status === 'refuted') return 0.95; // high confidence the claim is FALSE
  let base: number;
  switch (v.method) {
    case 'proof-executed':
      base = v.proof?.verdict === 'vulnerable' ? 0.97 : 0.6;
      break;
    case 'static-assertion':
      base = 0.88;
      break;
    case 'tool-output':
      base = 0.8;
      break;
    case 'code-read':
      base = 0.55;
      break;
    default:
      base = 0.35;
  }
  const executed = v.checks.filter((c) => c.outcome !== 'skip').length;
  base += Math.min(0.06, executed * 0.02);
  if (f.source === 'llm' && v.method === 'code-read') base -= 0.1;
  if (status === 'triaged-out') base = Math.min(base, 0.5);
  return Math.max(0.05, Math.min(0.99, Number(base.toFixed(2))));
}

export function statusFromVerification(
  claimType: 'factual' | 'behavioral',
  result: 'confirmed' | 'plausible' | 'refuted' | 'inconclusive',
  method: Finding['verification']['method'],
): FindingStatus {
  if (result === 'refuted') return 'refuted';
  if (result === 'confirmed') {
    if (method === 'code-read' || method === 'not-attempted') return 'plausible';
    if (claimType === 'behavioral' && method !== 'proof-executed') return 'plausible';
    return 'confirmed';
  }
  return 'plausible';
}

export function severityOrder(s: Severity): number {
  return SEVERITIES.indexOf(s);
}
