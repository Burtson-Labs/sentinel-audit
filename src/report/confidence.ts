import type { ConfidenceAssessment, Finding, ScanContext, Severity } from '../types.js';
import type { Profile } from '../profile.js';

/**
 * Confidence assessment.
 *
 * Derived, not authored. Every number traces to a count, and the document
 * states what share of the score rests on verified versus merely asserted
 * findings — which is the number a reader of a consultant review cannot get.
 */

const WEIGHT: Record<Severity, number> = { Blocker: 10, High: 5, Medium: 2, Low: 0.5, Info: 0 };

/**
 * Scoring uses saturating penalties per severity class rather than a linear sum.
 *
 * Why: a linear sum makes the score meaningless on any real codebase — twenty
 * Medium findings would subtract more than one confirmed Blocker, and every
 * mature repository would score zero. Saturation keeps the ordering honest: the
 * first finding in a class costs the most, additional ones add less, and no
 * amount of Medium noise can outweigh a verified Blocker.
 *
 * `cap` is the most a class can ever subtract; `k` is how fast it saturates.
 */
const PENALTY: Record<Severity, { cap: number; k: number }> = {
  Blocker: { cap: 5.0, k: 1.0 },
  High: { cap: 3.0, k: 2.0 },
  Medium: { cap: 1.6, k: 3.0 },
  Low: { cap: 0.6, k: 4.0 },
  Info: { cap: 0, k: 1 },
};

/**
 * Weighted, saturating penalty. Each finding contributes `0.5 + confidence/2`,
 * so an unverified finding costs about half what a proven one does — the report
 * should not be able to tank a score with guesses.
 */
function severityPenalty(findings: Finding[]): number {
  let total = 0;
  for (const sev of Object.keys(PENALTY) as Severity[]) {
    const weighted = findings.filter((f) => f.severity === sev).reduce((n, f) => n + (0.5 + f.confidence / 2), 0);
    if (weighted === 0) continue;
    const { cap, k } = PENALTY[sev];
    total += cap * (1 - Math.exp(-weighted / k));
  }
  return total;
}

export function assessConfidence(ctx: ScanContext, findings: Finding[], profile: Profile): ConfidenceAssessment {
  const live = findings.filter((f) => f.status !== 'refuted' && f.status !== 'triaged-out');
  const confirmed = findings.filter((f) => f.status === 'confirmed');
  const plausible = findings.filter((f) => f.status === 'plausible');
  const refuted = findings.filter((f) => f.status === 'refuted');
  const triagedOut = findings.filter((f) => f.status === 'triaged-out');

  const verifiedShare = live.length === 0 ? 1 : Number((confirmed.length / live.length).toFixed(2));

  // ---- overall score ------------------------------------------------------
  // Start at 10 and subtract weighted risk, then adjust for the engineering
  // signals that make a codebase recoverable or not.
  let score = 10 - severityPenalty(live);
  const hasTests = ctx.recon.testFileCount > 0;
  const testRatio = ctx.recon.testToSourceRatio;
  const gateCount = countGates(ctx);

  if (!hasTests) score -= 1.5;
  else if (testRatio < 0.1) score -= 0.75;
  if (gateCount === 0) score -= 1;
  if (ctx.recon.tsStrict === true) score += 0.5;
  if (ctx.recon.tsStrict === false) score -= 0.5;
  score = clamp(Math.round(score * 10) / 10, 0, 10);

  // ---- security posture ---------------------------------------------------
  const securityFindings = live.filter((f) => f.type === 'Security' || f.type === 'Secret' || f.type === 'Supply Chain');
  let sec = 10 - severityPenalty(securityFindings);
  if (!ctx.ci.workflows.some((w) => w.gates.audit || w.gates.sast || w.gates.secrets)) sec -= 1;
  sec = clamp(Math.round(sec * 10) / 10, 0, 10);

  const blockers = live.filter((f) => profile.gate.blockOn.includes(f.severity));
  const conditionals = live.filter((f) => profile.gate.conditionalOn.includes(f.severity));
  const confirmedBlockers = blockers.filter((f) => f.status === 'confirmed');

  const gateDecision: ConfidenceAssessment['gateDecision'] =
    confirmedBlockers.length > 0 ? 'block' : blockers.length > 0 || conditionals.length > 0 ? 'pass-with-conditions' : 'pass';

  // ---- narrative, assembled from facts ------------------------------------
  const whyNotLower: string[] = [];
  const whyNotHigher: string[] = [];

  if (hasTests) whyNotLower.push(`${ctx.recon.testFileCount} test module(s) exist (ratio ${testRatio} against ${ctx.recon.sourceFileCount} source modules), so some behaviour is pinned.`);
  if (ctx.recon.tsStrict === true) whyNotLower.push('TypeScript `strict` is enabled, so the compiler is doing real work.');
  if (gateCount > 0) whyNotLower.push(`CI enforces ${gateCount} gate(s), so not every standard is advisory.`);
  if (refuted.length > 0) whyNotLower.push(`${refuted.length} candidate finding(s) were refuted by executed checks, meaning protections that exist are actually working — they are listed rather than silently dropped.`);
  if (securityFindings.filter((f) => f.severity === 'Blocker').length === 0) whyNotLower.push('No release-blocking security finding survived verification.');
  if (whyNotLower.length === 0) whyNotLower.push('Nothing in the scan argues for a higher floor than the score already reflects.');

  const bySeverity = groupBySeverity(live);
  for (const sev of ['Blocker', 'High'] as Severity[]) {
    const list = bySeverity[sev] ?? [];
    if (list.length > 0) {
      whyNotHigher.push(`${list.length} ${sev.toLowerCase()} finding(s): ${list.slice(0, 4).map((f) => `${f.id} ${f.title}`).join('; ')}${list.length > 4 ? ` (+${list.length - 4} more)` : ''}.`);
    }
  }
  if (!hasTests) whyNotHigher.push('There are no test modules at all, so no claim the code makes about itself is verified by the repository.');
  else if (testRatio < 0.1) whyNotHigher.push(`The test-to-source ratio is ${testRatio}; coverage is present but thin relative to the shipped surface.`);
  const missingGates = missingGateNames(ctx);
  if (missingGates.length > 0) whyNotHigher.push(`CI does not enforce ${missingGates.join(', ')}, so those standards are intent rather than guarantee.`);
  if (verifiedShare < 0.5) whyNotHigher.push(`Only ${Math.round(verifiedShare * 100)}% of live findings are verified by an executed check; the rest are reported as plausible and should be confirmed before large remediation spend.`);
  if (whyNotHigher.length === 0) whyNotHigher.push('No material weakness was found in the areas this scan covers.');

  // ---- risk matrix --------------------------------------------------------
  const riskMatrix = live
    .filter((f) => f.severity === 'Blocker' || f.severity === 'High' || f.severity === 'Medium')
    .sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity] || b.confidence - a.confidence)
    .slice(0, 14)
    .map((f) => ({
      id: f.id,
      risk: f.title,
      likelihood: likelihoodOf(f),
      impact: impactOf(f),
      level: riskLevel(likelihoodOf(f), impactOf(f)),
    }));

  // ---- signals ------------------------------------------------------------
  const signals: ConfidenceAssessment['signals'] = [];
  if (confirmed.length > 0 && plausible.length > confirmed.length * 2) {
    signals.push({
      signal: `${confirmed.length} finding(s) are verified by execution while ${plausible.length} remain reasoned-only.`,
      interpretation:
        'The report is honest about its own limits, but the remediation plan should start with the verified set — spending weeks on an unproven finding is the classic failure mode of a review like this.',
    });
  }
  if (refuted.length > 0) {
    signals.push({
      signal: `${refuted.length} plausible-looking finding(s) did not survive verification (${refuted.slice(0, 3).map((f) => f.id).join(', ')}).`,
      interpretation:
        'Some defences in this codebase are real and working. A review that only reported what it suspected would have charged for fixing these.',
    });
  }
  if (!hasTests) {
    signals.push({
      signal: 'Zero test modules alongside a shipped product surface.',
      interpretation: 'Every protective behaviour is one cleanup away from disappearing, and no reviewer can distinguish intended behaviour from accident.',
    });
  }
  if (missingGates.includes('audit') || missingGates.includes('secrets')) {
    signals.push({
      signal: 'Dependency and secret scanning are absent from CI.',
      interpretation: 'Exposure is discovered by chance rather than by the pipeline. This is the cheapest gap to close and the one that compounds fastest if left.',
    });
  }
  const llmNote = ctx.llm.available
    ? null
    : {
        signal: 'The model-assisted review pass did not run.',
        interpretation: `Findings in this report come from deterministic collectors and lexical rules only (${ctx.llm.note}). Cross-module data-flow defects and logic errors are therefore under-reported; the coverage statement says so explicitly rather than implying full depth.`,
      };
  if (llmNote) signals.push(llmNote);

  // ---- remediation phases -------------------------------------------------
  const phases: ConfidenceAssessment['remediationPhases'] = [];
  const phase1 = live.filter((f) => (f.severity === 'Blocker' || f.severity === 'High') && f.status === 'confirmed');
  const phase1b = live.filter((f) => (f.severity === 'Blocker' || f.severity === 'High') && f.status !== 'confirmed');
  const phase2 = live.filter((f) => f.severity === 'Medium');
  const phase3 = live.filter((f) => f.severity === 'Low' || f.severity === 'Info');

  if (phase1.length > 0) phases.push({ phase: 'Phase 1 — verified high-severity work', items: phase1.map((f) => `${f.id} ${f.title} (${f.effortEstimate})`), estimate: estimateEffort(phase1) });
  if (phase1b.length > 0) phases.push({ phase: 'Phase 1b — high-severity but unproven: confirm before committing effort', items: phase1b.map((f) => `${f.id} ${f.title} (${f.effortEstimate})`), estimate: estimateEffort(phase1b) });
  if (phase2.length > 0) phases.push({ phase: 'Phase 2 — medium severity', items: phase2.map((f) => `${f.id} ${f.title} (${f.effortEstimate})`), estimate: estimateEffort(phase2) });
  if (phase3.length > 0) phases.push({ phase: 'Phase 3 — hygiene and debt', items: phase3.map((f) => `${f.id} ${f.title} (${f.effortEstimate})`), estimate: estimateEffort(phase3) });

  // ---- bottom line --------------------------------------------------------
  const bottomLine: string[] = [];
  bottomLine.push(
    gateDecision === 'block'
      ? `**Gate: block.** ${confirmedBlockers.length} verified release-blocking finding(s) — ${confirmedBlockers.map((f) => f.id).join(', ')}. These are confirmed by executed checks, not inferred.`
      : gateDecision === 'pass-with-conditions'
        ? `**Gate: pass with conditions.** No verified blocker, but ${blockers.length + conditionals.length} finding(s) at or above the conditional threshold need an owner and a date before release.`
        : '**Gate: pass.** Nothing at or above the profile threshold survived verification.',
  );
  bottomLine.push(
    `**How much to trust this report:** ${confirmed.length} of ${live.length} live findings (${Math.round(verifiedShare * 100)}%) were verified by something that ran. ${refuted.length} candidate(s) were refuted and ${triagedOut.length} triaged out with reasons — both are listed so you can disagree with the judgement rather than take it on faith.`,
  );
  bottomLine.push(
    ctx.llm.available
      ? `**Depth:** deterministic collectors, ${countRulesRun(ctx)} lexical rules, and a model-assisted review pass (${ctx.llm.calls} call(s), ${ctx.llm.failures} failure(s)).`
      : `**Depth:** deterministic collectors and lexical rules only. The model-assisted pass did not run, so this is a breadth-first result — see COVERAGE.md for what that costs.`,
  );

  return {
    overallScore: score,
    band: band(score),
    securityPostureScore: sec,
    productionReadiness: readiness(score, gateDecision, confirmedBlockers.length),
    whyNotLower,
    whyNotHigher,
    gateDecision,
    gateReason: `${profile.title}: ${profile.gate.note} Blocking severities: ${profile.gate.blockOn.join(', ')}; conditional: ${profile.gate.conditionalOn.join(', ')}.`,
    riskMatrix,
    signals,
    evidenceQuality: {
      confirmed: confirmed.length,
      plausible: plausible.length,
      refuted: refuted.length,
      triagedOut: triagedOut.length,
      verifiedShare,
    },
    remediationPhases: phases,
    bottomLine,
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

export function band(score: number): string {
  if (score <= 3) return 'critical / failing';
  if (score <= 5) return 'concerning / needs work';
  if (score <= 7) return 'acceptable / moderate';
  return 'good / passing';
}

function readiness(score: number, gate: ConfidenceAssessment['gateDecision'], confirmedBlockers: number): string {
  if (gate === 'block') {
    return `Not ready to ship: ${confirmedBlockers} verified blocking finding(s) must be closed first. The remainder of the codebase is not the obstacle.`;
  }
  if (score >= 8) return 'Ready to ship, with the listed hygiene work tracked as normal backlog.';
  if (score >= 6) return 'Shippable with conditions: the high-severity findings need an owner and a date, and the missing CI gates should land before the next release.';
  return 'Treat as pre-release until the high-severity findings are closed and CI enforces the basics; none of the work is architectural.';
}

function groupBySeverity(findings: Finding[]): Partial<Record<Severity, Finding[]>> {
  const out: Partial<Record<Severity, Finding[]>> = {};
  for (const f of findings) {
    const list = out[f.severity] ?? [];
    list.push(f);
    out[f.severity] = list;
  }
  return out;
}

function likelihoodOf(f: Finding): 'Low' | 'Medium' | 'High' {
  if (f.status === 'confirmed' && f.verification.method === 'proof-executed') return 'High';
  if (f.status === 'confirmed') return 'Medium';
  if (f.confidence >= 0.8) return 'Medium';
  return 'Low';
}

function impactOf(f: Finding): 'Low' | 'Medium' | 'High' | 'Critical' {
  if (f.severity === 'Blocker') return 'Critical';
  if (f.severity === 'High') return 'High';
  if (f.severity === 'Medium') return 'Medium';
  return 'Low';
}

function riskLevel(l: 'Low' | 'Medium' | 'High', i: 'Low' | 'Medium' | 'High' | 'Critical'): string {
  const li = { Low: 1, Medium: 2, High: 3 }[l];
  const ii = { Low: 1, Medium: 2, High: 3, Critical: 4 }[i];
  const product = li * ii;
  if (product >= 9) return 'Critical';
  if (product >= 6) return 'High';
  if (product >= 3) return 'Medium';
  return 'Low';
}

function estimateEffort(findings: Finding[]): string {
  const days = { S: 0.5, M: 2, L: 5, XL: 12 };
  const total = findings.reduce((n, f) => n + days[f.effortEstimate], 0);
  if (total <= 1) return '~1 engineer-day';
  if (total < 5) return `~${Math.round(total)} engineer-days`;
  return `~${(total / 5).toFixed(1)} engineer-weeks`;
}

function countGates(ctx: ScanContext): number {
  const gates = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  return gates.filter((g) => ctx.ci.workflows.some((w) => w.gates[g])).length;
}

function missingGateNames(ctx: ScanContext): string[] {
  const gates = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  return gates.filter((g) => !ctx.ci.workflows.some((w) => w.gates[g]));
}

function countRulesRun(ctx: ScanContext): number {
  const note = ctx.runs.find((r) => r.name === 'rules')?.note ?? '';
  return Number(/^(\d+) rules/.exec(note)?.[1] ?? 0);
}
