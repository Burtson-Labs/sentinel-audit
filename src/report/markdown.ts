import type { ConfidenceAssessment, Finding, ScanContext, Severity } from '../types.js';
import type { Profile } from '../profile.js';
import type { CoverageReport } from './coverage.js';
import { band } from './confidence.js';

/**
 * Markdown renderers. Three documents, matching what a reader of a
 * consultant-style review expects, plus the verification column that makes the
 * difference visible at a glance.
 */

const STATUS_MARK: Record<Finding['status'], string> = {
  confirmed: 'CONFIRMED',
  plausible: 'PLAUSIBLE',
  refuted: 'REFUTED',
  'triaged-out': 'TRIAGED OUT',
};

const SEVERITY_ORDER: Severity[] = ['Blocker', 'High', 'Medium', 'Low', 'Info'];

export function renderReport(ctx: ScanContext, findings: Finding[], profile: Profile, confidence: ConfidenceAssessment): string {
  const live = findings.filter((f) => f.status !== 'refuted' && f.status !== 'triaged-out');
  const refuted = findings.filter((f) => f.status === 'refuted');
  const triaged = findings.filter((f) => f.status === 'triaged-out');
  const out: string[] = [];

  out.push(`# Repository audit — ${repoName(ctx)}`);
  out.push('');
  out.push(`**Tool:** sentinel-audit · **Profile:** ${profile.title} (\`${profile.id}\`) · **Date:** ${new Date().toISOString().slice(0, 10)}`);
  out.push(`**Commit:** \`${ctx.recon.commitSha}\` on \`${ctx.recon.branch}\` · **Repository:** ${ctx.recon.repoUrl}`);
  out.push('');

  // ---- the headline table ------------------------------------------------
  out.push('## Verification summary');
  out.push('');
  out.push('Every finding below carries a verification record. A finding is only **confirmed** when something ran and agreed with it: an executed proof script for a claim about behaviour, or a re-assertion of the artefact from disk for a claim about the code. Findings that did not survive checking are kept as **refuted** rather than deleted.');
  out.push('');
  out.push('| Status | Count | What it means |');
  out.push('|---|---:|---|');
  out.push(`| Confirmed | ${findings.filter((f) => f.status === 'confirmed').length} | an executed check agreed with the claim |`);
  out.push(`| Plausible | ${findings.filter((f) => f.status === 'plausible').length} | reasoned from the code; no executed check established it |`);
  out.push(`| Refuted | ${refuted.length} | an executed check disproved the claim — listed, not hidden |`);
  out.push(`| Triaged out | ${triaged.length} | dismissed as noise, with the reason and a cited location |`);
  out.push('');
  out.push(`**Gate decision: ${confidence.gateDecision.toUpperCase()}** — ${confidence.gateReason}`);
  out.push('');

  out.push('| Severity | Live findings |');
  out.push('|---|---:|');
  for (const sev of SEVERITY_ORDER) {
    const n = live.filter((f) => f.severity === sev).length;
    if (n > 0) out.push(`| ${sev} | ${n} |`);
  }
  out.push('');

  // ---- recon -------------------------------------------------------------
  out.push('## Repository reconnaissance');
  out.push('');
  out.push(`- **Languages:** ${ctx.recon.languages.slice(0, 6).map((l) => `${l.language} (${l.files} files, ${l.loc.toLocaleString()} LOC)`).join(', ') || 'none detected'}`);
  out.push(`- **Frameworks/tooling:** ${ctx.recon.frameworks.join(', ') || 'none detected'}`);
  out.push(`- **Package manager:** ${ctx.recon.packageManager} · lockfiles: ${ctx.deps.lockfiles.join(', ') || 'none'}`);
  out.push(`- **Size:** ${ctx.recon.totalFiles.toLocaleString()} files, ${ctx.recon.totalLoc.toLocaleString()} LOC`);
  out.push(`- **Tests:** ${ctx.recon.testFileCount} test module(s) against ${ctx.recon.sourceFileCount} source module(s) (ratio ${ctx.recon.testToSourceRatio})`);
  out.push(`- **TypeScript strict:** ${ctx.recon.tsStrict === null ? 'not determined' : String(ctx.recon.tsStrict)}`);
  out.push(`- **Dependencies:** ${ctx.deps.total} installed, ${ctx.deps.direct} declared direct, ${ctx.deps.advisories.length} advisory record(s)`);
  out.push(`- **CI:** ${ctx.ci.workflows.length} workflow(s)${ctx.ci.workflows.length > 0 ? ` — ${ctx.ci.workflows.map((w) => w.file.replace('.github/workflows/', '')).join(', ')}` : ''}`);
  out.push(`- **Containers:** ${ctx.docker.files.length} Dockerfile(s)`);
  if (ctx.recon.largestFiles.length > 0) {
    out.push(`- **Largest modules:** ${ctx.recon.largestFiles.slice(0, 5).map((f) => `${f.file} (${f.loc.toLocaleString()} LOC)`).join(', ')}`);
  }
  out.push('');
  out.push(`**Analysis depth:** ${ctx.llm.available ? `deterministic collectors + lexical rules + model-assisted review (${ctx.llm.calls} call(s))` : 'deterministic collectors + lexical rules only — the model pass did not run'}. See COVERAGE.md.`);
  out.push('');

  // ---- severity legend ---------------------------------------------------
  out.push('## Legend');
  out.push('');
  out.push('**Severity** — Blocker: do not release. High: fix before the next release. Medium: schedule. Low: hygiene. Info: context.');
  out.push('');
  out.push('**Effort** — S: under a day. M: a few days. L: one to two weeks. XL: more than two weeks.');
  out.push('');
  out.push('**Verification method** — `proof-executed`: a generated script exercised the real code. `static-assertion`: the artefact was re-read from disk and the claim re-established. `tool-output`: a third-party scanner reported it. `code-read`: reasoning only.');
  out.push('');

  // ---- findings ----------------------------------------------------------
  out.push('---');
  out.push('');
  out.push('# Findings');
  out.push('');

  const groups: Array<{ title: string; items: Finding[] }> = [
    { title: 'Confirmed', items: findings.filter((f) => f.status === 'confirmed').sort(bySeverity) },
    { title: 'Plausible (unproven)', items: findings.filter((f) => f.status === 'plausible').sort(bySeverity) },
  ];

  for (const group of groups) {
    if (group.items.length === 0) continue;
    out.push(`## ${group.title} — ${group.items.length}`);
    out.push('');
    for (const f of group.items) out.push(renderFinding(f));
  }

  if (refuted.length > 0) {
    out.push('---');
    out.push('');
    out.push(`# Refuted — ${refuted.length}`);
    out.push('');
    out.push('These were raised by a rule or a scanner and then **disproved by an executed check**. They are published for two reasons: so the same pattern is not re-reported as a finding next quarter, and so you can audit the refutation rather than taking it on trust.');
    out.push('');
    for (const f of refuted) out.push(renderFinding(f));
  }

  if (triaged.length > 0) {
    out.push('---');
    out.push('');
    out.push(`# Triaged out — ${triaged.length}`);
    out.push('');
    out.push('Suppressed as noise. Each entry states the reason and cites a location, so a suppression you disagree with is visible and reversible.');
    out.push('');
    out.push('| ID | Title | Suppressed by | Reason | Cited evidence |');
    out.push('|---|---|---|---|---|');
    for (const f of triaged) {
      out.push(`| ${f.id} | ${esc(f.title)} | ${f.triage?.by ?? 'n/a'} | ${esc(truncate(f.triage?.reason ?? '', 220))} | \`${esc(f.triage?.evidenceCited ?? 'n/a')}\` |`);
    }
    out.push('');
  }

  // ---- merge blockers ----------------------------------------------------
  out.push('---');
  out.push('');
  out.push('# Merge blockers');
  out.push('');
  const blockers = live
    .filter((f) => profile.gate.blockOn.includes(f.severity) || (f.severity === 'High' && f.status === 'confirmed'))
    .sort(bySeverity);
  if (blockers.length === 0) {
    out.push('None. No finding at a blocking severity survived verification, and no high-severity finding was confirmed by an executed check.');
    out.push('');
    const unprovenHigh = live.filter((f) => f.severity === 'High' && f.status !== 'confirmed');
    if (unprovenHigh.length > 0) {
      out.push(`${unprovenHigh.length} high-severity finding(s) are reported as unproven (${unprovenHigh.map((f) => f.id).join(', ')}). Confirm them before treating them as blockers or as non-issues.`);
      out.push('');
    }
  } else {
    out.push('Each item below is either at the profile\'s blocking severity or a high-severity finding an executed check confirmed. The sub-items are the finding\'s own acceptance criteria, so "done" is testable rather than a matter of opinion.');
    out.push('');
    for (const f of blockers) {
      out.push(`- [ ] **${f.id}** (${f.severity}, ${f.status}) — ${esc(f.title)}`);
      for (const a of f.acceptanceCriteria) out.push(`  - [ ] ${esc(a)}`);
    }
    out.push('');
  }

  // ---- technical debt register -------------------------------------------
  const debt = live.filter((f) => f.type === 'Tech Debt' || f.type === 'Quality' || f.type === 'Testing').sort(bySeverity);
  if (debt.length > 0) {
    out.push('# Technical debt register');
    out.push('');
    out.push('Not security findings. Carried here because they are the reason the next security fix takes longer than it should.');
    out.push('');
    out.push('| ID | Item | Severity | Effort | Verified | Scope |');
    out.push('|---|---|---|---|---|---|');
    for (const f of debt) {
      out.push(
        `| ${f.id} | ${esc(f.title)} | ${f.severity} | ${f.effortEstimate} | ${f.status} | ${esc(truncate(f.fixPlan.estimatedDiffSize, 60))} |`,
      );
    }
    out.push('');
  }

  // ---- quality gates ----------------------------------------------------
  out.push('# Recommended quality gates');
  out.push('');
  const gateNames = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  const gateBlurb: Record<(typeof gateNames)[number], string> = {
    test: 'the test suite, failing the build on a regression',
    lint: 'lint as an error, not a warning — an unenforced standard is a preference',
    typecheck: 'a type check, so `strict` in the config means something at merge time',
    audit: 'a dependency audit failing on new high/critical advisories',
    sast: 'static security analysis (this tool, CodeQL, or an equivalent) with SARIF upload',
    secrets: 'secret scanning over history, not just the working tree',
  };
  const present = gateNames.filter((g) => ctx.ci.workflows.some((w) => w.gates[g]));
  const missing = gateNames.filter((g) => !present.includes(g));
  if (present.length > 0) out.push(`Already enforced on a PR-triggered workflow: ${present.join(', ')}.`);
  if (missing.length === 0) {
    out.push('');
    out.push('Every gate this tool checks for is present. The remaining question is whether they are *required* in branch protection — a workflow that runs but is not required does not gate, and that setting lives in the repository settings rather than in the workflow file.');
  } else {
    out.push('');
    out.push('Add, in this order — cheapest and highest-leverage first:');
    out.push('');
    for (const g of missing) out.push(`1. **${g}** — ${gateBlurb[g]}`);
    out.push('');
    out.push('Then mark them required in branch protection. A workflow that runs but is not required does not gate.');
    out.push('');
    out.push('```bash');
    out.push('# this tool, as a scheduled + PR gate with SARIF upload');
    out.push('sentinel init-workflow');
    out.push('```');
  }
  out.push('');

  // ---- remediation roadmap ----------------------------------------------
  out.push('---');
  out.push('');
  out.push('# Remediation plan');
  out.push('');
  for (const phase of confidence.remediationPhases) {
    out.push(`### ${phase.phase} — ${phase.estimate}`);
    out.push('');
    for (const item of phase.items) out.push(`- ${esc(item)}`);
    out.push('');
  }

  const agentExecutable = findings.filter((f) => f.fixPlan.agentExecutable);
  out.push('## Automatable subset');
  out.push('');
  if (agentExecutable.length === 0) {
    out.push('No finding in this report has a fix plan marked agent-executable. Each remaining fix needs a human decision first (a policy value, an allowlist, a product trade-off), and the per-finding fix plan says which.');
  } else {
    out.push(`${agentExecutable.length} finding(s) have a fix plan mechanical enough to hand to an agent. Each runs on its own branch, must pass the repository's test command, and opens a pull request for human review:`);
    out.push('');
    out.push('```bash');
    out.push(`sentinel fix <findings-dir> --only ${agentExecutable.map((f) => f.id).join(',')} --pr`);
    out.push('```');
    out.push('');
    out.push('| ID | Title | Risk | Diff size |');
    out.push('|---|---|---|---|');
    for (const f of agentExecutable) out.push(`| ${f.id} | ${esc(f.title)} | ${f.fixPlan.risk} | ${esc(f.fixPlan.estimatedDiffSize)} |`);
  }
  out.push('');

  out.push('---');
  out.push('');
  out.push('## Provenance');
  out.push('');
  out.push(`- **Repository:** ${ctx.recon.repoUrl}`);
  out.push(`- **Branch:** ${ctx.recon.branch}`);
  out.push(`- **Commit:** ${ctx.recon.commitSha}`);
  out.push(`- **Commit date:** ${ctx.recon.commitDate}`);
  out.push(`- **Scan started:** ${ctx.startedAt}`);
  out.push(`- **Scan finished:** ${ctx.finishedAt ?? 'n/a'}`);
  out.push(`- **Profile:** ${profile.id} (${profile.title})`);
  out.push(`- **Collectors:** ${ctx.runs.map((r) => `${r.name} ${r.ok ? 'ok' : 'degraded'} (${r.durationMs}ms)`).join(', ')}`);
  out.push('');

  return `${out.join('\n')}\n`;
}

function renderFinding(f: Finding): string {
  const out: string[] = [];
  out.push(`### ${f.id} — ${f.title}`);
  out.push('');
  out.push(`**${STATUS_MARK[f.status]}** · ${f.severity} · ${f.type} · confidence ${f.confidence.toFixed(2)} · effort ${f.effortEstimate} · area ${f.affectedArea}`);
  out.push('');
  out.push(`**Labels:** ${f.suggestedLabels.map((l) => `\`${l}\``).join(' ')}`);
  out.push('');
  out.push('**Evidence**');
  out.push('');
  out.push(f.evidence);
  out.push('');

  out.push('**Verification**');
  out.push('');
  out.push(`- Method: \`${f.verification.method}\` · claim type: \`${f.verification.claimType}\` · result: \`${f.verification.result}\``);
  for (const c of f.verification.checks.slice(0, 8)) {
    const mark = c.outcome === 'pass' ? 'checked' : c.outcome === 'fail' ? 'did not hold' : 'skipped';
    out.push(`- [${mark}] ${c.description} — ${esc(c.detail)}`);
  }
  if (f.verification.proof) {
    const p = f.verification.proof;
    out.push(`- **Proof:** \`${p.command}\` → verdict \`${p.verdict}\` in ${p.durationMs}ms (exit ${p.exitCode})`);
    out.push(`  - Predicted: ${esc(p.predicted)}`);
    out.push(`  - Observed: ${esc(p.observed)}`);
    if (p.stdoutExcerpt) out.push(`  - Output: \`${esc(truncate(p.stdoutExcerpt, 600))}\``);
  }
  out.push(`- Notes: ${esc(f.verification.notes)}`);
  out.push('');

  out.push('**Why this matters**');
  out.push('');
  out.push(f.whyThisMatters);
  out.push('');
  out.push(`**Standards mapping:** ${esc(f.standardMapping)}`);
  out.push('');
  out.push('**Recommendation**');
  out.push('');
  out.push(f.recommendation);
  out.push('');
  out.push('**Acceptance criteria**');
  out.push('');
  for (const a of f.acceptanceCriteria) out.push(`- ${a}`);
  out.push('');

  out.push('**Fix plan**');
  out.push('');
  out.push(`- Agent-executable: **${f.fixPlan.agentExecutable ? 'yes' : 'no'}**${f.fixPlan.agentExecutable ? '' : ` — ${esc(f.fixPlan.notAgentExecutableReason ?? 'no reason recorded')}`}`);
  out.push(`- Strategy: ${esc(f.fixPlan.strategy)}`);
  out.push(`- Risk: ${f.fixPlan.risk} · estimated diff: ${esc(f.fixPlan.estimatedDiffSize)}`);
  if (f.fixPlan.files.length > 0) {
    out.push('- Files:');
    for (const file of f.fixPlan.files.slice(0, 8)) out.push(`  - \`${file.path}\` — ${esc(file.change)}`);
  }
  if (f.fixPlan.acceptanceTests.length > 0) {
    out.push('- Tests to add:');
    for (const t of f.fixPlan.acceptanceTests) out.push(`  - \`${t.path}\` — ${esc(t.description)}`);
  }
  out.push('');

  if (f.notes && f.notes.length > 0) {
    out.push('**Notes**');
    out.push('');
    for (const n of f.notes) out.push(`- ${esc(n)}`);
    out.push('');
  }

  if (f.dependenciesRelated.length > 0) {
    out.push(`**Related:** ${f.dependenciesRelated.join(', ')}`);
    out.push('');
  }
  out.push('---');
  out.push('');
  return out.join('\n');
}

export function renderConfidence(ctx: ScanContext, c: ConfidenceAssessment, profile: Profile): string {
  const out: string[] = [];
  out.push(`# Audit confidence assessment — ${repoName(ctx)}`);
  out.push('');
  out.push('**The question this document answers:** how much should this repository worry you, and how much should you trust this report?');
  out.push('');
  out.push(`**Profile:** ${profile.title} · **Commit:** \`${ctx.recon.commitSha.slice(0, 12)}\` · **Date:** ${new Date().toISOString().slice(0, 10)}`);
  out.push('');
  out.push('---');
  out.push('');
  out.push('## Overall score');
  out.push('');
  out.push(`# ${c.overallScore} / 10 — ${band(c.overallScore)}`);
  out.push('');
  out.push('Bands: 0–3 critical/failing · 4–5 concerning/needs work · 6–7 acceptable/moderate · 8–10 good/passing.');
  out.push('');
  out.push('The score is computed from the finding set, not assigned: each live finding subtracts its severity weight scaled by its verification confidence, then engineering signals (tests present, CI gates, type strictness) adjust the result. A finding nobody verified therefore moves the score less than one that was proven.');
  out.push('');

  out.push('### Evidence quality');
  out.push('');
  out.push('| | Count |');
  out.push('|---|---:|');
  out.push(`| Confirmed by an executed check | ${c.evidenceQuality.confirmed} |`);
  out.push(`| Plausible (reasoned, unproven) | ${c.evidenceQuality.plausible} |`);
  out.push(`| Refuted by an executed check | ${c.evidenceQuality.refuted} |`);
  out.push(`| Triaged out as noise | ${c.evidenceQuality.triagedOut} |`);
  out.push(`| **Verified share of live findings** | **${Math.round(c.evidenceQuality.verifiedShare * 100)}%** |`);
  out.push('');

  out.push('### Why not lower');
  out.push('');
  for (const r of c.whyNotLower) out.push(`- ${esc(r)}`);
  out.push('');
  out.push('### Why not higher');
  out.push('');
  for (const r of c.whyNotHigher) out.push(`- ${esc(r)}`);
  out.push('');

  out.push('## Security posture');
  out.push('');
  out.push(`# ${c.securityPostureScore} / 10`);
  out.push('');
  out.push('## Production readiness');
  out.push('');
  out.push(c.productionReadiness);
  out.push('');
  out.push(`**Gate decision: ${c.gateDecision.toUpperCase()}.** ${esc(c.gateReason)}`);
  out.push('');

  if (c.riskMatrix.length > 0) {
    out.push('## Risk matrix');
    out.push('');
    out.push('| ID | Risk | Likelihood | Impact | Level |');
    out.push('|---|---|---|---|---|');
    for (const r of c.riskMatrix) out.push(`| ${r.id} | ${esc(r.risk)} | ${r.likelihood} | ${r.impact} | ${r.level} |`);
    out.push('');
    out.push('Likelihood is derived from verification strength: a finding with an executed proof is High, a confirmed factual claim is Medium, an unproven one is Low. That keeps the matrix from treating a guess and a demonstration as equals.');
    out.push('');
  }

  if (c.signals.length > 0) {
    out.push('## Signals and what they tell us');
    out.push('');
    for (const s of c.signals) {
      out.push(`**Signal:** ${esc(s.signal)}`);
      out.push('');
      out.push(`**Interpretation:** ${esc(s.interpretation)}`);
      out.push('');
    }
  }

  out.push('## Estimated remediation effort');
  out.push('');
  for (const phase of c.remediationPhases) {
    out.push(`**${phase.phase}** — ${phase.estimate}`);
    out.push('');
    for (const item of phase.items.slice(0, 12)) out.push(`- ${esc(item)}`);
    if (phase.items.length > 12) out.push(`- (+${phase.items.length - 12} more)`);
    out.push('');
  }

  out.push('## Bottom line');
  out.push('');
  for (const b of c.bottomLine) out.push(`- ${b}`);
  out.push('');
  out.push('---');
  out.push('');
  out.push('## Provenance');
  out.push('');
  out.push(`- **Repository:** ${ctx.recon.repoUrl}`);
  out.push(`- **Branch:** ${ctx.recon.branch}`);
  out.push(`- **Commit:** ${ctx.recon.commitSha}`);
  out.push(`- **Profile:** ${profile.id}`);
  out.push('');
  return `${out.join('\n')}\n`;
}

export function renderCoverage(ctx: ScanContext, cov: CoverageReport): string {
  const out: string[] = [];
  out.push(`# Coverage and limits — ${repoName(ctx)}`);
  out.push('');
  out.push('**Purpose:** state what this scan examined, what it did not, and which findings rest on an executed check versus on reasoning. Every row below is derived from what actually ran — if a tool was missing, it says so rather than leaving a gap that reads like a clean result.');
  out.push('');
  out.push(`**Commit:** \`${ctx.recon.commitSha}\` · **Date:** ${new Date().toISOString().slice(0, 10)}`);
  out.push('');

  for (const section of cov.sections) {
    out.push(`## ${section.title}`);
    out.push('');
    out.push('| Surface | Status | Detail |');
    out.push('|---|---|---|');
    for (const row of section.rows) {
      const mark = row.status === 'covered' ? 'covered' : row.status === 'partial' ? 'partial' : 'NOT COVERED';
      out.push(`| ${esc(row.item)} | ${mark} | ${esc(row.detail)} |`);
    }
    out.push('');
  }

  out.push('## Tools');
  out.push('');
  out.push('| Tool | Available | Note |');
  out.push('|---|---|---|');
  for (const t of cov.toolsUsed) out.push(`| ${esc(t.name)} | ${t.available ? 'yes' : 'no'} | ${esc(truncate(t.note, 240))} |`);
  out.push('');

  out.push('## Explicitly not examined');
  out.push('');
  out.push('Nothing below was looked at. Treat any statement about these areas as absent, not as negative.');
  out.push('');
  for (const n of cov.notExamined) out.push(`- ${esc(n)}`);
  out.push('');

  out.push('## Findings verified by something that ran');
  out.push('');
  if (cov.verifiedDirectly.length === 0) out.push('_None._');
  for (const v of cov.verifiedDirectly) out.push(`- ${esc(v)}`);
  out.push('');

  out.push('## Findings that rest on reasoning or third-party tool output only');
  out.push('');
  if (cov.inferredOnly.length === 0) out.push('_None — every finding in this report was checked by execution._');
  for (const v of cov.inferredOnly) out.push(`- ${esc(v)}`);
  out.push('');

  out.push('## Recommended follow-ups');
  out.push('');
  for (const r of cov.recommendedFollowUps) out.push(`- ${esc(r)}`);
  out.push('');
  out.push('---');
  out.push('');
  out.push(`- **Repository:** ${ctx.recon.repoUrl}`);
  out.push(`- **Commit:** ${ctx.recon.commitSha}`);
  out.push('');
  return `${out.join('\n')}\n`;
}

function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence;
}

function repoName(ctx: ScanContext): string {
  const fromUrl = /([^/]+?)(?:\.git)?$/.exec(ctx.recon.repoUrl)?.[1];
  return fromUrl && fromUrl !== 'unknown' ? fromUrl : (ctx.root.split('/').pop() ?? 'repository');
}

function esc(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}
