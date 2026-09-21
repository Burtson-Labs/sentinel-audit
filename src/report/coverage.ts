import { ALL_RULES } from '../rules/index.js';
import type { Finding, ScanContext } from '../types.js';

/**
 * Coverage statement.
 *
 * Derived from what actually ran, not hand-written. Every "not examined" line
 * traces to a collector that reported the gap, a tool that was missing, or a
 * structural limit of the analysis. The goal is that a reader can tell the
 * difference between "we looked and it was fine" and "we did not look".
 */

export interface CoverageSection {
  title: string;
  rows: Array<{ item: string; status: 'covered' | 'partial' | 'not-covered'; detail: string }>;
}

export interface CoverageReport {
  sections: CoverageSection[];
  notExamined: string[];
  verifiedDirectly: string[];
  inferredOnly: string[];
  recommendedFollowUps: string[];
  toolsUsed: Array<{ name: string; available: boolean; note: string }>;
}

export function buildCoverage(ctx: ScanContext, findings: Finding[]): CoverageReport {
  const sections: CoverageSection[] = [];

  // ---- what the scan set out to do --------------------------------------
  const gates = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  sections.push({
    title: 'Analysis surfaces',
    rows: [
      {
        item: 'Repository reconnaissance (languages, LOC, frameworks, entrypoints, test counts)',
        status: 'covered',
        detail: `${ctx.recon.totalFiles} files over ${ctx.recon.languages.length} languages, ${ctx.recon.totalLoc.toLocaleString()} LOC`,
      },
      {
        item: 'Dependency advisories',
        status: ctx.deps.auditAvailable ? 'covered' : 'not-covered',
        detail: ctx.deps.auditAvailable
          ? `${ctx.deps.advisories.length} advisory record(s) from \`${ctx.deps.auditCommand}\``
          : `audit did not run: ${ctx.deps.auditError ?? 'unknown'}`,
      },
      {
        item: 'Licence inventory',
        status: ctx.deps.dependencies.length > ctx.deps.direct ? 'covered' : 'partial',
        detail:
          ctx.deps.dependencies.length > ctx.deps.direct
            ? `${ctx.deps.dependencies.length} installed package(s), ${ctx.deps.unknownLicenseCount} without a declared licence`
            : `only ${ctx.deps.direct} direct declarations were read — node_modules was not installed, so transitive licences are unknown`,
      },
      {
        item: 'Secret scanning (working tree)',
        status: 'covered',
        detail: `${ctx.secrets.filesScanned} files scanned with ${ctx.secrets.candidates.length} candidate(s); ${ctx.secrets.candidates.filter((c) => c.likelyFalsePositive).length} triaged out with reasons`,
      },
      {
        item: 'Secret scanning (git history)',
        status: ctx.secrets.externalScanner.available || (ctx.secrets.history !== undefined && !ctx.secrets.history.capped) ? 'covered' : ctx.secrets.history !== undefined ? 'partial' : 'not-covered',
        detail: ctx.secrets.externalScanner.available
          ? ctx.secrets.externalScanner.note
          : ctx.secrets.history !== undefined
            ? `Sentinel's own pass over every blob reachable from any ref, precise provider patterns only — ${ctx.secrets.history.note}`
            : `not a git repository; ${ctx.secrets.externalScanner.note}`,
      },
      {
        item: 'CI gate analysis',
        status: ctx.ci.workflows.length > 0 ? 'covered' : 'not-covered',
        detail:
          ctx.ci.workflows.length > 0
            ? `${ctx.ci.workflows.length} workflow(s) parsed; gates present: ${gates.filter((g) => ctx.ci.workflows.some((w) => w.gates[g])).join(', ') || 'none'}`
            : 'no workflow files found in .github/workflows',
      },
      {
        item: 'Container configuration',
        status: ctx.docker.files.length > 0 ? 'covered' : 'not-covered',
        detail: ctx.docker.files.length > 0 ? `${ctx.docker.files.length} Dockerfile(s) analysed` : 'no Dockerfile found',
      },
      {
        item: 'JS/TS security and quality rules',
        status: 'covered',
        detail: `${ALL_RULES.length} rules over ${ctx.hits.length > 0 ? 'the full tree' : 'the full tree (no hits)'} — lexical, comment/string aware`,
      },
      {
        item: 'Runnable proof generation',
        status: findings.some((f) => f.verification.proof) ? 'covered' : 'partial',
        detail: `${findings.filter((f) => f.verification.proof).length} finding(s) carry an executed proof script; ${findings.filter((f) => f.verification.method === 'static-assertion').length} were verified by re-asserting the artefact from disk`,
      },
      {
        item: 'Model-assisted deep review',
        status: ctx.llm.available ? 'covered' : 'not-covered',
        detail: ctx.llm.available ? `${ctx.llm.calls} call(s), ${ctx.llm.failures} failure(s) — ${ctx.llm.note}` : ctx.llm.note,
      },
    ],
  });

  // ---- explicit non-coverage, derived from the collectors ----------------
  const notExamined: string[] = [];
  for (const r of ctx.runs) {
    for (const n of r.notExamined) notExamined.push(`${r.name}: ${n}`);
  }

  // structural limits that are true of every run
  notExamined.push(
    'runtime behaviour: no application was started, no request was issued against a running service, and no load or concurrency testing was performed',
    'authorisation correctness beyond code reading: whether a service actually rejects an unauthorised principal can only be proven against a running instance',
    'infrastructure outside the repository: ingress, WAF, CDN headers, network policy and secret-store configuration are not visible here and may add or remove protection',
    'dependency reachability: an advisory is matched to the installed version, but Sentinel does not prove the vulnerable function is called from this application',
    'accessibility, performance and bundle-size characteristics of any UI',
    'prompt-injection and model-safety behaviour of any AI feature in the audited code',
  );
  if (!ctx.recon.commitSha || ctx.recon.commitSha === 'unknown') {
    notExamined.push('git provenance: the working tree is not a git repository, so no commit or branch can be recorded');
  }

  // ---- verified vs inferred ---------------------------------------------
  const verifiedDirectly = findings
    .filter((f) => f.verification.performed && (f.verification.method === 'proof-executed' || f.verification.method === 'static-assertion'))
    .map((f) => `${f.id} (${f.verification.state} via ${f.verification.method}): ${f.title}`);
  const inferredOnly = findings
    .filter((f) => !f.verification.performed || f.verification.method === 'code-read' || f.verification.method === 'tool-output')
    .map((f) => `${f.id} (${f.verification.method}): ${f.title} — ${f.verification.notes.slice(0, 160)}`);

  // ---- follow-ups --------------------------------------------------------
  const recommendedFollowUps: string[] = [];
  if (!ctx.secrets.externalScanner.available) {
    recommendedFollowUps.push(
      ctx.secrets.history === undefined
        ? 'Run the scan inside the git repository (or run gitleaks/trufflehog over it) — this was not a git work tree, so history could not be examined and a rotated-but-committed credential would be invisible.'
        : ctx.secrets.history.capped
          ? `Run gitleaks or trufflehog over full git history — Sentinel's own pass hit its budget (${ctx.secrets.history.blobsSkipped} blob(s) not read), so history coverage is partial.`
          : "Run gitleaks or trufflehog over git history if you want generic high-entropy detection there — Sentinel's own pass applies the precise provider patterns only.",
    );
  }
  if (!ctx.deps.auditAvailable) {
    recommendedFollowUps.push('Re-run with registry access so dependency advisories are collected; this report makes no claim about advisory status.');
  }
  if (!ctx.llm.available) {
    recommendedFollowUps.push('Re-run with a model provider configured so the deep-review pass can look for cross-module data-flow and logic defects the lexical rules cannot see.');
  }
  const plausibleHigh = findings.filter((f) => f.status === 'plausible' && (f.severity === 'High' || f.severity === 'Blocker'));
  if (plausibleHigh.length > 0) {
    recommendedFollowUps.push(
      `Confirm or refute ${plausibleHigh.map((f) => f.id).join(', ')} before committing remediation budget — they are high severity but unproven, which is exactly where review effort is usually wasted.`,
    );
  }
  if (ctx.docker.files.length > 0) {
    recommendedFollowUps.push('Run a container scanner (trivy/grype) against the built image — Sentinel reads the Dockerfile but never builds or pulls an image, so base-image CVEs are out of scope here.');
  }
  recommendedFollowUps.push('Re-run after remediation; Sentinel fingerprints are stable, so closed findings disappear and new ones stand out.');

  const toolsUsed: CoverageReport['toolsUsed'] = [
    { name: 'sentinel deterministic collectors', available: true, note: 'recon, dependencies, secrets, CI, containers' },
    { name: ctx.deps.auditCommand ?? 'package-manager audit', available: ctx.deps.auditAvailable, note: ctx.deps.auditAvailable ? 'advisory source' : (ctx.deps.auditError ?? 'unavailable') },
    { name: ctx.secrets.externalScanner.name, available: ctx.secrets.externalScanner.available, note: ctx.secrets.externalScanner.note },
    { name: 'proof runner (node)', available: true, note: `${findings.filter((f) => f.verification.proof).length} proof script(s) generated and executed` },
    { name: 'model pass', available: ctx.llm.available, note: ctx.llm.note },
  ];

  return { sections, notExamined, verifiedDirectly, inferredOnly, recommendedFollowUps, toolsUsed };
}
