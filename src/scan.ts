import { join, resolve } from 'node:path';
import { collectRecon } from './collectors/recon.js';
import { collectDependencies } from './collectors/dependencies.js';
import { collectSecrets, gitignoredPredicate } from './collectors/secrets.js';
import { collectCi } from './collectors/ci.js';
import { collectDocker } from './collectors/docker.js';
import { runRules } from './rules/index.js';
import { analyze } from './analyze.js';
import { attachTexts } from './verify/index.js';
import { detectProvider } from './llm/client.js';
import { runLlmPasses, applyLlmResults } from './llm/passes.js';
import { assessConfidence } from './report/confidence.js';
import { buildCoverage } from './report/coverage.js';
import { renderReport, renderConfidence, renderCoverage } from './report/markdown.js';
import { renderHtml } from './report/html.js';
import { buildSarif } from './report/sarif.js';
import { validateFindings, scoreConfidence, isConfirmed } from './schema.js';
import { loadProfile, type Profile } from './profile.js';
import { ensureDir, writeFileEnsured, exists } from './util/fsx.js';
import type { ConfidenceAssessment, Finding, ScanContext } from './types.js';
import type { ValidationIssue } from './schema.js';

export const TOOL_VERSION = '0.1.0';

export type OutputFormat = 'md' | 'html' | 'json' | 'sarif';

export interface ScanOptions {
  repo: string;
  outDir: string;
  profile: string;
  formats: OutputFormat[];
  /** Disable the model pass. */
  noLlm?: boolean;
  /** Disable proof generation/execution. */
  noProofs?: boolean;
  /** Skip network-dependent collectors. */
  offline?: boolean;
  /** Path to the Bandit CLI entrypoint. */
  banditCli?: string;
  /** How many files the model review pass may read. */
  maxReviewFiles?: number;
  /**
   * Per-call budget for the model pass. The wall-clock cost of a scan is
   * dominated by this times the number of calls, and it varies by an order of
   * magnitude between a hosted frontier model and a local one — so it is a flag
   * rather than a constant.
   */
  llmTimeoutMs?: number;
  /** Print progress. */
  onProgress?: (msg: string) => void;
}

export interface ScanResult {
  ctx: ScanContext;
  profile: Profile;
  findings: Finding[];
  confidence: ConfidenceAssessment;
  validation: ValidationIssue[];
  written: string[];
  exitCode: number;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const root = resolve(options.repo);
  if (!exists(root)) throw new Error(`repository path does not exist: ${root}`);
  const outDir = resolve(options.outDir);
  const profile = loadProfile(options.profile);
  const progress = options.onProgress ?? ((): void => {});
  const startedAt = new Date().toISOString();

  progress(`scanning ${root}`);
  progress('recon…');
  const reconOut = collectRecon(root);

  progress('dependencies + licences…');
  const depsOut = collectDependencies(root, { offline: options.offline });

  progress('secrets…');
  const gitignored = gitignoredPredicate(root, reconOut.files.map((f) => f.path).slice(0, 5000));
  const secretsOut = collectSecrets(root, reconOut.files, { gitignored });

  progress('ci workflows…');
  const ciOut = collectCi(root, reconOut.recon.workflows);

  progress('containers…');
  const dockerOut = collectDocker(root, reconOut.recon.dockerfiles);

  progress('rules…');
  const rulesOut = runRules(root, reconOut.files);

  const provider = detectProvider({ disabled: options.noLlm, banditCli: options.banditCli });

  const ctx: ScanContext = {
    root,
    outDir,
    profileId: profile.id,
    recon: reconOut.recon,
    deps: depsOut.deps,
    secrets: secretsOut.secrets,
    ci: ciOut.ci,
    docker: dockerOut.docker,
    hits: rulesOut.hits,
    runs: [reconOut.run, depsOut.run, secretsOut.run, ciOut.run, dockerOut.run, rulesOut.run],
    llm: { provider: provider.label, available: provider.available, note: provider.note, calls: 0, failures: 0 },
    startedAt,
  };
  attachTexts(ctx, rulesOut.repoContext.texts);

  progress('verifying findings (re-assertions + proof execution)…');
  const proofDir = join(outDir, 'proofs');
  if (!options.noProofs) ensureDir(proofDir);
  const analysis = analyze(ctx, rulesOut.repoContext, {
    profile,
    proofDir,
    proofsEnabled: !options.noProofs,
    toolVersion: TOOL_VERSION,
  });
  let findings = analysis.findings;

  if (provider.available) {
    progress(`model pass via ${provider.label}…`);
    const pass = await runLlmPasses(provider, ctx, findings, {
      maxReviewFiles: options.maxReviewFiles ?? 4,
      texts: rulesOut.repoContext.texts,
      timeoutMs: options.llmTimeoutMs,
    });
    ctx.llm.calls = pass.calls;
    ctx.llm.failures = pass.failures;
    const merged = applyLlmResults(findings, pass);
    progress(`model pass: ${pass.calls} call(s), ${merged.applied} adjustment(s) applied, ${merged.rejected} rejected, ${pass.proposals.length} proposal(s)`);

    // Model proposals become findings, but they can never be `confirmed`:
    // `method: 'code-read'` caps them at `plausible` by schema rule.
    if (pass.proposals.length > 0) {
      findings = [...findings, ...proposalsToFindings(pass.proposals, ctx, profile, findings.length)];
    }
    for (const note of pass.notes) ctx.runs.push({ name: 'llm', ok: true, durationMs: 0, note, notExamined: [] });
  } else {
    progress(`model pass skipped: ${provider.note}`);
  }

  ctx.finishedAt = new Date().toISOString();

  progress('assessing confidence + coverage…');
  const confidence = assessConfidence(ctx, findings, profile);
  const coverage = buildCoverage(ctx, findings);
  const validation = validateFindings(findings);

  // ---- write artefacts ----------------------------------------------------
  const written: string[] = [];
  const write = (rel: string, content: string): void => {
    const path = join(outDir, rel);
    writeFileEnsured(path, content);
    written.push(path);
  };
  ensureDir(outDir);

  if (options.formats.includes('json')) {
    for (const f of findings) write(join('findings', `${f.id}.json`), `${JSON.stringify(f, null, 2)}\n`);
    write(
      'findings/index.json',
      `${JSON.stringify(
        {
          tool: 'sentinel-audit',
          toolVersion: TOOL_VERSION,
          profile: profile.id,
          provenance: {
            repoUrl: ctx.recon.repoUrl,
            branch: ctx.recon.branch,
            commitSha: ctx.recon.commitSha,
            scannedAt: startedAt,
          },
          counts: {
            total: findings.length,
            // `confirmed` is the coarse sum of the two confirmed states, kept so
            // a consumer written against the pre-0.2.0 schema still reads a
            // correct number. The split is the honest view.
            proofConfirmed: findings.filter((f) => f.status === 'proof-confirmed').length,
            patternConfirmed: findings.filter((f) => f.status === 'pattern-confirmed').length,
            confirmed: findings.filter((f) => isConfirmed(f)).length,
            plausible: findings.filter((f) => f.status === 'plausible').length,
            refuted: findings.filter((f) => f.status === 'refuted').length,
            triagedOut: findings.filter((f) => f.status === 'triaged-out').length,
            agentExecutable: findings.filter((f) => f.fixPlan.agentExecutable).length,
          },
          llmPass: ctx.llm.available ? 'ran' : 'not-run',
          findings: findings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            status: f.status,
            statusClass: f.verification.class,
            type: f.type,
            confidence: f.confidence,
            agentExecutable: f.fixPlan.agentExecutable,
            file: `${f.id}.json`,
          })),
          validation: validation.filter((v) => v.severity === 'error'),
        },
        null,
        2,
      )}\n`,
    );
    write('scan-context.json', `${JSON.stringify(redactContext(ctx), null, 2)}\n`);
  }
  if (options.formats.includes('md')) {
    write('REPORT.md', renderReport(ctx, findings, profile, confidence));
    write('CONFIDENCE.md', renderConfidence(ctx, confidence, profile));
    write('COVERAGE.md', renderCoverage(ctx, coverage));
  }
  if (options.formats.includes('html')) {
    write('REPORT.html', renderHtml(ctx, findings, profile, confidence));
  }
  if (options.formats.includes('sarif')) {
    write('report.sarif', buildSarif(ctx, findings, { toolVersion: TOOL_VERSION }));
  }

  const errors = validation.filter((v) => v.severity === 'error');
  if (errors.length > 0) {
    write(
      'SCHEMA-VALIDATION.md',
      [
        '# Schema validation issues',
        '',
        'Sentinel validates its own output against the finding schema, including the semantic invariants (a `confirmed` behavioural finding must carry an executed proof; a suppression must cite evidence). Anything listed here is a defect in Sentinel, not in the audited repository.',
        '',
        ...errors.map((e) => `- **${e.findingId}** \`${e.path}\`: ${e.message}`),
        '',
      ].join('\n'),
    );
  }

  const blocking = findings.filter(
    (f) => f.status !== 'refuted' && f.status !== 'triaged-out' && profile.gate.blockOn.includes(f.severity),
  );
  const exitCode = confidence.gateDecision === 'block' ? 2 : blocking.length > 0 ? 1 : 0;

  return { ctx, profile, findings, confidence, validation, written, exitCode };
}

/**
 * The machine-readable run record, with the things that do not belong in a
 * distributable artefact removed.
 *
 * The verifiers are handed an in-memory cache of every source file so they can
 * answer "does this policy exist anywhere" without a second pass. Serialising
 * the context verbatim therefore embedded the audited repository's entire source
 * in the output — a 3.8 MB artefact that quietly republishes a private codebase
 * into whatever bucket the report is uploaded to. An audit artefact must carry
 * findings and evidence, not a copy of the subject.
 */
function redactContext(ctx: ScanContext): Record<string, unknown> {
  const { recon, deps, secrets, ci, docker, runs, llm, hits, ...rest } = ctx as ScanContext & Record<string, unknown>;
  const omit = new Set(['__texts']);
  const carried = Object.fromEntries(Object.entries(rest).filter(([k]) => !omit.has(k)));
  return {
    ...carried,
    recon,
    // The full dependency inventory belongs in an SBOM, not here; the summary
    // is what a reader of the report needs.
    deps: {
      ...deps,
      dependencies: `${deps.dependencies.length} package(s) inventoried — omitted from this artefact; see licenseSummary`,
    },
    // Candidates carry masked values only, but there is no reason to repeat
    // every triaged-out match here when the report already lists them.
    secrets: {
      filesScanned: secrets.filesScanned,
      externalScanner: secrets.externalScanner,
      candidateCount: secrets.candidates.length,
      suppressedCount: secrets.candidates.filter((c) => c.likelyFalsePositive).length,
    },
    ci,
    docker,
    runs,
    llm,
    ruleHitCount: hits.length,
  };
}

function proposalsToFindings(
  proposals: Awaited<ReturnType<typeof runLlmPasses>>['proposals'],
  ctx: ScanContext,
  profile: Profile,
  offset: number,
): Finding[] {
  return proposals.map((p, i) => {
    const id = `LLM-${String(offset + i + 1).padStart(3, '0')}`;
    const f: Finding = {
      id,
      title: p.title,
      type: p.type,
      severity: p.severity,
      suggestedLabels: ['model-proposed', p.type.toLowerCase().replace(/\s+/g, '-')],
      affectedArea: p.file.split('/')[0] ?? 'Shared',
      evidence: p.evidence.includes(':') ? p.evidence : `${p.file}:${p.line} — ${p.evidence}`,
      whyThisMatters: p.whyThisMatters,
      recommendation: p.recommendation,
      acceptanceCriteria: ['the described defect no longer reproduces', 'a regression test covers the behaviour'],
      effortEstimate: 'M',
      dependenciesRelated: [],
      provenance: {
        repoUrl: ctx.recon.repoUrl,
        branch: ctx.recon.branch,
        commitSha: ctx.recon.commitSha,
        reviewDate: new Date().toISOString().slice(0, 10),
        tool: 'sentinel-audit',
        toolVersion: TOOL_VERSION,
        profile: profile.id,
        llmPass: 'ran',
      },
      standardMapping: `${profile.title}: not mapped — model-proposed findings are not auto-mapped to a control, because the mapping would be as unverified as the finding`,
      status: 'plausible',
      verification: {
        method: 'code-read',
        claimType: 'behavioral',
        performed: false,
        result: 'plausible',
        state: 'plausible',
        class: 'plausible',
        checks: [
          {
            description: 'model read the file and proposed this defect',
            outcome: 'skip',
            detail: `${p.file}:${p.line} — model self-reported confidence: ${p.confidenceSelfReported}`,
          },
        ],
        notes:
          'Proposed by the model-assisted review pass from reading the source. No check was executed, so this is reported as plausible and cannot be promoted to confirmed — the schema forbids it for a code-read verification. Treat it as a lead to verify, not a result.',
      },
      locations: [{ file: p.file, startLine: p.line }],
      standards: { profile: profile.id, controls: [], cwe: [], owasp: [] },
      fixPlan: {
        agentExecutable: false,
        strategy: p.recommendation,
        files: [{ path: p.file, change: p.recommendation }],
        acceptanceTests: [{ path: 'n/a', description: 'add a regression test for the described behaviour' }],
        risk: 'medium',
        estimatedDiffSize: 'unknown',
        notAgentExecutableReason:
          'the finding itself is unverified; automating a fix for an unconfirmed defect risks changing correct behaviour',
      },
      source: 'llm',
      ruleId: 'LLM-REVIEW',
      confidence: 0,
      fingerprint: `${p.file}:${p.line}:${p.title.slice(0, 40)}`,
      notes: [`Model self-reported confidence: ${p.confidenceSelfReported}`],
    };
    f.confidence = scoreConfidence(f);
    return f;
  });
}
