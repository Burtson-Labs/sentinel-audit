import { join } from 'node:path';
import { excerpt } from './util/fsx.js';
import { fingerprint } from './util/hash.js';
import { applyFloor, controlsFor, standardMappingText, severityRank, type Profile } from './profile.js';
import { scoreConfidence, statusClass, statusFromVerification } from './schema.js';
import { ALL_RULES, ruleById } from './rules/index.js';
import { copyleftDependencies } from './collectors/dependencies.js';
import { verify, advisoryMeta } from './verify/index.js';
import { inTestCodeNote, isCredentialSensitiveRule } from './util/testpaths.js';
import type {
  AdvisoryRecord,
  CodeLocation,
  Finding,
  FindingType,
  Provenance,
  RuleHit,
  ScanContext,
  Severity,
} from './types.js';
import type { RuleRepoContext } from './rules/types.js';

/**
 * Candidate assembly + verification.
 *
 * The shape of the pipeline matters: rules and collectors only ever produce
 * *candidates*. A candidate becomes a finding with a status only after the
 * verification stage has run, and the status is derived from what the
 * verification did — never asserted by whatever produced the candidate.
 */

const ID_PREFIX: Record<FindingType, string> = {
  Security: 'SEC',
  'Supply Chain': 'DEP',
  Secret: 'SECRET',
  'Tech Debt': 'TD',
  Quality: 'QUA',
  'CI-CD': 'CICD',
  Compliance: 'COMP',
  Architecture: 'ARCH',
  Testing: 'TEST',
};

export interface CandidateFinding {
  ruleId: string;
  title: string;
  type: FindingType;
  severity: Severity;
  area: string;
  labels: string[];
  evidence: string;
  why: string;
  recommendation: string;
  acceptance: string[];
  effort: Finding['effortEstimate'];
  claimType: 'factual' | 'behavioral';
  source: Finding['source'];
  hits: RuleHit[];
  locations: CodeLocation[];
  /** Preset triage for scanner noise we already know about. */
  triage?: Finding['triage'];
  notes?: string[];
  /**
   * Every cited location is in test/spec/fixture code. For the credential and
   * auth-storage family this caps the severity at Info: in a test, the construct
   * is usually the subject rather than an exposure. It does not suppress the
   * finding — see `isCredentialSensitiveRule`.
   */
  inTestCodeOnly?: boolean;
}

export interface AnalyzeOptions {
  profile: Profile;
  proofDir: string;
  proofsEnabled: boolean;
  toolVersion: string;
  /** Cap on findings emitted per rule family (advisories mostly). */
  maxAdvisoryFindings?: number;
}

export interface AnalyzeResult {
  findings: Finding[];
  /** Candidates that were dropped before becoming findings, with reasons. */
  dropped: Array<{ ruleId: string; reason: string; count: number }>;
}

export function analyze(ctx: ScanContext, repo: RuleRepoContext, options: AnalyzeOptions): AnalyzeResult {
  const candidates: CandidateFinding[] = [
    ...candidatesFromRules(ctx),
    ...candidatesFromAdvisories(ctx, options.maxAdvisoryFindings ?? 12),
    ...candidatesFromSecrets(ctx),
    ...candidatesFromCi(ctx),
    ...candidatesFromDocker(ctx),
    ...candidatesFromLicenses(ctx),
  ];

  const dropped: AnalyzeResult['dropped'] = [];
  const provenanceBase: Omit<Provenance, 'llmPass'> = {
    repoUrl: ctx.recon.repoUrl,
    branch: ctx.recon.branch,
    commitSha: ctx.recon.commitSha,
    reviewDate: new Date().toISOString().slice(0, 10),
    tool: 'sentinel-audit',
    toolVersion: options.toolVersion,
    profile: options.profile.id,
  };

  // Stable ordering before ids are assigned, so ids do not churn between runs
  // for an unchanged repository.
  candidates.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.type.localeCompare(b.type) ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const counters = new Map<string, number>();
  const findings: Finding[] = [];

  for (const c of candidates) {
    const prefix = ID_PREFIX[c.type];
    const n = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, n);
    const id = `${prefix}-${String(n).padStart(3, '0')}`;

    const verified = verify({
      ruleId: c.ruleId,
      claimType: c.claimType,
      hits: c.hits,
      findingId: id,
      ctx,
      proofDir: options.proofDir,
      proofsEnabled: options.proofsEnabled,
    });

    const status = c.triage?.suppressed
      ? ('triaged-out' as const)
      : statusFromVerification(
          c.claimType,
          verified.verification.result,
          verified.verification.method,
          verified.verification.proof?.verdict,
        );

    // The profile's severity *floor* expresses "this category is categorically
    // serious". It has no business raising a finding we are simultaneously
    // dismissing: `severityFloor: { Secret: "High" }` published "53 matches
    // triaged out as non-credentials" as a High, which any consumer counting
    // High findings would have believed.
    let severity = c.triage?.suppressed ? c.severity : applyFloor(options.profile, c.type, c.severity);
    // Path-aware severity. Deliberately applied *after* the profile floor:
    // `severityFloor: { Secret: "High" }` would otherwise drag a credential in a
    // fixture back up to High, which is the exact defect this guards against.
    const testCodeOnly = c.inTestCodeOnly === true && isCredentialSensitiveRule(c.ruleId);
    if (testCodeOnly) severity = 'Info';
    if (verified.severityHint === 'lower') severity = lower(severity);
    if (status === 'refuted') severity = 'Info';

    const rule = ruleById(c.ruleId);
    const fixSeed = rule
      ? rule.fixPlan(c.hits, repo)
      : genericFixSeed(c);

    const controls = controlsFor(options.profile, c.ruleId);
    const finding: Finding = {
      id,
      title: testCodeOnly ? `${c.title} — in test code only` : c.title,
      type: c.type,
      severity,
      suggestedLabels: c.labels,
      affectedArea: c.area,
      evidence: c.evidence,
      whyThisMatters: c.why,
      recommendation: c.recommendation,
      acceptanceCriteria: c.acceptance,
      effortEstimate: c.effort,
      dependenciesRelated: [],
      provenance: { ...provenanceBase, llmPass: ctx.llm.available ? 'ran' : ctx.llm.note.includes('disabled') ? 'disabled' : 'unavailable' },
      standardMapping: standardMappingText(options.profile, c.ruleId),
      status,
      // Stamped in one place, from one source, so `status`,
      // `verification.state` and `verification.class` cannot disagree.
      verification: { ...verified.verification, state: status, class: statusClass(status) },
      locations: c.locations,
      standards: {
        profile: options.profile.id,
        controls,
        cwe: controls.filter((x) => x.id.startsWith('CWE-')).map((x) => x.id),
        owasp: controls.filter((x) => x.id.startsWith('ASVS')).map((x) => x.id),
      },
      fixPlan: {
        agentExecutable: fixSeed.agentExecutable && status !== 'refuted' && status !== 'triaged-out',
        strategy: fixSeed.strategy,
        files: fixSeed.changes,
        acceptanceTests: fixSeed.acceptanceTests,
        risk: fixSeed.risk,
        estimatedDiffSize: fixSeed.estimatedDiffSize,
        agentPrompt: fixSeed.agentPrompt,
        notAgentExecutableReason:
          status === 'refuted'
            ? 'the finding was refuted by verification — there is nothing to fix'
            : status === 'triaged-out'
              ? 'the finding was triaged out as noise'
              : fixSeed.notAgentExecutableReason,
      },
      source: c.source,
      ruleId: c.ruleId,
      confidence: 0,
      fingerprint: fingerprint([c.ruleId, c.hits[0]?.file, c.hits[0]?.line, c.title]),
      triage: c.triage,
      notes: [
        ...(c.notes ?? []),
        ...(testCodeOnly ? [inTestCodeNote(Array.from(new Set(c.hits.map((h) => h.file))), c.ruleId)] : []),
        ...verified.notes,
      ],
    };
    finding.confidence = scoreConfidence(finding);
    findings.push(finding);
  }

  linkRelated(findings);
  return { findings, dropped };
}

function lower(s: Severity): Severity {
  const order: Severity[] = ['Info', 'Low', 'Medium', 'High', 'Blocker'];
  const i = order.indexOf(s);
  return order[Math.max(0, i - 1)] ?? 'Info';
}

// ---------------------------------------------------------------------------
// candidate builders
// ---------------------------------------------------------------------------

function candidatesFromRules(ctx: ScanContext): CandidateFinding[] {
  const byRule = new Map<string, RuleHit[]>();
  for (const h of ctx.hits) {
    const list = byRule.get(h.ruleId) ?? [];
    list.push(h);
    byRule.set(h.ruleId, list);
  }

  const out: CandidateFinding[] = [];
  for (const [ruleId, hits] of byRule) {
    const rule = ALL_RULES.find((r) => r.id === ruleId);
    if (!rule) continue;

    // Separate production from test-only hits: a construct that only appears in
    // tests is usually deliberate, so it is triaged out with that reason rather
    // than inflating the count.
    const prod = hits.filter((h) => h.meta?.inTest !== true);
    const testOnly = hits.filter((h) => h.meta?.inTest === true);
    const useHits = prod.length > 0 ? prod : testOnly;
    const testOnlyFinding = prod.length === 0 && testOnly.length > 0;

    // Put the most consequential sites first so the evidence string leads with
    // them rather than with whatever the directory walk happened to reach first.
    const ranked = [...useHits].sort((a, b) => hitWeight(b) - hitWeight(a));
    // A rule may dismiss its own finding once it has seen all the hits together
    // — the case a per-hit matcher cannot decide. Test-only triage wins, because
    // it is the stronger statement about where the code lives.
    const selfTriage = testOnlyFinding ? undefined : rule.triageFor?.(ranked);
    const cap = rule.maxEvidence ?? 6;
    const shown = ranked.slice(0, cap);
    const evidence = `${shown.map((h) => `${h.file}:${h.line} — ${h.message}`).join('; ')}${
      ranked.length > cap ? ` (+${ranked.length - cap} further site(s))` : ''
    }`;

    out.push({
      ruleId,
      title: rule.title,
      type: rule.type,
      severity: rule.severityFor ? rule.severityFor(ranked) : rule.severity,
      area: rule.area,
      labels: rule.labels,
      evidence,
      why: rule.why,
      recommendation: rule.recommendation,
      acceptance: rule.acceptance,
      effort: rule.effort,
      claimType: rule.claimType,
      source: 'rule',
      hits: ranked,
      locations: shown.map((h) => ({ file: h.file, startLine: h.line, endLine: h.endLine, excerpt: h.excerpt })),
      inTestCodeOnly: testOnlyFinding,
      triage: testOnlyFinding
        ? {
            suppressed: true,
            reason:
              'every match is in a test or fixture path, where the construct is normally deliberate (exercising the behaviour under test). Kept visible so the decision is auditable.',
            evidenceCited: `${testOnly[0]!.file}:${testOnly[0]!.line}`,
            by: 'heuristic',
          }
        : selfTriage
          ? {
              suppressed: true,
              reason: selfTriage.reason,
              evidenceCited: `${ranked[0]!.file}:${ranked[0]!.line}`,
              by: 'heuristic',
            }
          : undefined,
      notes:
        prod.length > 0 && testOnly.length > 0
          ? [`${testOnly.length} further match(es) in test paths were excluded from the evidence as deliberate test constructs.`]
          : undefined,
    });
  }
  return out;
}

/**
 * Significance of a single hit, used only for ordering evidence. A write beats a
 * read, a long-lived credential beats a short-lived protocol value, production
 * beats test, and a site with no mitigating construct nearby beats one where a
 * guard was spotted.
 */
function hitWeight(h: RuleHit): number {
  let n = 0;
  if (h.meta?.longLived === true) n += 8;
  if (h.meta?.isWrite === true) n += 4;
  if (h.meta?.protocolValue === true) n -= 2;
  if (h.meta?.inTest === true) n -= 6;
  if (h.meta?.sanitiserNearby === true || h.meta?.confinedNearby === true || h.meta?.guardedNearby === true) n -= 3;
  if (h.meta?.interpolated === true || h.meta?.shellTrue === true) n += 4;
  if (h.meta?.publicByDesign === true) n -= 4;
  if (typeof h.meta?.count === 'number') n += Math.min(4, h.meta.count / 10);
  if (typeof h.meta?.loc === 'number') n += Math.min(4, h.meta.loc / 1000);
  return n;
}

function candidatesFromAdvisories(ctx: ScanContext, maxIndividual: number): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  const { advisories, auditAvailable, auditCommand } = ctx.deps;
  if (!auditAvailable) {
    return [
      {
        ruleId: 'DEP-AUDIT-UNAVAILABLE',
        title: 'Dependency advisory data could not be collected',
        type: 'Supply Chain',
        severity: 'Info',
        area: 'Dependencies',
        labels: ['dependencies', 'coverage'],
        evidence: `package.json — audit could not run: ${ctx.deps.auditError ?? 'unknown reason'}`,
        why:
          'This is a coverage gap, not a vulnerability. It is recorded as a finding so the report cannot be mistaken for a clean supply-chain result: no advisory data was available for this run.',
        recommendation: 'Re-run with registry access, or point the scan at an installed tree so advisory data can be collected.',
        acceptance: ['a subsequent scan records advisory data', 'the CI workflow runs the audit with registry access'],
        effort: 'S',
        claimType: 'factual',
        source: 'collector',
        hits: [{ ruleId: 'DEP-AUDIT-UNAVAILABLE', file: 'package.json', line: 1, excerpt: 'n/a', message: 'audit unavailable' }],
        locations: [{ file: 'package.json', startLine: 1 }],
      },
    ];
  }

  // Group by module, not by advisory. Three advisories against one package are
  // one upgrade, and emitting them separately triples the apparent finding count
  // while tripling the work of closing it.
  const byModule = new Map<string, AdvisoryRecord[]>();
  for (const a of advisories) {
    if (a.severity !== 'critical' && a.severity !== 'high') continue;
    const list = byModule.get(a.module) ?? [];
    list.push(a);
    byModule.set(a.module, list);
  }
  const rest = advisories.filter((a) => a.severity !== 'critical' && a.severity !== 'high');

  const modules = Array.from(byModule.entries()).sort(
    (x, y) => worstRank(y[1]) - worstRank(x[1]) || x[0].localeCompare(y[0]),
  );

  for (const [moduleName, group] of modules.slice(0, maxIndividual)) {
    const worst = group.reduce((acc, a) => (rankOf(a.severity) > rankOf(acc.severity) ? a : acc), group[0]!);
    const allDev = group.every((a) => a.isDev);
    const sev: Severity = worst.severity === 'critical' ? (allDev ? 'Medium' : 'High') : allDev ? 'Low' : 'Medium';
    // The widest range across the group, so verification checks the installed
    // version against something that covers every advisory in it.
    const widestRange = group.map((a) => a.vulnerableVersions).filter((r): r is string => Boolean(r))[0] ?? '';
    out.push({
      ruleId: 'DEP-ADVISORY',
      title:
        group.length === 1
          ? `${worst.severity} advisory in ${moduleName}: ${excerpt(worst.title, 90)}`
          : `${group.length} ${worst.severity}/high advisories in ${moduleName}`,
      type: 'Supply Chain',
      severity: sev,
      area: 'Dependencies',
      labels: ['dependencies', 'security', allDev ? 'dev-only' : 'runtime'],
      evidence: `\`${auditCommand}\` reports ${group.length} advisor${group.length === 1 ? 'y' : 'ies'} against ${moduleName}${widestRange ? ` (vulnerable range ${widestRange})` : ''} as a ${worst.path} ${allDev ? 'development' : 'runtime'} dependency: ${group.map((a) => `${a.severity} — ${excerpt(a.title, 70)}${a.url ? ` (${a.url})` : ''}`).join('; ')}`,
      why: allDev
        ? 'A development-only advisory does not ship to users, but it does run on developer machines and in CI with repository credentials available, so it remains worth closing.'
        : 'The package is part of what ships. A known advisory in runtime code is exposure that needs either an upgrade or a documented, dated reason it does not apply here.',
      recommendation: group.every((a) => a.patchedIn === null)
        ? `No fix was available when audit ran. Record the exposure, pin the current version, and track upstream. If the vulnerable code path is unreachable from this application, document why.`
        : `Upgrade ${moduleName} past the vulnerable range (directly, or with an override/resolution if a parent pins it), then re-run audit to confirm all ${group.length} advisor${group.length === 1 ? 'y' : 'ies'} clear.`,
      acceptance: [
        `audit no longer reports ${group.length === 1 ? 'this advisory' : `these ${group.length} advisories`} for ${moduleName}`,
        'the lockfile change is reviewed and the application test suite passes',
        'if the upgrade is not possible, an exception with an owner and a review date exists',
      ],
      effort: worst.path === 'direct' ? 'S' : 'M',
      claimType: 'factual',
      source: 'scanner',
      hits: [
        {
          ruleId: 'DEP-ADVISORY',
          file: 'package.json',
          line: 1,
          excerpt: `${moduleName} ${widestRange}`.trim(),
          message: `${group.length} ${worst.severity}/high advisor${group.length === 1 ? 'y' : 'ies'}: ${excerpt(worst.title, 70)}`,
          meta: { ...advisoryMeta(worst), range: widestRange, advisoryCount: group.length },
        },
      ],
      locations: [{ file: 'package.json', startLine: 1 }],
    });
  }

  const overflowModules = modules.slice(maxIndividual);
  if (rest.length > 0 || overflowModules.length > 0) {
    const all = [...overflowModules.flatMap(([, g]) => g), ...rest];
    const bySeverity = all.reduce<Record<string, number>>((acc, a) => {
      acc[a.severity] = (acc[a.severity] ?? 0) + 1;
      return acc;
    }, {});
    out.push({
      ruleId: 'DEP-ADVISORY-AGGREGATE',
      title: `${all.length} lower-severity dependency advisories tracked in aggregate`,
      type: 'Supply Chain',
      severity: 'Low',
      area: 'Dependencies',
      labels: ['dependencies'],
      evidence: `\`${auditCommand}\` — ${Object.entries(bySeverity).map(([k, v]) => `${v} ${k}`).join(', ')}; modules: ${all.slice(0, 12).map((a) => a.module).join(', ')}${all.length > 12 ? `, +${all.length - 12} more` : ''}`,
      why:
        'Individually these do not warrant a ticket each; collectively they are the backlog that a scheduled dependency-update job exists to keep at zero. Reported as one item deliberately, because 60 tickets nobody closes is worse than one that someone owns.',
      recommendation: 'Enable automated dependency-update PRs and a scheduled audit so the aggregate trends toward zero without manual sweeps.',
      acceptance: ['automated update PRs are enabled', 'a scheduled audit reports the aggregate count', 'the count trends down across releases'],
      effort: 'S',
      claimType: 'factual',
      source: 'scanner',
      hits: [{ ruleId: 'DEP-ADVISORY-AGGREGATE', file: 'package.json', line: 1, excerpt: `${all.length} advisories`, message: `${all.length} lower-severity advisories` }],
      locations: [{ file: 'package.json', startLine: 1 }],
    });
  }

  return out;
}

function rankOf(s: AdvisoryRecord['severity']): number {
  return ['info', 'low', 'moderate', 'high', 'critical'].indexOf(s);
}

function worstRank(group: AdvisoryRecord[]): number {
  return group.reduce((n, a) => Math.max(n, rankOf(a.severity)), 0);
}

function candidatesFromSecrets(ctx: ScanContext): CandidateFinding[] {
  const { candidates } = ctx.secrets;
  const allLive = candidates.filter((c) => !c.likelyFalsePositive);
  // Test/fixture paths are split out rather than dropped. A credential in a spec
  // is usually scaffolding, so it does not belong in a High finding next to a
  // production leak — but it is still a credential-shaped value in the tree, so
  // it gets its own Info finding instead of disappearing.
  const live = allLive.filter((c) => !c.inTestPath);
  const liveInTests = allLive.filter((c) => c.inTestPath);
  const suppressed = candidates.filter((c) => c.likelyFalsePositive);
  const out: CandidateFinding[] = [];

  if (live.length > 0) {
    const shown = live.slice(0, 8);
    out.push({
      ruleId: 'SEC-SECRET-COMMITTED',
      title: `${live.length} credential-shaped value(s) present in the working tree`,
      type: 'Secret',
      severity: 'High',
      area: 'Repository',
      labels: ['security', 'secrets'],
      evidence: shown.map((c) => `${c.file}:${c.line} — ${c.description} (${c.masked}, entropy ${c.entropy})`).join('; ') + (live.length > 8 ? ` (+${live.length - 8} more)` : ''),
      why:
        'A credential in the repository is valid wherever it was issued, for as long as nobody rotates it. If the file is tracked by git, deleting it does not help — the value stays in history and in every clone.',
      recommendation:
        'Rotate every value first, then remove it from the working tree and move it to a secret store. Rewriting history is optional; rotation is not.',
      acceptance: [
        'every exposed value is rotated and the old one is proven invalid',
        'no credential-shaped value remains in tracked files',
        'a secret-scanning step runs in CI and fails the build',
      ],
      effort: 'M',
      claimType: 'factual',
      source: 'collector',
      hits: shown.map((c) => ({
        ruleId: 'SEC-SECRET-COMMITTED',
        file: c.file,
        line: c.line,
        excerpt: c.masked,
        message: `${c.description} (masked: ${c.masked})`,
        meta: { entropy: c.entropy, ruleId: c.ruleId, isExample: c.isExampleFile },
      })),
      locations: shown.map((c) => ({ file: c.file, startLine: c.line, excerpt: `${c.description}: ${c.masked}` })),
      notes:
        liveInTests.length > 0
          ? [`${liveInTests.length} further credential-shaped value(s) in test/fixture paths are reported separately at Info, so test scaffolding does not inflate this count.`]
          : undefined,
    });
  }

  if (liveInTests.length > 0) {
    const shown = liveInTests.slice(0, 8);
    out.push({
      ruleId: 'SEC-SECRET-IN-TEST',
      title: `${liveInTests.length} credential-shaped value(s) in test or fixture code`,
      type: 'Secret',
      // Info, not High: see the severity note in util/testpaths.ts. The profile's
      // `Secret: High` floor is deliberately bypassed for this rule.
      severity: 'Info',
      area: 'Tests',
      labels: ['secrets', 'tests'],
      evidence:
        shown.map((c) => `${c.file}:${c.line} — ${c.description} (${c.masked}, entropy ${c.entropy})`).join('; ') +
        (liveInTests.length > 8 ? ` (+${liveInTests.length - 8} more)` : ''),
      why:
        'A credential-shaped value in a test is usually a literal the test needs, and reporting it at High is how a secret section stops being read. It is still worth one Info line, for the case it is not scaffolding: a real production key pasted into a fixture is in the repository and in its history exactly like any other committed credential.',
      recommendation:
        'Read each value once. Anything that was ever valid against a real system must be rotated like any other leak; everything else should be an obviously-fake constant (`test-token`, `sk_test_…`) so the next scan — and the next reviewer — can tell at a glance.',
      acceptance: [
        'no value in a test path was ever valid against a real system',
        'test credentials are obviously synthetic, so a future scan can dismiss them on sight',
      ],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      inTestCodeOnly: true,
      hits: shown.map((c) => ({
        ruleId: 'SEC-SECRET-IN-TEST',
        file: c.file,
        line: c.line,
        excerpt: c.masked,
        message: `${c.description} in test code (masked: ${c.masked})`,
        meta: { entropy: c.entropy, ruleId: c.ruleId, inTest: true },
      })),
      locations: shown.map((c) => ({ file: c.file, startLine: c.line, excerpt: `${c.description}: ${c.masked}` })),
    });
  }

  // An external scanner's results are not re-derived, but they must not be
  // reduced to a footnote either: a credential in git history is a rotation job
  // whether or not this tool can enumerate it.
  //
  // They also must not bypass triage. Relaying the raw count at a hardcoded High
  // produced a report in which the *same* test fixture was Info under
  // SEC-SECRET-IN-TEST and High under this rule — two severities for one value,
  // in one document. So every relayed hit goes through the same placeholder,
  // publishable-key and test-path rules as Sentinel's own matches, and High
  // survives only when a hit does.
  const external = ctx.secrets.externalScanner;
  if (external.available && external.findings > 0) {
    const relayed = external.hits ?? [];
    const triaged = external.hitsParsed === true && relayed.length > 0;
    const dismissed = relayed.filter((h) => h.likelyFalsePositive);
    const surviving = relayed.filter((h) => !h.likelyFalsePositive);
    const inTests = surviving.filter((h) => h.inTestPath);
    const live = surviving.filter((h) => !h.inTestPath);
    const everythingDismissed = triaged && surviving.length === 0;
    const testOnly = triaged && live.length === 0 && inTests.length > 0;
    const shown = (live.length > 0 ? live : inTests.length > 0 ? inTests : dismissed).slice(0, 8);
    const describe = (h: (typeof relayed)[number]): string =>
      `${h.file}:${h.line} — ${h.description} (${h.masked}${h.commit !== undefined ? `, commit ${h.commit.slice(0, 8)}` : ''})${
        h.likelyFalsePositive ? ` — dismissed: ${excerpt(h.falsePositiveReason, 90)}` : h.inTestPath ? ' — in a test/fixture path' : ''
      }`;

    out.push({
      ruleId: 'SEC-SECRET-HISTORY',
      title: !triaged
        ? `${external.name} reported ${external.findings} secret finding(s), including git history`
        : live.length > 0
          ? `${live.length} of ${relayed.length} ${external.name} secret finding(s) survive triage, including git history`
          : everythingDismissed
            ? `${relayed.length} ${external.name} secret finding(s) triaged out as non-credentials`
            : `${inTests.length} ${external.name} secret finding(s), all in test or fixture paths`,
      type: 'Secret',
      // High only for a hit that survived triage. An untriageable count stays
      // High on purpose: "we could not check" is not "it is fine".
      severity: !triaged || live.length > 0 ? 'High' : 'Info',
      area: everythingDismissed || testOnly ? 'Tests' : 'Repository',
      labels: ['security', 'secrets', 'git-history'],
      evidence: triaged
        ? `${shown.map(describe).join('; ')}${shown.length < relayed.length ? ` (+${relayed.length - shown.length} more)` : ''}`
        : `${external.name} run over the repository: ${external.note}`,
      why:
        'A credential that reached git history stays in every clone and every fork, and deleting the file does not remove it. Sentinel relays another scanner\'s detections rather than re-deriving them, but it triages them with its own rules first — a placeholder in a README and a live key in a config are not the same finding, and a count that mixes them cannot be acted on.',
      recommendation: `Run \`${external.name}\` directly to list the results in full, rotate every value that survives triage, and only then decide whether history rewriting is worth the disruption. Rotation is the part that actually closes the exposure.`,
      acceptance: [
        `${external.name} reports zero findings, or every remaining one is an accepted, documented false positive`,
        'every value it named has been rotated and the old value is proven invalid',
        'the scanner runs in CI and fails the build on a new finding',
      ],
      effort: 'M',
      claimType: 'factual',
      source: 'scanner',
      inTestCodeOnly: testOnly,
      hits:
        shown.length > 0
          ? shown.map((h) => ({
              ruleId: 'SEC-SECRET-HISTORY',
              file: h.file,
              line: h.line,
              excerpt: h.masked,
              message: `${h.description} reported by ${external.name}${h.commit !== undefined ? ` in commit ${h.commit.slice(0, 8)}` : ''}`,
              meta: {
                scanner: external.name,
                scannerRule: h.ruleId,
                entropy: h.entropy,
                inTest: h.inTestPath,
                dismissed: h.likelyFalsePositive,
              },
            }))
          : [
              {
                ruleId: 'SEC-SECRET-HISTORY',
                file: '.git',
                line: 1,
                excerpt: `${external.findings} finding(s)`,
                message: `${external.name} reported ${external.findings} finding(s)`,
                meta: { scanner: external.name, findings: external.findings },
              },
            ],
      locations: shown.length > 0 ? shown.map((h) => ({ file: h.file, startLine: h.line, excerpt: `${h.description}: ${h.masked}` })) : [{ file: '.git', startLine: 1 }],
      triage: everythingDismissed
        ? {
            suppressed: true,
            reason: `every one of the ${relayed.length} relayed ${external.name} result(s) was dismissed by Sentinel's triage (top reason: ${excerpt(dismissed[0]?.falsePositiveReason ?? 'n/a', 120)})`,
            evidenceCited: `${dismissed[0]?.file ?? '.git'}:${dismissed[0]?.line ?? 1}`,
            by: 'heuristic',
          }
        : undefined,
      notes: triaged
        ? [
            `Sentinel does not re-detect another scanner's results — it relays them and applies its own triage so the severity is consistent with the rest of this report: ${live.length} surviving, ${inTests.length} in test/fixture paths, ${dismissed.length} dismissed. The detections themselves remain ${external.name}'s.`,
          ]
        : [
            `${external.name}'s individual results could not be parsed, so the count is relayed without triage and kept at High. That is deliberate: an untriaged count is unknown, not clean. Run the tool directly to see what it found.`,
          ],
    });
  }

  if (suppressed.length > 0) {
    const byReason = new Map<string, number>();
    for (const c of suppressed) byReason.set(c.falsePositiveReason ?? 'unspecified', (byReason.get(c.falsePositiveReason ?? 'unspecified') ?? 0) + 1);
    const top = Array.from(byReason.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const first = suppressed[0]!;
    out.push({
      ruleId: 'SEC-SECRET-TRIAGED',
      title: `${suppressed.length} secret-scanner match(es) triaged out as non-credentials`,
      type: 'Secret',
      severity: 'Info',
      area: 'Repository',
      labels: ['secrets', 'triage'],
      evidence: `${suppressed.length} matches dismissed; top reasons: ${top.map(([r, n]) => `${n}× ${excerpt(r, 90)}`).join('; ')}. First: ${first.file}:${first.line}`,
      why:
        'Suppressions are published rather than silently applied. A scanner that only prints what it believes cannot be audited; one that shows its dismissals with the reason can be corrected.',
      recommendation: 'Review the dismissal reasons. Anything you disagree with should be re-raised; anything you agree with belongs in a committed allowlist so the next run is quieter.',
      acceptance: ['the dismissal list has been reviewed at least once', 'agreed dismissals are encoded in a committed allowlist'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: suppressed.slice(0, 8).map((c) => ({
        ruleId: 'SEC-SECRET-TRIAGED',
        file: c.file,
        line: c.line,
        excerpt: c.masked,
        message: `${c.description} — dismissed: ${c.falsePositiveReason}`,
      })),
      locations: suppressed.slice(0, 8).map((c) => ({ file: c.file, startLine: c.line })),
      triage: {
        suppressed: true,
        reason: `heuristic triage dismissed these matches; the per-match reasons are in the evidence (top reason: ${excerpt(top[0]?.[0] ?? 'n/a', 120)})`,
        evidenceCited: `${first.file}:${first.line}`,
        by: 'heuristic',
      },
    });
  }

  return out;
}

function candidatesFromCi(ctx: ScanContext): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  const { workflows, unpinnedActions, riskyTriggers } = ctx.ci;

  const gateNames = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  const missing = gateNames.filter((g) => !workflows.some((w) => w.gates[g]));
  const hasAnyWorkflow = workflows.length > 0;

  if (missing.length > 0) {
    const securityGatesMissing = missing.filter((m) => m === 'audit' || m === 'sast' || m === 'secrets');
    out.push({
      ruleId: 'CI-NO-SECURITY-GATE',
      title: hasAnyWorkflow
        ? `PR gate does not enforce: ${missing.join(', ')}`
        : 'No CI workflows: nothing is enforced automatically',
      type: 'CI-CD',
      severity: securityGatesMissing.length >= 2 ? 'Medium' : 'Low',
      area: 'CI-CD',
      labels: ['ci-cd', 'standards', ...(securityGatesMissing.length > 0 ? ['security'] : [])],
      evidence: hasAnyWorkflow
        ? `${workflows.map((w) => `${w.file} (triggers: ${w.triggers.join('/') || 'none'}; gates: ${Object.entries(w.gates).filter(([, v]) => v).map(([k]) => k).join(',') || 'none'})`).join('; ')}`
        : '.github/workflows — no workflow files found',
      why:
        'A standard that is configured but not enforced is a preference. Without a blocking check, the first pull request under time pressure sets the real standard, and dependency/secret exposure is found by chance rather than by the pipeline.',
      recommendation: `Add blocking PR checks for ${missing.join(', ')}. Keep them fast enough that nobody wants to bypass them, and make them required in branch protection — a workflow that runs but is not required does not gate.`,
      acceptance: [
        `a pull request with a failing ${missing[0]} step cannot merge`,
        'the checks are marked required in branch protection',
        'the workflow runs on pull_request, not only on push to the default branch',
      ],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: [
        {
          ruleId: 'CI-NO-SECURITY-GATE',
          file: workflows[0]?.file ?? '.github/workflows',
          line: 1,
          excerpt: `missing gates: ${missing.join(', ')}`,
          message: `no blocking step for ${missing.join(', ')}`,
          meta: { missing: missing.join(','), workflowCount: workflows.length },
        },
      ],
      locations: workflows.length > 0 ? workflows.map((w) => ({ file: w.file, startLine: 1 })) : [{ file: '.github/workflows', startLine: 1 }],
    });
  }

  if (unpinnedActions.length > 0) {
    const thirdParty = unpinnedActions.filter((a) => !a.uses.startsWith('actions/') && !a.uses.startsWith('github/'));
    const shown = (thirdParty.length > 0 ? thirdParty : unpinnedActions).slice(0, 8);
    out.push({
      ruleId: 'CI-UNPINNED-ACTION',
      title: `${unpinnedActions.length} CI action reference(s) are not pinned to an immutable commit`,
      type: 'CI-CD',
      severity: thirdParty.length > 0 ? 'Medium' : 'Low',
      area: 'CI-CD',
      labels: ['ci-cd', 'supply-chain'],
      evidence: shown.map((a) => `${a.file}:${a.line} — uses: ${a.uses}`).join('; ') + (unpinnedActions.length > shown.length ? ` (+${unpinnedActions.length - shown.length} more)` : ''),
      why:
        'A tag is a moving pointer. Whoever controls the action repository can change what a tag points at, and that code runs in your pipeline with your secrets. Pinning to a commit makes the supply chain reviewable; Dependabot can still propose updates.',
      recommendation: 'Pin third-party actions to a full commit SHA with the version in a trailing comment, and let automated updates propose SHA bumps.',
      acceptance: ['every third-party action is pinned to a 40-character commit SHA', 'automated updates keep the pins current'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: shown.map((a) => ({ ruleId: 'CI-UNPINNED-ACTION', file: a.file, line: a.line, excerpt: `uses: ${a.uses}`, message: `unpinned action reference ${a.uses}` })),
      locations: shown.map((a) => ({ file: a.file, startLine: a.line, excerpt: `uses: ${a.uses}` })),
    });
  }

  if (riskyTriggers.length > 0) {
    out.push({
      ruleId: 'CI-RISKY-TRIGGER',
      title: 'Workflow triggers that run with repository secrets in a fork context',
      type: 'CI-CD',
      severity: 'High',
      area: 'CI-CD',
      labels: ['ci-cd', 'security', 'supply-chain'],
      evidence: riskyTriggers.map((t) => `${t.file}:${t.line} — ${t.trigger}`).join('; '),
      why:
        'pull_request_target, workflow_run and issue_comment run in the context of the base repository, with access to secrets, while the content they act on can come from a fork. Checking out the pull-request head in such a workflow hands a fork author your secrets.',
      recommendation: 'Avoid checking out untrusted refs in these workflows. Split the build (untrusted, no secrets) from the privileged step (trusted, no untrusted code), and gate on a label or an environment approval.',
      acceptance: ['no privileged workflow checks out a fork ref', 'privileged steps run in an environment with required reviewers'],
      effort: 'M',
      claimType: 'factual',
      source: 'collector',
      hits: riskyTriggers.map((t) => ({ ruleId: 'CI-RISKY-TRIGGER', file: t.file, line: t.line, excerpt: t.trigger, message: `${t.trigger} trigger with access to repository secrets` })),
      locations: riskyTriggers.map((t) => ({ file: t.file, startLine: t.line })),
    });
  }

  return out;
}

function candidatesFromDocker(ctx: ScanContext): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  const rootFiles = ctx.docker.files.filter((f) => f.runsAsRoot);
  const unpinned = ctx.docker.files.flatMap((f) => f.baseImages.filter((b) => !b.pinned).map((b) => ({ file: f.file, ...b })));
  const secretArgs = ctx.docker.files.flatMap((f) => f.secretsInArgs.map((s) => ({ file: f.file, ...s })));

  if (rootFiles.length > 0) {
    out.push({
      ruleId: 'DOCKER-ROOT',
      title: `${rootFiles.length} container image(s) run as root`,
      type: 'Security',
      severity: 'Medium',
      area: 'Containers',
      labels: ['security', 'containers'],
      evidence: rootFiles.map((f) => `${f.file}:${f.userLine ?? 1} — final stage has ${f.userLine ? 'USER root' : 'no USER directive'}`).join('; '),
      why:
        'Root in the container is root in the kernel namespace it shares. It turns a container escape or a writable mount from a contained problem into a host problem, and it is one line to fix.',
      recommendation: 'Create an unprivileged user in the final stage, chown what must be writable, and add USER before the entrypoint.',
      acceptance: ['the final stage sets a non-root USER', 'the container starts and passes its smoke test as that user', 'no runtime path needs write access outside its own volume'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: rootFiles.map((f) => ({ ruleId: 'DOCKER-ROOT', file: f.file, line: f.userLine ?? 1, excerpt: f.userLine ? 'USER root' : 'no USER directive', message: 'final stage runs as root' })),
      locations: rootFiles.map((f) => ({ file: f.file, startLine: f.userLine ?? 1 })),
    });
  }

  if (unpinned.length > 0) {
    out.push({
      ruleId: 'DOCKER-UNPINNED-BASE',
      title: `${unpinned.length} base image(s) are not pinned by digest`,
      type: 'Supply Chain',
      severity: 'Low',
      area: 'Containers',
      labels: ['containers', 'supply-chain'],
      evidence: unpinned.map((b) => `${b.file}:${b.line} — FROM ${b.image}`).join('; '),
      why: 'A tag can be re-pointed at different content, so two builds of the same commit can produce different images. That breaks reproducibility and makes "what is running" unanswerable during an incident.',
      recommendation: 'Pin base images by digest and let an automated update propose digest bumps.',
      acceptance: ['every FROM references a sha256 digest', 'automated updates keep digests current'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: unpinned.map((b) => ({ ruleId: 'DOCKER-UNPINNED-BASE', file: b.file, line: b.line, excerpt: `FROM ${b.image}`, message: `base image ${b.image} is tag-pinned, not digest-pinned` })),
      locations: unpinned.map((b) => ({ file: b.file, startLine: b.line })),
    });
  }

  if (secretArgs.length > 0) {
    out.push({
      ruleId: 'DOCKER-SECRET-ARG',
      title: 'Credential-shaped build arguments in a container image',
      type: 'Secret',
      severity: 'Medium',
      area: 'Containers',
      labels: ['security', 'secrets', 'containers'],
      evidence: secretArgs.map((s) => `${s.file}:${s.line} — ${s.name}`).join('; '),
      why: 'ARG and ENV values are recorded in image metadata and survive in every layer. Anyone who can pull the image can read them, and an ENV value is visible to every process in the container.',
      recommendation: 'Use BuildKit secret mounts for build-time credentials and inject runtime values from the orchestrator, never from image metadata.',
      acceptance: ['no credential-shaped ARG/ENV in any Dockerfile', 'build-time credentials use secret mounts', 'image history contains no credential'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: secretArgs.map((s) => ({ ruleId: 'DOCKER-SECRET-ARG', file: s.file, line: s.line, excerpt: s.name, message: `credential-shaped build argument ${s.name}` })),
      locations: secretArgs.map((s) => ({ file: s.file, startLine: s.line })),
    });
  }

  return out;
}

export function candidatesFromLicenses(ctx: ScanContext): CandidateFinding[] {
  const copyleft = copyleftDependencies(ctx.deps.dependencies);
  if (copyleft.length === 0) return [];
  return [
    {
      ruleId: 'DEP-LICENSE',
      title: `${copyleft.length} dependency/dependencies carry a strong-copyleft or source-available licence`,
      type: 'Compliance',
      severity: 'Low',
      area: 'Dependencies',
      labels: ['dependencies', 'legal'],
      // Evidence names the artefact the licences were read from. Without the
      // prefix, a list of package@version pairs failed Sentinel's own schema
      // check ("must cite a concrete reference") on every repository that had
      // a copyleft dependency — a validation error in the tool's output.
      evidence:
        'package.json (resolved through the lockfile): ' +
        copyleft.slice(0, 10).map((d) => `${d.name}@${d.version} — ${d.license}`).join('; ') +
        (copyleft.length > 10 ? ` (+${copyleft.length - 10} more)` : ''),
      why:
        'Strong-copyleft and source-available licences carry distribution obligations. Whether they matter depends on how this code is shipped — a decision that should be made deliberately once rather than discovered during diligence.',
      recommendation: 'Record a licence policy, confirm each of these is compatible with how the product is distributed, and add a licence check to CI so new ones are a conscious choice.',
      acceptance: ['each flagged licence has a recorded decision', 'a CI licence check flags new ones', 'the policy names the allowed set'],
      effort: 'S',
      claimType: 'factual',
      source: 'collector',
      hits: copyleft.slice(0, 10).map((d) => ({ ruleId: 'DEP-LICENSE', file: 'package.json', line: 1, excerpt: `${d.name}@${d.version} ${d.license}`, message: `${d.name} is ${d.license}` })),
      locations: [{ file: 'package.json', startLine: 1 }],
    },
  ];
}

function genericFixSeed(c: CandidateFinding): ReturnType<NonNullable<ReturnType<typeof ruleById>>['fixPlan']> {
  return {
    agentExecutable: false,
    strategy: c.recommendation,
    changes: Array.from(new Set(c.hits.map((h) => h.file))).map((p) => ({ path: p, change: c.recommendation })),
    acceptanceTests: c.acceptance.map((a) => ({ path: 'n/a', description: a })),
    risk: 'medium',
    estimatedDiffSize: 'unknown',
    notAgentExecutableReason: 'This finding comes from a collector rather than a code rule, so there is no mechanical change an agent can apply without a human decision first.',
  };
}

/** Cross-link findings that share a file or a theme, like the benchmark's `dependenciesRelated`. */
function linkRelated(findings: Finding[]): void {
  const byFile = new Map<string, string[]>();
  for (const f of findings) {
    for (const loc of f.locations) {
      const list = byFile.get(loc.file) ?? [];
      if (!list.includes(f.id)) list.push(f.id);
      byFile.set(loc.file, list);
    }
  }
  const themes: Array<{ match: RegExp; ids: string[] }> = [
    { match: /SEC-(XSS|MARKDOWN)|CSP/, ids: [] },
    { match: /TOKEN-WEBSTORAGE|JWT-CLIENT|CLIENT-SIDE-AUTHZ|CSP/, ids: [] },
    { match: /CI-|TEST-THINNESS|QUA-TEST/, ids: [] },
    { match: /DEP-|DOCKER-UNPINNED|CI-UNPINNED/, ids: [] },
  ];
  for (const f of findings) {
    for (const t of themes) if (t.match.test(f.ruleId ?? '')) t.ids.push(f.id);
  }
  for (const f of findings) {
    const related = new Set<string>();
    for (const loc of f.locations) {
      for (const id of byFile.get(loc.file) ?? []) if (id !== f.id) related.add(id);
    }
    for (const t of themes) {
      if (t.ids.includes(f.id)) for (const id of t.ids) if (id !== f.id) related.add(id);
    }
    f.dependenciesRelated = Array.from(related).sort().slice(0, 6);
  }
}

export function findingsDir(outDir: string): string {
  return join(outDir, 'findings');
}
