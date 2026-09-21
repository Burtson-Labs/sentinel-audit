/**
 * Sentinel finding schema.
 *
 * Design constraint: this is a *superset* of the common consultant-style
 * "review finding" record (id / title / type / severity / suggestedLabels /
 * affectedArea / evidence / whyThisMatters / recommendation /
 * acceptanceCriteria / effortEstimate / dependenciesRelated / provenance), so a
 * consumer written against that shape can read Sentinel output unchanged.
 *
 * Everything Sentinel adds is additive and optional from a consumer's point of
 * view: `verification`, `fixPlan`, `standards`, `locations`, `triage`,
 * `fingerprint`.
 */

export const SEVERITIES = ['Blocker', 'High', 'Medium', 'Low', 'Info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_TYPES = [
  'Security',
  'Supply Chain',
  'Secret',
  'Tech Debt',
  'Quality',
  'CI-CD',
  'Compliance',
  'Architecture',
  'Testing',
] as const;
export type FindingType = (typeof FINDING_TYPES)[number];

export const EFFORTS = ['S', 'M', 'L', 'XL'] as const;
export type Effort = (typeof EFFORTS)[number];

/**
 * The headline field, and the one most likely to be over-read.
 *
 * There are two ways a check can agree with a claim, and they are not worth the
 * same thing, so they do not share a label:
 *
 *  - `proof-confirmed`   — a generated script exercised the real code and
 *                          returned a `vulnerable` verdict. The strong claim.
 *  - `pattern-confirmed` — a static/lexical assertion was re-established from
 *                          disk: the construct *is* at that line, the policy
 *                          *is* absent, the vulnerable version *is* installed.
 *                          The pattern exists; exploitability is unproven.
 *
 * `refuted` findings are kept in the report on purpose.
 *
 * Schema note (0.2.0): these two values replace the single `confirmed` value.
 * `verification.class` carries the older coarse vocabulary for consumers written
 * against it — see `FindingStatusClass`.
 */
export const STATUSES = ['proof-confirmed', 'pattern-confirmed', 'plausible', 'refuted', 'triaged-out'] as const;
export type FindingStatus = (typeof STATUSES)[number];

/**
 * The coarser vocabulary: what `status` used to say. Emitted alongside the
 * precise state as `verification.class` so a consumer that only wants
 * "confirmed vs not" does not have to learn the split, and one written before
 * the split keeps working.
 */
export const STATUS_CLASSES = ['confirmed', 'plausible', 'refuted', 'triaged-out'] as const;
export type FindingStatusClass = (typeof STATUS_CLASSES)[number];

/**
 * What kind of claim the finding makes — this governs what "confirmed" is
 * allowed to mean:
 *  - `factual`    — a claim about what the code does or does not contain.
 *                   An executed re-check of the repository can confirm this
 *                   outright.
 *  - `behavioral` — a claim that some input produces some unsafe behavior.
 *                   Only an executed proof that exercises the real code may
 *                   confirm this; code-reading alone caps the finding at
 *                   `plausible`.
 */
export type ClaimType = 'factual' | 'behavioral';

export type VerificationMethod =
  | 'proof-executed' // a generated script exercised the real code
  | 'static-assertion' // an executed re-check of file contents / absence
  | 'tool-output' // a third-party scanner reported it (npm audit, gitleaks…)
  | 'code-read' // a human/LLM read the code and reasoned
  | 'not-attempted';

export interface ProofRun {
  /** Path to the generated proof script, relative to the output directory. */
  path: string;
  /** Exact command executed. */
  command: string;
  exitCode: number | null;
  durationMs: number;
  /** What the proof was expected to show if the finding is real. */
  predicted: string;
  /** What it actually showed. */
  observed: string;
  /** Machine verdict parsed from the proof's JSON line. */
  verdict: 'vulnerable' | 'safe' | 'inconclusive' | 'error';
  stdoutExcerpt: string;
  stderrExcerpt: string;
}

export interface VerificationCheck {
  description: string;
  outcome: 'pass' | 'fail' | 'skip';
  /** file:line or a short factual statement. Never prose-only. */
  detail: string;
}

export interface Verification {
  method: VerificationMethod;
  claimType: ClaimType;
  /** Did we actually run something, or is this reasoning only? */
  performed: boolean;
  /**
   * What the verifier concluded, independently of triage. Unchanged meaning
   * since 0.1.0 — `confirmed` here says "the check agreed", and the strength of
   * that agreement is read off `method`/`state`.
   */
  result: 'confirmed' | 'plausible' | 'refuted' | 'inconclusive';
  /**
   * The finding's precise status, mirrored here so the verification block can be
   * consumed on its own. Always equal to `Finding.status`.
   */
  state: FindingStatus;
  /** Coarse status for consumers written against the pre-0.2.0 vocabulary. */
  class: FindingStatusClass;
  /** Individual executed checks, each with file:line grade evidence. */
  checks: VerificationCheck[];
  /** Present when a runnable proof was generated and executed. */
  proof?: ProofRun;
  /** Why this verification result and not a stronger one. */
  notes: string;
}

/**
 * What a verifier produces. It deliberately cannot set `state`/`class`: those
 * depend on triage decisions made after verification, and are stamped in one
 * place (`analyze()`) so the two fields can never disagree with `status`.
 */
export type VerificationEvidence = Omit<Verification, 'state' | 'class'>;

export interface CodeLocation {
  /** Repo-relative POSIX path. */
  file: string;
  startLine: number;
  endLine?: number;
  /** Short excerpt (<=200 chars), redacted for secret findings. */
  excerpt?: string;
}

export interface StandardControl {
  id: string;
  title: string;
  url?: string;
}

export interface StandardsMapping {
  /** Profile id the mapping came from, e.g. `owasp-asvs`. */
  profile: string;
  controls: StandardControl[];
  cwe: string[];
  owasp: string[];
}

export interface FixPlanFile {
  path: string;
  /** The change *shape* — what to do, not a literal patch. */
  change: string;
}

export interface FixPlanTest {
  path: string;
  description: string;
}

export interface FixPlan {
  /**
   * True only when the change is mechanical enough for an agent to attempt
   * unsupervised *and* the repository has a test command that would catch a
   * regression. Human review of the PR is always still required.
   */
  agentExecutable: boolean;
  /** One-paragraph statement of the remediation approach. */
  strategy: string;
  files: FixPlanFile[];
  acceptanceTests: FixPlanTest[];
  risk: 'low' | 'medium' | 'high';
  estimatedDiffSize: string;
  /** Instruction handed to the coding agent by `sentinel fix`. */
  agentPrompt?: string;
  /** Why the fix is not agent-executable, when it is not. */
  notAgentExecutableReason?: string;
}

export interface Triage {
  suppressed: boolean;
  /** Required. A suppression without a reason is a bug. */
  reason: string;
  /** Required: file:line (or tool field) that justifies the dismissal. */
  evidenceCited: string;
  by: 'rule' | 'heuristic' | 'llm';
}

export interface Provenance {
  repoUrl: string;
  branch: string;
  commitSha: string;
  reviewDate: string;
  /** Sentinel version + profile + whether the LLM pass ran. */
  tool: string;
  toolVersion: string;
  profile: string;
  llmPass: 'ran' | 'unavailable' | 'disabled';
}

export interface Finding {
  // ---- consultant-schema compatible surface -------------------------------
  id: string;
  title: string;
  type: FindingType;
  severity: Severity;
  suggestedLabels: string[];
  affectedArea: string;
  evidence: string;
  whyThisMatters: string;
  recommendation: string;
  acceptanceCriteria: string[];
  effortEstimate: Effort;
  dependenciesRelated: string[];
  provenance: Provenance;
  /** Generic replacement for a private per-company catalogue mapping. */
  standardMapping: string;

  // ---- sentinel additions ------------------------------------------------
  status: FindingStatus;
  verification: Verification;
  locations: CodeLocation[];
  standards: StandardsMapping;
  fixPlan: FixPlan;
  /** Which layer produced the finding. */
  source: 'collector' | 'rule' | 'scanner' | 'llm';
  ruleId?: string;
  /** 0..1. Calibrated from `verification`, not vibes. See scoreConfidence(). */
  confidence: number;
  /** Stable across runs — id/ordering may move, this should not. */
  fingerprint: string;
  triage?: Triage;
  /** Free-form extra context for report rendering. */
  notes?: string[];
}

// ---------------------------------------------------------------------------
// Scan-level records
// ---------------------------------------------------------------------------

export interface LanguageStat {
  language: string;
  files: number;
  loc: number;
}

export interface ReconResult {
  root: string;
  repoUrl: string;
  branch: string;
  commitSha: string;
  commitDate: string;
  packageManager: string;
  languages: LanguageStat[];
  totalFiles: number;
  totalLoc: number;
  frameworks: string[];
  entrypoints: string[];
  sourceFileCount: number;
  testFileCount: number;
  testToSourceRatio: number;
  largestFiles: Array<{ file: string; loc: number }>;
  scripts: Record<string, string>;
  hasTypeScript: boolean;
  tsStrict: boolean | null;
  workflows: string[];
  dockerfiles: string[];
  /** Directories that were skipped (node_modules, dist, …). */
  excluded: string[];
}

export interface DependencyRecord {
  name: string;
  version: string;
  dev: boolean;
  license: string | null;
  direct: boolean;
}

export interface AdvisoryRecord {
  module: string;
  severity: 'critical' | 'high' | 'moderate' | 'low' | 'info';
  title: string;
  url?: string;
  vulnerableVersions?: string;
  patchedIn?: string | null;
  cwe?: string[];
  cve?: string[];
  /** `direct` when the repo depends on it directly. */
  path: 'direct' | 'transitive' | 'unknown';
  isDev: boolean;
}

export interface DependencyResult {
  manager: string;
  lockfiles: string[];
  total: number;
  direct: number;
  dev: number;
  advisories: AdvisoryRecord[];
  auditAvailable: boolean;
  auditCommand: string | null;
  auditError?: string;
  dependencies: DependencyRecord[];
  licenseSummary: Record<string, number>;
  unknownLicenseCount: number;
}

export interface SecretCandidate {
  file: string;
  line: number;
  ruleId: string;
  description: string;
  /** Always masked — never the raw secret. */
  masked: string;
  entropy: number;
  /** Heuristic pre-triage; the LLM pass can override with cited evidence. */
  likelyFalsePositive: boolean;
  falsePositiveReason?: string;
  inGitignoredPath: boolean;
  isExampleFile: boolean;
  /**
   * Does the match live in a test, spec, fixture or mock path? A credential
   * there is reported, but at Info — it is usually scaffolding, and reporting it
   * at High is how a secret section loses its reader.
   */
  inTestPath: boolean;
  /** Set for a match found in git history: the blob it was read from (short id). */
  blob?: string;
  /** The first commit that introduced that blob, when it could be found (short id). */
  commit?: string;
}

/**
 * One result relayed from another scanner, after Sentinel's own triage.
 *
 * Relaying a count with no triage is how one report said the same fixture was
 * Info in one finding and High in another. The detection still belongs to the
 * other tool — Sentinel does not re-derive it — but the *severity* has to go
 * through the same path-awareness and placeholder rules as everything else, or
 * the report contradicts itself.
 */
export interface ExternalScannerHit {
  file: string;
  line: number;
  /** The other scanner's rule id, prefixed with its name. */
  ruleId: string;
  description: string;
  /** Always masked — never the raw secret. */
  masked: string;
  entropy: number;
  /** Set when the hit came from git history rather than the working tree. */
  commit?: string;
  inTestPath: boolean;
  likelyFalsePositive: boolean;
  falsePositiveReason: string;
}

export interface SecretResult {
  candidates: SecretCandidate[];
  filesScanned: number;
  externalScanner: {
    name: string;
    available: boolean;
    findings: number;
    note: string;
    /**
     * The individual results, triaged. Absent when no scanner ran; empty with
     * `hitsParsed: false` when the output could not be parsed, in which case the
     * count is reported untriaged rather than silently downgraded.
     */
    hits?: ExternalScannerHit[];
    hitsParsed?: boolean;
  };
  /**
   * Sentinel's own pass over git history: every blob reachable from any ref that
   * is not byte-identical to a file in the working tree, checked with the precise
   * provider patterns. Absent when the tree is not a git repository or a
   * history-aware external scanner already covered it.
   */
  history?: SecretHistoryScan;
}

export interface SecretHistoryScan {
  blobsExamined: number;
  /** Blobs past the size, count or time budget; the coverage report says so. */
  blobsSkipped: number;
  capped: boolean;
  hits: SecretCandidate[];
  note: string;
}

export interface WorkflowJobStep {
  name?: string;
  uses?: string;
  run?: string;
  pinned?: boolean;
}

export interface WorkflowSummary {
  file: string;
  name: string;
  triggers: string[];
  permissions: string | null;
  jobs: Array<{ name: string; steps: WorkflowJobStep[] }>;
  /** Does any step actually *fail the build* on a quality/security signal? */
  gates: { test: boolean; lint: boolean; typecheck: boolean; audit: boolean; sast: boolean; secrets: boolean };
  parseError?: string;
}

export interface CiResult {
  workflows: WorkflowSummary[];
  hasRequiredStatusCheckHint: boolean;
  unpinnedActions: Array<{ file: string; uses: string; line: number }>;
  riskyTriggers: Array<{ file: string; trigger: string; line: number }>;
}

export interface DockerResult {
  files: Array<{
    file: string;
    baseImages: Array<{ image: string; pinned: boolean; line: number }>;
    runsAsRoot: boolean;
    userLine: number | null;
    secretsInArgs: Array<{ line: number; name: string }>;
    healthcheck: boolean;
    addUsed: Array<{ line: number }>;
  }>;
}

export interface RuleHit {
  ruleId: string;
  file: string;
  line: number;
  endLine?: number;
  excerpt: string;
  /** Per-hit message, used to build the finding evidence string. */
  message: string;
  /** Rule-provided extra data for proof generation. */
  meta?: Record<string, string | number | boolean>;
}

export interface CollectorRun {
  name: string;
  ok: boolean;
  durationMs: number;
  note: string;
  /** Explicit coverage statement — what this collector did NOT look at. */
  notExamined: string[];
}

export interface ScanContext {
  root: string;
  outDir: string;
  profileId: string;
  recon: ReconResult;
  deps: DependencyResult;
  secrets: SecretResult;
  ci: CiResult;
  docker: DockerResult;
  hits: RuleHit[];
  runs: CollectorRun[];
  llm: { provider: string; available: boolean; note: string; calls: number; failures: number };
  startedAt: string;
  finishedAt?: string;
}

export interface ConfidenceAssessment {
  overallScore: number;
  band: string;
  securityPostureScore: number;
  productionReadiness: string;
  whyNotLower: string[];
  whyNotHigher: string[];
  gateDecision: 'pass' | 'pass-with-conditions' | 'block';
  gateReason: string;
  riskMatrix: Array<{
    id: string;
    risk: string;
    likelihood: 'Low' | 'Medium' | 'High';
    impact: 'Low' | 'Medium' | 'High' | 'Critical';
    level: string;
  }>;
  signals: Array<{ signal: string; interpretation: string }>;
  /** How much of the score rests on verified vs asserted findings. */
  evidenceQuality: {
    /** An executed proof demonstrated the behaviour. */
    proofConfirmed: number;
    /** A static/lexical assertion re-matched. The pattern exists; nothing more. */
    patternConfirmed: number;
    /** Coarse sum of the two above, for continuity with the older vocabulary. */
    confirmed: number;
    plausible: number;
    refuted: number;
    triagedOut: number;
    /** Share of live findings in either confirmed state. */
    verifiedShare: number;
    /** Share of live findings an executed proof demonstrated. The strong number. */
    provenShare: number;
  };
  remediationPhases: Array<{ phase: string; items: string[]; estimate: string }>;
  bottomLine: string[];
}
