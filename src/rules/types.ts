import type { ClaimType, Effort, FindingType, RuleHit, Severity } from '../types.js';
export type { Severity };
import type { MaskedSource } from '../util/lex.js';
import type { RepoFile } from '../util/fsx.js';

export interface RuleFileContext {
  file: RepoFile;
  /** Original text. */
  src: string;
  /** Comments and string bodies blanked — match against this. */
  masked: MaskedSource;
  /** Is this a test/spec file? Most security rules downgrade or skip these. */
  isTest: boolean;
  /** Repo root absolute path. */
  root: string;
}

export interface RuleRepoContext {
  root: string;
  files: RepoFile[];
  /** Only text files that were read, keyed by repo-relative path. */
  texts: Map<string, string>;
  masked: Map<string, MaskedSource>;
  isTest: (p: string) => boolean;
}

export interface RuleFixPlanSeed {
  agentExecutable: boolean;
  strategy: string;
  /** Change shape per file; `{file}` is substituted with the first hit path. */
  changes: Array<{ path: string; change: string }>;
  acceptanceTests: Array<{ path: string; description: string }>;
  risk: 'low' | 'medium' | 'high';
  estimatedDiffSize: string;
  agentPrompt?: string;
  notAgentExecutableReason?: string;
}

export interface Rule {
  id: string;
  title: string;
  type: FindingType;
  severity: Severity;
  area: string;
  labels: string[];
  why: string;
  recommendation: string;
  acceptance: string[];
  effort: Effort;
  /**
   * `behavioral` rules assert that some input causes unsafe behavior — they can
   * only reach `confirmed` via an executed proof. `factual` rules assert the
   * code contains (or lacks) something, which a re-check can confirm outright.
   */
  claimType: ClaimType;
  /** Per-file matcher. */
  scan?: (ctx: RuleFileContext) => RuleHit[];
  /** Whole-repo matcher, for density/aggregate rules. */
  aggregate?: (ctx: RuleRepoContext) => RuleHit[];
  /** File filter for `scan`. */
  appliesTo?: (file: RepoFile) => boolean;
  /** Cap how many hits become evidence in one finding. */
  maxEvidence?: number;
  /**
   * Adjust the severity from what the hits actually look like. A rule's headline
   * severity describes its worst case; this is how it reports the case in front
   * of it. Without this, "exec() with a constant command" and "exec() with an
   * interpolated branch name" arrive at the same severity, and the reader stops
   * believing the column.
   */
  severityFor?: (hits: RuleHit[]) => Severity;
  fixPlan: (hits: RuleHit[], ctx: RuleRepoContext) => RuleFixPlanSeed;
}

export function hit(
  ruleId: string,
  file: string,
  line: number,
  excerptText: string,
  message: string,
  meta?: Record<string, string | number | boolean>,
  endLine?: number,
): RuleHit {
  return { ruleId, file, line, excerpt: excerptText, message, meta, endLine };
}

export const JS_TS = (f: RepoFile): boolean =>
  ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'].includes(f.ext);
