import { join } from 'node:path';
import { readTextSafe } from '../util/fsx.js';
import { tryParseYaml, type YamlValue } from '../util/yaml.js';
import type { CiResult, CollectorRun, WorkflowJobStep, WorkflowSummary } from '../types.js';

/**
 * CI collector. The question it answers is not "does a workflow exist" but
 * **does the gate actually gate** — i.e. is there a step that would fail the
 * build when tests, lint, types, dependency advisories, SAST or secret
 * scanning go wrong. `continue-on-error: true` and `|| true` are treated as
 * "not a gate", because they are not.
 */

const GATE_PATTERNS: Record<keyof WorkflowSummary['gates'], RegExp> = {
  test: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|\bvitest\b|\bjest\b|\bmocha\b|\bplaywright test\b|\bgo test\b|\bpytest\b|\bdotnet test\b|\bcargo test\b/,
  lint: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?lint\b|\beslint\b|\bbiome (?:check|lint)\b|\bruff\b|\bgolangci-lint\b|\bclippy\b|\bshellcheck\b|\bhadolint\b|\bactionlint\b|\byamllint\b|\bkubeconform\b|\bkube-linter\b/,
  typecheck: /\btsc\b|\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?typecheck\b|\bmypy\b|\bpyright\b/,
  audit: /\b(?:npm|pnpm|yarn)\s+audit\b|\bsnyk\b|\bosv-scanner\b|\btrivy\b|\bgrype\b|\bdependency-review-action\b|\bdependabot\b/,
  sast: /\bcodeql\b|\bsemgrep\b|\bsonar(?:cloud|qube)?\b|\bbandit\b(?!\s*-)|\bbrakeman\b|\bgosec\b|\bsentinel scan\b|\bsentinel-audit\b/i,
  secrets: /\bgitleaks\b|\btrufflehog\b|\bdetect-secrets\b|\bggshield\b/i,
};

const PINNED_SHA = /@[0-9a-f]{40}$/;

export interface CiOutput {
  ci: CiResult;
  run: CollectorRun;
}

export function collectCi(root: string, workflowPaths: string[]): CiOutput {
  const started = Date.now();
  const workflows: WorkflowSummary[] = [];
  const unpinnedActions: CiResult['unpinnedActions'] = [];
  const riskyTriggers: CiResult['riskyTriggers'] = [];
  const notExamined: string[] = [
    'branch-protection / required-status-check settings — those live in the GitHub API, not the repository',
    'self-hosted runner configuration and org-level reusable workflows',
  ];

  for (const rel of workflowPaths) {
    const text = readTextSafe(join(root, rel));
    if (text === null) continue;
    const summary = summariseWorkflow(rel, text);
    workflows.push(summary);

    // line-accurate extras straight from the text, so they survive a parse failure
    const lines = text.split('\n');
    for (const [i, line] of lines.entries()) {
      const usesMatch = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/.exec(line);
      if (usesMatch?.[1]) {
        const uses = usesMatch[1];
        const isLocal = uses.startsWith('./') || uses.startsWith('docker://');
        if (!isLocal && !PINNED_SHA.test(uses)) {
          unpinnedActions.push({ file: rel, uses, line: i + 1 });
        }
      }
      const triggerMatch = /^\s*(pull_request_target|workflow_run|issue_comment)\s*:/.exec(line);
      if (triggerMatch?.[1]) riskyTriggers.push({ file: rel, trigger: triggerMatch[1], line: i + 1 });
    }
  }

  return {
    ci: {
      workflows,
      hasRequiredStatusCheckHint: workflows.some((w) => w.triggers.includes('pull_request')),
      unpinnedActions,
      riskyTriggers,
    },
    run: {
      name: 'ci',
      ok: true,
      durationMs: Date.now() - started,
      note:
        workflows.length === 0
          ? 'no GitHub Actions workflows found'
          : `${workflows.length} workflow(s); gates present: ${describeGates(workflows)}`,
      notExamined,
    },
  };
}

function describeGates(workflows: WorkflowSummary[]): string {
  const union: WorkflowSummary['gates'] = { test: false, lint: false, typecheck: false, audit: false, sast: false, secrets: false };
  for (const w of workflows) {
    for (const k of Object.keys(union) as Array<keyof WorkflowSummary['gates']>) {
      if (w.gates[k]) union[k] = true;
    }
  }
  const on = Object.entries(union).filter(([, v]) => v).map(([k]) => k);
  return on.length > 0 ? on.join(', ') : 'none';
}

export function summariseWorkflow(file: string, text: string): WorkflowSummary {
  const parsed = tryParseYaml(text);
  const gates: WorkflowSummary['gates'] = { test: false, lint: false, typecheck: false, audit: false, sast: false, secrets: false };
  const jobs: WorkflowSummary['jobs'] = [];
  let name = file.split('/').pop() ?? file;
  let triggers: string[] = [];
  let permissions: string | null = null;

  const doc = parsed.value;
  if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
    const map = doc as Record<string, YamlValue>;
    if (typeof map.name === 'string') name = map.name;
    triggers = extractTriggers(map.on ?? map.true); // `on:` parses as boolean-true in YAML 1.1
    permissions = stringifyPermissions(map.permissions);
    const jobsMap = map.jobs;
    if (jobsMap && typeof jobsMap === 'object' && !Array.isArray(jobsMap)) {
      for (const [jobName, jobVal] of Object.entries(jobsMap as Record<string, YamlValue>)) {
        const steps: WorkflowJobStep[] = [];
        if (jobVal && typeof jobVal === 'object' && !Array.isArray(jobVal)) {
          const job = jobVal as Record<string, YamlValue>;
          const stepList = Array.isArray(job.steps) ? job.steps : [];
          // A `continue-on-error: true` step is not a gate on its own, but the
          // idiom "let the scan finish so its report uploads, then fail on its
          // recorded outcome" is: a later step tests `steps.<id>.outcome`
          // against `success`. The shipped workflow template is written that
          // way, and without this the tool told every repository using it that
          // its PR gate does not audit.
          const deferred = new Map<string, string>(); // step id -> haystack
          const reasserted = new Set<string>();
          for (const s of stepList) {
            if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
            const step = s as Record<string, YamlValue>;
            const runCmd = typeof step.run === 'string' ? step.run : undefined;
            const uses = typeof step.uses === 'string' ? step.uses : undefined;
            const softFail = step['continue-on-error'] === true;
            steps.push({
              name: typeof step.name === 'string' ? step.name : undefined,
              run: runCmd,
              uses,
              pinned: uses ? PINNED_SHA.test(uses) || uses.startsWith('./') : undefined,
            });
            // The action's `args` input is where `--offline` would go, so it is
            // part of what the step runs.
            const withMap = step.with && typeof step.with === 'object' && !Array.isArray(step.with) ? (step.with as Record<string, YamlValue>) : undefined;
            const actionArgs = uses && SENTINEL_ACTION.test(uses) && typeof withMap?.args === 'string' ? withMap.args : '';
            const haystack = `${runCmd ?? ''}\n${uses ?? ''}\n${actionArgs}`;
            if (!softFail && !isSoftFailed(runCmd)) markGates(haystack, gates);
            else if (softFail && typeof step.id === 'string') deferred.set(step.id, haystack);
            if (runCmd) {
              for (const m of runCmd.matchAll(OUTCOME_REASSERT)) reasserted.add((m[1] ?? m[2])!);
            }
          }
          for (const id of reasserted) {
            const haystack = deferred.get(id);
            if (haystack !== undefined) markGates(haystack, gates);
          }
        }
        jobs.push({ name: jobName, steps });
      }
    }
  }

  // Fallback: even if YAML parsing failed, grep the raw text so we never claim
  // "no gates" merely because our parser gave up. Parse failure is reported.
  if (parsed.error || jobs.length === 0) {
    for (const line of text.split('\n')) {
      if (/continue-on-error:\s*true/.test(line)) continue;
      if (isSoftFailed(line)) continue;
      markGates(line, gates);
    }
  }

  return {
    file,
    name,
    triggers,
    permissions,
    jobs,
    gates,
    parseError: parsed.error,
  };
}

/** `test "${{ steps.<id>.outcome }}" = "success"`, or the same in an expression. */
const OUTCOME_REASSERT = /steps\.([\w-]+)\.outcome\s*\}\}["']?\s*={1,3}\s*["']?success|steps\.([\w-]+)\.outcome\s*={2,3}\s*["']success/g;

/** `cmd || true`, `cmd || exit 0`, `set +e` defeat the gate. */
function isSoftFailed(cmd: string | undefined): boolean {
  if (!cmd) return false;
  return /\|\|\s*(true|exit\s+0|:)\b/.test(cmd) || /\bset\s+\+e\b/.test(cmd) || /--?no-fail|--exit-code[= ]0/.test(cmd);
}

/**
 * Sentinel's own scan, as the shipped workflow template invokes it (`npx
 * sentinel-audit scan`), as a global install does (`sentinel scan`), and as this
 * repository runs it from its build output (`node dist/cli.js scan`).
 */
const SENTINEL_SCAN = /(?:\bsentinel(?:-audit)?|(?:^|[\s/])dist\/cli\.js)\s+scan\b/m;

/** The GitHub Action (`uses: Burtson-Labs/sentinel-audit@<ref>`) runs the same scan. */
const SENTINEL_ACTION = /(?:^|\n)\s*burtson-labs\/sentinel-audit@/i;

function markGates(haystack: string, gates: WorkflowSummary['gates']): void {
  for (const key of Object.keys(GATE_PATTERNS) as Array<keyof WorkflowSummary['gates']>) {
    if (GATE_PATTERNS[key].test(haystack)) gates[key] = true;
  }
  // A Sentinel scan is static analysis, a dependency audit (advisories are
  // fetched unless `--offline`) and a secret scan that covers git history
  // itself — every historical blob not identical to a working-tree file is
  // checked with the precise provider patterns — so a repository that runs it
  // on pull requests has all three gates.
  if (SENTINEL_SCAN.test(haystack) || SENTINEL_ACTION.test(haystack)) {
    gates.sast = true;
    gates.secrets = true;
    if (!/--offline\b/.test(haystack)) gates.audit = true;
  }
}

function extractTriggers(on: YamlValue | undefined): string[] {
  if (on === undefined || on === null) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.filter((v): v is string => typeof v === 'string');
  if (typeof on === 'object') return Object.keys(on);
  return [];
}

function stringifyPermissions(p: YamlValue | undefined): string | null {
  if (p === undefined || p === null) return null;
  if (typeof p === 'string') return p;
  if (typeof p === 'object' && !Array.isArray(p)) {
    return Object.entries(p as Record<string, YamlValue>).map(([k, v]) => `${k}:${String(v)}`).join(' ');
  }
  return String(p);
}

/** True when at least one workflow would fail a PR on this signal. */
export function gateSatisfied(ci: CiResult, gate: keyof WorkflowSummary['gates'], onlyPrTriggers = true): boolean {
  return ci.workflows.some((w) => {
    if (!w.gates[gate]) return false;
    if (!onlyPrTriggers) return true;
    return w.triggers.some((t) => t === 'pull_request' || t === 'push' || t === 'merge_group');
  });
}
