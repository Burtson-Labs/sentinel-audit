import { join, resolve } from 'node:path';
import { readdirSync } from 'node:fs';
import { readJsonSafe, exists, writeFileEnsured } from '../util/fsx.js';
import { run, git, commandExists } from '../util/exec.js';
import { detectProvider, type LlmProvider } from '../llm/client.js';
import type { Finding } from '../types.js';

/**
 * Automated remediation.
 *
 * ## Trust model — read this before using `--apply` or `--pr`
 *
 * 1. **A human merges. Always.** Sentinel opens pull requests. It never pushes
 *    to the default branch, never merges, never force-pushes.
 * 2. **Tests are the gate.** A fix whose branch fails the repository's own test
 *    command is abandoned and reported as failed. If the repository has no test
 *    command, `--apply`/`--pr` refuse to run unless `--no-tests` is passed
 *    explicitly, and the PR body says the change was unverified.
 * 3. **One finding, one branch, one PR.** No batching, so a bad fix is one
 *    revert rather than an archaeology exercise.
 * 4. **Only findings whose fix plan is marked `agent-executable`.** That flag is
 *    set by the rule author or the fix-plan pass, and it is false by default for
 *    anything needing a policy decision, an allowlist, or a credential.
 * 5. **Refuted and triaged-out findings are never fixed.** There is nothing to
 *    fix, and acting on them would undo working protections.
 * 6. **A dirty working tree aborts the run.** Sentinel will not mix its changes
 *    with yours.
 * 7. **Dry run is the default.** With no `--apply`/`--pr`, nothing is written.
 */

export interface FixOptions {
  findingsDir: string;
  repo?: string;
  /** Commit the change on a branch, but do not push or open a PR. */
  apply?: boolean;
  /** Push the branch and open a pull request. Implies apply. */
  pr?: boolean;
  /** Glob-ish filter over finding ids, e.g. `SEC-*` or `SEC-001,QUA-003`. */
  only?: string;
  /** Proceed even though no test command was detected. */
  noTests?: boolean;
  /** Keep failed branches for inspection instead of deleting them. */
  keepFailed?: boolean;
  banditCli?: string;
  maxFixes?: number;
  branchPrefix?: string;
  onProgress?: (msg: string) => void;
}

export interface FixOutcome {
  id: string;
  title: string;
  branch: string | null;
  status: 'planned' | 'fixed' | 'tests-failed' | 'no-change' | 'agent-failed' | 'skipped' | 'pr-opened';
  detail: string;
  filesChanged: string[];
  testCommand: string | null;
  testPassed: boolean | null;
  prUrl?: string;
  agentDurationMs?: number;
}

export interface FixReport {
  repo: string;
  dryRun: boolean;
  provider: string;
  outcomes: FixOutcome[];
  startedAt: string;
  finishedAt: string;
}

export async function fix(options: FixOptions): Promise<FixReport> {
  const progress = options.onProgress ?? ((): void => {});
  const startedAt = new Date().toISOString();
  const findingsDir = resolve(options.findingsDir);
  const findings = loadFindings(findingsDir);
  if (findings.length === 0) throw new Error(`no findings found in ${findingsDir} (expected <ID>.json files)`);

  const repo = resolve(options.repo ?? inferRepo() ?? process.cwd());
  const dryRun = !options.apply && !options.pr;
  const provider = detectProvider({ banditCli: options.banditCli });
  const outcomes: FixOutcome[] = [];

  const selected = findings
    .filter((f) => matchesFilter(f.id, options.only))
    .filter((f) => {
      if (f.status === 'refuted') {
        outcomes.push(skip(f, 'the finding was refuted by verification — there is nothing to fix'));
        return false;
      }
      if (f.status === 'triaged-out') {
        outcomes.push(skip(f, 'the finding was triaged out as noise'));
        return false;
      }
      if (!f.fixPlan.agentExecutable) {
        outcomes.push(skip(f, `fix plan is not agent-executable: ${f.fixPlan.notAgentExecutableReason ?? 'no reason recorded'}`));
        return false;
      }
      if (!f.fixPlan.agentPrompt) {
        outcomes.push(skip(f, 'fix plan is marked agent-executable but carries no agent prompt — refusing to improvise one'));
        return false;
      }
      return true;
    })
    .slice(0, options.maxFixes ?? 10);

  const testCommand = detectTestCommand(repo);
  if (!dryRun && !testCommand && !options.noTests) {
    throw new Error(
      'no test command was detected in the repository (looked for a `test` script in package.json). Fixes are only applied when a test run can catch a regression — pass --no-tests to override, and expect the pull request to say the change is unverified.',
    );
  }

  if (!dryRun) {
    assertCleanTree(repo);
    if (!provider.available) {
      throw new Error(`no coding agent is available to implement fixes: ${provider.note}`);
    }
    if (options.pr && !commandExists('gh')) {
      throw new Error('--pr needs the GitHub CLI (`gh`) on PATH and authenticated');
    }
  }

  const baseBranch = currentBranch(repo);
  const prefix = options.branchPrefix ?? 'sentinel/fix';

  for (const f of selected) {
    if (dryRun) {
      outcomes.push({
        id: f.id,
        title: f.title,
        branch: `${prefix}-${f.id.toLowerCase()}`,
        status: 'planned',
        detail: `would implement on its own branch, run \`${testCommand ?? 'no test command'}\`, and ${options.pr ? 'open a pull request' : 'leave the commit on the branch'}. Agent instruction: ${truncate(f.fixPlan.agentPrompt ?? '', 400)}`,
        filesChanged: f.fixPlan.files.map((x) => x.path),
        testCommand,
        testPassed: null,
      });
      continue;
    }
    progress(`fixing ${f.id}…`);
    outcomes.push(await applyOne(f, { repo, provider, testCommand, baseBranch, prefix, options, progress }));
  }

  const report: FixReport = {
    repo,
    dryRun,
    provider: provider.label,
    outcomes,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
  writeFileEnsured(join(findingsDir, '..', 'fix-report.json'), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

async function applyOne(
  f: Finding,
  args: {
    repo: string;
    provider: LlmProvider;
    testCommand: string | null;
    baseBranch: string;
    prefix: string;
    options: FixOptions;
    progress: (m: string) => void;
  },
): Promise<FixOutcome> {
  const { repo, provider, testCommand, baseBranch, prefix, options, progress } = args;
  const branch = `${prefix}-${f.id.toLowerCase()}`;

  // Never work on the default branch: always a fresh branch off the current one.
  const created = git(repo, ['checkout', '-b', branch]);
  if (!created.ok) {
    return {
      id: f.id,
      title: f.title,
      branch,
      status: 'agent-failed',
      detail: `could not create branch ${branch}: ${firstLine(created.stderr)}`,
      filesChanged: [],
      testCommand,
      testPassed: null,
    };
  }

  const cleanup = (keep: boolean): void => {
    git(repo, ['reset', '--hard']);
    git(repo, ['clean', '-fd']);
    git(repo, ['checkout', baseBranch]);
    if (!keep) git(repo, ['branch', '-D', branch]);
  };

  const prompt = buildAgentPrompt(f, testCommand);
  const started = Date.now();
  const res = await provider.complete(prompt, { timeoutMs: 900_000 });
  const agentDurationMs = Date.now() - started;
  if (!res.ok) {
    cleanup(Boolean(options.keepFailed));
    return {
      id: f.id,
      title: f.title,
      branch,
      status: 'agent-failed',
      detail: `the coding agent produced no output: ${res.error ?? 'unknown'}`,
      filesChanged: [],
      testCommand,
      testPassed: null,
      agentDurationMs,
    };
  }

  const changed = changedFiles(repo);
  if (changed.length === 0) {
    cleanup(false);
    return {
      id: f.id,
      title: f.title,
      branch: null,
      status: 'no-change',
      detail: 'the agent ran but left the working tree unchanged — reported rather than presented as a fix',
      filesChanged: [],
      testCommand,
      testPassed: null,
      agentDurationMs,
    };
  }

  let testPassed: boolean | null = null;
  if (testCommand) {
    progress(`  running ${testCommand}…`);
    const [cmd, ...cmdArgs] = testCommand.split(' ');
    const test = run(cmd!, cmdArgs, { cwd: repo, timeoutMs: 900_000 });
    testPassed = test.ok;
    if (!test.ok) {
      const detail = `tests failed after the change (\`${testCommand}\`, exit ${test.code}): ${truncate(firstLine(test.stdout) || firstLine(test.stderr), 300)}`;
      cleanup(Boolean(options.keepFailed));
      return {
        id: f.id,
        title: f.title,
        branch: options.keepFailed ? branch : null,
        status: 'tests-failed',
        detail: `${detail}. The fix was abandoned${options.keepFailed ? ` (branch ${branch} kept for inspection)` : ''} rather than opening a pull request that breaks the build.`,
        filesChanged: changed,
        testCommand,
        testPassed: false,
        agentDurationMs,
      };
    }
  }

  git(repo, ['add', '-A']);
  const commitMessage = [
    `fix(${f.id.toLowerCase()}): ${truncate(f.title, 68)}`,
    '',
    `Addresses ${f.id} (${f.severity}, ${f.status}) reported by sentinel-audit.`,
    '',
    `Strategy: ${truncate(f.fixPlan.strategy, 300)}`,
    '',
    testPassed === null
      ? 'No test command was available, so this change is UNVERIFIED. Review carefully.'
      : `Verified by: ${testCommand}`,
  ].join('\n');
  const commit = run('git', ['-C', repo, 'commit', '-m', commitMessage], { timeoutMs: 60_000 });
  if (!commit.ok) {
    cleanup(Boolean(options.keepFailed));
    return {
      id: f.id,
      title: f.title,
      branch,
      status: 'agent-failed',
      detail: `commit failed: ${firstLine(commit.stderr)}`,
      filesChanged: changed,
      testCommand,
      testPassed,
      agentDurationMs,
    };
  }

  if (!options.pr) {
    git(repo, ['checkout', baseBranch]);
    return {
      id: f.id,
      title: f.title,
      branch,
      status: 'fixed',
      detail: `committed on ${branch}${testPassed === null ? ' (unverified — no test command)' : ' with tests passing'}. Not pushed. Review with \`git diff ${baseBranch}..${branch}\`.`,
      filesChanged: changed,
      testCommand,
      testPassed,
      agentDurationMs,
    };
  }

  const push = run('git', ['-C', repo, 'push', '-u', 'origin', branch], { timeoutMs: 180_000 });
  if (!push.ok) {
    git(repo, ['checkout', baseBranch]);
    return {
      id: f.id,
      title: f.title,
      branch,
      status: 'fixed',
      detail: `committed on ${branch} but push failed: ${firstLine(push.stderr)}. The branch exists locally.`,
      filesChanged: changed,
      testCommand,
      testPassed,
      agentDurationMs,
    };
  }

  const body = prBody(f, testCommand, testPassed, changed);
  const pr = run(
    'gh',
    ['pr', 'create', '--repo', repoSlug(repo) ?? '', '--base', baseBranch, '--head', branch, '--title', `fix(${f.id.toLowerCase()}): ${truncate(f.title, 68)}`, '--body', body],
    { cwd: repo, timeoutMs: 180_000 },
  );
  git(repo, ['checkout', baseBranch]);
  const url = /https:\/\/\S+/.exec(pr.stdout)?.[0];
  return {
    id: f.id,
    title: f.title,
    branch,
    status: pr.ok ? 'pr-opened' : 'fixed',
    detail: pr.ok ? `pull request opened for human review: ${url ?? 'url not captured'}` : `pushed ${branch} but \`gh pr create\` failed: ${firstLine(pr.stderr)}`,
    filesChanged: changed,
    testCommand,
    testPassed,
    prUrl: url,
    agentDurationMs,
  };
}

function buildAgentPrompt(f: Finding, testCommand: string | null): string {
  return `Implement one specific fix in this repository. Do not do anything else.

FINDING ${f.id} (${f.severity}) — ${f.title}

Evidence:
${f.evidence}

Why it matters:
${f.whyThisMatters}

What to do:
${f.fixPlan.agentPrompt}

Files expected to change:
${f.fixPlan.files.map((x) => `- ${x.path}: ${x.change}`).join('\n')}

Tests to add:
${f.fixPlan.acceptanceTests.map((t) => `- ${t.path}: ${t.description}`).join('\n')}

Hard constraints:
- Change only what this fix requires. No reformatting, no renaming, no refactoring of unrelated code, no dependency additions unless the instruction names one.
- Do not modify CI configuration, lockfiles, or version numbers.
- Do not create documentation or summary files.
- Preserve the existing code style exactly.
${testCommand ? `- The change must pass \`${testCommand}\`. It will be run, and the fix is discarded if it fails.` : '- No test command is configured, so be conservative: prefer the smallest change that closes the finding.'}
- If you conclude the fix cannot be made safely without a decision you do not have, make no changes and say so.`;
}

function prBody(f: Finding, testCommand: string | null, testPassed: boolean | null, changed: string[]): string {
  return `## What

Fixes **${f.id}** — ${f.title}

Reported by [sentinel-audit](https://github.com/Burtson-Labs/sentinel-audit) with status \`${f.status}\` and severity \`${f.severity}\`.

## Evidence from the audit

${f.evidence}

## Why this matters

${f.whyThisMatters}

## Verification

- **Finding verification method:** \`${f.verification.method}\` (${f.verification.claimType} claim, result \`${f.verification.result}\`)
${f.verification.proof ? `- **Proof:** \`${f.verification.proof.command}\` → \`${f.verification.proof.verdict}\`` : ''}
- **Tests after the change:** ${testPassed === null ? '**not run — no test command was configured. This change is UNVERIFIED.**' : testPassed ? `\`${testCommand}\` passed` : `\`${testCommand}\` FAILED`}

## Files changed

${changed.map((c) => `- \`${c}\``).join('\n')}

## Acceptance criteria from the finding

${f.acceptanceCriteria.map((a) => `- [ ] ${a}`).join('\n')}

---

This pull request was authored by an automated agent and **requires human review before merge**. Sentinel never merges, never pushes to the default branch, and abandons any fix whose tests fail.`;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

export function loadFindings(dir: string): Finding[] {
  if (!exists(dir)) return [];
  const out: Finding[] = [];
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  for (const entry of entries) {
    if (!entry.endsWith('.json') || entry === 'index.json') continue;
    const doc = readJsonSafe<Finding>(join(dir, entry));
    if (doc?.id) out.push(doc);
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** `SEC-*`, `SEC-001`, `SEC-001,QUA-002` — simple and predictable. */
export function matchesFilter(id: string, only: string | undefined): boolean {
  if (!only) return true;
  return only.split(',').some((token) => {
    const t = token.trim();
    if (t.length === 0) return false;
    if (t.endsWith('*')) return id.toUpperCase().startsWith(t.slice(0, -1).toUpperCase());
    return id.toUpperCase() === t.toUpperCase();
  });
}

/**
 * Findings record a repository *URL*, not a local path, so there is nothing
 * reliable to infer. Returning null makes `--repo` (or the current directory)
 * the only source of truth, which is the behaviour you want from a tool that
 * writes branches.
 */
function inferRepo(): string | null {
  return null;
}

export function detectTestCommand(repo: string): string | null {
  const pkg = readJsonSafe<{ scripts?: Record<string, string>; packageManager?: string }>(join(repo, 'package.json'));
  if (!pkg?.scripts?.test) return null;
  const pm = pkg.packageManager?.split('@')[0] ?? (exists(join(repo, 'pnpm-lock.yaml')) ? 'pnpm' : exists(join(repo, 'yarn.lock')) ? 'yarn' : 'npm');
  return pm === 'npm' ? 'npm test' : `${pm} test`;
}

function assertCleanTree(repo: string): void {
  const status = git(repo, ['status', '--porcelain']);
  if (!status.ok) throw new Error(`${repo} is not a git work tree, so fixes cannot be isolated on a branch`);
  if (status.stdout.trim().length > 0) {
    throw new Error(
      `the working tree at ${repo} has uncommitted changes. Sentinel refuses to mix its edits with yours — commit or stash first.`,
    );
  }
}

function currentBranch(repo: string): string {
  const res = git(repo, ['rev-parse', '--abbrev-ref', 'HEAD']);
  return res.ok ? res.stdout.trim() : 'main';
}

function changedFiles(repo: string): string[] {
  const res = git(repo, ['status', '--porcelain']);
  if (!res.ok) return [];
  return res.stdout
    .split('\n')
    .map((l) => l.slice(3).trim())
    .filter((l) => l.length > 0);
}

function repoSlug(repo: string): string | null {
  const res = git(repo, ['remote', 'get-url', 'origin']);
  if (!res.ok) return null;
  const m = /github\.com[:/]([^/]+\/[^/.]+)/.exec(res.stdout.trim());
  return m?.[1] ?? null;
}

function skip(f: Finding, detail: string): FixOutcome {
  return { id: f.id, title: f.title, branch: null, status: 'skipped', detail, filesChanged: [], testCommand: null, testPassed: null };
}

function firstLine(s: string): string {
  return s.split('\n').find((l) => l.trim().length > 0)?.trim() ?? '';
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}
