#!/usr/bin/env node
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { scan, TOOL_VERSION, type OutputFormat } from './scan.js';
import { fix } from './fix/index.js';
import { listProfiles, loadProfile } from './profile.js';
import { ALL_RULES } from './rules/index.js';
import { isProofSandboxMode, PROOF_SANDBOX_MODES } from './verify/sandbox.js';
import { isProviderChoice, PROVIDER_CHOICES } from './llm/client.js';
import { exists, writeFileEnsured } from './util/fsx.js';

/**
 * CLI. Hand-rolled argument parsing on purpose: a tool whose pitch is "your
 * supply chain is the attack surface" should not pull in a dependency tree to
 * read `--out`.
 */

const USAGE = `sentinel-audit ${TOOL_VERSION} — verified repository audit (security, quality, supply chain)

USAGE
  sentinel scan <repo> [options]
  sentinel fix <findings-dir> [options]
  sentinel rules [--json]
  sentinel profiles
  sentinel init-workflow [--out <path>]

SCAN OPTIONS
  --profile <id|path>     standards profile: ${listProfiles().join(' | ')} or a path to a profile JSON
                          (default: owasp-asvs)
  --out <dir>             output directory (default: ./sentinel-results/<repo-name>)
  --format <list>         comma-separated: md,html,json,sarif (default: md,html,json,sarif)
  --no-llm                skip the model-assisted pass (deterministic only)
  --no-proofs             skip generating and executing proof scripts
  --proof-sandbox <mode>  where proofs run: auto | container | host | off (default: auto).
                          Proofs execute the audited repository's code. auto and container
                          use docker/podman with no network, a read-only filesystem, no
                          capabilities and an empty environment, and skip proofs when no
                          runtime answers. host runs them as you, env scrubbed; opt-in only.
  --proof-image <image>   container image for proofs, Node 22.18+ (default: node:24-alpine)
  --offline               skip anything needing network access (dependency advisories) and keep
                          the model pass on this machine or network: hosted APIs are refused,
                          and without --provider there is no model pass
  --provider <name>       model for the review pass: auto | bandit | anthropic | openai | ollama
                          (default: auto). ollama uses OLLAMA_HOST (default 127.0.0.1:11434)
  --model <id>            model id for --provider (ollama default: first installed model)
  --no-external-scanners  do not run gitleaks/trufflehog even if installed; Sentinel scans git history itself
  --bandit-cli <path>     path to the Bandit CLI entrypoint used as the coding/review agent
  --max-review-files <n>  how many files the model review pass may read (default: 4)
  --llm-timeout <ms>      per-call budget for the model pass (default: 300000). Scan wall
                          time is dominated by this times the number of calls, and a local
                          model can be an order of magnitude slower than a hosted one.
  --quiet                 only print the summary

  Exit code: 0 clean · 1 findings at or above the conditional threshold · 2 gate blocked.

FIX OPTIONS
  --repo <dir>            repository to modify (default: current directory)
  --only <filter>         finding ids or prefixes, e.g. "SEC-*" or "SEC-001,QUA-003"
  --apply                 implement fixes on their own branches and commit (no push)
  --pr                    implement, push, and open one pull request per finding (implies --apply)
  --no-tests              proceed when the repository has no test command (the PR says it is unverified)
  --keep-failed           keep branches whose tests failed, for inspection
  --max-fixes <n>         cap the number of fixes attempted (default: 10)
  --bandit-cli <path>     path to the coding agent entrypoint

  With neither --apply nor --pr, fix is a dry run and writes nothing.

TRUST MODEL FOR FIX
  A human merges, always. Sentinel never pushes to the default branch, never merges,
  never force-pushes. Every fix runs on its own branch and is abandoned if the
  repository's tests fail. Only findings whose fix plan is marked agent-executable
  are attempted; refuted and triaged-out findings are never touched.
`;

interface Args {
  command: string;
  positional: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];
  let command = '';
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq > 0) {
        flags.set(token.slice(2, eq), token.slice(eq + 1));
        continue;
      }
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags.set(key, next);
        i += 1;
      } else {
        flags.set(key, true);
      }
      continue;
    }
    if (!command) command = token;
    else positional.push(token);
  }
  return { command, positional, flags };
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  // `--version` has no command, so it must be answered before the no-command
  // fallback prints the whole usage banner.
  if (args.flags.has('version') || args.command === 'version') {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (args.flags.has('help') || args.flags.has('h') || !args.command || args.command === 'help') {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  switch (args.command) {
    case 'scan':
      return runScan(args);
    case 'fix':
      return runFix(args);
    case 'rules':
      return runRulesList(args);
    case 'profiles':
      return runProfiles();
    case 'init-workflow':
      return runInitWorkflow(args);
    default:
      process.stderr.write(`unknown command: ${args.command}\n\n${USAGE}\n`);
      return 64;
  }
}

async function runScan(args: Args): Promise<number> {
  const repo = args.positional[0] ?? String(args.flags.get('repo') ?? '');
  if (!repo) {
    process.stderr.write('scan needs a repository path: sentinel scan <repo>\n');
    return 64;
  }
  const repoPath = resolve(repo);
  if (!exists(repoPath)) {
    process.stderr.write(`no such directory: ${repoPath}\n`);
    return 66;
  }
  const quiet = Boolean(args.flags.get('quiet'));
  const name = repoPath.split('/').filter(Boolean).pop() ?? 'repo';
  const outDir = String(args.flags.get('out') ?? join(process.cwd(), 'sentinel-results', name));
  const formats = String(args.flags.get('format') ?? 'md,html,json,sarif')
    .split(',')
    .map((f) => f.trim())
    .filter((f): f is OutputFormat => ['md', 'html', 'json', 'sarif'].includes(f));
  if (formats.length === 0) {
    process.stderr.write('no valid --format value (expected md, html, json, sarif)\n');
    return 64;
  }

  const provider = String(args.flags.get('provider') ?? 'auto');
  if (!isProviderChoice(provider)) {
    process.stderr.write(`invalid --provider "${provider}" (expected ${PROVIDER_CHOICES.join(', ')})\n`);
    return 64;
  }
  const proofSandbox = String(args.flags.get('proof-sandbox') ?? 'auto');
  if (!isProofSandboxMode(proofSandbox)) {
    process.stderr.write(`invalid --proof-sandbox "${proofSandbox}" (expected ${PROOF_SANDBOX_MODES.join(', ')})\n`);
    return 64;
  }

  const started = Date.now();
  const result = await scan({
    repo: repoPath,
    outDir,
    profile: String(args.flags.get('profile') ?? 'owasp-asvs'),
    formats,
    noLlm: Boolean(args.flags.get('no-llm')),
    noProofs: Boolean(args.flags.get('no-proofs')),
    proofSandbox,
    provider,
    model: args.flags.has('model') ? String(args.flags.get('model')) : undefined,
    proofImage: args.flags.has('proof-image') ? String(args.flags.get('proof-image')) : undefined,
    offline: Boolean(args.flags.get('offline')),
    noExternalScanners: Boolean(args.flags.get('no-external-scanners')),
    banditCli: args.flags.has('bandit-cli') ? String(args.flags.get('bandit-cli')) : undefined,
    maxReviewFiles: Number(args.flags.get('max-review-files') ?? 4),
    llmTimeoutMs: args.flags.has('llm-timeout') ? Number(args.flags.get('llm-timeout')) : undefined,
    onProgress: quiet ? undefined : (m) => process.stderr.write(`  ${m}\n`),
  });

  const { findings, confidence } = result;
  const count = (s: string): number => findings.filter((f) => f.status === s).length;
  const lines = [
    '',
    `sentinel-audit ${TOOL_VERSION} · profile ${result.profile.id} · ${((Date.now() - started) / 1000).toFixed(1)}s`,
    `repository: ${result.ctx.recon.repoUrl} @ ${result.ctx.recon.commitSha.slice(0, 12)}`,
    '',
    `  proof-confirmed   ${String(count('proof-confirmed')).padStart(3)}   (an executed proof demonstrated it)`,
    `  pattern-confirmed ${String(count('pattern-confirmed')).padStart(3)}   (the pattern re-matched; exploitability unproven)`,
    `  plausible         ${String(count('plausible')).padStart(3)}   (reasoned, unproven)`,
    `  refuted           ${String(count('refuted')).padStart(3)}   (an executed check disproved it)`,
    `  triaged out       ${String(count('triaged-out')).padStart(3)}   (noise, with reasons)`,
    '',
    `  score ${confidence.overallScore}/10 (${confidence.band}) · security ${confidence.securityPostureScore}/10 · gate ${confidence.gateDecision.toUpperCase()}`,
    `  confirmed share of live findings: ${Math.round(confidence.evidenceQuality.verifiedShare * 100)}% · proven by execution: ${Math.round(confidence.evidenceQuality.provenShare * 100)}%`,
    `  model pass: ${result.ctx.llm.available ? `ran (${result.ctx.llm.calls} call(s))` : 'did not run — deterministic only'}`,
    '',
    `  artefacts: ${outDir}`,
  ];
  const errors = result.validation.filter((v) => v.severity === 'error');
  if (errors.length > 0) {
    lines.push('', `  WARNING: ${errors.length} schema validation error(s) in Sentinel's own output — see SCHEMA-VALIDATION.md`);
  }
  const agentFixable = findings.filter((f) => f.fixPlan.agentExecutable);
  if (agentFixable.length > 0) {
    lines.push('', `  ${agentFixable.length} finding(s) have an agent-executable fix plan:`, `    sentinel fix ${join(outDir, 'findings')} --repo ${repoPath} --only ${agentFixable.map((f) => f.id).join(',')}`);
  }
  lines.push('');
  process.stdout.write(lines.join('\n'));
  return result.exitCode;
}

async function runFix(args: Args): Promise<number> {
  const findingsDir = args.positional[0] ?? String(args.flags.get('findings') ?? '');
  if (!findingsDir) {
    process.stderr.write('fix needs a findings directory: sentinel fix <findings-dir>\n');
    return 64;
  }
  try {
    const report = await fix({
      findingsDir,
      repo: args.flags.has('repo') ? String(args.flags.get('repo')) : undefined,
      apply: Boolean(args.flags.get('apply')),
      pr: Boolean(args.flags.get('pr')),
      only: args.flags.has('only') ? String(args.flags.get('only')) : undefined,
      noTests: Boolean(args.flags.get('no-tests')),
      keepFailed: Boolean(args.flags.get('keep-failed')),
      maxFixes: Number(args.flags.get('max-fixes') ?? 10),
      banditCli: args.flags.has('bandit-cli') ? String(args.flags.get('bandit-cli')) : undefined,
      onProgress: (m) => process.stderr.write(`  ${m}\n`),
    });

    const lines = ['', `sentinel fix · ${report.dryRun ? 'DRY RUN (nothing written)' : 'applied'} · agent: ${report.provider}`, `repository: ${report.repo}`, ''];
    for (const o of report.outcomes) {
      lines.push(`  [${o.status.padEnd(12)}] ${o.id} — ${o.title}`);
      lines.push(`                 ${o.detail}`);
      if (o.filesChanged.length > 0) lines.push(`                 files: ${o.filesChanged.join(', ')}`);
    }
    if (report.dryRun) {
      lines.push('', '  This was a dry run. Add --apply to commit on branches, or --pr to also open pull requests.');
      lines.push('  A human merges, always: Sentinel never pushes to the default branch and abandons fixes whose tests fail.');
    }
    lines.push('');
    process.stdout.write(lines.join('\n'));

    const failed = report.outcomes.filter((o) => o.status === 'tests-failed' || o.status === 'agent-failed');
    return failed.length > 0 ? 1 : 0;
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    return 70;
  }
}

function runRulesList(args: Args): number {
  if (args.flags.has('json')) {
    process.stdout.write(
      `${JSON.stringify(
        ALL_RULES.map((r) => ({
          id: r.id,
          title: r.title,
          type: r.type,
          severity: r.severity,
          claimType: r.claimType,
          effort: r.effort,
          area: r.area,
          labels: r.labels,
          mode: r.aggregate ? (r.scan ? 'per-file + aggregate' : 'aggregate') : 'per-file',
        })),
        null,
        2,
      )}\n`,
    );
    return 0;
  }
  const rows = ALL_RULES.map((r) => [r.id, r.severity, r.claimType, r.type, r.title]);
  const widths = [0, 1, 2, 3].map((i) => Math.max(...rows.map((row) => row[i]!.length)));
  process.stdout.write(`\n${ALL_RULES.length} rules\n\n`);
  for (const row of rows) {
    process.stdout.write(`  ${row[0]!.padEnd(widths[0]!)}  ${row[1]!.padEnd(widths[1]!)}  ${row[2]!.padEnd(widths[2]!)}  ${row[3]!.padEnd(widths[3]!)}  ${row[4]}\n`);
  }
  process.stdout.write(
    '\n  claim type: "behavioral" rules can only be confirmed by an executed proof; "factual" rules can be confirmed by re-asserting the artefact.\n\n',
  );
  return 0;
}

function runProfiles(): number {
  process.stdout.write('\nAvailable profiles\n\n');
  for (const id of listProfiles()) {
    try {
      const p = loadProfile(id);
      process.stdout.write(`  ${id.padEnd(20)} ${p.title}\n`);
      process.stdout.write(`  ${' '.repeat(20)} ${p.description}\n`);
      process.stdout.write(`  ${' '.repeat(20)} ${Object.keys(p.controls).length} rule mappings; blocks on ${p.gate.blockOn.join('/')}\n\n`);
    } catch (err) {
      process.stdout.write(`  ${id.padEnd(20)} <failed to load: ${err instanceof Error ? err.message : String(err)}>\n\n`);
    }
  }
  process.stdout.write('  Pass a path to your own profile JSON to express an internal standards catalogue.\n\n');
  return 0;
}

function runInitWorkflow(args: Args): number {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, '..', 'templates', 'sentinel.yml'), join(here, '..', '..', 'templates', 'sentinel.yml')];
  const template = candidates.find((c) => exists(c));
  if (!template) {
    process.stderr.write('workflow template not found in the installed package\n');
    return 70;
  }
  const out = String(args.flags.get('out') ?? '.github/workflows/sentinel.yml');
  writeFileEnsured(resolve(out), readFileSync(template, 'utf8'));
  process.stdout.write(`wrote ${resolve(out)}\n`);
  process.stdout.write('Commit it, then check the Security tab after the first run for the uploaded SARIF.\n');
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`sentinel: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exitCode = 70;
  });
