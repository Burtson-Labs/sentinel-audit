import { realpathSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { run, type RunResult } from '../util/exec.js';

/**
 * Where proof scripts execute.
 *
 * A proof imports the audited repository's own modules, so running one runs
 * that repository's code. Sentinel is pointed at repositories nobody has
 * reviewed yet, so this is the one place it executes untrusted code, and it
 * must not do that with the operator's shell environment (API keys, cloud
 * credentials, registry tokens) or their home directory in reach.
 *
 *   container  docker or podman: no network, read-only root, every capability
 *              dropped, no-new-privileges, pid/memory/cpu limits, noexec /tmp,
 *              the caller's uid:gid, and only the repository and the proof
 *              directory mounted, both read-only. The environment is empty
 *              apart from what `proofEnv` sets.
 *   host       the local `node`, with the same scrubbed environment. The code
 *              still runs as you and can read your files, so it is opt-in only.
 *   off        proofs are not executed; findings keep their pattern-level
 *              status and say why.
 *
 * `auto` (the default) picks `container` when a runtime answers and `off`
 * otherwise. It never falls back to `host`: a scanner that quietly degrades to
 * running untrusted code on the host is the defect this module exists to fix.
 */
export type ProofSandboxMode = 'auto' | 'container' | 'host' | 'off';

export const PROOF_SANDBOX_MODES: readonly ProofSandboxMode[] = ['auto', 'container', 'host', 'off'];

/**
 * Node 24 strips TypeScript types by default, so proofs against `.ts` modules
 * need no flag inside the container. An override image must be Node 22.18+ for
 * the same reason.
 */
export const DEFAULT_PROOF_IMAGE = 'node:24-alpine';

export interface ResolvedSandbox {
  kind: 'container' | 'host' | 'off';
  /** `docker` or `podman` when kind is container. */
  runtime?: string;
  image?: string;
  /** Why proofs are off, or which runtime was chosen, for the report. */
  reason: string;
}

export interface SandboxOptions {
  mode?: ProofSandboxMode;
  image?: string;
  /** Test seam: which container runtimes answer `info`. */
  probe?: (runtime: string) => boolean;
  /** Test seam: whether the image is present or could be pulled. */
  ensureImage?: (runtime: string, image: string) => boolean;
}

export function isProofSandboxMode(v: string): v is ProofSandboxMode {
  return (PROOF_SANDBOX_MODES as readonly string[]).includes(v);
}

function runtimeAnswers(runtime: string): boolean {
  // `info` needs the daemon (docker) or a working machine (podman on macOS);
  // `--version` would succeed with neither and then every proof would error.
  return run(runtime, ['info', '--format', '{{.ServerVersion}}'], { timeoutMs: 10_000 }).ok;
}

/** Pull once up front, so the first proof's 60s budget is not spent downloading. */
function imageReady(runtime: string, image: string): boolean {
  if (run(runtime, ['image', 'inspect', image], { timeoutMs: 15_000 }).ok) return true;
  return run(runtime, ['pull', image], { timeoutMs: 300_000 }).ok;
}

export function resolveProofSandbox(opts: SandboxOptions = {}): ResolvedSandbox {
  const mode = opts.mode ?? 'auto';
  if (mode === 'off') return { kind: 'off', reason: 'proof execution was turned off (--proof-sandbox off)' };
  if (mode === 'host') {
    return { kind: 'host', reason: 'proofs ran on the host with a scrubbed environment (--proof-sandbox host)' };
  }
  const image = opts.image ?? process.env.SENTINEL_PROOF_IMAGE ?? DEFAULT_PROOF_IMAGE;
  if (process.platform === 'win32') {
    return {
      kind: 'off',
      reason:
        'no proof sandbox on Windows: proofs embed absolute host paths that a Linux container cannot mount. Pass --proof-sandbox host to run them on this machine.',
    };
  }
  const probe = opts.probe ?? runtimeAnswers;
  const override = process.env.SENTINEL_CONTAINER_RUNTIME;
  for (const runtime of override ? [override] : ['docker', 'podman']) {
    if (!probe(runtime)) continue;
    if (!(opts.ensureImage ?? imageReady)(runtime, image)) {
      return {
        kind: 'off',
        reason: `${runtime} is running but the proof image ${image} is not present and could not be pulled, so proofs were not run. Pull it once while online, or set SENTINEL_PROOF_IMAGE to a local Node 22.18+ image.`,
      };
    }
    return { kind: 'container', runtime, image, reason: `proofs ran in a ${runtime} sandbox (${image}, no network)` };
  }
  return {
    kind: 'off',
    reason:
      'no container runtime answered (docker or podman), and proofs execute the audited repository’s code, so they were not run. Start Docker, or pass --proof-sandbox host to run them on this machine.',
  };
}

/**
 * The only environment a proof sees. Nothing is inherited from the caller:
 * an allowlist, not a denylist, because the secret names worth protecting are
 * unbounded (`*_TOKEN`, `AWS_*`, `NPM_CONFIG__AUTH`, ...).
 */
export function proofEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { NO_COLOR: '1', NODE_OPTIONS: '', LANG: 'C.UTF-8', TZ: 'UTC' };
  // A host run still has to find `node`'s shared libraries and a temp dir.
  for (const key of ['PATH', 'SystemRoot', 'TEMP', 'TMP', 'TMPDIR']) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  return { ...env, ...extra };
}

/** Absolute path as the host filesystem stores it, so a bind mount resolves. */
function real(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

export interface ContainerArgsInput {
  image: string;
  name: string;
  /** Repository root as the proof script refers to it. */
  root: string;
  /** Proof directory as the proof script refers to it. */
  proofDir: string;
  scriptPath: string;
  nodeArgs: string[];
  uid?: number;
  gid?: number;
}

/**
 * The `run` argv for one proof. Mounts use the same path inside the container
 * as outside, because proof scripts embed absolute paths to the modules they
 * import.
 */
export function containerArgs(i: ContainerArgsInput): string[] {
  const args = [
    'run',
    '--rm',
    '--name',
    i.name,
    '--network',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '128',
    '--memory',
    '1g',
    '--cpus',
    '2',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,size=64m',
    '-v',
    `${real(i.root)}:${i.root}:ro`,
    '-v',
    `${real(i.proofDir)}:${i.proofDir}:ro`,
    '-w',
    i.root,
    '-e',
    'NO_COLOR=1',
    '-e',
    'NODE_OPTIONS=',
    '-e',
    'HOME=/tmp',
  ];
  if (i.uid !== undefined && i.gid !== undefined) args.push('--user', `${i.uid}:${i.gid}`);
  args.push('--entrypoint', 'node', i.image, ...i.nodeArgs, i.scriptPath);
  return args;
}

export interface ProofExecution {
  result: RunResult;
  /** How the proof ran, for the report and for re-running by hand. */
  where: string;
}

export function executeInSandbox(
  sandbox: ResolvedSandbox,
  opts: { root: string; proofDir: string; scriptPath: string; hostNodeArgs: string[]; timeoutMs: number },
): ProofExecution | null {
  if (sandbox.kind === 'off') return null;
  if (sandbox.kind === 'host') {
    return {
      result: run(process.execPath, [...opts.hostNodeArgs, opts.scriptPath], { cwd: opts.root, timeoutMs: opts.timeoutMs, env: proofEnv() }),
      where: 'host, scrubbed environment',
    };
  }
  const runtime = sandbox.runtime!;
  const name = `sentinel-proof-${randomBytes(6).toString('hex')}`;
  const args = containerArgs({
    image: sandbox.image!,
    name,
    root: opts.root,
    proofDir: opts.proofDir,
    scriptPath: opts.scriptPath,
    nodeArgs: [],
    uid: process.getuid?.(),
    gid: process.getgid?.(),
  });
  // The runtime client keeps the caller's environment (it needs DOCKER_HOST,
  // the active context, credentials for a private image); the container does
  // not inherit it — it gets only the -e flags above.
  const result = run(runtime, args, { timeoutMs: opts.timeoutMs });
  if (result.timedOut) {
    // A killed client leaves the container running; take it down by name.
    run(runtime, ['rm', '-f', name], { timeoutMs: 15_000 });
  }
  return { result, where: `${runtime} ${sandbox.image}, no network, read-only` };
}
