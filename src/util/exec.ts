import { spawnSync, type SpawnSyncOptions } from 'node:child_process';

export interface RunResult {
  ok: boolean;
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Every external process Sentinel runs goes through here.
 *
 * Deliberately `shell: false` with an argv array: Sentinel runs against
 * untrusted repositories, and repository-derived strings (paths, package names,
 * branch names) end up in these arguments. A shell would make that injectable.
 */
export function run(
  cmd: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number; env?: NodeJS.ProcessEnv; input?: string; maxBuffer?: number } = {},
): RunResult {
  const started = Date.now();
  const opts: SpawnSyncOptions = {
    cwd: options.cwd,
    timeout: options.timeoutMs ?? 120_000,
    env: options.env ?? process.env,
    encoding: 'utf8',
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    shell: false,
    input: options.input,
    windowsHide: true,
  };
  const res = spawnSync(cmd, args, opts);
  const durationMs = Date.now() - started;
  const stdout = typeof res.stdout === 'string' ? res.stdout : '';
  const stderr = typeof res.stderr === 'string' ? res.stderr : '';
  const timedOut = Boolean(res.error && 'code' in res.error && res.error.code === 'ETIMEDOUT');
  return {
    ok: !res.error && res.status === 0,
    code: res.status,
    signal: res.signal ?? null,
    stdout,
    stderr: res.error && !stderr ? String(res.error.message) : stderr,
    durationMs,
    timedOut,
  };
}

export function commandExists(cmd: string): boolean {
  const probe = run(process.platform === 'win32' ? 'where' : 'which', [cmd], { timeoutMs: 5_000 });
  return probe.ok && probe.stdout.trim().length > 0;
}

export function git(root: string, args: string[], timeoutMs = 15_000): RunResult {
  return run('git', ['-C', root, ...args], { timeoutMs });
}
