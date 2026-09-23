import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { containerArgs, executeInSandbox, proofEnv, resolveProofSandbox, type ResolvedSandbox } from '../src/verify/sandbox.js';

/**
 * A proof imports the audited repository's modules, so it runs that
 * repository's code. These tests hold the line that made Sentinel safe to point
 * at a stranger's repo: no inherited secrets, no network, nothing writable, and
 * no silent fallback to the host.
 */

describe('proofEnv: an allowlist, not the caller environment', () => {
  it('drops every credential-shaped variable', () => {
    const saved = { ...process.env };
    try {
      process.env.ANTHROPIC_API_KEY = 'sk-ant-canary';
      process.env.OPENAI_API_KEY = 'sk-canary';
      process.env.AWS_SECRET_ACCESS_KEY = 'canary';
      process.env.NPM_TOKEN = 'canary';
      process.env.GITHUB_TOKEN = 'canary';
      const env = proofEnv();
      expect(Object.values(env)).not.toContain('sk-ant-canary');
      expect(Object.keys(env).sort()).toEqual(
        ['LANG', 'NODE_OPTIONS', 'NO_COLOR', 'TZ', ...['PATH', 'SystemRoot', 'TEMP', 'TMP', 'TMPDIR'].filter((k) => process.env[k] !== undefined)].sort(),
      );
      expect(env.NODE_OPTIONS).toBe('');
    } finally {
      process.env = saved;
    }
  });
});

describe('resolveProofSandbox: never falls back to the host', () => {
  it.skipIf(process.platform === 'win32')('auto picks a runtime that answers', () => {
    const s = resolveProofSandbox({ probe: (r) => r === 'podman', ensureImage: () => true });
    expect(s.kind).toBe('container');
    expect(s.runtime).toBe('podman');
  });

  it.skipIf(process.platform === 'win32')('auto and container turn proofs off, not onto the host, when no runtime answers', () => {
    for (const mode of ['auto', 'container'] as const) {
      const s = resolveProofSandbox({ mode, probe: () => false, ensureImage: () => true });
      expect(s.kind).toBe('off');
      expect(s.reason).toMatch(/--proof-sandbox host/);
    }
  });

  it.skipIf(process.platform === 'win32')('an image that cannot be pulled turns proofs off', () => {
    const s = resolveProofSandbox({ probe: () => true, ensureImage: () => false });
    expect(s.kind).toBe('off');
    expect(s.reason).toMatch(/could not be pulled/);
  });

  it('host and off are only ever explicit', () => {
    expect(resolveProofSandbox({ mode: 'host' }).kind).toBe('host');
    expect(resolveProofSandbox({ mode: 'off' }).kind).toBe('off');
  });

  it('off executes nothing', () => {
    expect(executeInSandbox({ kind: 'off', reason: 'x' }, { root: '/r', proofDir: '/p', scriptPath: '/p/x.mjs', hostNodeArgs: [], timeoutMs: 1000 })).toBeNull();
  });
});

describe('containerArgs', () => {
  const args = containerArgs({ image: 'node:24-alpine', name: 'n', root: '/repo', proofDir: '/out/proofs', scriptPath: '/out/proofs/p.mjs', nodeArgs: [], uid: 501, gid: 20 });
  const pair = (flag: string): string | undefined => args[args.indexOf(flag) + 1];

  it('isolates network, filesystem, privileges and resources', () => {
    expect(pair('--network')).toBe('none');
    expect(args).toContain('--read-only');
    expect(pair('--cap-drop')).toBe('ALL');
    expect(pair('--security-opt')).toBe('no-new-privileges');
    expect(pair('--pids-limit')).toBeTruthy();
    expect(pair('--memory')).toBeTruthy();
    expect(pair('--user')).toBe('501:20');
  });

  it('mounts only the repository and the proofs, both read-only, at their host paths', () => {
    const mounts = args.flatMap((a, i) => (args[i - 1] === '-v' ? [a] : []));
    expect(mounts).toHaveLength(2);
    expect(mounts.every((m) => m.endsWith(':ro'))).toBe(true);
    expect(mounts.map((m) => m.split(':')[1])).toEqual(['/repo', '/out/proofs']);
  });

  it('passes no environment beyond the fixed set', () => {
    const env = args.flatMap((a, i) => (args[i - 1] === '-e' ? [a] : []));
    expect(env).toEqual(['NO_COLOR=1', 'NODE_OPTIONS=', 'HOME=/tmp']);
    expect(args).not.toContain('--env-file');
  });
});

// The real thing: a hostile "proof" tries to exfiltrate, phone home and tamper.
const container: ResolvedSandbox = resolveProofSandbox({ mode: 'container' });
describe.skipIf(container.kind !== 'container')('container sandbox against a hostile proof', () => {
  let repo: string;
  let proofDir: string;

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), 'sentinel-sandbox-repo-'));
    proofDir = mkdtempSync(join(tmpdir(), 'sentinel-sandbox-proofs-'));
    writeFileSync(join(repo, 'index.js'), 'export const x = 1;\n');
  });

  afterAll(() => {
    for (const d of [repo, proofDir]) rmSync(d, { recursive: true, force: true });
  });

  it('sees no secrets, reaches no network, and writes nothing', () => {
    const script = join(proofDir, 'hostile.mjs');
    writeFileSync(
      script,
      `
import { writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
const out = { env: Object.keys(process.env), uid: process.getuid() };
try { writeFileSync(${JSON.stringify(join(repo, 'pwned'))}, 'x'); out.repoWrite = true; } catch { out.repoWrite = false; }
try { writeFileSync('/pwned', 'x'); out.rootWrite = true; } catch { out.rootWrite = false; }
try { await fetch('http://1.1.1.1', { signal: AbortSignal.timeout(3000) }); out.net = true; } catch { out.net = false; }
try { writeFileSync('/tmp/x.sh', '#!/bin/sh\\necho hi'); execSync('chmod +x /tmp/x.sh && /tmp/x.sh'); out.tmpExec = true; } catch { out.tmpExec = false; }
console.log('RESULT ' + JSON.stringify(out));
`,
    );
    const saved = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = 'sk-ant-canary';
    try {
      const exec = executeInSandbox(container, { root: repo, proofDir, scriptPath: script, hostNodeArgs: [], timeoutMs: 60_000 });
      expect(exec).not.toBeNull();
      const line = exec!.result.stdout.split('\n').find((l) => l.startsWith('RESULT '));
      expect(line, exec!.result.stderr).toBeTruthy();
      const r = JSON.parse(line!.slice(7)) as { env: string[]; uid: number; repoWrite: boolean; rootWrite: boolean; net: boolean; tmpExec: boolean };
      expect(r.env).not.toContain('ANTHROPIC_API_KEY');
      expect(r.env.filter((k) => /KEY|TOKEN|SECRET/i.test(k))).toEqual([]);
      expect(r.repoWrite).toBe(false);
      expect(r.rootWrite).toBe(false);
      expect(r.net).toBe(false);
      expect(r.tmpExec).toBe(false);
      if (process.getuid) expect(r.uid).toBe(process.getuid());
      expect(existsSync(join(repo, 'pwned'))).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = saved;
    }
  }, 90_000);
});
