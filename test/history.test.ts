import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectSecrets, scanGitHistory } from '../src/collectors/secrets.js';
import { walkRepo } from '../src/util/fsx.js';
import { scan } from '../src/scan.js';

/**
 * Secrets in git history, found by Sentinel itself.
 *
 * Before this pass, a credential that was committed and later deleted was found
 * only if gitleaks or trufflehog happened to be installed, and the coverage
 * report said so on every run. The fixture below commits a token, rotates it
 * out of the tree, and keeps a second token in the tree; the pass must report
 * the first, not the second, and must dismiss a placeholder in a deleted README
 * with the same reasons it uses for the working tree.
 */

const TOKEN_GONE = `ghp_${'a'.repeat(36)}`;
const TOKEN_KEPT = `sk_live_${'B1c2D3e4'.repeat(4)}`;

let repo: string;

const git = (...args: string[]): string =>
  execFileSync('git', ['-C', repo, '-c', 'user.email=t@example.org', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
  });

const write = (rel: string, content: string): void => {
  mkdirSync(join(repo, rel, '..'), { recursive: true });
  writeFileSync(join(repo, rel), content, 'utf8');
};

beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), 'sentinel-history-'));
  git('init', '-q');
  write('package.json', JSON.stringify({ name: 'history-fixture', version: '1.0.0', private: true, type: 'module', scripts: { test: 'node --test' } }, null, 2));
  write('src/config.ts', `export const GITHUB_TOKEN = '${TOKEN_GONE}';\n`);
  write('src/pay.ts', `export const STRIPE_KEY = '${TOKEN_KEPT}';\n`);
  write('docs/README.md', 'Point it at your database: `postgres://user:password@localhost:5432/app`\n');
  git('add', '-A');
  git('commit', '-q', '-m', 'add config');
  // rotate the GitHub token out of the tree; the Stripe key stays
  write('src/config.ts', "export const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? '';\n");
  unlinkSync(join(repo, 'docs/README.md'));
  git('add', '-A');
  git('commit', '-q', '-m', 'rotate');
});

afterAll(() => {
  try {
    rmSync(repo, { recursive: true, force: true });
  } catch {
    // a leftover temp directory is not worth failing the suite over
  }
});

describe('scanGitHistory', () => {
  it('reports a provider token that was committed and later removed, with its blob and commit', () => {
    const result = scanGitHistory(repo, { known: new Set() })!;
    expect(result).toBeDefined();
    expect(result.blobsExamined).toBeGreaterThan(0);
    expect(result.capped).toBe(false);
    const gone = result.hits.find((h) => h.file === 'src/config.ts' && !h.likelyFalsePositive);
    expect(gone, 'the rotated token must be found in history').toBeDefined();
    expect(gone!.ruleId).toBe('SECRET-github-pat');
    expect(gone!.blob).toMatch(/^[0-9a-f]{12}$/);
    expect(gone!.commit).toMatch(/^[0-9a-f]{7,}$/);
    expect(gone!.masked).not.toContain(TOKEN_GONE);
  });

  it('dismisses a placeholder in a deleted document with the working-tree reasons', () => {
    const result = scanGitHistory(repo, { known: new Set() })!;
    const readme = result.hits.find((h) => h.file === 'docs/README.md');
    expect(readme).toBeDefined();
    expect(readme!.likelyFalsePositive).toBe(true);
    expect(readme!.falsePositiveReason).toMatch(/loopback|placeholder/);
  });

  it('returns undefined outside a git repository', () => {
    const plain = mkdtempSync(join(tmpdir(), 'sentinel-plain-'));
    try {
      expect(scanGitHistory(plain)).toBeUndefined();
    } finally {
      rmSync(plain, { recursive: true, force: true });
    }
  });
});

describe('collectSecrets with history', () => {
  it('does not report from history a value the working tree already reported', () => {
    const out = collectSecrets(repo, walkRepo(repo), { useExternalScanner: false });
    const tree = out.secrets.candidates.filter((c) => !c.likelyFalsePositive).map((c) => c.file);
    expect(tree).toContain('src/pay.ts');
    const history = out.secrets.history!;
    expect(history).toBeDefined();
    expect(history.hits.some((h) => h.file === 'src/pay.ts'), 'the kept key is the tree finding, not a history one').toBe(false);
    expect(history.hits.some((h) => h.file === 'src/config.ts' && !h.likelyFalsePositive)).toBe(true);
  });

  it('says in the coverage notes that history was scanned, and no longer says only the tree was', () => {
    const out = collectSecrets(repo, walkRepo(repo), { useExternalScanner: false });
    const notes = out.run.notExamined.join(' ');
    expect(notes).toMatch(/Sentinel scanned it itself/);
    expect(notes).not.toMatch(/only the working tree was scanned/);
  });
});

describe('the history finding in a full scan', () => {
  let out: string;
  afterAll(() => {
    try {
      rmSync(out, { recursive: true, force: true });
    } catch {
      // leftover temp output is harmless
    }
  });

  it('is a High, pattern-confirmed SEC-SECRET-HISTORY finding citing the blob', async () => {
    out = mkdtempSync(join(tmpdir(), 'sentinel-history-out-'));
    // gitleaks may be installed on the machine running the suite; the subject
    // here is Sentinel's own pass, so the relay is switched off.
    const result = await scan({ repo, outDir: out, profile: 'owasp-asvs', formats: ['json', 'md'], noLlm: true, offline: true, noProofs: true, noExternalScanners: true });
    const coverage = readFileSync(join(out, 'COVERAGE.md'), 'utf8');
    expect(coverage).toMatch(/Secret scanning \(git history\) \| covered/);
    expect(coverage).toMatch(/Sentinel's own pass/);
    const f = result.findings.find((x) => x.ruleId === 'SEC-SECRET-HISTORY');
    expect(f, 'a history finding is expected').toBeDefined();
    expect(f!.severity).toBe('High');
    expect(f!.status).toBe('pattern-confirmed');
    expect(f!.evidence).toContain('src/config.ts@');
    expect(f!.evidence).toContain('GitHub personal access token');
    expect(f!.verification.checks.some((c) => c.description.includes('re-read blob') && c.outcome === 'pass')).toBe(true);
    expect(JSON.stringify(result.findings)).not.toContain(TOKEN_GONE);
  }, 120_000);
});
