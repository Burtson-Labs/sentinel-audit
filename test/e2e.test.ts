import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { proofNodeArgs } from '../src/verify/index.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/scan.js';
import { resolveProofSandbox } from '../src/verify/sandbox.js';
import { validateFindings } from '../src/schema.js';
import type { Finding } from '../src/types.js';

/**
 * End-to-end test against a synthetic repository with *known* defects and one
 * known non-defect.
 *
 * The non-defect is the important one: `safeRender.ts` escapes correctly, and
 * the test asserts Sentinel runs a real proof against it and reports the finding
 * as `refuted`. A tool that cannot produce a refutation is just a scanner with
 * better prose.
 */

let repo: string;
let out: string;
let findings: Finding[];

// The fixture is ours, so the host is an acceptable fallback here: this suite
// is about verdicts, and test/sandbox.test.ts owns isolation.
const proofSandbox = resolveProofSandbox({ mode: 'container' }).kind === 'container' ? 'container' : 'host';

const write = (rel: string, content: string): void => {
  const abs = join(repo, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content, 'utf8');
};

beforeAll(async () => {
  repo = mkdtempSync(join(tmpdir(), 'sentinel-e2e-repo-'));
  out = mkdtempSync(join(tmpdir(), 'sentinel-e2e-out-'));

  write(
    'package.json',
    JSON.stringify(
      {
        name: 'sentinel-e2e-fixture',
        version: '1.0.0',
        private: true,
        type: 'module',
        scripts: { test: 'node --test' },
        dependencies: {},
      },
      null,
      2,
    ),
  );
  write('tsconfig.json', JSON.stringify({ compilerOptions: { strict: true } }, null, 2));
  write('index.html', '<!doctype html>\n<html><head><title>fixture</title></head><body><div id="root"></div></body></html>\n');

  // --- a renderer that genuinely escapes: expect a REFUTED finding -----------
  // The escape table lives in a sibling imported as `./escapes.js` while the
  // file on disk is `escapes.ts` — the TypeScript ESM convention. The proof
  // can only reach safeRender through the harness's resolve hook.
  write(
    'src/escapes.ts',
    ['export const ESCAPES: Record<string, string> = {', `  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',`, '};', ''].join('\n'),
  );
  write(
    'src/safeRender.ts',
    [
      "import { ESCAPES } from './escapes.js';",
      '',
      'export function safeRender(input: string): string {',
      "  const escaped = input.replace(/[&<>\"']/g, (c) => ESCAPES[c] ?? c);",
      '  return `<p>${escaped}</p>`;',
      '}',
      '',
    ].join('\n'),
  );

  // --- the sink that consumes it ------------------------------------------
  write(
    'src/view.ts',
    ['import { safeRender } from "./safeRender.js";', '', 'export function mount(el: HTMLElement, body: string): void {', '  el.innerHTML = safeRender(body);', '}', ''].join('\n'),
  );

  // --- real defects -------------------------------------------------------
  write(
    'src/auth.ts',
    [
      "const TOKEN_KEY = 'app.accessToken';",
      '',
      'export const authStore = {',
      '  setToken: (token: string) => {',
      '    localStorage.setItem(TOKEN_KEY, token);',
      '  },',
      '  getToken: () => localStorage.getItem(TOKEN_KEY),',
      '};',
      '',
    ].join('\n'),
  );
  write(
    'src/server.ts',
    ['import express from "express";', '', 'export const app = express();', '', "app.post('/admin/wipe', (req, res) => {", '  res.json({ ok: true });', '});', ''].join('\n'),
  );
  write('src/shell.ts', ['import { exec } from "node:child_process";', '', 'export function checkout(branch: string): void {', '  exec(`git checkout ${branch}`);', '}', ''].join('\n'));
  write('src/crypto.ts', ['import { createHash } from "node:crypto";', '', 'export function sign(secret: string): string {', `  return createHash('md5').update(secret).digest('hex');`, '}', ''].join('\n'));
  write('src/swallow.ts', ['export function attempt(fn: () => void): void {', '  try {', '    fn();', '  } catch {}', '}', ''].join('\n'));
  write('Dockerfile', ['FROM node:22-alpine', 'WORKDIR /app', 'ARG NPM_TOKEN', 'COPY . .', 'CMD ["node", "src/server.js"]', ''].join('\n'));
  write(
    '.github/workflows/ci.yml',
    ['name: ci', 'on:', '  pull_request:', 'jobs:', '  build:', '    runs-on: ubuntu-latest', '    steps:', '      - uses: actions/checkout@v4', '      - run: npm test', ''].join('\n'),
  );

  const result = await scan({
    repo,
    outDir: out,
    profile: 'owasp-asvs',
    formats: ['md', 'json', 'sarif', 'html'],
    noLlm: true,
    offline: true,
    proofSandbox,
  });
  findings = result.findings;
}, 180_000);

afterAll(() => {
  for (const dir of [repo, out]) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // a leftover temp directory is not worth failing the suite over
    }
  }
});

const byRule = (ruleId: string): Finding | undefined => findings.find((f) => f.ruleId === ruleId);

describe('end-to-end scan of a synthetic repository', () => {
  it('produces findings', () => {
    expect(findings.length).toBeGreaterThan(4);
  });

  it('passes its own schema validation with no errors', () => {
    const errors = validateFindings(findings).filter((i) => i.severity === 'error');
    expect(errors.map((e) => `${e.findingId} ${e.path}: ${e.message}`)).toEqual([]);
  });

  it('writes every artefact', () => {
    for (const file of ['REPORT.md', 'CONFIDENCE.md', 'COVERAGE.md', 'REPORT.html', 'report.sarif', 'findings/index.json']) {
      expect(existsSync(join(out, file)), file).toBe(true);
    }
  });

  it('emits SARIF that parses and carries our properties', () => {
    const doc = JSON.parse(readFileSync(join(out, 'report.sarif'), 'utf8')) as {
      version: string;
      runs: Array<{ results: Array<{ properties: { sentinel: { status: string } } }> }>;
    };
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0]!.results.length).toBeGreaterThan(0);
    expect(doc.runs[0]!.results[0]!.properties.sentinel.status).toBeTruthy();
  });

  it('proof-confirms the token write, because a data-flow proof actually ran', () => {
    const f = byRule('SEC-TOKEN-WEBSTORAGE');
    expect(f).toBeDefined();
    // `authStore.setToken` is loadable outside a bundler, so the harness invokes
    // it and watches the credential land in storage. That earns the strong label.
    expect(f!.status).toBe('proof-confirmed');
    expect(f!.verification.state).toBe('proof-confirmed');
    expect(f!.verification.class).toBe('confirmed');
    expect(f!.verification.method).toBe('proof-executed');
    expect(f!.verification.proof!.verdict).toBe('vulnerable');
    expect(f!.evidence).toContain('src/auth.ts');
  });

  it('falls back to pattern-confirmed when no proof could run — same rule, weaker claim', async () => {
    const out4 = mkdtempSync(join(tmpdir(), 'sentinel-e2e-out4-'));
    const noProofs = await scan({ repo, outDir: out4, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true });
    const f = noProofs.findings.find((x) => x.ruleId === 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.status).toBe('pattern-confirmed');
    expect(f.verification.class).toBe('confirmed');
    expect(f.verification.proof).toBeUndefined();
    // and the weaker claim must cost confidence, not just wording
    const proven = findings.find((x) => x.ruleId === 'SEC-TOKEN-WEBSTORAGE')!;
    expect(f.confidence).toBeLessThan(proven.confidence);
    rmSync(out4, { recursive: true, force: true });
  }, 120_000);

  it('REFUTES the raw-HTML sink by running a proof against the real renderer', () => {
    const f = byRule('SEC-XSS-DANGEROUS-HTML');
    expect(f, 'the sink should have been flagged by the rule').toBeDefined();
    expect(f!.verification.proof, 'a proof should have been generated and executed').toBeDefined();
    expect(f!.verification.proof!.verdict).toBe('safe');
    expect(f!.status).toBe('refuted');
    expect(f!.severity).toBe('Info');
    expect(f!.verification.notes).toMatch(/disproved/i);
  });

  it('keeps the refuted finding in the report rather than dropping it', () => {
    const md = readFileSync(join(out, 'REPORT.md'), 'utf8');
    expect(md).toContain('# Refuted');
    const sarif = readFileSync(join(out, 'report.sarif'), 'utf8');
    expect(sarif).toContain('"suppressions"');
  });

  it('saves the proof script so it can be re-run by hand', () => {
    const f = byRule('SEC-XSS-DANGEROUS-HTML')!;
    expect(existsSync(join(out, f.verification.proof!.path))).toBe(true);
    const script = readFileSync(join(out, f.verification.proof!.path), 'utf8');
    expect(script).toContain('SENTINEL_PROOF');
    expect(script).toContain('safeRender');
  });

  it('flags the unauthenticated route as a blocker', () => {
    const f = byRule('SEC-UNAUTH-HANDLER');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('Blocker');
    expect(f!.evidence).toContain('src/server.ts');
  });

  it('flags the interpolated shell command at High', () => {
    const f = byRule('SEC-CHILD-PROCESS-SHELL');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('High');
  });

  it('flags md5 and the swallowed catch', () => {
    expect(byRule('SEC-WEAK-CRYPTO')).toBeDefined();
    expect(byRule('QUA-SWALLOWED-CATCH')).toBeDefined();
  });

  it('flags the root container and the credential build argument', () => {
    expect(byRule('DOCKER-ROOT')).toBeDefined();
    expect(byRule('DOCKER-SECRET-ARG')).toBeDefined();
  });

  it('confirms the missing CI gates by re-parsing the workflow', () => {
    const f = byRule('CI-NO-SECURITY-GATE');
    expect(f).toBeDefined();
    expect(f!.status).toBe('pattern-confirmed');
    // npm test is present, so the missing gates are the others
    expect(f!.verification.checks.some((c) => c.description.includes('audit'))).toBe(true);
  });

  it('confirms the absent CSP', () => {
    const f = byRule('SEC-CSP-MISSING');
    expect(f).toBeDefined();
    expect(f!.status).toBe('pattern-confirmed');
  });

  it('records that advisory data was not collected rather than implying a clean tree', () => {
    const f = byRule('DEP-AUDIT-UNAVAILABLE');
    expect(f).toBeDefined();
    const coverage = readFileSync(join(out, 'COVERAGE.md'), 'utf8');
    expect(coverage).toMatch(/NOT COVERED/);
  });

  it('threads the proof/pattern split through every artefact', () => {
    const md = readFileSync(join(out, 'REPORT.md'), 'utf8');
    expect(md).toContain('Pattern-confirmed');
    expect(md).toContain('exploitability is unproven');
    const conf = readFileSync(join(out, 'CONFIDENCE.md'), 'utf8');
    expect(conf).toMatch(/Pattern-confirmed \(the construct re-matched/);
    expect(conf).toMatch(/Proven-by-execution share/);
    const html = readFileSync(join(out, 'REPORT.html'), 'utf8');
    expect(html).toContain('data-filter="pattern-confirmed"');
    expect(html).toContain('data-status="pattern-confirmed"');
    const sarif = JSON.parse(readFileSync(join(out, 'report.sarif'), 'utf8')) as {
      runs: Array<{ properties: { sentinel: { counts: Record<string, number> } }; results: Array<{ properties: { sentinel: { status: string; statusClass: string } } }> }>;
    };
    const counts = sarif.runs[0]!.properties.sentinel.counts;
    expect(counts.patternConfirmed + counts.proofConfirmed).toBe(counts.confirmed);
    const index = JSON.parse(readFileSync(join(out, 'findings/index.json'), 'utf8')) as {
      counts: { confirmed: number; proofConfirmed: number; patternConfirmed: number };
      findings: Array<{ status: string; statusClass: string }>;
    };
    expect(index.counts.proofConfirmed + index.counts.patternConfirmed).toBe(index.counts.confirmed);
    // the coarse class travels alongside, so a consumer written against the old
    // vocabulary keeps working
    for (const f of index.findings) {
      if (f.status === 'pattern-confirmed' || f.status === 'proof-confirmed') expect(f.statusClass).toBe('confirmed');
      else expect(f.statusClass).toBe(f.status);
    }
  });

  it('states in every artefact that the model pass did not run', () => {
    for (const file of ['REPORT.md', 'CONFIDENCE.md', 'COVERAGE.md']) {
      expect(readFileSync(join(out, file), 'utf8'), file).toMatch(/model pass did not run|did not run|not-covered|NOT COVERED/i);
    }
  });

  it('gives every finding a non-zero derived confidence', () => {
    for (const f of findings) {
      expect(f.confidence, f.id).toBeGreaterThan(0);
      expect(f.confidence, f.id).toBeLessThanOrEqual(1);
    }
  });

  it('assigns ids in stable families', () => {
    for (const f of findings) expect(f.id).toMatch(/^[A-Z]{2,6}-\d{3}$/);
  });

  it('marks at least one fix plan agent-executable and gives it a prompt', () => {
    const executable = findings.filter((f) => f.fixPlan.agentExecutable);
    expect(executable.length).toBeGreaterThan(0);
    for (const f of executable) expect(f.fixPlan.agentPrompt, f.id).toBeTruthy();
  });

  it('never marks a refuted finding as agent-executable', () => {
    for (const f of findings.filter((x) => x.status === 'refuted')) {
      expect(f.fixPlan.agentExecutable, f.id).toBe(false);
    }
  });

  it('is reproducible: a second scan yields identical fingerprints', async () => {
    const out2 = mkdtempSync(join(tmpdir(), 'sentinel-e2e-out2-'));
    const again = await scan({ repo, outDir: out2, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true });
    const first = findings.map((f) => f.fingerprint).sort();
    const second = again.findings.map((f) => f.fingerprint).sort();
    expect(second).toEqual(first);
    rmSync(out2, { recursive: true, force: true });
  }, 120_000);

  it('changing the profile changes the standards mapping, not the findings', async () => {
    const out3 = mkdtempSync(join(tmpdir(), 'sentinel-e2e-out3-'));
    const cwe = await scan({ repo, outDir: out3, profile: 'cwe-top-25', formats: ['json'], noLlm: true, offline: true, noProofs: true });
    const xss = cwe.findings.find((f) => f.ruleId === 'SEC-XSS-DANGEROUS-HTML');
    expect(xss!.standards.cwe).toContain('CWE-79');
    expect(xss!.standardMapping).toMatch(/CWE/);
    expect(cwe.findings.map((f) => f.ruleId).sort()).toEqual(findings.map((f) => f.ruleId).sort());
    rmSync(out3, { recursive: true, force: true });
  }, 120_000);
});

describe('artefacts do not republish the audited repository', () => {
  it('scan-context.json carries no source text and stays small', () => {
    const raw = readFileSync(join(out, 'scan-context.json'), 'utf8');
    const doc = JSON.parse(raw) as Record<string, unknown>;
    expect(doc.__texts, 'the in-memory source cache must never be serialised').toBeUndefined();
    // a distinctive line from the fixture source must not appear anywhere
    expect(raw).not.toContain('ESCAPES: Record<string, string>');
    expect(raw).not.toContain('localStorage.setItem(TOKEN_KEY, token)');
    expect(raw.length).toBeLessThan(200_000);
    expect(doc.ruleHitCount).toBeTypeOf('number');
  });

  it('the report embeds only short excerpts, never whole files', () => {
    const md = readFileSync(join(out, 'REPORT.md'), 'utf8');
    // every excerpt the renderer emits is clamped; assert no long verbatim run
    const longest = md.split('\n').reduce((n, l) => Math.max(n, l.length), 0);
    expect(longest).toBeLessThan(4000);
    expect(md).not.toContain('ESCAPES: Record<string, string>');
  });
});

describe('gitignored paths are not part of the repository the rules audit', () => {
  // Two real scans cited `dev-dist/workbox-*.js` (a generated service worker,
  // gitignored) and `.bandit/backups/…` (an agent's own copies, gitignored) for
  // empty catches, missing origin checks and oversized modules. Every one was a
  // true match against a file nobody committed, reviews, or can fix.
  let repo2: string;
  let out2: string;
  let findings2: Finding[];

  beforeAll(async () => {
    repo2 = mkdtempSync(join(tmpdir(), 'sentinel-e2e-ignored-'));
    out2 = mkdtempSync(join(tmpdir(), 'sentinel-e2e-ignored-out-'));
    const w = (rel: string, content: string): void => {
      mkdirSync(join(repo2, rel, '..'), { recursive: true });
      writeFileSync(join(repo2, rel), content, 'utf8');
    };
    w('package.json', JSON.stringify({ name: 'ignored-fixture', version: '1.0.0', private: true, type: 'module', scripts: { test: 'node --test' } }, null, 2));
    w('.gitignore', 'dev-dist/\n.env\n');
    w('src/ok.ts', 'export const ok = 1;\n');
    w('src/swallow.ts', ['export function attempt(fn: () => void): void {', '  try {', '    fn();', '  } catch {}', '}', ''].join('\n'));
    w('dev-dist/sw.js', ['self.addEventListener("message", (event) => {', '  try {', '    handle(event.data);', '  } catch (e) {}', '});', ''].join('\n'));
    execFileSync('git', ['-C', repo2, 'init', '-q']);
    const result = await scan({ repo: repo2, outDir: out2, profile: 'owasp-asvs', formats: ['md', 'json'], noLlm: true, offline: true, noProofs: true });
    findings2 = result.findings;
  }, 120_000);

  afterAll(() => {
    for (const dir of [repo2, out2]) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // a leftover temp directory is not worth failing the suite over
      }
    }
  });

  it('never cites a gitignored file', () => {
    expect(JSON.stringify(findings2)).not.toContain('dev-dist/');
  });

  it('still reports the same defect in a tracked file', () => {
    expect(findings2.some((f) => f.evidence.includes('src/swallow.ts'))).toBe(true);
  });

  it('says how many paths it skipped, so the coverage statement stays honest', () => {
    const coverage = readFileSync(join(out2, 'COVERAGE.md'), 'utf8');
    expect(coverage).toMatch(/1 gitignored path\(s\) skipped/);
  });
});

describe('proofNodeArgs: proofs import TypeScript on every supported Node', () => {
  it('adds the flag on Node 22.6–22.17, where type stripping is opt-in', () => {
    expect(proofNodeArgs({ node: '22.15.1', typescript: undefined })).toEqual(['--experimental-strip-types']);
    expect(proofNodeArgs({ node: '22.6.0' })).toEqual(['--experimental-strip-types']);
    expect(proofNodeArgs({ node: '23.2.0', typescript: false })).toEqual(['--experimental-strip-types']);
  });

  it('adds nothing where the runtime already strips types', () => {
    expect(proofNodeArgs({ node: '22.18.0', typescript: 'strip' })).toEqual([]);
    expect(proofNodeArgs({ node: '24.1.0', typescript: 'strip' })).toEqual([]);
  });

  it('adds nothing below 22.6, where the flag does not exist', () => {
    expect(proofNodeArgs({ node: '20.19.0' })).toEqual([]);
  });
});
