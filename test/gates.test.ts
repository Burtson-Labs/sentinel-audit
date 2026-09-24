import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/scan.js';
import { summariseWorkflow } from '../src/collectors/ci.js';

/**
 * Required CI gates depend on what the repository contains. A hosting repo of
 * shell scripts, manifests and a Dockerfile owes lint and the security gates,
 * not a typecheck or a test suite it has no code for.
 */
const dirs: string[] = [];
const repo = (files: Record<string, string>): string => {
  const root = mkdtempSync(join(tmpdir(), 'sentinel-gates-'));
  dirs.push(root);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
};
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

const workflow = (steps: string): string => `name: verify
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
${steps}
`;
const infraSteps = `      - run: shellcheck scripts/*.sh
      - uses: Burtson-Labs/sentinel-audit@a760cbb00db0e8ac9333aa8192c5c291eb2dca1e # v0.2.1
`;

const gateFinding = async (root: string) => {
  const out = mkdtempSync(join(tmpdir(), 'sentinel-gates-out-'));
  dirs.push(out);
  const r = await scan({ repo: root, outDir: out, profile: 'owasp-asvs', formats: ['json'], noLlm: true, offline: true, noProofs: true, noExternalScanners: true });
  return r.findings.find((f) => f.ruleId === 'CI-NO-SECURITY-GATE');
};

describe('CI gates', () => {
  it('counts infrastructure linters as lint', () => {
    for (const cmd of ['shellcheck scripts/*.sh', 'hadolint Dockerfile', 'actionlint', 'kubeconform manifests/']) {
      expect(summariseWorkflow('.github/workflows/v.yml', workflow(`      - run: ${cmd}\n`)).gates.lint, cmd).toBe(true);
    }
  });

  it('does not demand typecheck or tests from a repo with no source code', async () => {
    const root = repo({
      'scripts/deploy.sh': '#!/usr/bin/env bash\nset -euo pipefail\necho deploy\n',
      'manifests/deploy.yaml': 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n',
      '.github/workflows/verify.yml': workflow(infraSteps),
    });
    expect(await gateFinding(root)).toBeUndefined();
  });

  it('still demands typecheck and tests once there is TypeScript', async () => {
    const root = repo({
      'src/index.ts': 'export const answer: number = 42;\n',
      'package.json': JSON.stringify({ name: 'x', version: '1.0.0', private: true }),
      '.github/workflows/verify.yml': workflow(infraSteps),
    });
    const f = await gateFinding(root);
    expect(f?.title).toMatch(/test/);
    expect(f?.title).toMatch(/typecheck/);
  });
});
