import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { readJsonSafe, readTextSafe, exists } from '../util/fsx.js';
import { run, commandExists } from '../util/exec.js';
import type { AdvisoryRecord, CollectorRun, DependencyRecord, DependencyResult } from '../types.js';

/**
 * Supply-chain collector.
 *
 * Advisory data comes from the package manager's own audit endpoint — we do not
 * ship a vulnerability database, because a stale embedded database is worse
 * than no database. If audit cannot run (offline, no registry access) the
 * result says so and COVERAGE.md records the gap instead of the report
 * implying a clean bill of health.
 */

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  packageManager?: string;
  pnpm?: { overrides?: Record<string, string> };
  overrides?: Record<string, string>;
  resolutions?: Record<string, string>;
}

const SEVERITY_MAP: Record<string, AdvisoryRecord['severity']> = {
  critical: 'critical',
  high: 'high',
  moderate: 'moderate',
  medium: 'moderate',
  low: 'low',
  info: 'info',
};

export interface DependencyOutput {
  deps: DependencyResult;
  /** Declared version pins that exist purely to float a transitive fix. */
  securityOverrides: Array<{ name: string; version: string; field: string }>;
  run: CollectorRun;
}

export function collectDependencies(root: string, options: { offline?: boolean; timeoutMs?: number } = {}): DependencyOutput {
  const started = Date.now();
  const notExamined: string[] = [];
  const pkg = readJsonSafe<PackageJson>(join(root, 'package.json'));

  const lockfiles = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lockb', 'bun.lock', 'npm-shrinkwrap.json']
    .filter((f) => exists(join(root, f)));

  const manager = pkg?.packageManager?.split('@')[0] ?? inferManager(lockfiles);

  const direct: DependencyRecord[] = [];
  for (const [name, version] of Object.entries(pkg?.dependencies ?? {})) {
    direct.push({ name, version, dev: false, license: null, direct: true });
  }
  for (const [name, version] of Object.entries(pkg?.devDependencies ?? {})) {
    direct.push({ name, version, dev: true, license: null, direct: true });
  }

  // license inventory from installed node_modules (the only place the real
  // licence text lives). If the tree is not installed, we say so.
  const installed = inventoryInstalled(root);
  if (installed.length === 0) {
    notExamined.push('transitive dependency licences — node_modules is not installed, so only direct declarations were read');
  }
  const byName = new Map(installed.map((d) => [d.name, d]));
  for (const d of direct) {
    const hit = byName.get(d.name);
    if (hit) {
      d.license = hit.license;
      hit.direct = true;
      hit.dev = d.dev;
    }
  }
  const dependencies = installed.length > 0 ? installed : direct;

  const licenseSummary: Record<string, number> = {};
  let unknownLicenseCount = 0;
  for (const d of dependencies) {
    const key = d.license ?? 'UNKNOWN';
    licenseSummary[key] = (licenseSummary[key] ?? 0) + 1;
    if (!d.license) unknownLicenseCount += 1;
  }

  const overrides: Array<{ name: string; version: string; field: string }> = [];
  for (const [field, map] of [
    ['pnpm.overrides', pkg?.pnpm?.overrides],
    ['overrides', pkg?.overrides],
    ['resolutions', pkg?.resolutions],
  ] as const) {
    for (const [name, version] of Object.entries(map ?? {})) {
      overrides.push({ name, version: String(version), field });
    }
  }

  const audit = options.offline
    ? { advisories: [], available: false, command: null, error: 'skipped (--offline)' }
    : runAudit(root, manager, options.timeoutMs ?? 180_000);
  if (!audit.available) {
    notExamined.push(`dependency advisories — ${audit.error ?? 'audit unavailable'}`);
  }

  return {
    deps: {
      manager,
      lockfiles,
      total: dependencies.length,
      direct: direct.length,
      dev: direct.filter((d) => d.dev).length,
      advisories: audit.advisories,
      auditAvailable: audit.available,
      auditCommand: audit.command,
      auditError: audit.error,
      dependencies,
      licenseSummary,
      unknownLicenseCount,
    },
    securityOverrides: overrides,
    run: {
      name: 'dependencies',
      ok: true,
      durationMs: Date.now() - started,
      note: audit.available
        ? `${dependencies.length} packages, ${audit.advisories.length} advisories via \`${audit.command}\``
        : `${dependencies.length} packages, advisories unavailable (${audit.error ?? 'unknown'})`,
      notExamined,
    },
  };
}

function inferManager(lockfiles: string[]): string {
  if (lockfiles.includes('pnpm-lock.yaml')) return 'pnpm';
  if (lockfiles.includes('yarn.lock')) return 'yarn';
  if (lockfiles.some((l) => l.startsWith('bun.'))) return 'bun';
  if (lockfiles.includes('package-lock.json')) return 'npm';
  return 'npm';
}

/** Walk node_modules one/two levels deep (incl. scoped) for name/version/license. */
function inventoryInstalled(root: string): DependencyRecord[] {
  const modules = join(root, 'node_modules');
  if (!exists(modules)) return [];
  const out: DependencyRecord[] = [];
  const seen = new Set<string>();
  const readPkg = (dir: string): void => {
    const manifest = readJsonSafe<{ name?: string; version?: string; license?: unknown; licenses?: unknown }>(
      join(dir, 'package.json'),
    );
    if (!manifest?.name || seen.has(manifest.name)) return;
    seen.add(manifest.name);
    out.push({
      name: manifest.name,
      version: manifest.version ?? 'unknown',
      dev: false,
      license: normaliseLicense(manifest.license ?? manifest.licenses),
      direct: false,
    });
  };
  let entries: string[];
  try {
    entries = readdirSync(modules);
  } catch {
    return [];
  }
  for (const entry of entries) {
    if (entry.startsWith('.')) continue;
    const abs = join(modules, entry);
    if (entry.startsWith('@')) {
      let scoped: string[] = [];
      try {
        scoped = readdirSync(abs);
      } catch {
        continue;
      }
      for (const s of scoped) readPkg(join(abs, s));
    } else {
      readPkg(abs);
    }
  }
  return out;
}

function normaliseLicense(license: unknown): string | null {
  if (typeof license === 'string') return license;
  if (license && typeof license === 'object' && 'type' in license) {
    const t = (license as { type?: unknown }).type;
    if (typeof t === 'string') return t;
  }
  if (Array.isArray(license)) {
    const names = license
      .map((l) => (typeof l === 'string' ? l : typeof l === 'object' && l && 'type' in l ? String((l as any).type) : null))
      .filter((x): x is string => Boolean(x));
    return names.length > 0 ? names.join(' OR ') : null;
  }
  return null;
}

interface AuditOutcome {
  advisories: AdvisoryRecord[];
  available: boolean;
  command: string | null;
  error?: string;
}

function runAudit(root: string, manager: string, timeoutMs: number): AuditOutcome {
  const attempts: Array<{ cmd: string; args: string[] }> = [];
  if (manager === 'pnpm') attempts.push({ cmd: 'pnpm', args: ['audit', '--json'] });
  if (manager === 'yarn') attempts.push({ cmd: 'yarn', args: ['npm', 'audit', '--json'] });
  attempts.push({ cmd: 'npm', args: ['audit', '--json'] });

  let lastError = 'no package manager available';
  for (const attempt of attempts) {
    if (!commandExists(attempt.cmd)) {
      lastError = `${attempt.cmd} not found on PATH`;
      continue;
    }
    const res = run(attempt.cmd, attempt.args, { cwd: root, timeoutMs });
    const command = `${attempt.cmd} ${attempt.args.join(' ')}`;
    const text = res.stdout.trim();
    if (text.length === 0) {
      lastError = res.timedOut ? `${command} timed out after ${timeoutMs}ms` : `${command} produced no output: ${firstLine(res.stderr)}`;
      continue;
    }
    const parsed = parseAuditJson(text);
    if (parsed) return { advisories: parsed, available: true, command };
    lastError = `could not parse output of ${command}`;
  }
  return { advisories: [], available: false, command: null, error: lastError };
}

function firstLine(s: string): string {
  return s.split('\n').find((l) => l.trim().length > 0)?.trim().slice(0, 200) ?? '';
}

/**
 * Handles the three shapes in the wild:
 *  - npm v7+ `auditReportVersion: 2` (`vulnerabilities` keyed by module)
 *  - npm v6 / pnpm `advisories` map
 *  - pnpm / yarn newline-delimited JSON advisory objects
 */
export function parseAuditJson(text: string): AdvisoryRecord[] | null {
  const records: AdvisoryRecord[] = [];
  const pushV2 = (doc: any): boolean => {
    if (!doc || typeof doc !== 'object' || !doc.vulnerabilities) return false;
    for (const [module, entry] of Object.entries<any>(doc.vulnerabilities)) {
      const via = Array.isArray(entry.via) ? entry.via : [];
      const detailed = via.filter((v: any) => v && typeof v === 'object');
      if (detailed.length === 0) {
        records.push({
          module,
          severity: SEVERITY_MAP[String(entry.severity)] ?? 'info',
          title: `Vulnerable version of ${module} reachable via ${via.filter((v: any) => typeof v === 'string').join(', ') || 'dependency tree'}`,
          vulnerableVersions: entry.range,
          patchedIn: entry.fixAvailable === false ? null : undefined,
          path: entry.isDirect ? 'direct' : 'transitive',
          isDev: Boolean(entry.effects?.length === 0 && entry.isDirect === false && entry.dev),
        });
        continue;
      }
      for (const v of detailed) {
        records.push({
          module: v.name ?? module,
          severity: SEVERITY_MAP[String(v.severity ?? entry.severity)] ?? 'info',
          title: String(v.title ?? `Advisory in ${module}`),
          url: typeof v.url === 'string' ? v.url : undefined,
          vulnerableVersions: v.range ?? entry.range,
          patchedIn: entry.fixAvailable === false ? null : undefined,
          cwe: Array.isArray(v.cwe) ? v.cwe.map(String) : [],
          cve: Array.isArray(v.cves) ? v.cves.map(String) : [],
          path: entry.isDirect ? 'direct' : 'transitive',
          isDev: Boolean(entry.dev),
        });
      }
    }
    return true;
  };

  const pushV1 = (doc: any): boolean => {
    if (!doc || typeof doc !== 'object' || !doc.advisories) return false;
    for (const adv of Object.values<any>(doc.advisories)) {
      records.push({
        module: String(adv.module_name ?? 'unknown'),
        severity: SEVERITY_MAP[String(adv.severity)] ?? 'info',
        title: String(adv.title ?? 'advisory'),
        url: typeof adv.url === 'string' ? adv.url : undefined,
        vulnerableVersions: adv.vulnerable_versions,
        patchedIn: adv.patched_versions ?? null,
        cwe: adv.cwe ? [String(adv.cwe)] : [],
        cve: Array.isArray(adv.cves) ? adv.cves.map(String) : [],
        path: Array.isArray(adv.findings) && adv.findings.some((f: any) => (f.paths ?? []).some((p: string) => !p.includes('>')))
          ? 'direct'
          : 'transitive',
        isDev: Boolean(adv.dev),
      });
    }
    return true;
  };

  // single JSON document
  try {
    const doc = JSON.parse(text);
    if (pushV2(doc) || pushV1(doc)) return dedupe(records);
    if (Array.isArray(doc)) {
      for (const item of doc) {
        if (!pushV2(item)) pushV1(item);
      }
      if (records.length > 0) return dedupe(records);
    }
  } catch {
    // fall through to NDJSON
  }

  // newline-delimited JSON
  let sawAny = false;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const doc = JSON.parse(trimmed);
      sawAny = true;
      if (pushV2(doc) || pushV1(doc)) continue;
      if (doc.advisory) {
        const adv = doc.advisory;
        records.push({
          module: String(adv.module_name ?? adv.moduleName ?? 'unknown'),
          severity: SEVERITY_MAP[String(adv.severity)] ?? 'info',
          title: String(adv.title ?? 'advisory'),
          url: typeof adv.url === 'string' ? adv.url : undefined,
          vulnerableVersions: adv.vulnerable_versions,
          patchedIn: adv.patched_versions ?? null,
          cwe: adv.cwe ? [String(adv.cwe)] : [],
          cve: Array.isArray(adv.cves) ? adv.cves.map(String) : [],
          path: 'unknown',
          isDev: false,
        });
      }
    } catch {
      continue;
    }
  }
  if (records.length > 0 || sawAny) return dedupe(records);
  return null;
}

function dedupe(records: AdvisoryRecord[]): AdvisoryRecord[] {
  const seen = new Set<string>();
  const out: AdvisoryRecord[] = [];
  for (const r of records) {
    const key = `${r.module}|${r.title}|${r.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out.sort((a, b) => rank(b.severity) - rank(a.severity) || a.module.localeCompare(b.module));
}

function rank(s: AdvisoryRecord['severity']): number {
  return ['info', 'low', 'moderate', 'high', 'critical'].indexOf(s);
}

/** Licences that usually need a decision before shipping closed-source. */
export const COPYLEFT = [/^AGPL/i, /^GPL-[23]/i, /^SSPL/i, /^BUSL/i, /^CC-BY-NC/i, /^EUPL/i, /^OSL/i];

export function copyleftDependencies(deps: DependencyRecord[]): DependencyRecord[] {
  return deps.filter((d) => d.license && COPYLEFT.some((re) => re.test(d.license!)));
}

export function readLockfileIntegrityNote(root: string): string {
  const pnpm = join(root, 'pnpm-lock.yaml');
  if (!exists(pnpm)) return '';
  const text = readTextSafe(pnpm, 12_000_000);
  if (!text) return 'pnpm-lock.yaml present but too large to read';
  const hasIntegrity = text.includes('integrity:') || text.includes('resolution: {');
  return hasIntegrity ? 'lockfile carries integrity hashes' : 'lockfile has no integrity hashes';
}
