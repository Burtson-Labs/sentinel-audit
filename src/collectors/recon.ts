import { join } from 'node:path';
import { walkRepo, readTextSafe, readJsonSafe, countLines, exists, DEFAULT_EXCLUDES, type RepoFile } from '../util/fsx.js';
import { git } from '../util/exec.js';
import type { CollectorRun, LanguageStat, ReconResult } from '../types.js';

const LANGUAGE_BY_EXT: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript (JSX)',
  '.mts': 'TypeScript',
  '.cts': 'TypeScript',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript (JSX)',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.cs': 'C#',
  '.py': 'Python',
  '.go': 'Go',
  '.rs': 'Rust',
  '.rb': 'Ruby',
  '.java': 'Java',
  '.kt': 'Kotlin',
  '.swift': 'Swift',
  '.php': 'PHP',
  '.sh': 'Shell',
  '.bash': 'Shell',
  '.zsh': 'Shell',
  '.sql': 'SQL',
  '.css': 'CSS',
  '.scss': 'SCSS',
  '.html': 'HTML',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
  '.yml': 'YAML',
  '.yaml': 'YAML',
  '.json': 'JSON',
  '.md': 'Markdown',
  '.toml': 'TOML',
  '.tf': 'Terraform',
  '.dockerfile': 'Dockerfile',
};

export const CODE_EXTS = new Set([
  '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs',
  '.cs', '.py', '.go', '.rs', '.rb', '.java', '.kt', '.swift', '.php',
]);

export const JS_TS_EXTS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);

const TEST_PATH = /(^|\/)(__tests__|tests?|spec|e2e|cypress|playwright)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|Test\.(cs|java|kt)$/i;

export interface ReconOutput {
  recon: ReconResult;
  files: RepoFile[];
  run: CollectorRun;
}

interface PackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  main?: string;
  bin?: string | Record<string, string>;
  packageManager?: string;
  repository?: string | { url?: string };
}

const FRAMEWORK_MARKERS: Array<{ dep: string; label: string }> = [
  { dep: 'react', label: 'React' },
  { dep: 'react-dom', label: 'React DOM' },
  { dep: 'next', label: 'Next.js' },
  { dep: 'vue', label: 'Vue' },
  { dep: 'svelte', label: 'Svelte' },
  { dep: '@angular/core', label: 'Angular' },
  { dep: 'vite', label: 'Vite' },
  { dep: 'webpack', label: 'webpack' },
  { dep: 'express', label: 'Express' },
  { dep: 'fastify', label: 'Fastify' },
  { dep: 'hono', label: 'Hono' },
  { dep: 'koa', label: 'Koa' },
  { dep: '@nestjs/core', label: 'NestJS' },
  { dep: 'vitest', label: 'Vitest' },
  { dep: 'jest', label: 'Jest' },
  { dep: 'mocha', label: 'Mocha' },
  { dep: '@playwright/test', label: 'Playwright' },
  { dep: 'cypress', label: 'Cypress' },
  { dep: 'electron', label: 'Electron' },
  { dep: '@tauri-apps/api', label: 'Tauri' },
  { dep: '@tauri-apps/cli', label: 'Tauri' },
  { dep: 'zustand', label: 'Zustand' },
  { dep: 'redux', label: 'Redux' },
  { dep: '@tanstack/react-query', label: 'TanStack Query' },
  { dep: '@mui/material', label: 'MUI' },
  { dep: 'tailwindcss', label: 'Tailwind' },
  { dep: 'axios', label: 'axios' },
  { dep: 'prisma', label: 'Prisma' },
  { dep: 'mongoose', label: 'Mongoose' },
  { dep: 'typeorm', label: 'TypeORM' },
  { dep: 'socket.io', label: 'Socket.IO' },
  { dep: 'react-router-dom', label: 'React Router' },
];

export function collectRecon(root: string): ReconOutput {
  const started = Date.now();
  const files = walkRepo(root);
  const notExamined: string[] = [
    `excluded directories: ${DEFAULT_EXCLUDES.join(', ')}`,
    'binary assets (images, fonts, archives, compiled artefacts) are inventoried but not read',
    'symlinks are not followed',
  ];

  const langMap = new Map<string, LanguageStat>();
  const largest: Array<{ file: string; loc: number }> = [];
  let totalLoc = 0;
  let sourceFileCount = 0;
  let testFileCount = 0;

  for (const f of files) {
    if (f.binary) continue;
    const language = LANGUAGE_BY_EXT[f.ext];
    const text = readTextSafe(f.absolute);
    if (text === null) continue;
    const loc = countLines(text);
    totalLoc += loc;
    if (language) {
      const stat = langMap.get(language) ?? { language, files: 0, loc: 0 };
      stat.files += 1;
      stat.loc += loc;
      langMap.set(language, stat);
    }
    if (CODE_EXTS.has(f.ext)) {
      if (TEST_PATH.test(f.path)) testFileCount += 1;
      else sourceFileCount += 1;
      largest.push({ file: f.path, loc });
    }
  }

  largest.sort((a, b) => b.loc - a.loc);

  const pkg = readJsonSafe<PackageJson>(join(root, 'package.json'));
  const allDeps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
  const frameworks = Array.from(
    new Set(FRAMEWORK_MARKERS.filter((m) => m.dep in allDeps).map((m) => m.label)),
  ).sort();

  const packageManager = detectPackageManager(root, pkg?.packageManager);
  const entrypoints = detectEntrypoints(root, pkg, files);
  const { strict, hasTs } = detectTsConfig(root, files);

  const workflows = files
    .filter((f) => /^\.github\/workflows\/.+\.(ya?ml)$/.test(f.path))
    .map((f) => f.path)
    .sort();
  const dockerfiles = files
    .filter((f) => /(^|\/)(Dockerfile|Containerfile)([.\w-]*)$/i.test(f.path))
    .map((f) => f.path)
    .sort();

  const gitUrl = git(root, ['remote', 'get-url', 'origin']);
  const branch = git(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const sha = git(root, ['rev-parse', 'HEAD']);
  const commitDate = git(root, ['log', '-1', '--format=%cI']);
  if (!sha.ok) notExamined.push('git provenance unavailable (not a git work tree or git missing)');

  const recon: ReconResult = {
    root,
    repoUrl: gitUrl.ok ? gitUrl.stdout.trim() : normaliseRepoUrl(pkg?.repository) || 'unknown',
    branch: branch.ok ? branch.stdout.trim() : 'unknown',
    commitSha: sha.ok ? sha.stdout.trim() : 'unknown',
    commitDate: commitDate.ok ? commitDate.stdout.trim() : 'unknown',
    packageManager,
    languages: Array.from(langMap.values()).sort((a, b) => b.loc - a.loc),
    totalFiles: files.length,
    totalLoc,
    frameworks,
    entrypoints,
    sourceFileCount,
    testFileCount,
    testToSourceRatio: sourceFileCount === 0 ? 0 : Number((testFileCount / sourceFileCount).toFixed(3)),
    largestFiles: largest.slice(0, 12),
    scripts: pkg?.scripts ?? {},
    hasTypeScript: hasTs,
    tsStrict: strict,
    workflows,
    dockerfiles,
    excluded: DEFAULT_EXCLUDES,
  };

  return {
    recon,
    files,
    run: {
      name: 'recon',
      ok: true,
      durationMs: Date.now() - started,
      note: `${files.length} files, ${totalLoc.toLocaleString()} LOC, ${recon.languages.length} languages`,
      notExamined,
    },
  };
}

function normaliseRepoUrl(repo: PackageJson['repository']): string {
  if (!repo) return '';
  if (typeof repo === 'string') return repo;
  return repo.url ?? '';
}

function detectPackageManager(root: string, declared: string | undefined): string {
  if (declared) return declared;
  if (exists(join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (exists(join(root, 'yarn.lock'))) return 'yarn';
  if (exists(join(root, 'bun.lockb')) || exists(join(root, 'bun.lock'))) return 'bun';
  if (exists(join(root, 'package-lock.json'))) return 'npm';
  if (exists(join(root, 'requirements.txt')) || exists(join(root, 'pyproject.toml'))) return 'pip/poetry';
  if (exists(join(root, 'go.mod'))) return 'go modules';
  if (exists(join(root, 'Cargo.toml'))) return 'cargo';
  return 'unknown';
}

function detectEntrypoints(root: string, pkg: PackageJson | null, files: RepoFile[]): string[] {
  const out = new Set<string>();
  if (pkg?.main) out.add(pkg.main);
  if (typeof pkg?.bin === 'string') out.add(pkg.bin);
  else if (pkg?.bin) for (const v of Object.values(pkg.bin)) out.add(v);
  const candidates = [
    'src/main.ts', 'src/main.tsx', 'src/index.ts', 'src/index.tsx', 'src/app.ts',
    'src/server.ts', 'index.html', 'src/cli.ts', 'main.go', 'app.py', 'manage.py',
    'Program.cs', 'src/main.rs',
  ];
  for (const c of candidates) if (exists(join(root, c))) out.add(c);
  for (const f of files) {
    if (/^(src\/)?(pages|routes|app)\/.*\.(tsx?|jsx?)$/.test(f.path) && out.size < 24) {
      // route-ish entrypoints are interesting but noisy; cap them
      if (/\b(index|layout|route|page)\b/i.test(f.path)) out.add(f.path);
    }
  }
  return Array.from(out).sort();
}

function detectTsConfig(root: string, files: RepoFile[]): { strict: boolean | null; hasTs: boolean } {
  const hasTs = files.some((f) => f.ext === '.ts' || f.ext === '.tsx');
  const candidates = ['tsconfig.json', 'tsconfig.base.json', 'tsconfig.app.json'];
  for (const name of candidates) {
    const abs = join(root, name);
    if (!exists(abs)) continue;
    const text = readTextSafe(abs);
    if (!text) continue;
    // tsconfig allows comments; parse permissively rather than failing
    const stripped = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
    try {
      const cfg = JSON.parse(stripped) as { compilerOptions?: { strict?: boolean } };
      if (typeof cfg.compilerOptions?.strict === 'boolean') return { strict: cfg.compilerOptions.strict, hasTs };
    } catch {
      // a tsconfig we cannot parse is reported as unknown strictness, not as false
      return { strict: null, hasTs };
    }
  }
  return { strict: hasTs ? null : null, hasTs };
}

export function isTestPath(p: string): boolean {
  return TEST_PATH.test(p);
}
