import { readFileSync, readdirSync, statSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep, extname } from 'node:path';

/** Directories never worth reading. Reported in COVERAGE.md as excluded. */
export const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.turbo',
  '.cache',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.pnpm-store',
  'target', // rust
  '.sentinel',
  '.release-artifacts',
];

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.icns', '.svg', '.pdf',
  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.zip', '.gz', '.tgz', '.bz2',
  '.xz', '.7z', '.rar', '.mp3', '.mp4', '.mov', '.avi', '.wav', '.webm',
  '.so', '.dylib', '.dll', '.exe', '.bin', '.wasm', '.node', '.class', '.jar',
  '.lockb', '.db', '.sqlite', '.pack', '.idx',
]);

export interface WalkOptions {
  excludes?: string[];
  maxFileBytes?: number;
  /** Hard cap so a pathological repo cannot hang the scan. */
  maxFiles?: number;
}

export interface RepoFile {
  /** Repo-relative POSIX path. */
  path: string;
  absolute: string;
  bytes: number;
  ext: string;
  binary: boolean;
}

export function walkRepo(root: string, options: WalkOptions = {}): RepoFile[] {
  const excludes = new Set(options.excludes ?? DEFAULT_EXCLUDES);
  const maxFiles = options.maxFiles ?? 50_000;
  const out: RepoFile[] = [];

  const visit = (dir: string): void => {
    if (out.length >= maxFiles) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return; // unreadable dir — surfaced by the caller's coverage note
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return;
      if (excludes.has(entry)) continue;
      const abs = join(dir, entry);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        visit(abs);
        continue;
      }
      if (!st.isFile()) continue;
      const ext = extname(entry).toLowerCase();
      out.push({
        path: toPosix(relative(root, abs)),
        absolute: abs,
        bytes: st.size,
        ext,
        binary: BINARY_EXT.has(ext),
      });
    }
  };

  visit(root);
  return out;
}

export function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

export function readTextSafe(abs: string, maxBytes = 2_000_000): string | null {
  try {
    const st = statSync(abs);
    if (st.size > maxBytes) return null;
    const buf = readFileSync(abs);
    // crude binary sniff: a NUL byte in the first 4 KiB
    const probe = buf.subarray(0, 4096);
    if (probe.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

export function readJsonSafe<T>(abs: string): T | null {
  const text = readTextSafe(abs);
  if (text === null) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 1;
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) n += 1;
  return text.endsWith('\n') ? n - 1 : n;
}

export function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function writeFileEnsured(path: string, content: string): void {
  const idx = Math.max(path.lastIndexOf('/'), path.lastIndexOf(sep));
  if (idx > 0) ensureDir(path.slice(0, idx));
  writeFileSync(path, content, 'utf8');
}

export function exists(p: string): boolean {
  return existsSync(p);
}

/** 1-based line number for a character offset. */
export function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function lineTextAt(text: string, line: number): string {
  const lines = text.split('\n');
  return lines[line - 1] ?? '';
}

/** Trim + clamp an excerpt so reports never carry large source blocks. */
export function excerpt(raw: string, max = 200): string {
  const one = raw.replace(/\s+/g, ' ').trim();
  return one.length <= max ? one : `${one.slice(0, max - 1)}…`;
}
