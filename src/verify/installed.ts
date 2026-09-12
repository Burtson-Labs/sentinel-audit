import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { exists, readJsonSafe } from '../util/fsx.js';

/**
 * Find every installed copy of a package, across the three layouts in the wild.
 *
 * This matters for advisory verification: `npm audit` reports against the
 * dependency *graph*, but what ships is the installed tree. Under pnpm the
 * package usually is not at `node_modules/<name>` at all — it lives in
 * `node_modules/.pnpm/<name>@<version>/node_modules/<name>`, and there can be
 * several versions at once. Reading only the hoisted copy would report
 * "cannot verify" for most of a pnpm project's advisories, or worse, clear an
 * advisory because the hoisted copy happens to be patched while a nested one is
 * not.
 */

export interface InstalledCopy {
  version: string;
  /** Repo-relative-ish path, for the verification evidence line. */
  location: string;
}

export function resolveInstalledVersions(root: string, name: string): InstalledCopy[] {
  const out: InstalledCopy[] = [];
  const seen = new Set<string>();
  const add = (version: string | undefined, location: string): void => {
    if (!version) return;
    const key = `${version}@${location}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ version, location });
  };

  // 1. hoisted / npm + yarn classic layout
  const hoisted = join(root, 'node_modules', name, 'package.json');
  if (exists(hoisted)) {
    add(readJsonSafe<{ version?: string }>(hoisted)?.version, `node_modules/${name}/package.json`);
  }

  // 2. pnpm virtual store: node_modules/.pnpm/<name>@<version>[_peer]/node_modules/<name>
  const store = join(root, 'node_modules', '.pnpm');
  if (exists(store)) {
    // pnpm escapes a scope's slash as `+`: @scope/pkg -> @scope+pkg
    const encoded = name.startsWith('@') ? name.replace('/', '+') : name;
    let entries: string[] = [];
    try {
      entries = readdirSync(store);
    } catch {
      entries = [];
    }
    for (const entry of entries) {
      if (!entry.startsWith(`${encoded}@`)) continue;
      const manifest = join(store, entry, 'node_modules', ...name.split('/'), 'package.json');
      if (!exists(manifest)) continue;
      add(readJsonSafe<{ version?: string }>(manifest)?.version, `node_modules/.pnpm/${entry}/node_modules/${name}/package.json`);
    }
  }

  // 3. nested copies one level down (npm's deduplication fallback)
  if (out.length === 0) {
    const modules = join(root, 'node_modules');
    if (exists(modules)) {
      let top: string[] = [];
      try {
        top = readdirSync(modules);
      } catch {
        top = [];
      }
      for (const parent of top.slice(0, 400)) {
        if (parent.startsWith('.')) continue;
        const nested = join(modules, parent, 'node_modules', ...name.split('/'), 'package.json');
        if (!exists(nested)) continue;
        add(readJsonSafe<{ version?: string }>(nested)?.version, `node_modules/${parent}/node_modules/${name}/package.json`);
      }
    }
  }

  return out;
}
