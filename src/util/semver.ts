/**
 * Minimal semver comparison and range satisfaction.
 *
 * Scope: exactly what advisory verification needs — comparators (`<`, `<=`,
 * `>`, `>=`, `=`), space-joined conjunctions, `||` disjunctions, and the `*`
 * wildcard. That is the grammar `npm audit` emits in its `range` field.
 *
 * Out of scope: `^`, `~`, hyphen ranges and x-ranges. `satisfies` returns
 * `null` for anything it does not fully understand, and every caller treats
 * `null` as "cannot verify" rather than "not affected" — a range we cannot
 * parse must never silently clear an advisory.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

export function parse(version: string): SemVer | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ? m[4].split('.') : [],
  };
}

export function compare(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  // a version with a prerelease is lower than the same version without one
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;
  const len = Math.max(a.prerelease.length, b.prerelease.length);
  for (let i = 0; i < len; i += 1) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const nx = Number(x);
      const ny = Number(y);
      if (nx !== ny) return nx < ny ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

const COMPARATOR = /^(>=|<=|>|<|=)?\s*(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;

/**
 * Does `version` satisfy `range`?
 * Returns null when the range uses syntax this parser does not implement.
 */
export function satisfies(version: string, range: string): boolean | null {
  const v = parse(version);
  if (!v) return null;
  const trimmed = range.trim();
  if (trimmed === '' || trimmed === '*' || trimmed === 'x' || trimmed === 'all versions') return true;

  const alternatives = trimmed.split('||');
  let anyUnderstood = false;
  for (const alt of alternatives) {
    const parts = alt.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    let allMatch = true;
    let understood = true;
    for (const part of parts) {
      const m = COMPARATOR.exec(part);
      if (!m) {
        understood = false;
        break;
      }
      const op = m[1] ?? '=';
      const target = parse(m[2]!);
      if (!target) {
        understood = false;
        break;
      }
      const cmp = compare(v, target);
      const ok =
        op === '>' ? cmp > 0 : op === '>=' ? cmp >= 0 : op === '<' ? cmp < 0 : op === '<=' ? cmp <= 0 : cmp === 0;
      if (!ok) {
        allMatch = false;
        break;
      }
    }
    if (!understood) continue;
    anyUnderstood = true;
    if (allMatch) return true;
  }
  return anyUnderstood ? false : null;
}

/** Strip a declared range down to its version core, for display. */
export function coerce(spec: string): string | null {
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/.exec(spec);
  return m?.[1] ?? null;
}
