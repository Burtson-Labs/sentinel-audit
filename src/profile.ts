import { dirname, join, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJsonSafe, exists } from './util/fsx.js';
import { buildTestPathPredicate, type TestPathConfig } from './util/testpaths.js';
import type { Severity, FindingType, StandardControl } from './types.js';

export interface Profile {
  id: string;
  title: string;
  description: string;
  reference?: string;
  severityFloor?: Partial<Record<FindingType, Severity>>;
  gate: { blockOn: Severity[]; conditionalOn: Severity[]; note: string };
  controls: Record<string, StandardControl[]>;
  /**
   * Which paths count as test/fixture/mock code. Credential and auth-storage
   * rules report at `Info` there instead of at their headline severity, because
   * in a test the construct is usually what is being exercised. Every repository
   * spells these directories differently, so the list is configurable.
   */
  testPaths?: TestPathConfig;
}

export const BUILTIN_PROFILE_IDS = ['owasp-asvs', 'cwe-top-25', 'generic-enterprise'] as const;
export type BuiltinProfileId = (typeof BUILTIN_PROFILE_IDS)[number];

function profilesDir(): string {
  // dist/profile.js -> ../profiles ; src/profile.ts -> ../profiles
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, '..', 'profiles'), join(here, '..', '..', 'profiles')];
  return candidates.find((c) => exists(c)) ?? candidates[0]!;
}

export function listProfiles(): string[] {
  return [...BUILTIN_PROFILE_IDS];
}

/**
 * Load a profile by builtin id or by path to a JSON file. A custom path is the
 * supported way to express an internal standards catalogue: fork
 * `profiles/generic-enterprise.json`, swap the control ids, pass the path.
 */
export function loadProfile(idOrPath: string): Profile {
  const direct = isAbsolute(idOrPath) || idOrPath.startsWith('.') || idOrPath.endsWith('.json');
  const path = direct ? resolve(idOrPath) : join(profilesDir(), `${idOrPath}.json`);
  if (!exists(path)) {
    throw new Error(
      `profile not found: ${idOrPath}\n  builtins: ${BUILTIN_PROFILE_IDS.join(', ')}\n  or pass a path to a profile JSON file`,
    );
  }
  const raw = readJsonSafe<Profile>(path);
  if (!raw) throw new Error(`profile is not valid JSON: ${path}`);
  const problems = validateProfile(raw);
  if (problems.length > 0) throw new Error(`invalid profile ${path}:\n  - ${problems.join('\n  - ')}`);
  return raw;
}

/** The profile's test/fixture path predicate, built once per scan. */
export function testPathPredicate(profile: Profile): (path: string) => boolean {
  return buildTestPathPredicate(profile.testPaths);
}

export function validateProfile(p: Partial<Profile>): string[] {
  const problems: string[] = [];
  if (!p.id) problems.push('missing id');
  if (!p.title) problems.push('missing title');
  if (p.testPaths) {
    if (p.testPaths.patterns !== undefined && !Array.isArray(p.testPaths.patterns)) {
      problems.push('testPaths.patterns must be an array of regex strings');
    }
    if (p.testPaths.mode !== undefined && p.testPaths.mode !== 'extend' && p.testPaths.mode !== 'replace') {
      problems.push('testPaths.mode must be "extend" or "replace"');
    }
    for (const src of p.testPaths.patterns ?? []) {
      try {
        new RegExp(src);
      } catch {
        problems.push(`testPaths.patterns entry is not a valid regular expression: ${src}`);
      }
    }
  }
  if (!p.controls || typeof p.controls !== 'object') problems.push('missing controls map');
  if (!p.gate) problems.push('missing gate');
  else {
    if (!Array.isArray(p.gate.blockOn)) problems.push('gate.blockOn must be an array');
    if (!Array.isArray(p.gate.conditionalOn)) problems.push('gate.conditionalOn must be an array');
  }
  for (const [ruleId, controls] of Object.entries(p.controls ?? {})) {
    if (!Array.isArray(controls)) {
      problems.push(`controls.${ruleId} must be an array`);
      continue;
    }
    for (const c of controls) {
      if (!c || typeof c.id !== 'string' || typeof c.title !== 'string') {
        problems.push(`controls.${ruleId} entries need {id,title}`);
        break;
      }
    }
  }
  return problems;
}

/** Controls for a rule id, falling back to the rule family prefix. */
export function controlsFor(profile: Profile, ruleId: string): StandardControl[] {
  const exact = profile.controls[ruleId];
  if (exact) return exact;
  // DEP-ADVISORY-LODASH -> DEP-ADVISORY
  const parts = ruleId.split('-');
  for (let take = parts.length - 1; take >= 2; take -= 1) {
    const candidate = parts.slice(0, take).join('-');
    const hit = profile.controls[candidate];
    if (hit) return hit;
  }
  return [];
}

export function standardMappingText(profile: Profile, ruleId: string): string {
  const controls = controlsFor(profile, ruleId);
  if (controls.length === 0) return `${profile.title}: no mapped control (general engineering quality)`;
  return `${profile.title}: ${controls.map((c) => `${c.id} — ${c.title}`).join('; ')}`;
}

const SEVERITY_ORDER: Severity[] = ['Info', 'Low', 'Medium', 'High', 'Blocker'];

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Apply the profile's per-type severity floor. */
export function applyFloor(profile: Profile, type: FindingType, severity: Severity): Severity {
  const floor = profile.severityFloor?.[type];
  return floor ? maxSeverity(severity, floor) : severity;
}
