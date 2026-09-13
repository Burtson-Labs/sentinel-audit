import { maskSource, type MaskedSource } from '../util/lex.js';
import { readTextSafe, type RepoFile } from '../util/fsx.js';
import { isTestOrFixturePath } from '../util/testpaths.js';
import type { CollectorRun, RuleHit } from '../types.js';
import { SECURITY_RULES } from './security.js';
import { CRYPTO_RULES } from './crypto.js';
import { SERVER_RULES } from './server.js';
import { QUALITY_RULES } from './quality.js';
import { WEB_RULES } from './web.js';
import type { Rule, RuleFileContext, RuleRepoContext } from './types.js';

export const ALL_RULES: Rule[] = [...SECURITY_RULES, ...CRYPTO_RULES, ...SERVER_RULES, ...QUALITY_RULES, ...WEB_RULES];

export function ruleById(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export interface RuleEngineResult {
  hits: RuleHit[];
  run: CollectorRun;
  repoContext: RuleRepoContext;
}

/**
 * Runs every rule. Per-file rules see a masked copy of each source file;
 * aggregate rules see the whole repository at once.
 *
 * Files are read once and shared, so the cost is one pass over the tree no
 * matter how many rules are registered.
 */
export function runRules(
  root: string,
  files: RepoFile[],
  options: {
    maxFileBytes?: number;
    /**
     * Which paths count as test/fixture code. Supplied by the profile so a
     * repository can name its own directories; falls back to the built-in set.
     */
    isTest?: (path: string) => boolean;
  } = {},
): RuleEngineResult {
  const started = Date.now();
  const isTest = options.isTest ?? isTestOrFixturePath;
  const texts = new Map<string, string>();
  const masked = new Map<string, MaskedSource>();
  const skipped: string[] = [];
  const maxFileBytes = options.maxFileBytes ?? 1_500_000;

  const vendored: string[] = [];
  const allText = files.filter((f) => !f.binary);
  for (const f of allText) {
    if (f.bytes > maxFileBytes) {
      skipped.push(`${f.path} (${Math.round(f.bytes / 1024)} KiB exceeds the ${Math.round(maxFileBytes / 1024)} KiB per-file limit)`);
      continue;
    }
    const text = readTextSafe(f.absolute, maxFileBytes);
    if (text === null) continue;
    texts.set(f.path, text);
  }

  // Vendored and bundled artefacts are read (reporters and verifiers search
  // them) but excluded from the code rules. Reporting `exec()` inside a
  // checked-in 47 KiB bundle is how a scanner trains its reader to ignore it:
  // the finding is not actionable, the line number is meaningless, and the code
  // is not this repository's to change.
  const textFiles = allText.filter((f) => {
    const text = texts.get(f.path);
    if (text === undefined) return false;
    if (!isVendoredArtifact(f.path, text)) return true;
    vendored.push(f.path);
    return false;
  });

  // Mask only what a rule might need to match against.
  for (const [path, text] of texts) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts|json|html?|conf|ya?ml|env|sh|md|toml)$/.test(path) && path.includes('.')) continue;
    masked.set(path, maskSource(text));
  }

  const ruleTexts = new Map(textFiles.map((f) => [f.path, texts.get(f.path)!] as const));
  const ruleMasked = new Map([...masked].filter(([p]) => ruleTexts.has(p)));
  const repoContext: RuleRepoContext = { root, files: textFiles, texts: ruleTexts, masked: ruleMasked, isTest };
  const hits: RuleHit[] = [];
  const ruleErrors: string[] = [];

  for (const rule of ALL_RULES) {
    try {
      if (rule.scan) {
        for (const f of textFiles) {
          if (rule.appliesTo && !rule.appliesTo(f)) continue;
          const src = texts.get(f.path);
          const m = masked.get(f.path);
          if (src === undefined || m === undefined) continue;
          const ctx: RuleFileContext = { file: f, src, masked: m, isTest: isTest(f.path), root };
          hits.push(...rule.scan(ctx));
        }
      }
      if (rule.aggregate) hits.push(...rule.aggregate(repoContext));
    } catch (err) {
      // A rule that throws must not take the scan down; the failure is reported
      // in COVERAGE.md so the report never silently loses a rule.
      ruleErrors.push(`${rule.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const notExamined = [
    'rules are lexical (comment/string-aware regex), not full-AST: cross-module data flow is not tracked, so a sanitiser or guard called from another module is not seen',
    'non-JS/TS languages get secret, dependency, CI and container coverage only — no language-specific security rules',
  ];
  if (skipped.length > 0) notExamined.push(`files skipped for size: ${skipped.slice(0, 5).join('; ')}${skipped.length > 5 ? ` (+${skipped.length - 5} more)` : ''}`);
  if (vendored.length > 0) {
    notExamined.push(
      `vendored/bundled artefacts excluded from the code rules (read, but not this repository's source to change): ${vendored.slice(0, 6).join(', ')}${vendored.length > 6 ? ` (+${vendored.length - 6} more)` : ''}`,
    );
  }
  if (ruleErrors.length > 0) notExamined.push(`rules that errored and produced no findings: ${ruleErrors.join('; ')}`);

  return {
    hits,
    repoContext,
    run: {
      name: 'rules',
      ok: ruleErrors.length === 0,
      durationMs: Date.now() - started,
      note: `${ALL_RULES.length} rules over ${ruleTexts.size} source files (${vendored.length} vendored/bundled excluded) produced ${hits.length} raw hits`,
      notExamined,
    },
  };
}

/**
 * Is this a build output, a minified bundle, or vendored third-party code?
 *
 * Signals, any one of which is enough: a vendor-ish directory, a `.min.` name, a
 * sourcemap comment, a generated-file banner, or a line long enough that only a
 * bundler would write it.
 */
export function isVendoredArtifact(path: string, text: string): boolean {
  if (/(^|\/)(vendor|vendors|third[_-]?party|externals?|bundled?|lib\/generated|\.yarn)\//i.test(path)) return true;
  if (/\.(min|bundle|chunk|umd|iife)\.(js|mjs|cjs|css)$/i.test(path)) return true;
  if (/(^|\/)(dist|build|out|release|public\/assets)\//.test(path)) return true;
  if (/sourceMappingURL=/.test(text)) return true;
  if (/^\s*(?:\/\/|\/\*|#)\s*(?:@generated|generated by|DO NOT EDIT|auto-generated|prettier-ignore-start)/im.test(text.slice(0, 2000))) {
    return true;
  }
  let longest = 0;
  let lines = 0;
  for (const line of text.split('\n')) {
    longest = Math.max(longest, line.length);
    lines += 1;
    if (lines > 400 && longest < 400) break; // clearly hand-written
  }
  return longest > 1500;
}

export { SECURITY_RULES, CRYPTO_RULES, SERVER_RULES, QUALITY_RULES, WEB_RULES };
export type { Rule, RuleFileContext, RuleRepoContext };
