import { matchCode } from '../util/lex.js';
import { excerpt, countLines } from '../util/fsx.js';
import type { RuleHit } from '../types.js';
import { hit, JS_TS, type Rule, type RuleRepoContext } from './types.js';

/**
 * Quality rules.
 *
 * These are aggregate by nature: one swallowed catch is a judgement call, two
 * hundred is a pattern. Each rule therefore reports a *density* with the worst
 * offenders as evidence, rather than emitting one finding per site — which is
 * how a scanner turns a real signal into 200 tickets nobody closes.
 */

const FILE_SIZE_WARN = 600;
const FILE_SIZE_FAIL = 1200;

export const swallowedCatchRule: Rule = {
  id: 'QUA-SWALLOWED-CATCH',
  title: 'Errors discarded by empty or comment-only catch blocks',
  type: 'Quality',
  severity: 'Medium',
  area: 'Shared',
  labels: ['quality', 'observability', 'error-handling'],
  claimType: 'factual',
  why:
    'A catch block with no body turns a failure into a silent wrong answer. At scale it means production problems surface as user reports instead of signals, and a security-relevant failure (a rejected token, a refused write) looks identical to success.',
  recommendation:
    'Decide per site: log with context, rethrow as a typed error, or — when ignoring truly is correct — keep the empty block but name the reason in a comment so the next reader does not have to guess. Ban the unexplained form with a lint rule.',
  acceptance: [
    'no catch block is both empty and unexplained',
    'deliberate ignores carry a one-line reason',
    'a lint rule fails the build on a new unexplained empty catch',
  ],
  effort: 'L',
  appliesTo: JS_TS,
  aggregate: (ctx) => {
    const hits: RuleHit[] = [];
    for (const [path, masked] of ctx.masked) {
      const src = ctx.texts.get(path);
      if (!src) continue;
      for (const m of matchCode(src, masked, /catch\s*(?:\(([^)]*)\))?\s*\{([^{}]{0,200})\}/g)) {
        const body = m.match[2] ?? '';
        // body is masked: comments already became spaces, so an "empty" body
        // here means empty-or-comment-only in the real source.
        if (body.trim().length > 0) continue;
        const realBody = src.slice(m.index, m.index + m.match[0].length);
        const hasComment = /\/\/|\/\*/.test(realBody);
        hits.push(
          hit(
            swallowedCatchRule.id,
            path,
            m.line,
            excerpt(m.lineText),
            hasComment ? 'catch block with only a comment' : 'empty catch block',
            { explained: hasComment, inTest: ctx.isTest(path) },
          ),
        );
      }
    }
    return hits;
  },
  maxEvidence: 8,
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Add the lint rule first so the count cannot grow, then work the list down by module. Each site needs a decision (log / rethrow / document), and that decision is context-specific.',
    changes: [
      { path: 'eslint.config.js', change: 'enable no-empty with allowEmptyCatch:false so new sites fail the build' },
      ...topFiles(hits).map((p) => ({ path: p, change: 'log, rethrow, or document each discarded error' })),
    ],
    acceptanceTests: [{ path: 'n/a — enforced by lint', description: 'lint fails on a new unexplained empty catch' }],
    risk: 'low',
    estimatedDiffSize: `${hits.length} sites across ${new Set(hits.map((h) => h.file)).size} files`,
    notAgentExecutableReason:
      'Whether a given error should be logged, rethrown, or genuinely ignored is a per-site judgement; an agent applying one policy everywhere would add noise or change control flow.',
  }),
};

export const consoleLoggingRule: Rule = {
  id: 'QUA-CONSOLE-LOGGING',
  title: 'console.* used as the production logging mechanism',
  type: 'Quality',
  severity: 'Low',
  area: 'Shared',
  labels: ['quality', 'observability'],
  claimType: 'factual',
  why:
    'console output has no level filtering, no structure, no correlation id, and no redaction. It cannot be queried in an incident, and it is the most common way credential-shaped values reach a log aggregator.',
  recommendation: 'Route logging through one module with levels and redaction; keep console for CLI user-facing output only, behind an explicit "this is UI" helper.',
  acceptance: ['application code logs through a single abstraction', 'credential-shaped fields are redacted centrally', 'a lint rule restricts direct console use to the designated output module'],
  effort: 'M',
  appliesTo: JS_TS,
  aggregate: (ctx) => {
    const hits: RuleHit[] = [];
    for (const [path, masked] of ctx.masked) {
      if (ctx.isTest(path)) continue;
      const src = ctx.texts.get(path);
      if (!src) continue;
      const matches = matchCode(src, masked, /\bconsole\s*\.\s*(log|info|warn|error|debug|trace)\s*\(/g);
      if (matches.length === 0) continue;
      const first = matches[0]!;
      hits.push(
        hit(consoleLoggingRule.id, path, first.line, excerpt(first.lineText), `${matches.length} direct console call(s) in this module`, {
          count: matches.length,
        }),
      );
    }
    return hits.sort((a, b) => Number(b.meta?.count ?? 0) - Number(a.meta?.count ?? 0));
  },
  maxEvidence: 8,
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Introduce a logger module with levels and redaction, migrate module by module, then restrict console with a lint rule.',
    changes: [
      { path: 'src/observability/logger.ts', change: 'new module: levelled structured logger with redaction' },
      ...topFiles(hits).map((p) => ({ path: p, change: 'replace console calls with the logger' })),
    ],
    acceptanceTests: [{ path: 'test/observability/logger.test.ts', description: 'credential-shaped fields are redacted; levels filter as configured' }],
    risk: 'low',
    estimatedDiffSize: `${hits.reduce((n, h) => n + Number(h.meta?.count ?? 0), 0)} call sites`,
    notAgentExecutableReason: 'Log destination and levels are operational choices; a blanket rewrite also silences CLI output users rely on.',
  }),
};

export const anyDensityRule: Rule = {
  id: 'QUA-ANY-DENSITY',
  title: 'TypeScript escape hatches weaken the type guarantee',
  type: 'Tech Debt',
  severity: 'Low',
  area: 'Shared',
  labels: ['quality', 'types'],
  claimType: 'factual',
  why:
    '`any`, `as unknown as`, and `@ts-ignore` each switch off checking at a boundary. A handful at genuine trust boundaries is correct engineering; a high density means the compiler is no longer the thing that catches refactors, and `strict` in the config overstates the real guarantee.',
  recommendation: 'Type the trust boundaries once (a parser or validator per external input) and make the interior honest. Treat `no-explicit-any` as an error with narrow, reviewed exceptions.',
  acceptance: ['escape-hatch density is measured in CI and does not increase', 'no-explicit-any is an error with file-scoped exceptions', 'each remaining suppression carries a reason'],
  effort: 'L',
  appliesTo: (f) => ['.ts', '.tsx', '.mts', '.cts'].includes(f.ext),
  aggregate: (ctx) => {
    const hits: RuleHit[] = [];
    let totalAny = 0;
    let totalLoc = 0;
    const perFile: Array<{ path: string; count: number; loc: number; line: number; text: string }> = [];
    for (const [path, masked] of ctx.masked) {
      if (!/\.(ts|tsx|mts|cts)$/.test(path)) continue;
      const src = ctx.texts.get(path);
      if (!src) continue;
      const loc = countLines(src);
      totalLoc += loc;
      const matches = [
        ...matchCode(src, masked, /:\s*any\b|\bas\s+any\b|<any>|\bany\[\]|Array<any>|Record<string,\s*any>/g),
        ...matchCode(src, masked, /@ts-(?:ignore|nocheck|expect-error)/g),
        ...matchCode(src, masked, /\bas\s+unknown\s+as\b/g),
      ];
      if (matches.length === 0) continue;
      totalAny += matches.length;
      const first = matches[0]!;
      perFile.push({ path, count: matches.length, loc, line: first.line, text: first.lineText });
    }
    if (totalLoc === 0) return [];
    const perKloc = (totalAny / totalLoc) * 1000;
    if (perKloc < 2 && totalAny < 25) return [];
    perFile.sort((a, b) => b.count - a.count);
    for (const f of perFile.slice(0, 10)) {
      hits.push(
        hit(anyDensityRule.id, f.path, f.line, excerpt(f.text), `${f.count} escape hatch(es) in ${f.loc} LOC`, {
          count: f.count,
          perKloc: Number(perKloc.toFixed(2)),
          totalAny,
          totalLoc,
        }),
      );
    }
    return hits;
  },
  maxEvidence: 10,
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Add a density check to CI to stop growth, then type the external-input boundaries so interior annotations can be removed.',
    changes: [
      { path: 'eslint.config.js', change: 'promote no-explicit-any to error with narrow file-scoped exceptions' },
      ...topFiles(hits).map((p) => ({ path: p, change: 'introduce real types at the boundary and drop interior escape hatches' })),
    ],
    acceptanceTests: [{ path: 'n/a — enforced by lint and a density check', description: 'escape-hatch count does not increase' }],
    risk: 'low',
    estimatedDiffSize: `${hits[0]?.meta?.totalAny ?? 0} sites`,
    notAgentExecutableReason: 'Correct types must come from the real shape of the external data; an agent guessing them produces types that lie.',
  }),
};

export const fileSizeRule: Rule = {
  id: 'QUA-FILE-SIZE',
  title: 'Oversized modules are hostile to review',
  type: 'Tech Debt',
  severity: 'Low',
  area: 'Shared',
  labels: ['quality', 'maintainability'],
  claimType: 'factual',
  why:
    'A module past a few hundred lines cannot be reviewed in one pass, collects unrelated responsibilities, and becomes a merge-conflict magnet for every team touching the area. The cost is paid on every future change, including security fixes.',
  recommendation: `Split the largest modules along their responsibility seams and add a soft lint budget (warn above ${FILE_SIZE_WARN} LOC) so new files stay reviewable.`,
  acceptance: [`no module above ${FILE_SIZE_FAIL} LOC without a documented exception`, 'a lint budget warns above the threshold', 'extraction preserves behaviour under existing tests'],
  effort: 'XL',
  appliesTo: JS_TS,
  aggregate: (ctx) => {
    const rows: Array<{ path: string; loc: number }> = [];
    for (const [path, src] of ctx.texts) {
      if (!/\.(ts|tsx|js|jsx|mts|cts|mjs|cjs)$/.test(path)) continue;
      if (ctx.isTest(path)) continue;
      const loc = countLines(src);
      if (loc >= FILE_SIZE_FAIL) rows.push({ path, loc });
    }
    rows.sort((a, b) => b.loc - a.loc);
    return rows.slice(0, 10).map((r) => hit(fileSizeRule.id, r.path, 1, `${r.loc} LOC`, `module is ${r.loc} LOC (budget ${FILE_SIZE_WARN}, hard threshold ${FILE_SIZE_FAIL})`, { loc: r.loc }));
  },
  maxEvidence: 10,
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Extract cohesive units from the largest modules one at a time, leaning on existing tests as the safety net. Add the lint budget first so the trend reverses.',
    changes: topFiles(hits).map((p) => ({ path: p, change: 'extract cohesive units into sibling modules; keep the public surface stable' })),
    acceptanceTests: [{ path: 'existing suite', description: 'behaviour unchanged after extraction' }],
    risk: 'medium',
    estimatedDiffSize: `${hits.length} large modules`,
    notAgentExecutableReason: 'Finding the right seams is design work; a mechanical split produces modules that are smaller but no clearer.',
  }),
};

export const testThinnessRule: Rule = {
  id: 'QUA-TEST-THINNESS',
  title: 'Automated test coverage is thin relative to the shipped surface',
  type: 'Testing',
  severity: 'Medium',
  area: 'Testing',
  labels: ['testing', 'quality'],
  claimType: 'factual',
  why:
    'Without tests, every claim the code makes about itself is unverified, and a refactor cannot be distinguished from a regression. It matters most for security behaviour: a guard with no test is a guard that will be removed by a well-meaning cleanup.',
  recommendation: 'Write tests risk-first rather than coverage-first: every security guard, every data transform, every error path that changes what a user sees. Put a floor in CI and raise it as you go.',
  acceptance: ['every security-relevant behaviour has a test that fails when the guard is removed', 'a coverage floor is enforced in CI', 'the ratio of test to source modules is tracked'],
  effort: 'L',
  appliesTo: () => false,
  aggregate: (ctx) => {
    let source = 0;
    let tests = 0;
    for (const path of ctx.texts.keys()) {
      if (!/\.(ts|tsx|js|jsx|mts|cts|mjs|cjs|py|go|rs|cs|java|kt|rb)$/.test(path)) continue;
      if (ctx.isTest(path)) tests += 1;
      else source += 1;
    }
    if (source === 0) return [];
    const ratio = tests / source;
    if (ratio >= 0.25) return [];
    const severityNote = tests === 0 ? 'no test files at all' : `${tests} test module(s) for ${source} source module(s)`;
    return [
      hit(
        testThinnessRule.id,
        'package.json',
        1,
        `${tests} test modules / ${source} source modules`,
        `${severityNote} — ratio ${ratio.toFixed(3)}, below the 0.25 threshold`,
        { tests, source, ratio: Number(ratio.toFixed(3)) },
      ),
    ];
  },
  fixPlan: () => ({
    agentExecutable: false,
    strategy: 'Pick the highest-risk behaviours first (auth handling, rendering of untrusted content, data transforms) and write tests that fail when the protection is removed. Add a floor to CI once there is something to hold.',
    changes: [{ path: 'test/', change: 'add risk-first test modules starting with security-relevant behaviour' }],
    acceptanceTests: [{ path: 'test/', description: 'security guards covered by tests that fail when the guard is removed' }],
    risk: 'low',
    estimatedDiffSize: 'new test modules',
    notAgentExecutableReason: 'Deciding what is worth testing is the work; generated tests that assert current behaviour lock in bugs.',
  }),
};

export const todoDensityRule: Rule = {
  id: 'QUA-TODO-DENSITY',
  title: 'Deferred work tracked in comments rather than the issue tracker',
  type: 'Tech Debt',
  severity: 'Info',
  area: 'Shared',
  labels: ['tech-debt'],
  claimType: 'factual',
  why: 'TODO/FIXME/HACK markers are invisible to planning. Each one is a decision someone deferred without anyone agreeing to it, and security-relevant ones ("FIXME: validate this") never reach a backlog.',
  recommendation: 'Convert markers that matter into issues and reference the issue id in the comment; delete the rest.',
  acceptance: ['remaining markers reference a tracked issue', 'a CI check reports the count so it cannot drift upward silently'],
  effort: 'S',
  appliesTo: JS_TS,
  aggregate: (ctx) => {
    const perFile = new Map<string, { count: number; line: number; text: string; security: number }>();
    let total = 0;
    for (const [path, src] of ctx.texts) {
      if (!/\.(ts|tsx|js|jsx|mts|cts|mjs|cjs)$/.test(path)) continue;
      const lines = src.split('\n');
      for (const [i, line] of lines.entries()) {
        const m = /(?:\/\/|\/\*|\*)\s*(TODO|FIXME|HACK|XXX|BUG)\b/.exec(line);
        if (!m) continue;
        total += 1;
        const existing = perFile.get(path) ?? { count: 0, line: i + 1, text: line, security: 0 };
        existing.count += 1;
        if (/auth|secur|token|secret|validat|sanit|escape|permission|inject/i.test(line)) existing.security += 1;
        perFile.set(path, existing);
      }
    }
    if (total < 20) return [];
    return Array.from(perFile.entries())
      .sort((a, b) => b[1].security - a[1].security || b[1].count - a[1].count)
      .slice(0, 8)
      .map(([path, v]) =>
        hit(todoDensityRule.id, path, v.line, excerpt(v.text), `${v.count} deferred-work marker(s)${v.security > 0 ? `, ${v.security} with security-relevant wording` : ''}`, {
          count: v.count,
          security: v.security,
          total,
        }),
      );
  },
  maxEvidence: 8,
  fixPlan: () => ({
    agentExecutable: false,
    strategy: 'Triage the markers: security-relevant ones become issues immediately, the rest are converted or deleted.',
    changes: [{ path: '<various>', change: 'convert markers to tracked issues and reference the id' }],
    acceptanceTests: [{ path: 'n/a', description: 'marker count reported in CI' }],
    risk: 'low',
    estimatedDiffSize: 'comment edits only',
    notAgentExecutableReason: 'Deciding which deferred work still matters needs product context.',
  }),
};

function topFiles(hits: RuleHit[]): string[] {
  return Array.from(new Set(hits.map((h) => h.file))).slice(0, 6);
}

export const QUALITY_RULES: Rule[] = [
  swallowedCatchRule,
  consoleLoggingRule,
  anyDensityRule,
  fileSizeRule,
  testThinnessRule,
  todoDensityRule,
];

export { FILE_SIZE_WARN, FILE_SIZE_FAIL };
export type { RuleRepoContext };
