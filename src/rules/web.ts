import { excerpt } from '../util/fsx.js';
import { declaresHeader, isEdgeConfigPath, isKubernetesEdgeConfig, SECURITY_HEADERS, surveyCsp, surveyEdgeConfig } from '../util/edge.js';
import type { RuleHit } from '../types.js';
import { hit, type Rule, type RuleRepoContext } from './types.js';

/**
 * Web delivery rules: the headers and build settings that decide what an XSS
 * can do if one ever lands. These are deliberately aggregate — "this
 * application ships no CSP" is one finding, not one per HTML file.
 *
 * Header *absence* is checked against every surface that could set one,
 * including Helm charts and ingress annotations (see util/edge.ts). A header set
 * by `nginx.ingress.kubernetes.io/hsts` is set; a rule that only reads nginx
 * confs and calls it missing is reporting its own blind spot as the
 * application's defect.
 */

/**
 * Is this a web application at all, and which surfaces could carry the header?
 *
 * Shared by the two CSP rules so they cannot disagree about what they searched:
 * one reports the header absent, the other reports it present-but-inert, and
 * exactly one of them may fire.
 */
function cspSurfaces(ctx: RuleRepoContext): { entry: string; htmlFiles: string[]; searchable: Array<readonly [string, string]> } | null {
  // Require an HTML entry document.
  const htmlFiles = Array.from(ctx.texts.keys()).filter((p) => /\.html?$/.test(p) && !p.includes('node_modules'));
  if (htmlFiles.length === 0) return null;
  const entry = htmlFiles.find((p) => /(^|\/)index\.html?$/.test(p)) ?? htmlFiles[0]!;
  // Every surface that could set a header, not just the ones this rule used to
  // know about. `charts/*/values.yaml` is where the header lives in a
  // Kubernetes deployment, and it was the file this rule never opened.
  const searchable = Array.from(ctx.texts.entries()).filter(([p]) => isEdgeConfigPath(p));
  return { entry, htmlFiles, searchable };
}

export const cspMissingRule: Rule = {
  id: 'SEC-CSP-MISSING',
  title: 'Web application ships without a Content-Security-Policy',
  type: 'Security',
  severity: 'Medium',
  area: 'Build',
  labels: ['security', 'headers', 'web'],
  claimType: 'factual',
  why:
    'CSP is the control that decides what an injected script is allowed to do. Without it, one XSS — including one arriving through a dependency — has the full capability of the origin: read web storage, call the API with the user\'s credentials, and exfiltrate to any host. It is the single highest-leverage header for an application that renders any untrusted content.',
  recommendation:
    'Serve a CSP from the edge (the server or CDN that serves index.html), starting in report-only mode to find violations, then enforce. Prefer `default-src \'self\'` with explicit exceptions for the API origin and any required font/style source, and avoid `unsafe-inline` for scripts.',
  acceptance: [
    'index.html responses carry a Content-Security-Policy header (not only a meta tag)',
    'the policy denies inline script and restricts connect-src to the known API origins',
    'a report-only period is documented and violations triaged before enforcement',
    'a test or smoke check asserts the header is present on a served response',
  ],
  effort: 'M',
  appliesTo: () => false,
  aggregate: (ctx) => {
    const surfaces = cspSurfaces(ctx);
    if (!surfaces) return [];
    const { entry, htmlFiles, searchable } = surfaces;

    // Only an *enforcing* header clears this finding. `Content-Security-Policy-
    // Report-Only` blocks nothing, so an application that ships only that one
    // ships no policy — it gets SEC-CSP-REPORT-ONLY instead of this, which is
    // why report-only returns empty here rather than falling through.
    const csp = surveyCsp(searchable);
    if (csp.posture !== 'none') return [];

    const missingHeaders = SECURITY_HEADERS.filter((h) => !searchable.some(([, text]) => declaresHeader(h, text))).map((h) => h.name);

    const survey = surveyEdgeConfig(searchable);
    const k8sEdge = searchable.filter(([, text]) => isKubernetesEdgeConfig(text)).map(([p]) => p);

    return [
      hit(
        cspMissingRule.id,
        entry,
        1,
        excerpt(ctx.texts.get(entry)?.split('\n').find((l) => /<head|<meta/i.test(l)) ?? '<head>'),
        `no Content-Security-Policy found in the HTML entry document or in any of the ${searchable.length} server/edge configuration file(s) in the repository${
          k8sEdge.length > 0 ? ` (including ${k8sEdge.length} Kubernetes/Helm edge manifest(s))` : ''
        }; also absent: ${missingHeaders.filter((n) => n !== 'Content-Security-Policy').join(', ') || 'none'}${
          survey.unresolved.length > 0 ? `. ${survey.unresolved.length} edge surface(s) could not be evaluated from this repository` : ''
        }`,
        {
          entry,
          missingHeaders: missingHeaders.join(','),
          htmlFiles: htmlFiles.length,
          edgeSurfaces: searchable.length,
          k8sEdgeSurfaces: k8sEdge.length,
          unresolvedEdge: survey.unresolved.slice(0, 3).join(' | '),
        },
      ),
    ];
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Add the header at the layer that serves index.html, in report-only mode first. A meta tag is a weaker fallback (it cannot express frame-ancestors or report endpoints) but is better than nothing when the edge is not in this repository.',
    changes: [
      { path: hits[0]?.file ?? 'index.html', change: 'optionally add a meta CSP as a fallback' },
      { path: '<edge/server config>', change: 'set Content-Security-Policy-Report-Only, then Content-Security-Policy, plus HSTS, X-Content-Type-Options, Referrer-Policy and frame-ancestors' },
    ],
    acceptanceTests: [{ path: 'test/security/headers.test.ts', description: 'a served response carries the expected security headers' }],
    risk: 'medium',
    estimatedDiffSize: 'a handful of configuration lines',
    notAgentExecutableReason:
      'A policy that is wrong breaks the application at runtime in ways tests usually do not catch, and the correct connect-src list is deployment knowledge.',
  }),
};

export const cspReportOnlyRule: Rule = {
  id: 'SEC-CSP-REPORT-ONLY',
  title: 'Content-Security-Policy is report-only, so it enforces nothing',
  type: 'Security',
  // Low, deliberately. A report-only policy is the correct *first* step and
  // means someone has already done the hard part; it is one header rename away
  // from being a control. Reporting it at the severity of a missing policy would
  // punish the team that did the work.
  severity: 'Low',
  area: 'Build',
  labels: ['security', 'headers', 'web'],
  claimType: 'factual',
  why:
    'A `Content-Security-Policy-Report-Only` header is a measurement, not a control: the browser evaluates the policy, reports what it would have blocked, and then renders the page exactly as it would have without the header. Until the header is renamed, an injected script has the full capability of the origin — the protection the policy describes is not in force. The risk is that the header *looks* like a CSP to everything that checks for one, including scanners, so a repository can sit in report-only mode for years believing it is protected.',
  recommendation:
    'Collect violations for a defined period, fix or allowlist each one, then rename the header to `Content-Security-Policy`. Keep a report-only copy alongside the enforcing one if you want to keep testing a tighter policy — both headers may be sent at once, which is how the next tightening is staged.',
  acceptance: [
    'an enforcing Content-Security-Policy header is served on index.html responses',
    'the report-only period produced zero unexplained violations before the flip',
    'a test or smoke check asserts the enforcing header (not only the report-only one) is present on a served response',
  ],
  effort: 'S',
  appliesTo: () => false,
  aggregate: (ctx) => {
    const surfaces = cspSurfaces(ctx);
    if (!surfaces) return [];
    const csp = surveyCsp(surfaces.searchable);
    // Enforcing anywhere means the application has a policy; a report-only
    // header alongside it is a staging copy, which is good practice.
    if (csp.posture !== 'report-only') return [];
    const first = csp.reportOnly[0]!;
    return [
      hit(
        cspReportOnlyRule.id,
        first.path,
        first.line,
        excerpt(first.excerpt),
        `CSP is report-only — it reports violations but blocks nothing. The policy is declared at ${first.path}:${first.line} (${first.where}) as Content-Security-Policy-Report-Only, and no enforcing Content-Security-Policy header was found on any of the ${surfaces.searchable.length} server/edge configuration surface(s) in this repository`,
        {
          reportOnlyAt: `${first.path}:${first.line}`,
          where: first.where,
          declarations: csp.reportOnly.length,
          edgeSurfaces: surfaces.searchable.length,
        },
      ),
    ];
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Rename the header from `Content-Security-Policy-Report-Only` to `Content-Security-Policy` once the violation log is clean. The policy text does not change; what changes is whether the browser acts on it.',
    changes: [{ path: hits[0]?.file ?? '<edge/server config>', change: 'rename the report-only header to the enforcing one once violations are triaged' }],
    acceptanceTests: [{ path: 'test/security/headers.test.ts', description: 'a served response carries an enforcing Content-Security-Policy header' }],
    risk: 'medium',
    estimatedDiffSize: 'one header name',
    notAgentExecutableReason:
      'Flipping the header is what makes the policy break things. Whether the violation log is clean enough to enforce is an operational judgement, and an agent that renames the header unsupervised ships the outage the report-only period exists to prevent.',
  }),
};

export const sourcemapExposureRule: Rule = {
  id: 'SEC-SOURCEMAP-PUBLISHED',
  title: 'Production build publishes source maps',
  type: 'Security',
  severity: 'Low',
  area: 'Build',
  labels: ['security', 'build'],
  claimType: 'factual',
  why:
    'Published source maps hand a reader the original module layout, comments and internal endpoint names. That is not a vulnerability by itself, but it removes the cost of reconnaissance — and comments frequently mention the things the code is careful about.',
  recommendation: 'Disable source maps in production builds, or upload them to the error-tracking service and exclude them from the deployed artefact.',
  acceptance: ['production bundles ship without .map files', 'maps are retained for error tracking out of band'],
  effort: 'S',
  appliesTo: () => false,
  aggregate: (ctx) => {
    const hits: RuleHit[] = [];
    for (const [path, text] of ctx.texts) {
      if (!/(vite|webpack|rollup|next|tsup|esbuild)\.config\.[cm]?[jt]s$/.test(path)) continue;
      const m = /sourcemap\s*:\s*(true|['"]inline['"]|['"]both['"])/i.exec(text);
      if (!m) continue;
      const line = text.slice(0, m.index).split('\n').length;
      const conditional = /mode\s*===|isProd|NODE_ENV|command\s*===/.test(
        text.slice(Math.max(0, m.index - 200), m.index + 200),
      );
      if (conditional) continue;
      hits.push(hit(sourcemapExposureRule.id, path, line, excerpt(m[0]), 'bundler configured to emit source maps unconditionally', { setting: m[1] ?? 'true' }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Make sourcemap emission conditional on the development mode, or switch it to "hidden" so maps exist for upload but are not referenced by the bundle.',
    changes: (hits.length > 0 ? hits.map((h) => h.file) : ['<bundler config>']).map((p) => ({ path: p, change: 'gate sourcemap on development mode or set it to "hidden"' })),
    acceptanceTests: [{ path: 'test/build/sourcemaps.test.ts', description: 'production build output contains no .map reference' }],
    risk: 'low',
    estimatedDiffSize: 'one configuration line',
    agentPrompt:
      'In each flagged bundler configuration, make source-map emission conditional so production builds do not publish maps: either gate the option on the development mode/command, or set it to "hidden" if the project uploads maps to an error tracker. Do not change any other build setting.',
  }),
};

export const WEB_RULES: Rule[] = [cspMissingRule, cspReportOnlyRule, sourcemapExposureRule];
