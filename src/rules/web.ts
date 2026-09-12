import { excerpt } from '../util/fsx.js';
import { declaresHeader, isEdgeConfigPath, isKubernetesEdgeConfig, SECURITY_HEADERS, surveyEdgeConfig } from '../util/edge.js';
import type { RuleHit } from '../types.js';
import { hit, type Rule } from './types.js';

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

const CSP_SOURCES = [
  { re: /<meta[^>]+http-equiv\s*=\s*["']?Content-Security-Policy/i, where: 'meta tag' },
  { re: /add_header\s+Content-Security-Policy/i, where: 'nginx add_header' },
  { re: /Content-Security-Policy\s*[:=]/i, where: 'header configuration' },
  { re: /contentSecurityPolicy/i, where: 'helmet/middleware configuration' },
  { re: /nginx\.ingress\.kubernetes\.io\/(?:configuration|server)-snippet[\s\S]{0,400}?Content-Security-Policy/i, where: 'ingress snippet annotation' },
];

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
    // Is this even a web app? Require an HTML entry document.
    const htmlFiles = Array.from(ctx.texts.keys()).filter((p) => /\.html?$/.test(p) && !p.includes('node_modules'));
    if (htmlFiles.length === 0) return [];
    const entry = htmlFiles.find((p) => /(^|\/)index\.html?$/.test(p)) ?? htmlFiles[0]!;

    // Every surface that could set a header, not just the ones this rule used to
    // know about. `charts/*/values.yaml` is where the header lives in a
    // Kubernetes deployment, and it was the file this rule never opened.
    const searchable = Array.from(ctx.texts.entries()).filter(([p]) => isEdgeConfigPath(p));

    const found: Array<{ where: string; path: string }> = [];
    for (const [path, text] of searchable) {
      for (const src of CSP_SOURCES) {
        if (src.re.test(text)) found.push({ where: src.where, path });
      }
    }
    if (found.length > 0) {
      // CSP exists somewhere — not a finding, but record where for the coverage note.
      return [];
    }

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

export const WEB_RULES: Rule[] = [cspMissingRule, sourcemapExposureRule];
