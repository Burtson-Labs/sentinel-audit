import { excerpt } from '../util/fsx.js';
import type { RuleHit } from '../types.js';
import { hit, type Rule } from './types.js';

/**
 * Web delivery rules: the headers and build settings that decide what an XSS
 * can do if one ever lands. These are deliberately aggregate — "this
 * application ships no CSP" is one finding, not one per HTML file.
 */

const CSP_SOURCES = [
  { re: /<meta[^>]+http-equiv\s*=\s*["']?Content-Security-Policy/i, where: 'meta tag' },
  { re: /add_header\s+Content-Security-Policy/i, where: 'nginx add_header' },
  { re: /Content-Security-Policy\s*[:=]/i, where: 'header configuration' },
  { re: /contentSecurityPolicy/i, where: 'helmet/middleware configuration' },
];

const HEADER_CHECKS: Array<{ name: string; re: RegExp; why: string }> = [
  { name: 'Content-Security-Policy', re: /Content-Security-Policy/i, why: 'decides whether an injected script can execute or exfiltrate' },
  { name: 'Strict-Transport-Security', re: /Strict-Transport-Security/i, why: 'prevents a downgrade to plaintext on the next visit' },
  { name: 'X-Content-Type-Options', re: /X-Content-Type-Options/i, why: 'stops MIME sniffing turning an upload into script' },
  { name: 'Referrer-Policy', re: /Referrer-Policy/i, why: 'keeps URLs (and ids in them) out of third-party logs' },
  { name: 'X-Frame-Options or frame-ancestors', re: /X-Frame-Options|frame-ancestors/i, why: 'prevents clickjacking of authenticated views' },
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

    const searchable = Array.from(ctx.texts.entries()).filter(
      ([p]) => /\.html?$/.test(p) || /nginx|\.conf$|headers|vercel\.json|netlify\.toml|staticwebapp\.config\.json|_headers$/i.test(p) || /vite\.config|next\.config|server\.(t|j)s/i.test(p),
    );

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

    const missingHeaders = HEADER_CHECKS.filter(
      (h) => !searchable.some(([, text]) => h.re.test(text)),
    ).map((h) => h.name);

    return [
      hit(
        cspMissingRule.id,
        entry,
        1,
        excerpt(ctx.texts.get(entry)?.split('\n').find((l) => /<head|<meta/i.test(l)) ?? '<head>'),
        `no Content-Security-Policy found in the HTML entry document or in any server/edge configuration in the repository; also absent: ${missingHeaders.filter((n) => n !== 'Content-Security-Policy').join(', ') || 'none'}`,
        { entry, missingHeaders: missingHeaders.join(','), htmlFiles: htmlFiles.length },
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
