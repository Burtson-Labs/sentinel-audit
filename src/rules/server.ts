import { matchCode } from '../util/lex.js';
import { excerpt } from '../util/fsx.js';
import type { RuleHit } from '../types.js';
import { hit, JS_TS, type Rule } from './types.js';

/**
 * Server-surface rules.
 *
 * The interesting one is SEC-UNAUTH-HANDLER. Naive versions of this check are
 * famously noisy, so it only fires when *no* authentication-shaped token
 * appears anywhere in the registration chain: not in the route's middleware
 * list, not on the router the route hangs off, and not as a global `app.use`
 * earlier in the file. When a global guard exists the rule stays silent and
 * records that fact, because "we found a route" is not a finding.
 */

const AUTH_TOKEN = /\b(auth|authn|authz|authenticate|authorize|requireAuth|ensureAuth|isAuthenticated|verifyToken|verifyJwt|jwtVerify|bearer|passport|guard|requireUser|withAuth|checkPermission|requireRole|session|apiKey|protect|csrf)\b/i;
const PUBLIC_BY_DESIGN = /\b(health|healthz|readyz|livez|ping|status|metrics|version|favicon|robots|\.well-known|openapi|swagger|docs|login|signin|signup|register|logout|callback|oauth|webhook|public)\b/i;

const ROUTE_RE = /\b(?:app|router|server|api|fastify|hono|instance|r)\s*\.\s*(get|post|put|patch|delete|options|head|all|route)\s*\(\s*(['"`])([^'"`]*)\2\s*([^)]{0,400})/g;

export const unauthHandlerRule: Rule = {
  id: 'SEC-UNAUTH-HANDLER',
  title: 'HTTP handler registered with no authentication in its chain',
  type: 'Security',
  severity: 'Blocker',
  area: 'API',
  labels: ['security', 'api', 'auth'],
  claimType: 'factual',
  why:
    'A network-exposed handler with no authentication is reachable by anything that can reach the port. Whatever the handler does — read data, write files, run work — becomes available without a credential, and without a principal there is nothing to attribute the request to afterwards.',
  recommendation:
    'Apply authentication as a router-level default so new routes inherit it, and make "public" an explicit, enumerated exception list. Reject with 401 before any handler body runs.',
  acceptance: [
    'every route either sits behind an authentication middleware or appears on an explicit public allowlist',
    'a test asserts 401 for each non-public route without a credential',
    'a test asserts the authenticated path still works',
    'new routes inherit the default rather than opting in',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    if (ctx.isTest) return [];
    const hits: RuleHit[] = [];
    // A global guard anywhere in the file covers every route below it.
    const globalGuard = matchCode(ctx.src, ctx.masked, /\b(?:app|server|router|fastify|instance)\s*\.\s*(?:use|addHook|register)\s*\(([^)]{0,200})/g)
      .find((m) => AUTH_TOKEN.test(m.match[1] ?? '') || AUTH_TOKEN.test(m.lineText));

    // Route paths are string literals, so match the comments-blanked view.
    const withStrings = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, withStrings, ROUTE_RE)) {
      const method = m.match[1]!;
      const path = m.match[3] ?? '';
      const rest = m.match[4] ?? '';
      if (method === 'route' && rest.trim().length === 0) continue;
      const chain = `${rest}\n${m.lineText}`;
      if (AUTH_TOKEN.test(chain)) continue;
      if (globalGuard && globalGuard.index < m.index) continue;
      const publicByDesign = PUBLIC_BY_DESIGN.test(path);
      hits.push(
        hit(
          unauthHandlerRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          `${method.toUpperCase()} ${path || '/'} registered with no authentication token in its middleware chain${publicByDesign ? ' (path looks intentionally public)' : ''}`,
          { method, route: path, publicByDesign, hasGlobalGuard: Boolean(globalGuard) },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Add one authentication middleware mounted at the router level so routes inherit it, then move genuinely public routes onto an explicit allowlist. Add a test per route asserting 401 without a credential.',
    changes: [
      { path: 'src/middleware/requireAuth.ts', change: 'new middleware: verify the credential, 401 on absence or invalidity, attach the principal' },
      ...Array.from(new Set(hits.map((h) => h.file))).map((p) => ({ path: p, change: 'mount requireAuth at the router level; list public routes explicitly' })),
    ],
    acceptanceTests: [
      { path: 'test/api/auth.test.ts', description: '401 without a credential for each non-public route; success with a valid one' },
      { path: 'test/api/publicAllowlist.test.ts', description: 'the public allowlist matches the documented set exactly' },
    ],
    risk: 'high',
    estimatedDiffSize: 'one middleware module plus router wiring, and one test file',
    notAgentExecutableReason:
      'The credential format and the issuer are deployment decisions; an agent inventing a scheme would produce a guard that rejects legitimate traffic or accepts forged tokens.',
  }),
};

export const swallowedErrorServerRule: Rule = {
  id: 'SEC-NO-REQUEST-LOGGING',
  title: 'HTTP surface with no request logging or correlation id',
  type: 'Security',
  severity: 'Medium',
  area: 'API',
  labels: ['security', 'observability', 'api'],
  claimType: 'factual',
  why:
    'Without a per-request log line carrying a correlation id, an incident cannot be reconstructed: you cannot say who called, when, with what, or what the service did in response. That turns every security question about the service into an unanswerable one.',
  recommendation: 'Log one structured line per request (method, path, status, duration, principal, correlation id), propagate the id to downstream calls, and redact credential-shaped values.',
  acceptance: ['one structured log line per request including a correlation id', 'the id propagates to outbound calls', 'a test asserts the id appears in both the response header and the log line'],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    if (ctx.isTest) return [];
    const routes = matchCode(ctx.src, { ...ctx.masked, code: ctx.masked.codeAndStrings }, ROUTE_RE);
    if (routes.length === 0) return [];
    const hasLogging = /\b(requestId|correlationId|traceId|x-request-id|pino|winston|morgan|bunyan|httpLogger|onRequest.*log)\b/i.test(ctx.src);
    if (hasLogging) return [];
    const first = routes[0]!;
    return [
      hit(
        swallowedErrorServerRule.id,
        ctx.file.path,
        first.line,
        excerpt(first.lineText),
        `${routes.length} HTTP route(s) registered in this module with no request-logging or correlation-id mechanism anywhere in the file`,
        { routeCount: routes.length },
      ),
    ];
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Add a request-logging middleware that assigns or adopts a correlation id, logs one structured line per request, and echoes the id in a response header.',
    changes: Array.from(new Set(hits.map((h) => h.file))).map((p) => ({ path: p, change: 'mount a request-logging middleware ahead of the routes' })),
    acceptanceTests: [{ path: 'test/api/requestLogging.test.ts', description: 'every request produces one structured line with an id echoed in the response header' }],
    risk: 'low',
    estimatedDiffSize: 'one middleware plus wiring',
    notAgentExecutableReason: 'Log destination, format and retention are operational decisions outside the repository.',
  }),
};

export const SERVER_RULES: Rule[] = [unauthHandlerRule, swallowedErrorServerRule];
