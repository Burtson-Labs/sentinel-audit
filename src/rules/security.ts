import { matchCode, windowAfter } from '../util/lex.js';
import { excerpt } from '../util/fsx.js';
import { publishableKeyMatch } from '../collectors/secrets.js';
import type { RuleHit } from '../types.js';
import { hit, JS_TS, type Rule, type RuleFileContext } from './types.js';

/**
 * Security rules for JS/TS.
 *
 * Every rule matches against the *masked* source (comments and string bodies
 * blanked by src/util/lex.ts), so a match is real code rather than prose in a
 * docblock. Where a rule can be fooled by a pattern it cannot see — a sanitiser
 * imported from another module, an auth check in a wrapper — it says so in
 * `why`/`notes` and the verification stage decides whether the claim survives.
 */

/**
 * Providers whose *client* key is published on purpose — analytics write keys,
 * error-ingest DSNs, browser map keys, bot-protection site keys. Used by the
 * client-bundle rule: `VITE_POSTHOG_KEY` names a publishable value, and a High
 * "secret exposed in the bundle" for it is the rule reading the word KEY and
 * stopping there. Kept as a name list because the rule sees a variable name, not
 * a value; the value-shaped allowlist lives in `collectors/secrets.ts`.
 */
// `(?:^|_)` rather than `\b`: an underscore is a word character, so `\bPOSTHOG\b`
// never matches inside `VITE_POSTHOG_KEY` — which is the only shape this list
// ever sees.
const PUBLISHABLE_PROVIDER =
  /(?:^|_)(?:POSTHOG|MIXPANEL|SEGMENT|AMPLITUDE|SENTRY|HEAP|PLAUSIBLE|FATHOM|UMAMI|MATOMO|HOTJAR|LOGROCKET|FULLSTORY|GA4|GTAG|GTM|MAPS|FIREBASE|RECAPTCHA|TURNSTILE|HCAPTCHA|ALGOLIA_SEARCH|STRIPE_PUBLISHABLE|SUPABASE_ANON|PUSHER_APP|INTERCOM|CRISP)(?:_|$)/;

const TOKEN_KEY =
  /(token|jwt|secret|password|passwd|credential|apikey|api[_-]key|session|bearer|refresh|id[_-]?token|access[_-]?token|verifier|nonce|oidc[_.-]?state|pkce)/i;

/** Loopback, link-local, and the reserved TLDs that exist for documentation. */
const LOOPBACK_OR_RESERVED =
  /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|host\.docker\.internal|169\.254(?:\.\d{1,3}){2}|(?:[\w-]+\.)*(?:local|localhost|internal|test|invalid|localdomain)|(?:[\w-]+\.)*example\.(?:com|org|net))$/i;

/** Hosts that appear in source as citations: licences, specs, schemas. */
const SPEC_OR_LICENCE_HOST =
  /^(?:www\.)?(?:w3\.org|apache\.org|opensource\.org|gnu\.org|creativecommons\.org|ietf\.org|whatwg\.org|json-schema\.org|schema\.org|purl\.org|xmlsoap\.org|tools\.ietf\.org|mozilla\.org|unlicense\.org)$/i;

/** RFC1918 plus CGNAT: a plaintext LAN endpoint is a deliberate local choice. */
function isPrivateIpv4(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}
const USER_INPUT = /\b(req\.(?:query|params|body|headers)|request\.(?:query|params|body|headers)|ctx\.(?:query|params|request)|searchParams\.get|useParams|useSearchParams|location\.(?:search|hash|href)|window\.location|process\.argv|event\.data|message\.data|\bpayload\b|\binput\b|\buserInput\b|\bfilename\b|\bfilePath\b|\brelPath\b)/;

export const dangerousHtmlRule: Rule = {
  id: 'SEC-XSS-DANGEROUS-HTML',
  title: 'Raw HTML injection sink used with non-literal content',
  type: 'Security',
  severity: 'High',
  area: 'UI',
  labels: ['security', 'ui', 'xss'],
  claimType: 'behavioral',
  why:
    'A raw-HTML sink renders whatever string it is given. If any path to that string carries model output, API content, or user text, an attacker controls script execution in the origin — which in a browser app means access to whatever the page can reach, including tokens held in web storage.',
  recommendation:
    'Route every raw-HTML sink through a sanitiser with an element/attribute allowlist (DOMPurify or an equivalent), or render text nodes instead of HTML. Assert the sanitiser in a unit test with a payload corpus rather than trusting the renderer.',
  acceptance: [
    'every raw-HTML sink receives sanitiser output, or renders text rather than markup',
    'a unit test feeds a payload corpus (script tag, svg/onload, img/onerror, javascript: href, style expression) through the render path and asserts no executable construct survives',
    'a lint rule or review checklist prevents new unsanitised sinks',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const patterns: Array<{ re: RegExp; what: string }> = [
      { re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}/g, what: 'React dangerouslySetInnerHTML' },
      { re: /\.innerHTML\s*=(?!=)\s*([^;\n]+)/g, what: 'Element.innerHTML assignment' },
      { re: /\.outerHTML\s*=(?!=)\s*([^;\n]+)/g, what: 'Element.outerHTML assignment' },
      { re: /insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]+)\)/g, what: 'insertAdjacentHTML' },
      { re: /document\.write(?:ln)?\s*\(\s*([^)]+)\)/g, what: 'document.write' },
    ];
    for (const { re, what } of patterns) {
      for (const m of matchCode(ctx.src, ctx.masked, re)) {
        const argRaw = (m.match[1] ?? '').trim();
        // A pure string literal is blanked by the masker, so an empty/quote-only
        // argument means a constant: not a finding.
        const isLiteral = argRaw.length === 0 || /^['"`]\s*['"`]$/.test(argRaw);
        if (isLiteral) continue;
        const sanitised = /sanit|purify|DOMPurify|escapeHtml|clean\(/i.test(m.lineText);
        hits.push(
          hit(
            dangerousHtmlRule.id,
            ctx.file.path,
            m.line,
            excerpt(m.lineText),
            `${what} with non-literal content${sanitised ? ' (a sanitiser name appears on the same line — verify it covers this path)' : ''}`,
            { sink: what, sanitiserNearby: sanitised, inTest: ctx.isTest },
          ),
        );
      }
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Introduce one sanitise-at-the-sink helper and route each flagged sink through it, then add a payload-corpus unit test per sink. The sanitiser choice changes what the product can render (tables, code blocks, links), so a human has to decide the allowlist.',
    changes: [
      ...uniquePaths(hits).map((p) => ({ path: p, change: 'wrap the raw-HTML sink in the shared sanitiser, or render text instead of HTML' })),
      { path: 'src/security/sanitizeHtml.ts', change: 'new module: single allowlist-based sanitiser used by every sink' },
    ],
    acceptanceTests: [
      { path: 'test/security/sanitizeHtml.test.ts', description: 'payload corpus in, no script/handler/javascript: URL out' },
      { path: 'test/security/renderPipeline.test.ts', description: 'end-to-end: untrusted markdown/HTML through the real render path yields inert DOM' },
    ],
    risk: 'medium',
    estimatedDiffSize: 'one new module plus one line per sink, and two test files',
    notAgentExecutableReason:
      'Choosing the allowlist is a product decision — an agent picking it unsupervised either breaks legitimate rendering or leaves a hole.',
  }),
};

export const markdownHtmlSinkRule: Rule = {
  id: 'SEC-MARKDOWN-HTML-SINK',
  title: 'Hand-rolled markup generator feeds a raw-HTML sink',
  type: 'Security',
  severity: 'High',
  area: 'UI',
  labels: ['security', 'ui', 'xss'],
  claimType: 'behavioral',
  why:
    'A hand-written markdown/markup renderer that builds an HTML string is an ad-hoc escaping implementation. Unless it escapes `<`, `>`, `&`, quotes and URL schemes at every branch, some input shape emits attacker-chosen markup, and the raw-HTML sink downstream executes it.',
  recommendation:
    'Either escape all text before interpolation and allowlist URL schemes inside the renderer, or hand the renderer output to a sanitiser before the sink. Back it with a payload-corpus test that runs the real renderer.',
  acceptance: [
    'the renderer escapes HTML metacharacters on every text branch',
    'href/src values are restricted to http, https, and mailto',
    'a test runs the real renderer over a payload corpus and asserts no script, event handler, or javascript: URL survives',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    // Only interesting when the module itself assembles HTML tags from pieces.
    const buildsTags = matchCode(ctx.src, ctx.masked, /[`'"]<\s*(?:a|img|div|span|p|code|pre|h[1-6]|li|table|iframe|svg)\b/g);
    if (buildsTags.length < 3) return [];
    const hasEscape = /escapeHtml|escapeHTML|htmlEscape|replace\(\s*\/[&<>]/i.test(ctx.src);
    const hasSchemeAllowlist = /\b(https?|mailto):/i.test(ctx.src) && /startsWith\(|\btest\(|allowlist|allowList|whitelist/i.test(ctx.src);
    const first = buildsTags[0]!;
    return [
      hit(
        markdownHtmlSinkRule.id,
        ctx.file.path,
        first.line,
        excerpt(first.lineText),
        `module assembles HTML tag strings at ${buildsTags.length} sites; escaping helper ${hasEscape ? 'present' : 'absent'}, URL-scheme allowlist ${hasSchemeAllowlist ? 'present' : 'absent'}`,
        { tagSites: buildsTags.length, hasEscape, hasSchemeAllowlist, inTest: ctx.isTest },
      ),
    ];
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Add the payload-corpus test first so the current behaviour is pinned, then make the renderer escape text on every branch and allowlist URL schemes — or replace it with a vetted markdown library plus a sanitiser.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'escape text on every interpolation branch; allowlist href/src schemes' })),
    acceptanceTests: [
      { path: 'test/security/markdownRender.test.ts', description: 'real renderer over a payload corpus: no executable construct in the output' },
    ],
    risk: 'medium',
    estimatedDiffSize: 'renderer-local changes plus one test file',
    notAgentExecutableReason: 'Escaping changes rendered output; a human must confirm the product still renders what it intends to.',
  }),
};

export const tokenWebStorageRule: Rule = {
  id: 'SEC-TOKEN-WEBSTORAGE',
  title: 'Authentication material written to web storage readable by page script',
  type: 'Security',
  severity: 'High',
  area: 'UI',
  labels: ['security', 'auth', 'ui'],
  claimType: 'factual',
  why:
    'localStorage and sessionStorage are readable by any script in the origin, are not scoped to a path, and survive tab close (localStorage). One XSS — including one from a dependency — exfiltrates the credential, and the credential remains valid wherever it was issued for. HttpOnly cookies or in-memory-only tokens remove that class of theft.',
  recommendation:
    'Hold access tokens in memory for the page lifetime and keep the refresh credential in an HttpOnly, Secure, SameSite cookie set by the server. If web storage is a deliberate trade-off, record it as an accepted risk with the compensating controls (short expiry, CSP, no raw-HTML sinks) and test those controls.',
  acceptance: [
    'no access or refresh token is written to localStorage or sessionStorage',
    'session continuity across reload works via an HttpOnly cookie or a silent re-auth call',
    'a test asserts that after sign-in no storage key matches /token|jwt|secret|password/i',
  ],
  effort: 'L',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b(localStorage|sessionStorage)\s*\.\s*(setItem|getItem)\s*\(\s*([^,)]*)/g;
    const withStrings = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, withStrings, re)) {
      const store = m.match[1]!;
      const op = m.match[2]!;
      // The key literal is blanked in `masked`, so read it from the real line.
      const keyFromSource = /\.(?:setItem|getItem)\s*\(\s*['"`]([^'"`]+)['"`]/.exec(m.lineText)?.[1] ?? '';
      const keyIdent = m.match[3]?.trim() ?? '';
      // Match on the *key expression only*. Including the whole line makes
      // `sessionStorage` itself match /session/, which flags every cache write
      // in the repository — a textbook way to drown a real finding in noise.
      const keyExpression = `${keyFromSource} ${keyIdent}`;
      if (!TOKEN_KEY.test(keyExpression)) continue;
      if (/^(?:ui|theme|layout|pref|prefs|settings)/i.test(keyFromSource)) continue;
      // A long-lived bearer/refresh credential is the finding; a short-lived
      // protocol value (OIDC state, PKCE verifier, nonce) has to live in the
      // browser for the flow to work at all, so it is recorded at lower weight.
      const longLived = /(token|jwt|secret|password|passwd|credential|bearer|refresh|apikey|api[_-]key)/i.test(keyExpression);
      const protocolValue = /(state|nonce|verifier|challenge)/i.test(keyExpression) && !longLived;
      hits.push(
        hit(
          tokenWebStorageRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          `${store}.${op} with credential-shaped key ${keyFromSource ? `"${keyFromSource}"` : `(computed: ${excerpt(keyIdent, 40)})`}${protocolValue ? ' — short-lived protocol value, not a long-lived credential' : ''}`,
          { store, op, key: keyFromSource, keyExpression, longLived, protocolValue, isWrite: op === 'setItem', inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Move tokens behind one accessor module, switch the store to an in-memory map, and have the server issue an HttpOnly refresh cookie. This is a cross-repo change (the token issuer must set the cookie), so the client-side half alone does not close the finding.',
    changes: [
      { path: 'src/auth/tokenStore.ts', change: 'new module: in-memory token accessor, the only place tokens are read/written' },
      ...uniquePaths(hits).map((p) => ({ path: p, change: 'replace direct web-storage access with the token accessor' })),
    ],
    acceptanceTests: [
      { path: 'test/auth/tokenStore.test.ts', description: 'no credential-shaped key reaches localStorage/sessionStorage' },
      { path: 'test/auth/sessionRestore.test.ts', description: 'reload path re-authenticates without reading a persisted token' },
    ],
    risk: 'high',
    estimatedDiffSize: 'one new module, every call site, plus a server-side cookie change outside this repository',
    notAgentExecutableReason:
      'Closing it requires a server-side cookie contract that does not live in this repository; an agent would ship a client that can no longer restore a session.',
  }),
};

export const clientSideAuthzRule: Rule = {
  id: 'SEC-CLIENT-SIDE-AUTHZ',
  title: 'Authorisation decision made from client-held claims',
  type: 'Security',
  severity: 'Medium',
  area: 'UI',
  labels: ['security', 'authz', 'ui'],
  claimType: 'factual',
  why:
    'A role/permission check in client code is a UI affordance, not a control: the user owns the runtime and can flip it. It is only a vulnerability when the server does not repeat the check — but it reliably becomes one, because the visible check makes the server-side check look redundant to the next contributor.',
  recommendation:
    'Keep the client check for UX, and make the server the authority for every action it guards. Document in the component that the check is cosmetic, and add a server-side test for each guarded action.',
  acceptance: [
    'every action guarded in the client is independently rejected by the service for an unauthorised principal',
    'client-side guards carry a comment stating they are cosmetic',
    'a service test proves rejection without relying on the client',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b(?:if|&&|\?|return)\s*\(?\s*[\w.?]*\b(?:isAdmin|hasRole|hasPermission|canEdit|canDelete|isOwner|role\s*===|roles\.includes|permissions\.includes|claims\.|scopes\.includes)/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      hits.push(
        hit(
          clientSideAuthzRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          'client-side role/permission predicate used in a control-flow decision',
          { inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Confirm each guarded action is enforced server-side; annotate the client guard as cosmetic.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'annotate the guard as cosmetic and confirm a server-side equivalent exists' })),
    acceptanceTests: [{ path: '<service-test-suite>', description: 'unauthorised principal is rejected by the API for each guarded action' }],
    risk: 'low',
    estimatedDiffSize: 'comments in the client plus service tests outside this repository',
    notAgentExecutableReason: 'The authority that must be fixed is the service, which is not in this repository.',
  }),
};

export const jwtClientTrustRule: Rule = {
  id: 'SEC-JWT-CLIENT-TRUST',
  title: 'JWT payload decoded without signature verification',
  type: 'Security',
  severity: 'Medium',
  area: 'UI',
  labels: ['security', 'auth'],
  claimType: 'factual',
  why:
    'Splitting a JWT and base64-decoding the payload yields attacker-editable data: anyone can forge claims in a token they hold. Reading it for display (showing an email, scheduling a refresh) is fine; using it for a security decision is not.',
  recommendation:
    'Treat a client-decoded payload as untrusted display data. Never branch on it for access control, and never trust its expiry as a security boundary — let the service reject the token.',
  acceptance: [
    'decoded claims are used only for display or refresh scheduling',
    'no access-control branch reads a client-decoded claim',
    'a comment at the decode site states the payload is unverified',
  ],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b(?:atob|Buffer\.from|decodeURIComponent)\s*\(\s*[\w.[\]]*(?:token|jwt)[\w.[\]]*\.split|\btoken\.split\s*\(\s*['"`]?\.|jwtDecode|decodeJwt|parseJwt/gi;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      hits.push(hit(jwtClientTrustRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'JWT payload decoded client-side without verification', { inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Add an explicit comment at each decode site recording that the payload is unverified, and confirm no access-control branch consumes it.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'annotate the decode site as unverified display-only data' })),
    acceptanceTests: [{ path: 'test/auth/jwtDecode.test.ts', description: 'decode helper returns display data and is not consulted by any guard' }],
    risk: 'low',
    estimatedDiffSize: 'a comment per decode site; no behaviour change',
    agentPrompt:
      'At each listed line, add a short comment immediately above stating that the decoded JWT payload is unverified and must only be used for display or refresh scheduling, never for an access-control decision. Change no runtime behaviour. Then grep the repository for access-control branches that read the decoded claims and report them without editing.',
  }),
};

export const childProcessShellRule: Rule = {
  id: 'SEC-CHILD-PROCESS-SHELL',
  title: 'Process execution through a shell with interpolated arguments',
  type: 'Security',
  severity: 'High',
  area: 'API',
  labels: ['security', 'injection'],
  claimType: 'behavioral',
  why:
    'A shell splits its argument on metacharacters. Any value interpolated into that string — a branch name, a filename, a model-authored argument — can close the quoting and append a second command, which runs with the process\'s privileges.',
  recommendation: 'Use the argv form (`spawn`/`execFile` with an array, `shell: false`). When a shell is genuinely needed, pass untrusted values through the environment rather than the command string.',
  acceptance: [
    'no exec/execSync/spawn with shell:true carries an interpolated value',
    'command execution uses an argv array',
    'a test asserts that a value containing `; touch pwned` does not execute a second command',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    // The boundary excludes `.` so a dotted call only matches through the
    // receiver group below — otherwise `/re/.exec(s)` reads as a bare `exec(`.
    const re = /(^|[^\w$.])((?:[\w$]+\s*\.\s*)?)(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(/g;
    // Namespaces that really are the child_process API, so `cp.exec(...)` still
    // counts. Anything else with a receiver — `TAG.exec(sql)`,
    // `/^\$[A-Za-z_]*\$/.exec(s)` — is RegExp.prototype.exec, and reporting it
    // turns every SQL parser into a shell-injection finding.
    const spawnNamespaces = new Set(
      [...ctx.masked.codeAndStrings.matchAll(/import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+['"`](?:node:)?(child_process|execa|cross-spawn|shelljs|zx)['"`]/g)].map((m) => m[1]!),
    );
    for (const m of ctx.masked.codeAndStrings.matchAll(/(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"`](?:node:)?(?:child_process|execa|cross-spawn|shelljs|zx)/g)) {
      spawnNamespaces.add(m[1]!);
    }
    for (const n of ['cp', 'childProcess', 'child_process', 'proc', 'nodeChildProcess']) spawnNamespaces.add(n);

    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      const receiver = (m.match[2] ?? '').replace(/[\s.]/g, '');
      if (receiver !== '' && !spawnNamespaces.has(receiver)) continue;
      const fn = m.match[3]!;
      const windowText = windowAfter(ctx.masked, m.index, 300);
      const srcWindow = ctx.src.slice(m.index, m.index + 300);
      const shellTrue = /shell\s*:\s*true/.test(windowText) || /shell\s*:\s*true/.test(srcWindow) || /shell\s*:\s*['"`]/.test(srcWindow);
      const interpolated = /\$\{|\s\+\s|concat\(/.test(srcWindow.split(')')[0] ?? '');
      const isShellFamily = fn === 'exec' || fn === 'execSync';
      if (!isShellFamily && !shellTrue) continue;
      if (isShellFamily && !interpolated && !shellTrue) {
        // a constant command through the shell family is lower risk but still flagged
        hits.push(hit(childProcessShellRule.id, ctx.file.path, m.line, excerpt(m.lineText), `${fn}() runs through a shell with a constant command`, { fn, interpolated: false, shellTrue, inTest: ctx.isTest }));
        continue;
      }
      hits.push(
        hit(
          childProcessShellRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          `${fn}() ${shellTrue ? 'with shell:true' : 'through a shell'}${interpolated ? ' and an interpolated command string' : ''}`,
          { fn, interpolated, shellTrue, inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  severityFor: (hits) => {
    const risky = hits.filter((h) => h.meta?.interpolated === true || h.meta?.shellTrue === true);
    // A constant command through the shell is a hardening item, not an injection
    // vector: there is nothing for an attacker to influence.
    return risky.length > 0 ? 'High' : 'Low';
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Convert each shell invocation to the argv form: `execFile`/`spawn` with an array and `shell: false`, moving any untrusted value into an argument rather than the command string.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'replace shell execution with an argv array; drop shell:true' })),
    acceptanceTests: [{ path: 'test/security/exec.test.ts', description: 'an argument containing shell metacharacters is passed through verbatim and executes nothing extra' }],
    risk: 'medium',
    estimatedDiffSize: 'a few lines per call site plus one test',
    agentPrompt:
      'Convert each flagged child_process call to the argv form: use execFile/execFileSync/spawn with the command and an array of arguments, never a single interpolated string, and never shell:true. Preserve cwd, env, timeout and encoding options. Where the current command uses shell features (pipes, globs, &&), split it into separate calls or keep the shell but move every interpolated value into an environment variable referenced by the script. Then add a test that passes an argument containing "; echo INJECTED" and asserts the value arrives verbatim as a single argument.',
  }),
};

export const pathTraversalRule: Rule = {
  id: 'SEC-PATH-TRAVERSAL',
  title: 'Filesystem path built from caller-influenced input without confinement',
  type: 'Security',
  severity: 'High',
  area: 'API',
  labels: ['security', 'injection'],
  claimType: 'behavioral',
  why:
    '`path.join(root, userValue)` happily escapes `root` when the value contains `..`, and an absolute value makes `path.resolve` discard the root entirely. The result is read/write access anywhere the process can reach.',
  recommendation:
    'Resolve the candidate, then verify the resolved path is inside the realpath of the root (prefix check on a separator boundary) before touching the filesystem. Reject rather than normalise.',
  acceptance: [
    'every path derived from input is confined to a realpath-checked root',
    'absolute inputs and `..` segments are rejected, not silently rebased',
    'tests cover `../../etc/passwd`, an absolute path, a URL-encoded traversal, and a symlink pointing outside the root',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b(?:path\.)?(join|resolve)\s*\(([^)]{0,200})\)/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      const args = m.match[2] ?? '';
      if (!USER_INPUT.test(args) && !USER_INPUT.test(m.lineText)) continue;
      const confined = /startsWith\(|realpath|isInside|withinRoot|assertInside|relative\(/i.test(
        ctx.src.slice(Math.max(0, m.index - 400), m.index + 400),
      );
      hits.push(
        hit(
          pathTraversalRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          `path.${m.match[1]} over caller-influenced input${confined ? ' (a containment check appears nearby — verify it runs on this path)' : ' with no containment check within 400 characters'}`,
          { confinedNearby: confined, inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Add one `resolveWithin(root, candidate)` helper that realpaths the root, resolves the candidate, rejects anything outside, and use it at every flagged site.',
    changes: [
      { path: 'src/security/resolveWithin.ts', change: 'new helper: realpath root, resolve candidate, throw when outside' },
      ...uniquePaths(hits).map((p) => ({ path: p, change: 'route path construction through resolveWithin' })),
    ],
    acceptanceTests: [{ path: 'test/security/resolveWithin.test.ts', description: 'rejects ../ traversal, absolute paths, encoded traversal, and symlink escape' }],
    risk: 'medium',
    estimatedDiffSize: 'one helper (~30 lines), one line per call site, one test file',
    agentPrompt:
      'Create a helper that takes a root directory and a candidate path, resolves the root with fs.realpathSync, resolves the candidate against it, and throws unless the resolved candidate equals the root or starts with root + path.sep. Reject absolute candidates outright. Use it at every flagged call site. Add a vitest suite covering "../../etc/passwd", an absolute path, "..%2F..%2Fetc", and a symlink inside the root that points outside it.',
  }),
};

export const ssrfFetchRule: Rule = {
  id: 'SEC-SSRF-FETCH',
  title: 'Outbound request to a caller-influenced destination without an allowlist',
  type: 'Security',
  severity: 'Medium',
  area: 'API',
  labels: ['security', 'ssrf'],
  claimType: 'behavioral',
  why:
    'When the destination of a server-side request is influenced by a caller, that caller can aim it at internal addresses — cloud metadata services, admin endpoints, databases on the loopback interface — and read the response through your service. Blocklists that parse only dotted-quad addresses miss decimal, octal, hex and IPv6-mapped forms, and a host that resolves to a public address at check time can resolve to a private one at connect time.',
  recommendation:
    'Validate against a destination allowlist (scheme + host), resolve the host yourself and check every resolved address against private ranges in their numeric form, and pin the connection to the address you checked. Disable automatic redirect following or re-validate each hop.',
  acceptance: [
    'destinations are allowlisted by scheme and host',
    'address checks operate on the parsed numeric address, covering decimal/octal/hex/IPv6-mapped encodings',
    'redirects are not followed blindly; each hop is re-validated',
    'tests cover 169.254.169.254, 2130706433, 0x7f000001, [::ffff:127.0.0.1], and a redirect to a private address',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got|request|http\.get|https\.get|undici\.request)\s*\(\s*([^,)]{0,160})/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      const arg = (m.match[1] ?? '').trim();
      const dynamic = arg.length > 0 && !/^['"`]/.test(ctx.src.slice(m.index + m.match[0].length - arg.length, m.index + m.match[0].length).trim());
      const lineHasTemplate = /\$\{|\s\+\s/.test(m.lineText);
      const fromInput = USER_INPUT.test(m.lineText) || /\bbaseUrl\b|\bendpoint\b|\bhost\b|\btargetUrl\b|\burl\b/.test(arg);
      if (!dynamic && !lineHasTemplate) continue;
      if (!fromInput) continue;
      const guarded = /allowlist|allowList|whitelist|isPrivate|isLoopback|assertPublic|URL\(/i.test(
        ctx.src.slice(Math.max(0, m.index - 300), m.index + 200),
      );
      hits.push(
        hit(
          ssrfFetchRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          `outbound request with a computed destination${guarded ? ' (a guard appears nearby — verify it covers numeric encodings and redirects)' : ' and no visible destination guard'}`,
          { guardedNearby: guarded, inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Add a destination validator used by every outbound call that can be influenced by a caller, covering numeric address encodings and redirect hops.',
    changes: [
      { path: 'src/security/assertAllowedDestination.ts', change: 'new validator: scheme/host allowlist plus numeric private-range check' },
      ...uniquePaths(hits).map((p) => ({ path: p, change: 'validate the destination before the request; stop following redirects blindly' })),
    ],
    acceptanceTests: [{ path: 'test/security/ssrf.test.ts', description: 'metadata IP, decimal/octal/hex encodings, IPv6-mapped loopback, and a redirect to a private address are all rejected' }],
    risk: 'medium',
    estimatedDiffSize: 'one validator plus one call per site',
    notAgentExecutableReason: 'The allowlist is deployment-specific; an agent cannot know which hosts the product is meant to reach.',
  }),
};

export const weakCryptoRule: Rule = {
  id: 'SEC-WEAK-CRYPTO',
  title: 'Weak hash or non-cryptographic randomness in a security context',
  type: 'Security',
  severity: 'Medium',
  area: 'Shared',
  labels: ['security', 'crypto'],
  claimType: 'factual',
  why:
    'MD5 and SHA-1 are collision-broken, and `Math.random()` is a predictable PRNG seeded from observable state. Either one in an identifier, token, nonce or signature path makes the value guessable or forgeable. (Both are legitimate for cache keys and UI jitter — the finding is about the context, which is why it is reported with the surrounding line.)',
  recommendation: 'Use SHA-256 or better for hashing, and `crypto.randomUUID()` / `crypto.getRandomValues()` for any value that must be unguessable.',
  acceptance: [
    'no MD5/SHA-1 in a signature, token, or password path',
    'every security-relevant random value comes from a CSPRNG',
    'remaining non-cryptographic uses carry a comment saying so',
  ],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    // The algorithm name is a string literal, so match the comments-blanked
    // view: the code-only view has already blanked it to spaces.
    const withStrings = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, withStrings, /createHash\s*\(\s*['"`]?\s*(md5|sha1)/gi)) {
      hits.push(hit(weakCryptoRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'broken hash algorithm (MD5/SHA-1)', { kind: 'hash', inTest: ctx.isTest }));
    }
    for (const m of matchCode(ctx.src, ctx.masked, /\bMath\.random\s*\(\s*\)/g)) {
      const context = ctx.src.slice(Math.max(0, m.index - 160), m.index + 160);
      // `id`/`key` alone are not security words — Math.random() for a React key,
      // a toast id, or animation jitter is correct. Require a word that only
      // appears when the value is meant to be unguessable.
      if (!/\b(token|secret|nonce|salt|password|passwd|credential|csrf|sessionId|session[_-]?id|apiKey|api[_-]key|privateKey|signature|otp|verifier|challenge)\b|crypto|uuid|guid/i.test(context)) continue;
      // A correlation/trace id built from Math.random() is an observability
      // concern, not a credential: record it but say which it is.
      const observabilityOnly = /\b(trace|span|correlation|request)[_-]?id\b/i.test(context);
      // The common correct shape is `if (crypto.getRandomValues) … else Math.random()`.
      // Reporting the documented fallback branch as weak crypto is wrong: the
      // primary path is a CSPRNG, and the fallback only runs where none exists.
      const csprngFallback =
        /(?:getRandomValues|randomUUID|randomBytes|webcrypto)/.test(context) &&
        /\b(?:else|\?\?|\|\||if\s*\(\s*!)/.test(context);
      hits.push(
        hit(
          weakCryptoRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText),
          csprngFallback
            ? 'Math.random() appears only as the fallback branch where a CSPRNG is unavailable (primary path uses getRandomValues/randomUUID)'
            : observabilityOnly
              ? 'Math.random() generates a trace/correlation id (collision risk rather than a guessability risk)'
              : 'Math.random() used where the value appears to be security-relevant',
          { kind: 'prng', observabilityOnly, csprngFallback, inTest: ctx.isTest },
        ),
      );
    }
    for (const m of matchCode(ctx.src, ctx.masked, /createCipher\s*\(|createDecipher\s*\(/g)) {
      hits.push(hit(weakCryptoRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'createCipher/createDecipher derives a key with MD5 and has no authentication tag', { kind: 'cipher', inTest: ctx.isTest }));
    }
    return hits;
  },
  severityFor: (hits) => {
    if (hits.some((h) => h.meta?.kind === 'hash' || h.meta?.kind === 'cipher')) return 'Medium';
    // Only PRNG hits, and every one of them either a CSPRNG fallback branch or an
    // observability id: collision risk, not a guessability risk.
    const benign = hits.every((h) => h.meta?.observabilityOnly === true || h.meta?.csprngFallback === true);
    return benign ? 'Low' : 'Medium';
  },
  fixPlan: (hits) => {
    // When every hit is a documented CSPRNG fallback or an observability id,
    // there is no mechanical change to make — the primary path is already
    // correct, and an agent "fixing" it would delete a deliberate fallback.
    const nothingMechanical = hits.every((h) => h.meta?.csprngFallback === true || h.meta?.observabilityOnly === true);
    if (nothingMechanical) {
      return {
        agentExecutable: false,
        strategy:
          'No code change is indicated. Each site is either a fallback branch that only runs where no CSPRNG exists, or an identifier whose risk is collision rather than guessability. Record the decision in a comment so the next reader does not re-raise it.',
        changes: uniquePaths(hits).map((p) => ({ path: p, change: 'annotate why the non-cryptographic primitive is correct here' })),
        acceptanceTests: [{ path: 'n/a', description: 'no behaviour change; the annotation prevents the finding being re-raised' }],
        risk: 'low' as const,
        estimatedDiffSize: 'a comment per site',
        notAgentExecutableReason:
          'Every site is already correct: the primary path uses a CSPRNG and the flagged line is the documented fallback. An agent rewriting it would remove a deliberate degradation path.',
      };
    }
    return {
    agentExecutable: true,
    strategy: 'Replace broken primitives: SHA-256 for hashing, crypto.randomUUID()/getRandomValues for random material, createCipheriv with AES-GCM for encryption.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'swap the weak primitive for the modern equivalent' })),
    acceptanceTests: [{ path: 'test/security/crypto.test.ts', description: 'no MD5/SHA-1/Math.random in security paths; random values are unique across many draws' }],
    risk: 'low' as const,
    estimatedDiffSize: 'one line per site',
    agentPrompt:
      'Replace each flagged weak primitive. createHash("md5"|"sha1") becomes createHash("sha256") unless the value is a cache key, in which case add a comment saying the hash is non-cryptographic and leave it. Math.random() in a security-relevant context becomes crypto.randomUUID() or crypto.getRandomValues on a Uint8Array. createCipher/createDecipher becomes createCipheriv/createDecipheriv with aes-256-gcm and an explicit random IV. Keep output formats stable where persisted data depends on them, and say so in the PR body if you cannot. Do not remove a fallback branch that exists for environments without a CSPRNG.',
    };
  },
};

export const evalRule: Rule = {
  id: 'SEC-EVAL',
  title: 'Dynamic code evaluation of runtime data',
  type: 'Security',
  severity: 'High',
  area: 'Shared',
  labels: ['security', 'injection'],
  claimType: 'factual',
  why: 'eval, new Function, and string-bodied timers compile runtime data as code. Any influence over that string is arbitrary code execution in the process.',
  recommendation: 'Replace dynamic evaluation with a data structure: a lookup table of handlers, JSON.parse for data, or a purpose-built expression evaluator with a fixed grammar.',
  acceptance: ['no eval/new Function/string-bodied timer over runtime data', 'a lint rule bans the constructs', 'behaviour preserved by tests'],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*['"`]|\bsetInterval\s*\(\s*['"`]/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      hits.push(hit(evalRule.id, ctx.file.path, m.line, excerpt(m.lineText), `dynamic evaluation construct: ${m.match[0].trim()}`, { inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Replace each evaluation site with an explicit dispatch table or parser.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'replace dynamic evaluation with explicit dispatch' })),
    acceptanceTests: [{ path: 'test/security/noEval.test.ts', description: 'source contains no eval/new Function; behaviour preserved' }],
    risk: 'high',
    estimatedDiffSize: 'varies with what the evaluated code does',
    notAgentExecutableReason: 'Replacing evaluation needs an understanding of the evaluated language; an unsupervised rewrite risks silent behaviour change.',
  }),
};

export const tlsDisabledRule: Rule = {
  id: 'SEC-TLS-DISABLED',
  title: 'TLS certificate validation disabled',
  type: 'Security',
  severity: 'High',
  area: 'Shared',
  labels: ['security', 'transport'],
  claimType: 'factual',
  why: 'With validation off, any network position can present its own certificate and read or rewrite the traffic, including credentials. The setting usually arrives for a local certificate problem and then ships.',
  recommendation: 'Remove the override and install the needed CA certificate instead (NODE_EXTRA_CA_CERTS). If a local-only escape hatch is required, gate it on an explicit development flag that cannot be set in a production build.',
  acceptance: ['no rejectUnauthorized:false and no NODE_TLS_REJECT_UNAUTHORIZED=0 in shipped code', 'internal CAs trusted via the certificate store', 'a test asserts the production configuration validates certificates'],
  effort: 'S',
  appliesTo: (f) => JS_TS(f) || ['.json', '.yml', '.yaml', '.sh', '.env', ''].includes(f.ext),
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"`]?0|strictSSL\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      hits.push(hit(tlsDisabledRule.id, ctx.file.path, m.line, excerpt(m.lineText), `certificate validation disabled: ${m.match[0].trim()}`, { inTest: ctx.isTest }));
    }
    // also check raw text for env-file style settings the masker would blank
    for (const m of matchCode(ctx.src, { ...ctx.masked, code: ctx.masked.codeAndStrings }, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0/g)) {
      if (hits.some((h) => h.line === m.line)) continue;
      hits.push(hit(tlsDisabledRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate validation process-wide', { inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Delete the override; trust the required CA through the certificate store instead.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'remove the validation override' })),
    acceptanceTests: [{ path: 'test/security/tls.test.ts', description: 'client configuration validates certificates in production mode' }],
    risk: 'medium',
    estimatedDiffSize: 'one line per site',
    agentPrompt:
      'Remove each TLS-validation override. Where a local development certificate is genuinely needed, replace the override with a comment explaining that NODE_EXTRA_CA_CERTS should point at the local CA, and gate any remaining escape hatch behind an explicit development-only flag. Do not weaken production behaviour.',
  }),
};

export const corsWildcardRule: Rule = {
  id: 'SEC-CORS-WILDCARD',
  title: 'Permissive CORS configuration',
  type: 'Security',
  severity: 'Medium',
  area: 'API',
  labels: ['security', 'api'],
  claimType: 'factual',
  why: 'Reflecting the request origin, or allowing `*` alongside credentials, lets any site make authenticated cross-origin calls on a visitor\'s behalf and read the responses.',
  recommendation: 'Allowlist the exact origins that need access, and never pair credentialed requests with a reflected or wildcard origin.',
  acceptance: ['allowed origins are an explicit list', 'credentialed responses never carry a wildcard or reflected origin', 'a test asserts an unlisted origin is refused'],
  effort: 'S',
  appliesTo: (f) => JS_TS(f) || ['.conf', '.yaml', '.yml'].includes(f.ext),
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /Access-Control-Allow-Origin['"`\s:,]+\*|origin\s*:\s*(?:true|['"`]\*['"`])|cors\s*\(\s*\)|credentials\s*:\s*true/g;
    for (const m of matchCode(ctx.src, ctx.masked, re)) {
      const token = m.match[0];
      const credentialed = /credentials\s*:\s*true/.test(ctx.src.slice(Math.max(0, m.index - 200), m.index + 200));
      if (/credentials\s*:\s*true/.test(token) && !/origin\s*:\s*(?:true|['"`]\*)/.test(ctx.src.slice(Math.max(0, m.index - 200), m.index + 200))) continue;
      hits.push(hit(corsWildcardRule.id, ctx.file.path, m.line, excerpt(m.lineText), `permissive CORS: ${token.trim()}${credentialed ? ' combined with credentials:true' : ''}`, { credentialed, inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Replace the wildcard/reflection with an explicit origin allowlist drawn from configuration.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'replace wildcard/reflected origin with a configured allowlist' })),
    acceptanceTests: [{ path: 'test/security/cors.test.ts', description: 'listed origin allowed, unlisted origin refused, no wildcard with credentials' }],
    risk: 'medium',
    estimatedDiffSize: 'configuration plus one call site',
    notAgentExecutableReason: 'The correct origin list is deployment knowledge the repository does not contain.',
  }),
};

export const postMessageOriginRule: Rule = {
  id: 'SEC-POSTMESSAGE-ORIGIN',
  title: 'Cross-document message handling without origin validation',
  type: 'Security',
  severity: 'Medium',
  area: 'UI',
  labels: ['security', 'ui'],
  claimType: 'factual',
  why: 'A `message` listener that does not check `event.origin` accepts instructions from any frame or window that can reach it, and `postMessage(data, "*")` broadcasts the payload to whatever currently occupies the target — which may not be what the code expects.',
  recommendation: 'Check `event.origin` against an expected value as the first statement of every message handler, and pass an explicit target origin instead of `*`.',
  acceptance: ['every message listener validates origin before reading data', 'no postMessage call targets "*" with sensitive data', 'a test asserts a message from an unexpected origin is ignored'],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const withStrings = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, withStrings, /addEventListener\s*\(\s*['"`]?message['"`]?\s*,/g)) {
      const window400 = ctx.src.slice(m.index, m.index + 600);
      if (/\.origin\b/.test(window400)) continue;
      hits.push(hit(postMessageOriginRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'message listener with no event.origin check in the following 600 characters', { kind: 'listener', inTest: ctx.isTest }));
    }
    for (const m of matchCode(ctx.src, withStrings, /postMessage\s*\(([^)]{0,200})\)/g)) {
      if (!/['"`]\s*\*\s*['"`]/.test(m.lineText)) continue;
      hits.push(hit(postMessageOriginRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'postMessage with a "*" target origin', { kind: 'send', inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Add an origin check as the first statement of each listener and replace "*" targets with the expected origin.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'validate event.origin first; pass an explicit target origin' })),
    acceptanceTests: [{ path: 'test/security/postMessage.test.ts', description: 'message from an unexpected origin is ignored' }],
    risk: 'low',
    estimatedDiffSize: 'two or three lines per handler',
    agentPrompt:
      'For each flagged message listener, add an early return unless event.origin equals the expected origin (derive it from existing configuration — window.location.origin or an existing config constant — and add a named constant if none exists). For each postMessage with a "*" target, replace "*" with that same expected origin. Add a vitest case dispatching a MessageEvent with a foreign origin and asserting the handler does nothing.',
  }),
};

export const secretInClientBundleRule: Rule = {
  id: 'SEC-SECRET-IN-CLIENT-BUNDLE',
  title: 'Secret-shaped value exposed through a client-inlined build variable',
  type: 'Security',
  severity: 'High',
  area: 'Build',
  labels: ['security', 'secrets', 'build'],
  claimType: 'factual',
  why:
    'Build-time variables with a public prefix (VITE_, NEXT_PUBLIC_, REACT_APP_, PUBLIC_, EXPO_PUBLIC_) are string-substituted into the shipped bundle. Anything secret-shaped in one is published to every visitor, and rotating it means rebuilding and redeploying.',
  recommendation: 'Move the value behind a server endpoint that holds the credential and exposes only the result. If the value genuinely is public (a client id, a publishable key), rename it so the next reader knows.',
  acceptance: [
    'no public-prefixed build variable holds a credential',
    'secret-dependent calls go through a server endpoint',
    'a CI check fails when a public-prefixed variable name matches a secret pattern',
  ],
  effort: 'M',
  appliesTo: (f) => JS_TS(f) || ['.env', '.html', '.json', '.yml', '.yaml', ''].includes(f.ext) || f.path.includes('.env'),
  // A finding made entirely of publishable values is a naming observation, not an
  // exposure, and must not arrive at the severity of a leaked credential.
  severityFor: (hits) => (hits.every((h) => h.meta?.benign === true) ? 'Info' : 'High'),
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    const re = /\b((?:VITE|NEXT_PUBLIC|REACT_APP|PUBLIC|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|VUE_APP)_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)[A-Z0-9_]*)\b/g;
    // Values live in string literals, so search the comments-blanked view
    // rather than raw source: a URL quoted inside an explanatory comment is
    // documentation, not an endpoint this code calls.
    const searchSpace = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, searchSpace, re)) {
      const name = m.match[1]!;
      // The whole premise is that a *build variable* gets string-substituted
      // into the bundle. An ordinary module constant that happens to start with
      // `PUBLIC_` is not one — `export const PUBLIC_KEY_FILE = 'audit.pub'` in a
      // Node CLI is a filename, and reporting it as a published credential is
      // the rule mistaking a prefix for a mechanism.
      const region = ctx.src.slice(Math.max(0, m.index - 60), m.index + name.length + 4);
      const isBuildVariable =
        /(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env|\benv\s*\.|\bdefine\s*:|^\s*$)/m.test(region) ||
        /\.env/.test(ctx.file.path) ||
        ['.env', '.yml', '.yaml', '.json', '.html', ''].includes(ctx.file.ext);
      if (!isBuildVariable) continue;
      // `VITE_OIDC_TOKEN_URL` holds a URL. The credential word is qualified by a
      // locator suffix, so the variable names an endpoint, not a secret.
      if (/_(?:URL|URI|ENDPOINT|PATH|HOST|ORIGIN|BASE|DOMAIN|ISSUER|AUDIENCE|SCOPE|SCOPES|NAME|TTL|EXPIRY|TIMEOUT|HEADER|PARAM|PREFIX|ENABLED|MODE|FILE|FILENAME|DIR|EXT)$/.test(name)) continue;
      // `*_PUBLIC_KEY` / publishable keys are designed to be shipped, and so is
      // the key of a provider whose keys are publishable by design. `VITE_POSTHOG_KEY`
      // holds a write-only project key; reporting it as a High "secret exposed in
      // the bundle" is the rule reading the word KEY and nothing else.
      //
      // The provider exemption is withdrawn the moment the name carries a word
      // that means a real credential: `VITE_SENTRY_AUTH_TOKEN` uploads source maps
      // and is emphatically not publishable.
      const nameSuffixBenign = /_(?:PUBLIC_KEY|PUBLISHABLE_KEY|CLIENT_ID|SITE_KEY|ANON_KEY)$/.test(name);
      const namesRealCredential = /(?:SECRET|PRIVATE|AUTH_TOKEN|ADMIN|PASSWORD|PASSWD|SERVICE_ACCOUNT|MASTER)/.test(name);
      const providerBenign = PUBLISHABLE_PROVIDER.test(name) && !namesRealCredential;
      // Classify the *value* with the same allowlist the secret collector uses,
      // taking the literal from the line or from the identifier's declaration
      // elsewhere in the module. `const PUBLIC_PROJECT_TOKEN = 'phc_…'` is a
      // PostHog project key: the name says nothing useful, the value settles it,
      // and the flagged occurrence is often a *reference* rather than the
      // declaration.
      const literal = /['"`]([^'"`\n]{8,200})['"`]/.exec(m.lineText)?.[1] ?? declaredLiteral(ctx.src, name);
      const valueBenign =
        literal !== undefined &&
        !namesRealCredential &&
        publishableKeyMatch({ value: literal, assignedTo: name, lineText: m.lineText }) !== undefined;
      const benign = nameSuffixBenign || providerBenign || valueBenign;
      hits.push(
        hit(
          secretInClientBundleRule.id,
          ctx.file.path,
          m.line,
          excerpt(m.lineText.replace(/=.*/, '=<value redacted>')),
          `client-inlined build variable with a credential-shaped name: ${name}${
            providerBenign || valueBenign
              ? ' — publishable by design: this provider\'s client key is meant to ship in the bundle, so it is reported at Info for confirmation rather than as an exposure'
              : benign
                ? ' (name suggests a publishable value — confirm)'
                : ''
          }`,
          { name, benign, inTest: ctx.isTest },
        ),
      );
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy: 'Decide per variable whether the value is publishable. Publishable values get renamed; real credentials move behind a server endpoint and are rotated.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'rename publishable values; move real credentials server-side' })),
    acceptanceTests: [{ path: 'test/build/noSecretsInBundle.test.ts', description: 'built bundle contains no value matching the credential patterns' }],
    risk: 'high',
    estimatedDiffSize: 'configuration plus a new server endpoint per real credential',
    notAgentExecutableReason: 'Whether a value is publishable is product knowledge, and rotation happens outside the repository.',
  }),
};

/**
 * The string literal `name` is declared with in this module, if any. Used so a
 * *reference* to a publishable constant is classified the same way as its
 * declaration — the rule usually flags the reference.
 */
export function declaredLiteral(src: string, name: string): string | undefined {
  const re = new RegExp(`(?:const|let|var|readonly)\\s+${name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\s*(?::[^=]*)?=\\s*['"\`]([^'"\`\\n]{8,200})['"\`]`);
  return re.exec(src)?.[1];
}

export const httpEndpointRule: Rule = {
  id: 'SEC-HTTP-ENDPOINT',
  title: 'Plaintext HTTP endpoint for a non-loopback host',
  type: 'Security',
  severity: 'Low',
  area: 'Shared',
  labels: ['security', 'transport'],
  claimType: 'factual',
  why: 'A plaintext endpoint exposes the request and response — including any credential in headers — to every network hop. Loopback and local development names are fine; a routable host is not.',
  recommendation: 'Use https for every routable host. Keep http for loopback only, and make the distinction explicit in configuration rather than per call site.',
  acceptance: ['no http:// URL for a routable host in shipped configuration', 'loopback URLs are clearly development-only'],
  effort: 'S',
  appliesTo: (f) =>
    (JS_TS(f) || ['.json', '.yml', '.yaml', '.env', '.html', '.conf', ''].includes(f.ext)) &&
    // Licence and documentation text is full of http:// references to specs and
    // licences. They are citations, not endpoints this application calls.
    !/(^|\/)(LICEN[SC]E|NOTICE|COPYING|CHANGELOG|README|CONTRIBUTING|SECURITY)(\.|$)/i.test(f.path) &&
    f.ext !== '.md',
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    // Require a dotted host with a letter-only suffix, or an IPv4 literal, so
    // `http://x` inside a regex or a shell snippet does not become a finding.
    const re = /http:\/\/((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/g;
    // Values live in string literals, so search the comments-blanked view
    // rather than raw source: a URL quoted inside an explanatory comment is
    // documentation, not an endpoint this code calls.
    const searchSpace = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, searchSpace, re)) {
      const host = m.match[1] ?? '';
      if (LOOPBACK_OR_RESERVED.test(host)) continue;
      if (isPrivateIpv4(host)) continue; // LAN endpoints are a deliberate local-network choice
      if (SPEC_OR_LICENCE_HOST.test(host)) continue;
      // A namespace/claim-type URI is an identifier that happens to look like a
      // URL. Nothing ever connects to it, so "use https" is meaningless advice.
      if (/^schemas?\./i.test(host)) continue;
      if (/xmlns|schemaLocation|namespace|\bNS\b|\bDTD\b|@see|\bcitation\b|\bSCHEMA\b|\bCLAIM(?:S|_TYPE)?\b|\$schema/i.test(m.lineText)) continue;
      // A path under /ws/<year>/…/claims or /ns/ is a namespace, not an endpoint.
      if (/\/(?:ws|ns)\/\d{4}\//.test(ctx.src.slice(m.index, m.index + 120))) continue;
      // A host whose final label is a file extension came from a filename in prose.
      if (/\.(?:md|txt|js|ts|tsx|jsx|json|ya?ml|html?|css|py|go|rs|sh|png|jpe?g|svg|pdf|lock|toml|conf)$/i.test(host)) continue;
      hits.push(hit(httpEndpointRule.id, ctx.file.path, m.line, excerpt(m.lineText), `plaintext endpoint for routable host ${host}`, { host, inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Switch routable hosts to https; leave loopback alone.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'change http:// to https:// for routable hosts' })),
    acceptanceTests: [{ path: 'test/config/endpoints.test.ts', description: 'no configured endpoint uses http for a routable host' }],
    risk: 'low',
    estimatedDiffSize: 'one character per site',
    agentPrompt:
      'Change each flagged http:// URL to https:// where the host is routable. Leave localhost, 127.0.0.1, ::1, *.local and *.test untouched. If a host is known not to serve TLS, leave it and add a comment naming the reason instead of changing it.',
  }),
};

export const targetBlankRule: Rule = {
  id: 'SEC-TARGET-BLANK',
  title: 'External link opens a new context without dropping opener/referrer',
  type: 'Security',
  severity: 'Low',
  area: 'UI',
  labels: ['security', 'ui'],
  claimType: 'factual',
  why:
    'Without opener protection, the opened page receives a handle to your window and can navigate it. Modern browsers imply noopener for `target="_blank"`, so this is hardening and older embedded webviews rather than a live hole. `rel="noreferrer"` satisfies it too: the spec makes noreferrer imply noopener, so a link carrying either token is protected.',
  recommendation: 'Add `rel="noopener noreferrer"` to every `target="_blank"` anchor. Either token alone drops the opener; both also drop the Referer header.',
  acceptance: ['every target="_blank" anchor carries rel="noopener" or rel="noreferrer"', 'a lint rule enforces it'],
  effort: 'S',
  appliesTo: (f) => JS_TS(f) || f.ext === '.html',
  scan: (ctx) => {
    const hits: RuleHit[] = [];
    // Values live in string literals, so search the comments-blanked view
    // rather than raw source: a URL quoted inside an explanatory comment is
    // documentation, not an endpoint this code calls.
    const searchSpace = { ...ctx.masked, code: ctx.masked.codeAndStrings };
    for (const m of matchCode(ctx.src, searchSpace, /target\s*=\s*["'{]?\s*_blank/g)) {
      const region = ctx.src.slice(Math.max(0, m.index - 300), m.index + 300);
      // `noreferrer` implies `noopener` — the HTML spec says so, and every
      // browser that implements one implements the implication. A rule that
      // tests only for the literal string `noopener` reports `rel="noreferrer"`
      // as missing opener protection, which is advice to add a token that
      // changes nothing.
      if (/rel\s*=\s*["'{]?[^"'}]*\b(?:noopener|noreferrer)\b/.test(region)) continue;
      hits.push(hit(targetBlankRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'target="_blank" without rel="noopener" or rel="noreferrer"', { inTest: ctx.isTest }));
    }
    return hits;
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy: 'Add rel="noopener noreferrer" to each flagged anchor.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'add rel="noopener noreferrer"' })),
    acceptanceTests: [{ path: 'test/ui/links.test.ts', description: 'no target="_blank" without rel="noopener"' }],
    risk: 'low',
    estimatedDiffSize: 'one attribute per anchor',
    agentPrompt:
      'Add rel="noopener noreferrer" to every anchor or link element that sets target="_blank" at the listed locations. If a rel attribute already exists, append the missing tokens instead of replacing it. Change nothing else.',
  }),
};

function uniquePaths(hits: RuleHit[]): string[] {
  return Array.from(new Set(hits.map((h) => h.file)));
}

export const SECURITY_RULES: Rule[] = [
  dangerousHtmlRule,
  markdownHtmlSinkRule,
  tokenWebStorageRule,
  clientSideAuthzRule,
  jwtClientTrustRule,
  childProcessShellRule,
  pathTraversalRule,
  ssrfFetchRule,
  weakCryptoRule,
  evalRule,
  tlsDisabledRule,
  corsWildcardRule,
  postMessageOriginRule,
  secretInClientBundleRule,
  httpEndpointRule,
  targetBlankRule,
];

export type { RuleFileContext };
