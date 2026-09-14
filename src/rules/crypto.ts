import { matchCode } from '../util/lex.js';
import { excerpt } from '../util/fsx.js';
import type { RuleHit } from '../types.js';
import { hit, JS_TS, type Rule, type RuleFileContext } from './types.js';

/**
 * Cryptographic-usage rules for JS/TS.
 *
 * These exist because the rest of the security set checks whether a *primitive*
 * is obsolete (MD5, SHA-1, `Math.random()`) and stops there. The failures that
 * actually break a signing or verification library are not obsolete primitives
 * — they are correct primitives wired up wrongly:
 *
 *  - an authenticator compared with `===`, which leaks it a byte at a time;
 *  - a nonce/IV that is fixed, predictable, or generated once and reused;
 *  - SubtleCrypto called with a broken digest, an extractable private key, or a
 *    key-derivation cost nobody updated since 2010;
 *  - a verification call whose boolean result is thrown away, or wrapped in a
 *    `catch` that returns success.
 *
 * Every rule here is `factual`: each one claims "this construct is at this
 * line", which a re-read from disk can settle. None of them claims
 * exploitability — that would need an executed proof, and these are exactly the
 * cases where the consequence depends on a key the scanner cannot see.
 *
 * As everywhere else, matching happens against the *masked* source, so an
 * example in a docblock is not a finding.
 */

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

function uniquePaths(hits: RuleHit[]): string[] {
  return Array.from(new Set(hits.map((h) => h.file)));
}

/**
 * Split an identifier path into lowercase word tokens.
 *
 * `claimedSig` → `['claimed','sig']`, `raw.prevHash` → `['raw','prev','hash']`,
 * `AUTH_TAG` → `['auth','tag']`. Token-splitting rather than substring matching
 * is what keeps `signal` out of a rule about `sig`, and `macOS` out of a rule
 * about MACs — the two false positives this rule family would otherwise be
 * famous for.
 */
export function wordTokens(identifier: string): string[] {
  return identifier
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Tokens whose value *is* an authenticator whatever the surrounding file does.
 * Every one of these names a thing you present in order to be believed.
 *
 * `session`/`sessionId` is deliberately absent. In application code it means a
 * chat session, an editor session, a telemetry session far more often than an
 * authentication cookie, and a rule that reports every session-list render
 * teaches its reader to skip the whole category. The names that remain are the
 * ones worth interrupting someone for.
 */
const KEYED_TOKENS = new Set([
  'secret',
  'password',
  'passwd',
  'passphrase',
  'apikey',
  'otp',
  'totp',
  'csrf',
  'xsrf',
  'bearer',
  'credential',
  'credentials',
]);

/**
 * `token` on its own does not mean authenticator.
 *
 * It is the most overloaded word in a JS codebase: a lexer token, an LLM token,
 * a design token, and — the one that produced six identical wrong High findings
 * — a monotonic sequence number used to discard a stale async result:
 *
 *     const token = ++tokenRef.current;
 *     const data = await fetch(url);
 *     if (token !== tokenRef.current) return;   // a newer call started
 *
 * That is a correctness guard over an integer counter. Reported as "Authenticator
 * compared with a short-circuiting operator" at High, it is wrong about the
 * value, wrong about the consequence, and wrong in a file containing no crypto
 * at all. So `token` has to earn the classification: either the file performs a
 * signing/verification operation, or the value is plausibly secret-derived (see
 * `plausiblySecretValued`). A counter-valued operand is disqualified outright —
 * even in a crypto module, `++seq` is not an authenticator.
 */
const AMBIGUOUS_KEYED_TOKENS = new Set(['token']);

/**
 * Where a credential plausibly comes from: configuration, the environment, a
 * request header or cookie, a store, or a literal in the source. A value with
 * one of these on its right-hand side is the kind of thing that can be compared
 * wrongly; `++n` is not.
 */
const SECRET_SOURCE =
  /process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env|Deno\s*\.\s*env|getenv|\bconfig\b|\bsettings\b|\bsecrets?\b|\bheaders?\b|\bauthorization\b|getHeader|\breq\b|\brequest\b|\bcookies?\b|\bbody\b|\bquery\b|\bparams\b|localStorage|sessionStorage|keychain|vault|credential|atob\s*\(|Buffer\s*\.\s*from|decode|['"`]/i;

/**
 * Initialisers that prove the value is a counter or a clock reading.
 *
 * `++x`, a bare integer, `useRef(0)` and `Date.now()` are the four shapes the
 * stale-async-result idiom actually uses. `useRef(null)` is deliberately absent:
 * a ref initialised to null is a perfectly ordinary place to keep a token.
 */
const COUNTER_VALUED =
  /(?:\+\+|--)|^-?\d+(?:\.\d+)?$|Date\s*\.\s*now|performance\s*\.\s*now|process\s*\.\s*hrtime|\buse(?:Ref|State|Memo)\s*\(\s*-?\d+\s*\)|\.\s*length\b/;

/**
 * The identifiers worth looking up a declaration for: the root of the path and
 * its final segment. `this` is not one of them.
 */
function resolvableNames(identifier: string): string[] {
  const segments = identifier.split(/[.[\]]+/).filter((s) => /^[A-Za-z_$][\w$]*$/.test(s) && s !== 'this');
  const first = segments[0];
  const last = segments[segments.length - 1];
  return Array.from(new Set([first, last].filter((s): s is string => s !== undefined)));
}

/** The first right-hand side this identifier is assigned in the module, if any. */
function assignedValue(name: string, masked: string): string | undefined {
  const re = new RegExp(`\\b${name}\\s*(?::[^=\\n]{0,80})?=\\s*([^;\\n]{0,160})`);
  return re.exec(masked)?.[1]?.trim();
}

/** Is this operand an integer counter or a clock reading rather than a secret? */
export function counterValued(identifier: string, masked: string): boolean {
  for (const name of resolvableNames(identifier)) {
    const value = assignedValue(name, masked);
    if (value !== undefined && COUNTER_VALUED.test(value)) return true;
  }
  return false;
}

/**
 * Could this operand plausibly hold secret material?
 *
 * Name-only classification cannot answer it, so this reads the module: a
 * declaration from configuration/environment/header, a string-typed declaration
 * or parameter, or a literal initialiser. With no source to read, it falls back
 * to the crypto-context gate, which is how the ambiguous names behaved before
 * this check existed.
 */
export function plausiblySecretValued(identifier: string, fileDoesCrypto: boolean, masked?: string): boolean {
  if (fileDoesCrypto) return true;
  if (masked === undefined) return false;
  for (const name of resolvableNames(identifier)) {
    const value = assignedValue(name, masked);
    if (value !== undefined && SECRET_SOURCE.test(value)) return true;
    // A string-typed declaration or parameter: `(providedToken: string)`.
    if (new RegExp(`\\b${name}\\s*\\??\\s*:\\s*string\\b`).test(masked)) return true;
  }
  return false;
}

/**
 * Tokens that mean "authenticator" in a crypto module and "fingerprint"
 * everywhere else. `buildDiagnosticsSignature()` produces a signature; comparing
 * it with `!==` is change detection. These count only in a file that actually
 * performs a signing or verification operation.
 */
const CRYPTO_CONTEXT_TOKENS = new Set(['signature', 'sig', 'hmac', 'authtag', 'mac']);

/**
 * Tokens that count only as the *last* word of a name.
 *
 * A MAC value is called `computedMac` or `claimedMac`; `macOsVersion` and
 * `macAddress` are not MACs. Requiring the tail position costs nothing real —
 * nobody names a message authentication code `macValue` — and removes the whole
 * Apple-platform false-positive family.
 */
const TAIL_ONLY_TOKENS = new Set(['mac']);

/** Does this file do signing/verification at all? */
const CRYPTO_CONTEXT = /createHmac|createSign|createVerify|subtle\s*\.\s*(?:sign|verify)|\b(?:sign|verify)Bytes\b|timingSafeEqual|\bverifyEd25519\b|jsonwebtoken|\bjwt\s*\./;

/** Tokens that name a digest. A digest is only an authenticator if it is keyed. */
const DIGEST_TOKENS = new Set(['hash', 'digest', 'checksum']);

/** Tokens that mark a value as deliberately public — comparing one leaks nothing. */
const PUBLIC_TOKENS = new Set(['public', 'pub', 'pubkey', 'publickey']);

/**
 * Final path segments that name *metadata about* an authenticator rather than
 * the authenticator. `secret.id`, `token.type`, `credential.expiresAt` are
 * identifiers and labels; comparing one reveals nothing the holder of the record
 * did not already have. Without this, every list-selection check in a UI that
 * renders secrets becomes a timing finding.
 */
const METADATA_TAIL = new Set([
  'id',
  'ids',
  'uuid',
  'type',
  'types',
  'kind',
  'name',
  'label',
  'title',
  'index',
  'count',
  'size',
  'status',
  'state',
  'scope',
  'scopes',
  'provider',
  'source',
  'prefix',
  'suffix',
  'mask',
  'masked',
  'hint',
  'preview',
  'error',
  'message',
  'url',
  'uri',
  'path',
  'exp',
  'iat',
  'createdat',
  'updatedat',
  'expiresat',
  'lastfour',
]);

/**
 * Tokens that mark a comparison of two values the *same* party supplied — a
 * password against its confirmation field. Both sides are already in the
 * attacker's hands when the attacker is the user, so there is no oracle.
 */
const SAME_ORIGIN_TOKENS = new Set(['confirm', 'confirmation', 'confirmed', 'repeat', 'repeated', 'again', 'retype', 'reenter']);

export type OperandClass = 'keyed' | 'digest' | null;

/**
 * What kind of value does this identifier hold, judged by its name alone?
 *
 * Name-only classification is a deliberate limit, not an oversight: the
 * alternative is cross-module type inference, which this tool does not do and
 * does not claim to. The cost is paid in the other direction — `digest` hits
 * are dropped unless the file shows the value was keyed (see `isKeyedDigest`),
 * so an unkeyed content hash never becomes a finding.
 */
export function classifyOperand(identifier: string, fileDoesCrypto = true, masked?: string): OperandClass {
  const tokens = wordTokens(identifier);
  if (tokens.length === 0) return null;
  if (tokens.some((t) => PUBLIC_TOKENS.has(t))) return null;
  if (tokens.some((t) => SAME_ORIGIN_TOKENS.has(t))) return null;
  // An integer counter is not an authenticator whatever it is called, and
  // whatever the file around it does.
  if (masked !== undefined && counterValued(identifier, masked)) return null;
  // `secret.id` holds an identifier, not the secret. Judge the last segment of
  // the path, because that is what the expression actually evaluates to.
  const tail = wordTokens(identifier.split('.').pop() ?? identifier);
  const last = tail[tail.length - 1];
  if (last !== undefined && METADATA_TAIL.has(last) && !KEYED_TOKENS.has(last)) return null;
  // Two-word names like `apiKey` tokenize apart, so test the joined form too.
  const adjacentPairs = tokens.slice(0, -1).map((t, i) => t + tokens[i + 1]!);
  const all = [...tokens, ...adjacentPairs];
  const counts = (t: string): boolean => (TAIL_ONLY_TOKENS.has(t) ? t === last : true);
  if (all.some((t) => KEYED_TOKENS.has(t) && counts(t))) return 'keyed';
  // `token` only counts when the file does crypto or the value looks
  // secret-derived — the gate CRYPTO_CONTEXT_TOKENS has always had, and which
  // this set was missing while producing the same class of false positive.
  if (all.some((t) => AMBIGUOUS_KEYED_TOKENS.has(t) && counts(t)) && plausiblySecretValued(identifier, fileDoesCrypto, masked)) {
    return 'keyed';
  }
  if (fileDoesCrypto && all.some((t) => CRYPTO_CONTEXT_TOKENS.has(t) && counts(t))) return 'keyed';
  if (tokens.some((t) => DIGEST_TOKENS.has(t))) return 'digest';
  return null;
}

/**
 * Do both operands name the same field?
 *
 * `this.apiKey === options.apiKey` asks "is this instance configured like that
 * one" — a config-equality check between two objects the process already holds.
 * An authentication decision never looks like this: it compares a *supplied*
 * value against a *stored* one, and those get different names (`header` vs
 * `expected`, `supplied` vs `stored`). Identical tails are the cheapest reliable
 * signal that nobody is being authenticated.
 */
export function sameFieldComparison(left: string, right: string): boolean {
  const tail = (p: string): string => (p.split('.').pop() ?? p).toLowerCase();
  return left.includes('.') && right.includes('.') && tail(left) === tail(right) && left !== right;
}

/**
 * Masked code with import/require lines blanked.
 *
 * Needed because the "is there a `timingSafeEqual` nearby?" guard would
 * otherwise be satisfied by the import at the top of the file — which is how a
 * rule ends up silently disabled in exactly the modules that do crypto.
 */
function withoutImports(maskedCode: string): string {
  return maskedCode.replace(/^[ \t]*(?:import\b[^\n]*|(?:const|let|var)\b[^\n]*\brequire\s*\([^\n]*)$/gm, (line) => ' '.repeat(line.length));
}

/**
 * Was this digest produced with a key?
 *
 * A SHA-256 content hash compared with `===` is not a timing oracle: both sides
 * are public and the attacker already holds one of them. An HMAC compared the
 * same way is the textbook CWE-208. The difference is whether a key went in, so
 * the rule looks for the assignment and asks exactly that.
 */
export function isKeyedDigest(identifier: string, masked: string): boolean {
  const base = identifier.split(/[.[]/)[0] ?? identifier;
  if (!/^[A-Za-z_$][\w$]*$/.test(base)) return false;
  const assignment = new RegExp(
    `\\b${base}\\b\\s*=[^;\\n]*(createHmac|\\bhmac\\b|subtle\\s*\\.\\s*sign|\\.\\s*sign\\s*\\(|pbkdf2|scrypt|hkdf|deriveBits|deriveKey)`,
    'i',
  );
  return assignment.test(masked);
}

/** The identifier path immediately left of `at`, or '' when the operand is a literal/expression. */
function operandBefore(masked: string, at: number): string {
  const slice = masked.slice(Math.max(0, at - 80), at);
  const m = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(slice);
  return m ? m[1]!.replace(/\s+/g, '') : '';
}

/** The identifier path immediately right of `at`, or '' when the operand is a literal/expression. */
function operandAfter(masked: string, at: number): string {
  const slice = masked.slice(at, at + 80);
  const m = /^\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)/.exec(slice);
  return m ? m[1]!.replace(/\s+/g, '') : '';
}

// ---------------------------------------------------------------------------
// SEC-TIMING-UNSAFE-COMPARE
// ---------------------------------------------------------------------------

const NON_VALUE_OPERAND = /(?:^|\.)length$|^(?:undefined|null|true|false|NaN)$|^\d/;

export const timingUnsafeCompareRule: Rule = {
  id: 'SEC-TIMING-UNSAFE-COMPARE',
  title: 'Authenticator compared with a short-circuiting operator',
  type: 'Security',
  severity: 'High',
  area: 'Shared',
  labels: ['security', 'crypto', 'timing'],
  claimType: 'factual',
  why:
    "`===`, `==`, `Buffer.prototype.equals` and `Buffer.compare` stop at the first differing byte, so the time they take depends on how much of the supplied value was correct. Against a signature, HMAC, session token or API key that turns forgery from 256^n guesses into n*256 measurements — the attacker recovers the value one byte at a time without ever seeing it. The comparison is also the one line in a verification path where being wrong is silent: every test still passes.",
  recommendation:
    "Compare authenticators with `crypto.timingSafeEqual` (Node) or by verifying a signature through `crypto.subtle.verify`, never with an equality operator. `timingSafeEqual` throws on length mismatch, so compare fixed-length encodings — hash both sides to a constant width first if the input length is attacker-controlled, since the length check itself is an oracle.",
  acceptance: [
    'no signature, MAC, token, password or API key is compared with ==, ===, Buffer.compare or Buffer.equals',
    'every such comparison goes through crypto.timingSafeEqual or a verify() primitive',
    'inputs are normalised to a fixed length before the comparison so the length check leaks nothing',
  ],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx: RuleFileContext) => {
    const hits: RuleHit[] = [];
    const seen = new Set<number>();
    // The one correct reason to compare lengths with `!==` next to an
    // authenticator is the guard in front of `timingSafeEqual`, which throws on
    // unequal lengths. That shape fits in three lines, so the exemption is scoped
    // to three lines. A character window wide enough to reach the next function
    // would switch the rule off for every module that imports a safe comparator —
    // precisely the modules it exists to check.
    const guardLines = withoutImports(ctx.masked.code).split('\n');
    const fileDoesCrypto = CRYPTO_CONTEXT.test(ctx.masked.code);
    // The masked module is passed so an operand can be judged by how it is
    // *assigned*, not only by its name: `const token = ++tokenRef.current` is a
    // sequence number, and no name-only rule can tell.
    const classify = (name: string): OperandClass => classifyOperand(name, fileDoesCrypto, ctx.masked.code);
    const nearSafeCompare = (line: number): boolean =>
      guardLines
        .slice(Math.max(0, line - 2), line + 1)
        .some((l) => /timingSafeEqual|constantTimeEqual/.test(l));

    const push = (line: number, lineText: string, message: string, meta: Record<string, string | number | boolean>): void => {
      if (seen.has(line)) return;
      seen.add(line);
      hits.push(hit(timingUnsafeCompareRule.id, ctx.file.path, line, excerpt(lineText), message, meta));
    };

    // 1. Equality operators.
    for (const m of matchCode(ctx.src, ctx.masked, /(===|!==|==(?!=)|!=(?!=))/g)) {
      const op = m.match[1]!;
      const left = operandBefore(ctx.masked.code, m.index);
      const right = operandAfter(ctx.masked.code, m.index + op.length);
      if (left === '' || right === '') continue; // one side is a literal or an expression
      if (NON_VALUE_OPERAND.test(left) || NON_VALUE_OPERAND.test(right)) continue;
      if (/\btypeof\s*$/.test(ctx.masked.code.slice(Math.max(0, m.index - 100), m.index - left.length))) continue;
      // `password !== confirm`: one side names the other's confirmation field, so
      // the comparison decides nothing an attacker could not already compute.
      if ([...wordTokens(left), ...wordTokens(right)].some((t) => SAME_ORIGIN_TOKENS.has(t))) continue;
      if (sameFieldComparison(left, right)) continue;

      const classes: Array<[string, OperandClass]> = [
        [left, classify(left)],
        [right, classify(right)],
      ];
      const keyed = classes.find(([, c]) => c === 'keyed');
      const digest = classes.find(([name, c]) => c === 'digest' && isKeyedDigest(name, ctx.masked.code));
      const chosen = keyed ?? digest;
      if (!chosen) continue;

      // A length pre-check in front of timingSafeEqual is correct, not a finding.
      if (nearSafeCompare(m.line)) continue;

      push(m.line, m.lineText, `\`${left} ${op} ${right}\` compares ${keyed ? 'an authenticator' : 'a keyed digest'} with a short-circuiting operator`, {
        kind: 'equality',
        operator: op,
        operand: chosen[0],
        keyed: keyed !== undefined,
        inTest: ctx.isTest,
      });
    }

    // 2. Buffer comparisons, which short-circuit the same way.
    //
    // A byte-wise comparison is itself the context the ambiguous names need:
    // nobody runs `Buffer.compare` over a sequence number, so the call supplies
    // the evidence that a name alone cannot. The counter check inside
    // `classifyOperand` still applies.
    const classifyBytes = (name: string): OperandClass => classifyOperand(name, true, ctx.masked.code);
    for (const m of matchCode(ctx.src, ctx.masked, /\bBuffer\s*\.\s*compare\s*\(\s*([\w$.]+)\s*,\s*([\w$.]+)/g)) {
      const names = [m.match[1]!, m.match[2]!];
      if (sameFieldComparison(names[0]!, names[1]!)) continue;
      const which = names.find((n) => classifyBytes(n) === 'keyed' || (classifyBytes(n) === 'digest' && isKeyedDigest(n, ctx.masked.code)));
      if (!which) continue;
      if (nearSafeCompare(m.line)) continue;
      push(m.line, m.lineText, `Buffer.compare() over ${which} returns on the first differing byte`, { kind: 'buffer-compare', operand: which, keyed: true, inTest: ctx.isTest });
    }

    for (const m of matchCode(ctx.src, ctx.masked, /\b([\w$.]+)\s*\.\s*equals\s*\(\s*([\w$.]+)/g)) {
      const names = [m.match[1]!, m.match[2]!];
      if (sameFieldComparison(names[0]!, names[1]!)) continue;
      const which = names.find((n) => classifyBytes(n) === 'keyed' || (classifyBytes(n) === 'digest' && isKeyedDigest(n, ctx.masked.code)));
      if (!which) continue;
      if (nearSafeCompare(m.line)) continue;
      push(m.line, m.lineText, `Buffer.equals() over ${which} returns on the first differing byte`, { kind: 'buffer-equals', operand: which, keyed: true, inTest: ctx.isTest });
    }

    return hits;
  },
  severityFor: (hits) => {
    const live = hits.filter((h) => h.meta?.inTest !== true);
    if (live.length === 0) return 'Low';
    // A keyed digest compared loosely is the same defect as a signature
    // compared loosely; only name-derived uncertainty separates them.
    return live.some((h) => h.meta?.keyed === true) ? 'High' : 'Medium';
  },
  fixPlan: (hits) => ({
    agentExecutable: true,
    strategy:
      'Replace each comparison with a constant-time one. In Node that is `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` guarded by an equal-length check; in a browser or worker it is `crypto.subtle.verify`, or a constant-time XOR-accumulate over equal-length byte arrays.',
    changes: uniquePaths(hits).map((p) => ({ path: p, change: 'swap the equality/Buffer comparison for a constant-time comparison of equal-length encodings' })),
    acceptanceTests: [
      { path: 'test/security/timingSafeCompare.test.ts', description: 'a wrong authenticator is rejected, a right one accepted, and the comparison helper rejects unequal lengths rather than returning false early' },
    ],
    risk: 'low',
    estimatedDiffSize: 'one helper plus one line per comparison',
    agentPrompt:
      'At each listed location an authenticator (signature, MAC, token, password or API key) is compared with ===, !==, ==, !=, Buffer.compare or Buffer.equals. Introduce a single shared helper — e.g. src/security/constantTimeEqual.ts — that takes two strings or Uint8Arrays, returns false when the byte lengths differ, and otherwise compares with crypto.timingSafeEqual (Node) or an XOR-accumulating loop that always walks the full length (portable). Route every flagged comparison through it, keeping the boolean sense of the original expression identical, including negations. Do not change the encoding of any persisted or transmitted value. Do not touch comparisons against undefined, null, or a length.',
  }),
};

// ---------------------------------------------------------------------------
// SEC-CRYPTO-IV-REUSE
// ---------------------------------------------------------------------------

/** Zero-filled or literal byte sources — a fixed IV however it is spelled. */
const STATIC_BYTES = /Buffer\s*\.\s*alloc\s*\(|new\s+Uint8Array\s*\(\s*(?:\d+\s*)?\)|new\s+Uint8Array\s*\(\s*\[|Buffer\s*\.\s*from\s*\(\s*['"`[]|^['"`]|^null$|^0$/;
const RANDOM_SOURCE = /randomBytes|getRandomValues|randomFillSync|randomUUID|webcrypto/;
/** Counters and clocks: not secret, not unique across restarts, trivially replayed. */
const PREDICTABLE_SOURCE = /Date\s*\.\s*now|new\s+Date|performance\s*\.\s*now|\+\+|process\s*\.\s*hrtime|Math\s*\.\s*random/;

/** How is this IV/nonce expression sourced? */
export function classifyIv(expr: string, masked: string): { kind: string; detail: string } | null {
  const trimmed = expr.trim();
  if (trimmed === '') return null;
  if (RANDOM_SOURCE.test(trimmed)) return null;
  if (PREDICTABLE_SOURCE.test(trimmed)) return { kind: 'predictable', detail: 'derived from a clock or counter' };
  if (STATIC_BYTES.test(trimmed)) return { kind: 'static', detail: 'a zero-filled or literal byte sequence' };

  // A bare identifier: find its declaration and judge that instead.
  const idMatch = /^([A-Za-z_$][\w$]*)$/.exec(trimmed);
  if (!idMatch) return null;
  const name = idMatch[1]!;
  const decl = new RegExp(`(?:^|\\n)([ \\t]*)(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]+)?=\\s*([^;\\n]+)`).exec(masked);
  if (!decl) return null;
  const indent = decl[1]!;
  const init = decl[2]!.trim();
  if (PREDICTABLE_SOURCE.test(init)) return { kind: 'predictable', detail: `\`${name}\` is derived from a clock or counter` };
  if (RANDOM_SOURCE.test(init)) {
    // Random, but drawn once at module scope: every encryption reuses it, which
    // for GCM/CTR is the catastrophic case rather than the cosmetic one.
    if (indent.length === 0) return { kind: 'module-scope', detail: `\`${name}\` is drawn once at module scope and reused by every call` };
    return null;
  }
  if (STATIC_BYTES.test(init)) return { kind: 'static', detail: `\`${name}\` is a fixed byte sequence` };
  return null;
}

export const ivReuseRule: Rule = {
  id: 'SEC-CRYPTO-IV-REUSE',
  title: 'Encryption nonce/IV is fixed, predictable, or reused across messages',
  type: 'Security',
  severity: 'High',
  area: 'Shared',
  labels: ['security', 'crypto', 'nonce'],
  claimType: 'factual',
  why:
    'AES-GCM, ChaCha20-Poly1305 and AES-CTR are stream constructions: the key and nonce generate a keystream that is XORed with the plaintext. Reuse the nonce under the same key and the XOR of two ciphertexts is the XOR of two plaintexts — and for GCM it is worse than confidentiality loss, because two messages under one nonce leak the authentication subkey and let an attacker forge tags for that key. A fixed or clock-derived nonce, or one drawn once at module load, is reuse on every call after the first. ECB is the degenerate case: no nonce at all, so identical plaintext blocks produce identical ciphertext blocks.',
  recommendation:
    'Draw a fresh nonce per encryption from a CSPRNG (`randomBytes(12)` for GCM, `getRandomValues` in a browser) and store or transmit it alongside the ciphertext — nonces are not secret, only unique. Never take a nonce from a counter, a timestamp, or a module-level constant, and never use ECB.',
  acceptance: [
    'every encryption call receives a nonce/IV generated inside that call from a CSPRNG',
    'the nonce travels with the ciphertext rather than being recomputed from anything',
    'no ECB mode anywhere, and AEAD tags are verified on decrypt',
    'a test encrypts the same plaintext twice and asserts the ciphertexts differ',
  ],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx: RuleFileContext) => {
    const hits: RuleHit[] = [];

    // Node: createCipheriv(algorithm, key, iv).
    for (const m of matchCode(ctx.src, ctx.masked, /\bcreate(?:De)?cipheriv\s*\(([^;\n]*)/gi)) {
      const args = splitArgs(m.match[1] ?? '');
      const algorithm = ctx.src.slice(m.index, m.index + 120);
      if (/-ecb|_ecb|ECB/.test(algorithm)) {
        hits.push(hit(ivReuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'ECB mode: no IV, so equal plaintext blocks produce equal ciphertext blocks', { kind: 'ecb', inTest: ctx.isTest }));
        continue;
      }
      if (args.length < 3) continue;
      const verdict = classifyIv(args[2]!, ctx.masked.code);
      if (!verdict) continue;
      hits.push(
        hit(ivReuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `IV argument to createCipheriv is ${verdict.detail}`, { kind: verdict.kind, api: 'createCipheriv', inTest: ctx.isTest }),
      );
    }

    // WebCrypto: { name: 'AES-GCM', iv } / { name: 'AES-CTR', counter }.
    for (const m of matchCode(ctx.src, ctx.masked, /\b(?:iv|counter|nonce)\s*:\s*([^,}\n]+)/g)) {
      const region = ctx.src.slice(Math.max(0, m.index - 160), m.index + 160);
      if (!/AES-GCM|AES-CBC|AES-CTR|AES-KW|ChaCha|chacha|aes-\d{3}-(?:gcm|cbc|ctr)/.test(region)) continue;
      const verdict = classifyIv(m.match[1] ?? '', ctx.masked.code);
      if (!verdict) continue;
      hits.push(hit(ivReuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `WebCrypto nonce parameter is ${verdict.detail}`, { kind: verdict.kind, api: 'subtle', inTest: ctx.isTest }));
    }

    // ECB named in a WebCrypto algorithm object or a cipher string.
    for (const m of matchCode(ctx.src, { ...ctx.masked, code: ctx.masked.codeAndValues }, /\b(?:AES-ECB|aes-\d{3}-ecb)\b/g)) {
      if (hits.some((h) => h.line === m.line)) continue;
      hits.push(hit(ivReuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'ECB mode named in a cipher specification', { kind: 'ecb', inTest: ctx.isTest }));
    }

    return hits;
  },
  severityFor: (hits) => (hits.every((h) => h.meta?.inTest === true) ? 'Low' : 'High'),
  fixPlan: (hits) => ({
    agentExecutable: false,
    strategy:
      'Generate the nonce inside each encryption call and persist it with the ciphertext. That changes the stored/transmitted format, so anything already encrypted under the old scheme has to be read with the old path while new writes use the new one — a migration, not an edit.',
    changes: [
      ...uniquePaths(hits).map((p) => ({ path: p, change: 'draw a per-message nonce from a CSPRNG and prefix it to the ciphertext; switch any ECB mode to an AEAD' })),
      { path: 'docs/crypto-migration.md', change: 'new: how existing ciphertexts are read during the transition and when the old path is removed' },
    ],
    acceptanceTests: [
      { path: 'test/security/nonce.test.ts', description: 'encrypting the same plaintext twice yields different ciphertexts; decrypt round-trips both; a tampered tag fails' },
    ],
    risk: 'high',
    estimatedDiffSize: 'the encrypt/decrypt pair plus a read path for existing data',
    notAgentExecutableReason:
      'Changing the nonce scheme changes the ciphertext format. Without knowing what is already encrypted and where it lives, an unsupervised rewrite makes existing data undecryptable — that decision belongs to whoever owns the data.',
  }),
};

/** Split a call's argument list on top-level commas. */
function splitArgs(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of text) {
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') {
      // The call's own closing paren: the argument being accumulated is the last
      // one, and dropping it is how a three-argument createCipheriv looked like
      // it had two and never got its IV checked.
      if (depth === 0) break;
      depth -= 1;
    }
    if (ch === ',' && depth === 0) {
      out.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') out.push(current);
  return out.map((a) => a.trim());
}

// ---------------------------------------------------------------------------
// SEC-WEBCRYPTO-MISUSE
// ---------------------------------------------------------------------------

/** Key usages that only a private/secret key has. */
const PRIVATE_USAGES = /'(?:sign|decrypt|deriveKey|deriveBits|unwrapKey)'|"(?:sign|decrypt|deriveKey|deriveBits|unwrapKey)"/;
/** OWASP's 2023 floor for PBKDF2-HMAC-SHA256. Below it, the KDF is decoration. */
export const PBKDF2_ITERATION_FLOOR = 100_000;

export const webCryptoMisuseRule: Rule = {
  id: 'SEC-WEBCRYPTO-MISUSE',
  title: 'SubtleCrypto called with a broken digest, an extractable private key, or a weak KDF cost',
  type: 'Security',
  severity: 'Medium',
  area: 'Shared',
  labels: ['security', 'crypto', 'webcrypto'],
  claimType: 'factual',
  why:
    'WebCrypto takes its parameters as data, so its misuses are invisible to a type checker and silent at runtime: `digest("SHA-1", …)` returns a digest, `importKey(…, true, ["sign"])` returns a key, `deriveBits` with 1000 iterations returns bits. What changes is the guarantee. SHA-1 is collision-broken, so a SHA-1 digest cannot bind a signature to one document. An extractable private key can be read back out by any script in the origin and exfiltrated as JSON — the one property that stops an XSS from becoming a stolen signing key. A PBKDF2 cost below the modern floor puts a stolen hash within reach of commodity hardware.',
  recommendation:
    'Use SHA-256 or better for every digest and signature. Import or generate private/secret keys with `extractable: false` unless the key must be exported, and say why in a comment when it must. Set PBKDF2 iterations at or above the current OWASP floor, or prefer Argon2id/scrypt where available. Keep AES-GCM at the default 128-bit tag.',
  acceptance: [
    'no SHA-1 or MD5 passed to subtle.digest, subtle.sign, subtle.verify or an HMAC/RSA hash parameter',
    'every importKey/generateKey producing a private or secret key passes extractable: false',
    `PBKDF2 iteration counts are at or above ${PBKDF2_ITERATION_FLOOR.toLocaleString('en-US')}`,
    'AES-GCM tagLength is 128 where it is set at all',
  ],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx: RuleFileContext) => {
    const hits: RuleHit[] = [];
    // Algorithm names are string literals, so search the comments-blanked view.
    const withStrings = { ...ctx.masked, code: ctx.masked.codeAndValues };

    // 1. Broken digests named as a WebCrypto algorithm.
    //
    // Deliberately NOT matching `createHash('md5')` — SEC-WEAK-CRYPTO owns that,
    // and two findings for one line teaches the reader the count is inflated.
    // This rule's subject is the parameter form: a digest passed to SubtleCrypto
    // positionally, or set as the `hash`/`name` of an algorithm object.
    const digestPatterns = [
      /(?:subtle\s*\.\s*)?(?:digest|sign|verify|deriveBits|deriveKey|unwrapKey|importKey)\s*\(\s*['"`]\s*(SHA-?1|MD5)\s*['"`]/gi,
      /\b(?:hash|name)\s*:\s*['"`]\s*(SHA-?1|MD5)\s*['"`]/gi,
    ];
    const digestLines = new Set<number>();
    for (const re of digestPatterns) {
      for (const m of matchCode(ctx.src, withStrings, re)) {
        if (digestLines.has(m.line)) continue;
        digestLines.add(m.line);
        hits.push(hit(webCryptoMisuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `${m.match[1]!.toUpperCase()} named as a WebCrypto algorithm — collision-broken, so it cannot bind a signature to one input`, { kind: 'weak-digest', algorithm: m.match[1]!.toUpperCase(), inTest: ctx.isTest }));
      }
    }

    // 2. Extractable private/secret key material.
    for (const m of matchCode(ctx.src, withStrings, /\b(importKey|generateKey|unwrapKey)\s*\(([^;]{0,400})/g)) {
      const api = m.match[1]!;
      const args = m.match[2] ?? '';
      if (!PRIVATE_USAGES.test(args)) continue;
      // `extractable` is the argument immediately before the usages array.
      const beforeUsages = args.slice(0, args.search(/\[[^\]]*(?:sign|decrypt|deriveKey|deriveBits|unwrapKey)/));
      if (!/\btrue\s*,\s*$/.test(beforeUsages) && !/\bextractable\s*:\s*true/.test(args)) continue;
      hits.push(hit(webCryptoMisuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `${api}() marks a key with private usages as extractable — any script in the origin can export it`, { kind: 'extractable-private-key', api, inTest: ctx.isTest }));
    }

    // 3. Key-derivation cost.
    for (const m of matchCode(ctx.src, ctx.masked, /\biterations\s*:\s*([\d_]+)/g)) {
      const region = ctx.src.slice(Math.max(0, m.index - 240), m.index + 240);
      if (!/PBKDF2|pbkdf2/.test(region)) continue;
      const iterations = Number((m.match[1] ?? '0').replace(/_/g, ''));
      if (iterations >= PBKDF2_ITERATION_FLOOR) continue;
      hits.push(hit(webCryptoMisuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `PBKDF2 iteration count ${iterations.toLocaleString('en-US')} is below the ${PBKDF2_ITERATION_FLOOR.toLocaleString('en-US')} floor`, { kind: 'weak-kdf', iterations, inTest: ctx.isTest }));
    }

    // 4. Truncated AEAD tags.
    for (const m of matchCode(ctx.src, ctx.masked, /\btagLength\s*:\s*(\d+)/g)) {
      const tagLength = Number(m.match[1] ?? '0');
      if (tagLength >= 128) continue;
      hits.push(hit(webCryptoMisuseRule.id, ctx.file.path, m.line, excerpt(m.lineText), `AES-GCM tagLength ${tagLength} truncates the authentication tag below the 128-bit default`, { kind: 'short-tag', tagLength, inTest: ctx.isTest }));
    }

    return hits;
  },
  severityFor: (hits) => {
    const live = hits.filter((h) => h.meta?.inTest !== true);
    if (live.length === 0) return 'Low';
    return live.some((h) => h.meta?.kind === 'extractable-private-key' || h.meta?.kind === 'weak-digest') ? 'High' : 'Medium';
  },
  fixPlan: (hits) => {
    const kinds = new Set(hits.map((h) => String(h.meta?.kind ?? '')));
    // Raising a PBKDF2 cost or widening a digest invalidates stored outputs; an
    // agent that does not know what is stored cannot be trusted with that.
    const migrationNeeded = kinds.has('weak-kdf') || kinds.has('weak-digest');
    if (migrationNeeded) {
      return {
        agentExecutable: false,
        strategy:
          'Move to SHA-256 and a modern KDF cost, keeping a read path for values already derived or digested under the old parameters until they are rotated.',
        changes: uniquePaths(hits).map((p) => ({ path: p, change: 'widen the digest / raise the KDF cost, and version the stored output so old values are still readable' })),
        acceptanceTests: [{ path: 'test/security/webcrypto.test.ts', description: 'new values use the new parameters, previously stored values still verify, and the old parameters are refused for new writes' }],
        risk: 'medium',
        estimatedDiffSize: 'the crypto call sites plus a versioned read path',
        notAgentExecutableReason:
          'Changing a digest or a KDF cost changes every value derived from it. Whether stored hashes can be re-derived, re-verified lazily, or must be rotated is a data decision an agent cannot make from the source alone.',
      };
    }
    return {
      agentExecutable: true,
      strategy: 'Pass `extractable: false` when importing or generating keys with private usages, and leave AES-GCM tags at the 128-bit default.',
      changes: uniquePaths(hits).map((p) => ({ path: p, change: 'flip extractable to false / drop the truncated tagLength' })),
      acceptanceTests: [{ path: 'test/security/webcrypto.test.ts', description: 'exportKey on an imported signing key rejects, and the sign/verify round trip still passes' }],
      risk: 'low',
      estimatedDiffSize: 'one argument per call site',
      agentPrompt:
        'At each listed location, a SubtleCrypto call creates a key with private usages (sign, decrypt, deriveKey, deriveBits, unwrapKey) and marks it extractable, or truncates an AES-GCM authentication tag. Set the extractable argument to false, and remove a tagLength below 128 so the default 128-bit tag applies. If a call site genuinely needs to export the key, leave it and add a comment naming what exports it and why. Run the test suite: a test calling exportKey on a now-unextractable key will fail, and that test is the thing to update, not the flag.',
    };
  },
};

// ---------------------------------------------------------------------------
// SEC-SIGNATURE-VERIFY-DISCARDED
// ---------------------------------------------------------------------------

const VERIFY_CALL = /\b(?:await\s+)?(?:[\w$]+\s*\.\s*)*?(verify|verifyLog|verifySignature|verifySig|verifyBytes|verifyHmac|verifyToken|verifyJwt|timingSafeEqual|constantTimeEqual)\s*\(/g;
/** Anything on the line before the call that consumes the result. */
const CONSUMES_RESULT = /[=!<>&|?+([,:]\s*$|\b(?:return|if|while|await|assert|expect|throw|const|let|var|case|yield|do|not)\s*$/;

export const verifyResultDiscardedRule: Rule = {
  id: 'SEC-SIGNATURE-VERIFY-DISCARDED',
  title: 'Signature verification result is discarded or fails open',
  type: 'Security',
  severity: 'Blocker',
  area: 'Shared',
  labels: ['security', 'crypto', 'authentication'],
  claimType: 'factual',
  why:
    'Every verification primitive in JS reports failure by returning `false`, not by throwing: `crypto.verify`, `subtle.verify` and `timingSafeEqual` all return a boolean. Call one as a bare statement and the check is decorative — the code reads as if it verifies, the log says it verified, and every forgery is accepted. The same hole opens from the other end when a `catch` around a verification returns success, because malformed input then passes instead of failing, or when a flag short-circuits the check in a build that was meant to be development-only. A signing library with any of these has the strongest possible claim and none of the guarantee.',
  recommendation:
    'Consume the boolean: `if (!(await verify(...))) throw new VerificationError(...)`. Let a `catch` around a verification return failure, never success — unparseable input is failed verification. Delete bypass flags rather than defaulting them off; a flag that can turn verification off is a feature an attacker can ask for.',
  acceptance: [
    'every verification call is used in a condition, assignment, or return — never as a bare statement',
    'no catch around a verification path returns a success value',
    'no flag, environment variable, or option can skip signature verification at runtime',
    "a test feeds a tampered input through the real verification entrypoint and asserts it is rejected",
  ],
  effort: 'S',
  appliesTo: JS_TS,
  scan: (ctx: RuleFileContext) => {
    const hits: RuleHit[] = [];

    // 1. The result is never read.
    for (const m of matchCode(ctx.src, ctx.masked, VERIFY_CALL)) {
      const lineStart = ctx.masked.code.lastIndexOf('\n', m.index) + 1;
      const before = ctx.masked.code.slice(lineStart, m.index);
      if (CONSUMES_RESULT.test(before)) continue;
      if (before.trim() !== '' && !/^\s*await\s+$/.test(before)) continue;
      // A callback-style verify reports through its callback, not its return value.
      const after = ctx.masked.code.slice(m.index, m.index + 300);
      const statementEnd = after.search(/;|\n/);
      const call = statementEnd === -1 ? after : after.slice(0, statementEnd);
      if (/=>|\bfunction\b|\(\s*err/.test(call)) continue;
      hits.push(hit(verifyResultDiscardedRule.id, ctx.file.path, m.line, excerpt(m.lineText), `${m.match[1]!}() is called as a statement, so its boolean result is discarded`, { kind: 'result-discarded', fn: m.match[1]!, inTest: ctx.isTest }));
    }

    // 2. A catch that returns success out of a verification path.
    //
    // `return true` only means success if the enclosing predicate is positive.
    // `isTokenExpired() { try { … } catch { return true } }` returns *expired* —
    // fail-closed, and exactly the construct a naive version of this rule
    // reports as its headline finding. Two guards keep it out: the try block has
    // to contain a real verification primitive (not merely the word "verify"),
    // and the enclosing name must not be a negative predicate.
    for (const m of matchCode(ctx.src, ctx.masked, /\bcatch\s*(?:\([^)]*\))?\s*\{([^{}]{0,200})\}/g)) {
      const body = m.match[1] ?? '';
      if (!/\breturn\s+(?:true|1)\b|\breturn\s*\{\s*(?:ok|valid|verified)\s*:\s*true/.test(body)) continue;
      const region = ctx.masked.code.slice(Math.max(0, m.index - 600), m.index);
      if (!/\b(?:verify|verifyLog|verifySignature|verifySig|verifyBytes|verifyHmac|verifyToken|verifyJwt|timingSafeEqual|constantTimeEqual|createHmac)\s*\(|subtle\s*\.\s*verify/.test(region)) continue;
      if (negativePredicateName(region)) continue;
      hits.push(hit(verifyResultDiscardedRule.id, ctx.file.path, m.line, excerpt(m.lineText), 'catch in a verification path returns success — malformed input is accepted rather than rejected', { kind: 'fail-open-catch', inTest: ctx.isTest }));
    }

    // 3. A runtime switch that turns verification off. One per line: the flag is
    //    usually declared and read on the same line, and reporting it twice
    //    inflates a count the reader is being asked to trust.
    const switchLines = new Set<number>();
    for (const m of matchCode(ctx.src, ctx.masked, /\b(?:skip|disable|bypass|ignore|no)[_A-Za-z]*(?:verif|signature|sigcheck|attestation)[_A-Za-z]*\b/gi)) {
      if (switchLines.has(m.line)) continue;
      switchLines.add(m.line);
      hits.push(hit(verifyResultDiscardedRule.id, ctx.file.path, m.line, excerpt(m.lineText), `\`${m.match[0]!}\` can turn signature verification off at runtime`, { kind: 'bypass-switch', switch: m.match[0]!, inTest: ctx.isTest }));
    }

    // 4. `none` accepted as a signature algorithm.
    for (const m of matchCode(ctx.src, { ...ctx.masked, code: ctx.masked.codeAndValues }, /\balgorithms?\s*:\s*(?:\[\s*)?['"`]\s*none\s*['"`]/gi)) {
      hits.push(hit(verifyResultDiscardedRule.id, ctx.file.path, m.line, excerpt(m.lineText), "the `none` algorithm is accepted, which makes an unsigned token verify", { kind: 'alg-none', inTest: ctx.isTest }));
    }

    return hits;
  },
  maxEvidence: 8,
  severityFor: (hits) => {
    const live = hits.filter((h) => h.meta?.inTest !== true);
    if (live.length === 0) return 'Low';
    if (live.some((h) => h.meta?.kind === 'result-discarded' || h.meta?.kind === 'alg-none' || h.meta?.kind === 'fail-open-catch')) return 'Blocker';
    // A bypass switch is reported as High rather than Blocker: it is a real hole
    // only if it is reachable in a production build, which this rule cannot see.
    return 'High';
  },
  fixPlan: (hits) => {
    const kinds = new Set(hits.map((h) => String(h.meta?.kind ?? '')));
    const onlySwitches = kinds.size === 1 && kinds.has('bypass-switch');
    if (onlySwitches) {
      return {
        agentExecutable: false,
        strategy:
          'Decide, per switch, whether verification may ever be skipped. If not, delete the branch. If it may be skipped locally, make the flag unreadable in a production build (compile-time constant, not an environment variable) and fail loudly when it is set.',
        changes: uniquePaths(hits).map((p) => ({ path: p, change: 'remove the bypass branch, or bind it to a build-time development constant' })),
        acceptanceTests: [{ path: 'test/security/verification.test.ts', description: 'a production-configured instance rejects a tampered input regardless of environment variables' }],
        risk: 'medium',
        estimatedDiffSize: 'one branch per switch',
        notAgentExecutableReason:
          'Whether the escape hatch is load-bearing for local development is a product decision, and removing one that is wired into a test harness breaks the suite that would otherwise prove the fix.',
      };
    }
    return {
      agentExecutable: true,
      strategy: 'Consume every verification result and invert the fail-open handlers: a discarded boolean becomes a guarded throw, and a catch that returned success returns failure.',
      changes: uniquePaths(hits).map((p) => ({ path: p, change: 'use the verification result in a condition; make the surrounding catch return failure' })),
      acceptanceTests: [
        { path: 'test/security/verification.test.ts', description: 'a tampered payload and a malformed payload are both rejected by the real verification entrypoint, and a valid one is accepted' },
      ],
      risk: 'medium',
      estimatedDiffSize: 'one condition per call site',
      agentPrompt:
        'At each listed location a verification result is thrown away or a failure is turned into a success. For a call used as a bare statement, capture the boolean and act on it — throw a descriptive error, or return the failure to the caller in whatever shape that function already uses for failure. Do not invent a new error type if one exists. For a catch that returns true (or an object with ok/valid/verified true), change it to return the failure value, because input that cannot be parsed has not been verified. For an accepted `none` algorithm, remove `none` from the allowlist and leave the remaining algorithms unchanged. Then add or extend a test that runs a tampered input through the real entrypoint and asserts rejection; the test must fail against the original code.',
    };
  },
};

/**
 * Is the nearest enclosing function a *negative* predicate?
 *
 * `isExpired`, `isRevoked`, `hasTampered`: in those, `return true` is the
 * rejection, so a catch returning true fails closed. The check looks at the last
 * declaration name before the catch, which is the right one in the overwhelming
 * majority of cases and wrong only for a nested closure — and being wrong there
 * costs a missed finding rather than a false one.
 */
export function negativePredicateName(regionBeforeCatch: string): boolean {
  const names = [...regionBeforeCatch.matchAll(/(?:function\s+|const\s+|let\s+|async\s+)?([A-Za-z_$][\w$]*)\s*(?:=\s*(?:async\s*)?)?\([^)]*\)\s*(?::[^{;]+)?\{/g)].map((m) => m[1]!);
  const last = names[names.length - 1];
  if (last === undefined) return false;
  return /expired|expires|invalid|revoked|tamper|stale|reject|unauthori[sz]ed|denied|blocked|mismatch|failed/i.test(last);
}

export const CRYPTO_RULES: Rule[] = [timingUnsafeCompareRule, ivReuseRule, webCryptoMisuseRule, verifyResultDiscardedRule];
