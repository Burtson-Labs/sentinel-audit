import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { ensureDir, exists, writeFileEnsured, excerpt } from '../util/fsx.js';
import { run, git } from '../util/exec.js';
import { satisfies } from '../util/semver.js';
import { gateSatisfied } from '../collectors/ci.js';
import { analyseDockerfile } from '../collectors/docker.js';
import { resolveInstalledVersions } from './installed.js';
import type {
  AdvisoryRecord,
  ProofRun,
  RuleHit,
  ScanContext,
  Verification,
  VerificationCheck,
} from '../types.js';
import { parseProofOutput, SSRF_PAYLOADS } from './harness.js';
import {
  buildGuardRejectionProof,
  buildHtmlSinkProof,
  buildPathTraversalProof,
  buildWebStorageProof,
  findHtmlProducer,
  resolveIdentifier,
  type ProofSpec,
} from './proofs.js';

/**
 * Verification stage.
 *
 * Nothing in a Sentinel report says "confirmed" unless something ran. There are
 * exactly two ways to earn it:
 *
 *  - **static-assertion** — we re-read the artefact from disk at report time,
 *    independently of the rule pass, and re-established the factual claim
 *    (the construct is at that line; the guard is absent from every file it
 *    could live in; the vulnerable version is the one installed). Good enough
 *    for claims *about the code*.
 *
 *  - **proof-executed** — we generated a script, ran it against the
 *    repository's real modules, and read the verdict. Required for any claim
 *    about *behaviour*.
 *
 * Everything else is `plausible`, and the report says so next to the finding.
 */

export interface VerifyInput {
  ruleId: string;
  claimType: 'factual' | 'behavioral';
  hits: RuleHit[];
  findingId: string;
  ctx: ScanContext;
  /** Where generated proofs are written. */
  proofDir: string;
  /** Skip proof execution (CI with no install, or --no-proofs). */
  proofsEnabled: boolean;
}

export interface VerifyResult {
  verification: Verification;
  /** Severity adjustment suggested by verification, if any. */
  severityHint?: 'raise' | 'lower';
  /** Extra notes for the report. */
  notes: string[];
}

export function verify(input: VerifyInput): VerifyResult {
  const byRule: Record<string, (i: VerifyInput) => VerifyResult> = {
    'SEC-XSS-DANGEROUS-HTML': verifyHtmlSink,
    'SEC-MARKDOWN-HTML-SINK': verifyHtmlSink,
    'SEC-TOKEN-WEBSTORAGE': verifyWebStorage,
    'SEC-PATH-TRAVERSAL': verifyPathTraversal,
    'SEC-SSRF-FETCH': verifySsrf,
    'SEC-CSP-MISSING': verifyCspAbsence,
    'SEC-SECRET-COMMITTED': verifySecretCommitted,
    'CI-NO-SECURITY-GATE': verifyCiGate,
    'DEP-ADVISORY': verifyAdvisory,
    'DOCKER-ROOT': verifyDockerRoot,
    'SEC-SECRET-HISTORY': verifyExternalScanner,
  };
  const handler = byRule[input.ruleId] ?? (input.ruleId.startsWith('DEP-ADVISORY') ? verifyAdvisory : undefined);
  if (handler) return handler(input);
  return verifyByReassertion(input);
}

// ---------------------------------------------------------------------------
// static re-assertion: the default for factual claims
// ---------------------------------------------------------------------------

/**
 * Re-read each cited file from disk and confirm the construct is still there at
 * the cited line. This is not theatre: it is an independent check that catches
 * stale line numbers, a rule matching inside a region the masker should have
 * blanked, and evidence that simply is not where the report says it is.
 */
function verifyByReassertion(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const checks: VerificationCheck[] = [];
  let confirmedSites = 0;

  for (const h of hits.slice(0, 12)) {
    const abs = join(ctx.root, h.file);
    if (!exists(abs)) {
      checks.push({ description: `cited file exists: ${h.file}`, outcome: 'fail', detail: `${h.file} not found on disk at verification time` });
      continue;
    }
    let line: string;
    try {
      line = readFileSync(abs, 'utf8').split('\n')[h.line - 1] ?? '';
    } catch {
      checks.push({ description: `re-read ${h.file}:${h.line}`, outcome: 'skip', detail: `${h.file}:${h.line} could not be re-read` });
      continue;
    }
    const stillThere = reassert(input.ruleId, line, h);
    checks.push({
      description: `re-read ${h.file}:${h.line} and re-matched the construct`,
      outcome: stillThere ? 'pass' : 'fail',
      detail: `${h.file}:${h.line} — ${excerpt(line, 120)}`,
    });
    if (stillThere) confirmedSites += 1;
  }

  const total = Math.min(hits.length, 12);
  const allConfirmed = total > 0 && confirmedSites === total;
  const noneConfirmed = total > 0 && confirmedSites === 0;

  return {
    verification: {
      method: 'static-assertion',
      claimType: input.claimType,
      performed: total > 0,
      result: noneConfirmed ? 'refuted' : allConfirmed ? 'confirmed' : 'plausible',
      checks,
      notes: noneConfirmed
        ? 'every cited location was re-read and the construct was not present — the finding does not survive re-checking'
        : allConfirmed
          ? `all ${total} cited location(s) were re-read from disk and the construct was re-matched.${
              input.claimType === 'behavioral'
                ? ' The claim is behavioural, so this confirms the construct exists, not that it is exploitable — status is capped at plausible by the schema.'
                : ''
            }`
          : `${confirmedSites} of ${total} cited location(s) re-matched; the remainder are reported as-is with the failing check visible`,
    },
    notes: [],
  };
}

/** Rule-specific re-assertion patterns, so the re-check is not a tautology. */
function reassert(ruleId: string, line: string, h: RuleHit): boolean {
  const patterns: Record<string, RegExp> = {
    'SEC-TOKEN-WEBSTORAGE': /(localStorage|sessionStorage)\s*\.\s*(setItem|getItem)/,
    'SEC-CLIENT-SIDE-AUTHZ': /isAdmin|hasRole|hasPermission|canEdit|canDelete|isOwner|role\s*===|roles\.includes|permissions\.includes|claims\.|scopes\.includes/,
    'SEC-JWT-CLIENT-TRUST': /atob|Buffer\.from|jwtDecode|decodeJwt|parseJwt|\.split\s*\(/,
    'SEC-CHILD-PROCESS-SHELL': /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(/,
    'SEC-EVAL': /\beval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['"`]/,
    'SEC-WEAK-CRYPTO': /createHash|Math\.random|createCipher/,
    // Crypto-usage rules: re-assert the *construct*, never the consequence. Each
    // pattern is deliberately narrower than the rule's own matcher, so a line
    // that drifted into a comment or lost the operator fails the re-check.
    'SEC-TIMING-UNSAFE-COMPARE': /===|!==|==|!=|Buffer\s*\.\s*compare|\.\s*equals\s*\(/,
    'SEC-CRYPTO-IV-REUSE': /create(?:De)?cipheriv|\b(?:iv|counter|nonce)\s*:|ecb|ECB/,
    'SEC-WEBCRYPTO-MISUSE': /SHA-?1|MD5|importKey|generateKey|unwrapKey|iterations|tagLength/i,
    'SEC-SIGNATURE-VERIFY-DISCARDED': /verif|timingSafeEqual|constantTimeEqual|catch|skip|disable|bypass|ignore|none/i,
    'SEC-TLS-DISABLED': /rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|strictSSL|InsecureSkipVerify/,
    'SEC-CORS-WILDCARD': /Access-Control-Allow-Origin|origin\s*:|cors\s*\(|credentials\s*:/,
    'SEC-POSTMESSAGE-ORIGIN': /addEventListener|postMessage/,
    'SEC-SECRET-IN-CLIENT-BUNDLE': /(?:VITE|NEXT_PUBLIC|REACT_APP|PUBLIC|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|VUE_APP)_/,
    'SEC-HTTP-ENDPOINT': /http:\/\//,
    'SEC-TARGET-BLANK': /_blank/,
    'SEC-UNAUTH-HANDLER': /\.\s*(get|post|put|patch|delete|options|head|all|route)\s*\(/,
    'SEC-NO-REQUEST-LOGGING': /\.\s*(get|post|put|patch|delete|options|head|all|route)\s*\(/,
    'QUA-SWALLOWED-CATCH': /catch\s*(\(|\{)/,
    'QUA-CONSOLE-LOGGING': /console\s*\./,
    'QUA-ANY-DENSITY': /\bany\b|@ts-(?:ignore|nocheck|expect-error)|as\s+unknown/,
    'SEC-SOURCEMAP-PUBLISHED': /sourcemap/i,
    'DOCKER-ROOT': /FROM|USER/i,
    'DOCKER-UNPINNED-BASE': /FROM/i,
    'DOCKER-SECRET-ARG': /ARG|ENV/i,
    'CI-UNPINNED-ACTION': /uses\s*:/,
    'CI-RISKY-TRIGGER': /pull_request_target|workflow_run|issue_comment/,
  };
  const re = patterns[ruleId];
  if (!re) {
    // No pattern: fall back to "the file still has at least this many lines",
    // which is weak, so such findings stay plausible rather than confirmed.
    return line.length > 0 || h.line === 1;
  }
  return re.test(line);
}

// ---------------------------------------------------------------------------
// behavioral proofs
// ---------------------------------------------------------------------------

function verifyHtmlSink(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const base = verifyByReassertion(input);
  if (!input.proofsEnabled) {
    base.verification.notes += ' Proof execution was disabled for this run, so exploitability is unproven.';
    base.verification.result = 'plausible';
    return base;
  }

  // Try every distinct producer feeding a sink, not just the first. An
  // application usually has several (a syntax highlighter, a markdown
  // renderer), and the one that cannot be loaded outside its bundler is often
  // not the one that decides the answer. A `vulnerable` verdict wins
  // immediately; otherwise the strongest conclusive verdict is used, and an
  // inconclusive run is only reported when nothing conclusive was reachable.
  const attempted = new Set<string>();
  let lastInconclusive: { proof: ProofRun; producer: string; at: string } | null = null;
  let safeResult: { proof: ProofRun; producer: string; at: string } | null = null;

  for (const h of hits.slice(0, 8)) {
    const src = ctx.root ? safeRead(join(ctx.root, h.file)) : null;
    if (!src) continue;
    const producer =
      input.ruleId === 'SEC-MARKDOWN-HTML-SINK'
        ? resolveIdentifier(src, guessRendererExport(src) ?? '', ctx.root, h.file)
        : findHtmlProducer(src, h.line, ctx.root, h.file);
    if (!producer) continue;
    const key = `${producer.identifier}|${producer.specifier ?? producer.localPath ?? ''}`;
    if (attempted.has(key)) continue;
    attempted.add(key);

    const spec = buildHtmlSinkProof({ root: ctx.root, findingId: `${input.findingId}-${attempted.size}`, producer, sinkFile: h.file, sinkLine: h.line });
    if (!spec) continue;
    const proof = executeProof(spec, input);
    if (!proof) continue;
    const at = `${h.file}:${h.line}`;

    if (proof.verdict === 'vulnerable') {
      const stubbed = /stubbed unresolvable modules:/.test(proof.observed);
      return finaliseProof(base, proof, {
        vulnerableNote: `payloads survived ${producer.identifier}() and reach the raw-HTML sink at ${at}`,
        safeNote: '',
        stubSensitive: stubbed,
        claimType: 'behavioral',
      });
    }
    if (proof.verdict === 'safe') safeResult = { proof, producer: producer.identifier, at };
    else lastInconclusive = { proof, producer: producer.identifier, at };
  }

  if (safeResult) {
    const unproven = Array.from(attempted).length - 1;
    return finaliseProof(base, safeResult.proof, {
      vulnerableNote: '',
      safeNote: `${safeResult.producer}() neutralised every payload in the corpus, so the sink at ${safeResult.at} does not render attacker markup from this path${unproven > 0 ? `. ${unproven} other producer(s) feeding a sink in the same module could not be loaded outside the bundler, so they remain unchecked — see the checks above` : ''}`,
      stubSensitive: false,
      claimType: 'behavioral',
    });
  }

  if (lastInconclusive) {
    base.verification.method = 'proof-executed';
    base.verification.proof = lastInconclusive.proof;
    base.verification.checks.push({
      description: `generated and executed ${attempted.size} proof script(s); none reached a verdict`,
      outcome: 'skip',
      detail: `${lastInconclusive.proof.path} — ${excerpt(lastInconclusive.proof.observed, 220)}`,
    });
    base.verification.notes += ` ${attempted.size} proof script(s) were generated and executed, but the producing functions could not be loaded outside their bundler (path aliases and sibling imports do not resolve in a bare Node process), so exploitability is unproven. Running the same payload corpus inside the project's own test runner would settle it.`;
    base.verification.result = 'plausible';
    return base;
  }

  base.verification.notes +=
    ' No runnable proof could be built: the value assigned to the sink is not a single-hop call to a resolvable function, so exploitability was not established by execution.';
  base.verification.result = 'plausible';
  return base;
}

function guessRendererExport(src: string): string | null {
  const m = /export\s+(?:default\s+)?(?:async\s+)?function\s+(\w*(?:render|markdown|html|format)\w*)/i.exec(src)
    ?? /export\s+const\s+(\w*(?:render|markdown|html|format)\w*)\s*=/i.exec(src);
  return m?.[1] ?? null;
}

/**
 * Web storage is a **factual** claim: "this code writes a credential-shaped key
 * into storage that page script can read". Re-assertion settles it, and the
 * proof is only ever a bonus demonstration of the data flow.
 *
 * That asymmetry is enforced here: the proof can *strengthen* the finding (by
 * showing the write happen with a real token value) but it can never refute it.
 * An earlier version allowed a `safe` verdict through, and because the setter
 * heuristic had picked an unrelated exported function in a different module, it
 * refuted a true finding — the worst possible outcome for a tool whose pitch is
 * verification. The fix is twofold: only exercise the function that *encloses*
 * the flagged write, and never let the proof lower the result.
 */
function verifyWebStorage(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const base = verifyByReassertion(input);
  if (!input.proofsEnabled) return base;

  // Only long-lived credential writes are worth a data-flow demonstration, and
  // only in the module that performs them.
  const candidates = hits.filter((h) => h.meta?.isWrite === true && h.meta?.longLived === true);
  for (const h of candidates.slice(0, 4)) {
    const abs = join(ctx.root, h.file);
    const src = safeRead(abs);
    if (!src) continue;
    const setter = findEnclosingSetter(src, h.line);
    if (!setter) continue;
    const spec = buildWebStorageProof({
      root: ctx.root,
      findingId: input.findingId,
      module: { identifier: setter.owner, specifier: null, localPath: abs },
      setterExport: setter.method,
      sampleValue: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbC1wcm9vZiIsImV4cCI6MjUzNDAyMzAwNzk5fQ.sentinel',
    });
    if (!spec) continue;
    const proof = executeProof(spec, input);
    if (!proof) continue;

    base.verification.proof = proof;
    base.verification.checks.push({
      description: `executed a data-flow proof against ${setter.owner}.${setter.method}(), the function enclosing ${h.file}:${h.line}`,
      outcome: proof.verdict === 'vulnerable' ? 'pass' : 'skip',
      detail: `${proof.path} — verdict "${proof.verdict}": ${excerpt(proof.observed, 200)}`,
    });

    if (proof.verdict === 'vulnerable') {
      base.verification.method = 'proof-executed';
      base.verification.result = 'confirmed';
      base.verification.notes = `an executed proof invoked the application's own ${setter.owner}.${setter.method}() against an instrumented storage double and observed the credential land in web storage: ${proof.observed}. The script is saved alongside this report and can be re-run unchanged.`;
      return base;
    }
    base.verification.notes += ` A data-flow proof was generated and executed against ${setter.owner}.${setter.method}() but did not reproduce the write outside the bundler (${excerpt(proof.observed, 180)}). The finding stands on re-assertion: the write is present in the source at the cited lines. A proof that fails to load the module is never treated as a refutation.`;
    return base;
  }

  if (candidates.length > 0) {
    base.verification.notes +=
      ' No data-flow proof was attempted: the write is not inside an exported function this harness can invoke in isolation. The factual claim rests on re-assertion of the cited lines, which is what this claim type requires.';
  }
  return base;
}

/**
 * Find the exported function (or exported-object method) whose body contains
 * `line`. Brace-counting from the candidate's opening brace, so a method in a
 * different object is never mistaken for the enclosing one.
 */
export function findEnclosingSetter(src: string, line: number): { owner: string; method: string } | null {
  const lines = src.split('\n');
  const offsetOfLine = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);

  // 1. `export const owner = { ... method: (x) => { <line> } ... }`
  const objRe = /export\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = objRe.exec(src)) !== null) {
    const open = src.indexOf('{', m.index + m[0].length - 1);
    const close = matchBrace(src, open);
    if (open < 0 || close < 0 || offsetOfLine < open || offsetOfLine > close) continue;
    const owner = m[1]!;
    // the nearest `name:` or `name(` above the line, inside this object
    const region = src.slice(open, offsetOfLine);
    const methods = [...region.matchAll(/(?:^|[{,\s])([A-Za-z_$][\w$]*)\s*(?::\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|\s*\([^)]*\)\s*(?::[^{]*)?\{)/g)];
    const last = methods[methods.length - 1];
    if (last?.[1]) return { owner, method: last[1] };
  }

  // 2. `export function owner(...) { <line> }` / `export const owner = (...) => {`
  const fnRe = /export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|export\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]*)?=>\s*\{/g;
  let best: { owner: string; start: number } | null = null;
  while ((m = fnRe.exec(src)) !== null) {
    const name = m[1] ?? m[2];
    if (!name) continue;
    const open = src.indexOf('{', m.index + m[0].length - 1);
    const close = matchBrace(src, open);
    if (open < 0 || close < 0 || offsetOfLine < open || offsetOfLine > close) continue;
    if (!best || open > best.start) best = { owner: name, start: open };
  }
  if (best) return { owner: best.owner, method: best.owner };
  return null;
}

function matchBrace(src: string, open: number): number {
  if (open < 0 || src[open] !== '{') return -1;
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function verifyPathTraversal(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const base = verifyByReassertion(input);
  if (!input.proofsEnabled) return base;
  for (const h of hits.slice(0, 4)) {
    const src = safeRead(join(ctx.root, h.file));
    if (!src) continue;
    const fn = /export\s+(?:async\s+)?function\s+(\w*(?:resolve|path|file|read|within)\w*)/i.exec(src)?.[1];
    if (!fn) continue;
    const spec = buildPathTraversalProof({
      root: ctx.root,
      findingId: input.findingId,
      target: { identifier: fn, specifier: null, localPath: join(ctx.root, h.file) },
      rootArgName: 'root',
    });
    if (!spec) continue;
    const proof = executeProof(spec, input);
    if (!proof || proof.verdict === 'inconclusive') continue;
    return finaliseProof(base, proof, {
      vulnerableNote: `traversal payloads passed to ${fn}() resolved outside the supplied root`,
      safeNote: `${fn}() contained or rejected every traversal payload`,
      stubSensitive: false,
      claimType: 'behavioral',
    });
  }
  base.verification.notes += ' No self-contained path-building function could be loaded, so containment was not tested by execution.';
  base.verification.result = 'plausible';
  return base;
}

function verifySsrf(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const base = verifyByReassertion(input);
  if (!input.proofsEnabled) return base;
  for (const h of hits.slice(0, 4)) {
    const src = safeRead(join(ctx.root, h.file));
    if (!src) continue;
    const guard = /export\s+(?:async\s+)?(?:function\s+)?(\w*(?:assert|validate|check|isAllowed|allow)\w*(?:Url|Host|Destination|Target)?)/i.exec(src)?.[1];
    if (!guard) continue;
    const spec = buildGuardRejectionProof({
      root: ctx.root,
      findingId: input.findingId,
      guard: { identifier: guard, specifier: null, localPath: join(ctx.root, h.file) },
      payloads: SSRF_PAYLOADS,
      expectation: 'reject',
    });
    if (!spec) continue;
    const proof = executeProof(spec, input);
    if (!proof || proof.verdict === 'inconclusive') continue;
    return finaliseProof(base, proof, {
      vulnerableNote: `${guard}() accepted destinations a correct guard must refuse, including numeric and IPv6-mapped loopback encodings`,
      safeNote: `${guard}() refused every destination in the corpus, including decimal, hex, octal and IPv6-mapped encodings`,
      stubSensitive: false,
      claimType: 'behavioral',
    });
  }
  base.verification.notes +=
    ' No named destination guard was found to exercise, so the claim rests on the absence of a visible allowlist rather than on a demonstrated request.';
  base.verification.result = 'plausible';
  return base;
}

// ---------------------------------------------------------------------------
// targeted factual verifiers
// ---------------------------------------------------------------------------

/**
 * CSP absence is a claim about *every* place a policy could live. Verify it by
 * enumerating those places and showing each one lacks the header — and by
 * listing which places we could look in, so the reader can see the limit.
 */
function verifyCspAbsence(input: VerifyInput): VerifyResult {
  const { ctx } = input;
  const checks: VerificationCheck[] = [];
  const candidates = [
    'index.html',
    'public/index.html',
    'src/index.html',
    'nginx/nginx.conf',
    'nginx/default.conf',
    'nginx.conf',
    'vercel.json',
    'netlify.toml',
    'public/_headers',
    '_headers',
    'staticwebapp.config.json',
    'firebase.json',
  ];
  let found = false;
  for (const rel of candidates) {
    const abs = join(ctx.root, rel);
    if (!exists(abs)) {
      checks.push({ description: `checked ${rel} for a policy`, outcome: 'skip', detail: `${rel}:0 — file not present` });
      continue;
    }
    const text = safeRead(abs) ?? '';
    const hasCsp = isPolicyDeclaration(text);
    if (hasCsp) found = true;
    checks.push({
      description: `searched ${rel} for a Content-Security-Policy declaration`,
      outcome: hasCsp ? 'fail' : 'pass',
      detail: `${rel}:1 — ${hasCsp ? 'policy declaration present' : 'no Content-Security-Policy declaration'}`,
    });
  }

  // Also scan every repo file we read, so a policy in an unusual place is found.
  // Two filters keep this from producing a false refutation:
  //  - the match must look like a *declaration* (a directive list, a header
  //    assignment, or a meta tag) rather than a mention of the header's name;
  //  - vendored or bundled artefacts are excluded, because a bundled library
  //    that merely knows the header's name is not this application's policy.
  const anywhere: Array<{ path: string; why: string }> = [];
  const mentionsOnly: string[] = [];
  let textCount = 0;
  for (const [path, text] of repoTexts(ctx)) {
    textCount += 1;
    if (!/Content-Security-Policy/i.test(text)) continue;
    if (looksVendored(path, text)) {
      mentionsOnly.push(`${path} (vendored/bundled artefact)`);
      continue;
    }
    if (!isPolicyDeclaration(text)) {
      mentionsOnly.push(`${path} (mentions the header name, no directive list)`);
      continue;
    }
    anywhere.push({ path, why: 'declares a policy' });
  }
  if (anywhere.length > 0) found = true;
  checks.push({
    description: 'searched every text file in the repository for a Content-Security-Policy declaration',
    outcome: anywhere.length > 0 ? 'fail' : 'pass',
    detail:
      anywhere.length > 0
        ? `declaration found in: ${anywhere.slice(0, 5).map((a) => a.path).join(', ')}`
        : `0 of ${textCount} text files declare a policy${mentionsOnly.length > 0 ? `; ${mentionsOnly.length} file(s) mention the header name without declaring one: ${mentionsOnly.slice(0, 3).join(', ')}` : ''}`,
  });

  return {
    verification: {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: found ? 'refuted' : 'confirmed',
      checks,
      notes: found
        ? 'a Content-Security-Policy directive was found in the repository, so the finding is refuted'
        : 'no Content-Security-Policy directive exists anywhere in the repository. This confirms the repository ships none; it cannot rule out a policy injected by a CDN, ingress controller or reverse proxy configured outside this repository, which is recorded in COVERAGE.md.',
    },
    notes: [],
  };
}

/**
 * Does this text *declare* a CSP, as opposed to mentioning the header's name?
 * A declaration carries at least one directive, or sets the header explicitly.
 */
function isPolicyDeclaration(text: string): boolean {
  const idx = text.search(/Content-Security-Policy/i);
  if (idx < 0) return false;
  const window = text.slice(Math.max(0, idx - 200), idx + 400);
  if (/\b(?:default|script|style|img|connect|font|frame|object|base|form)-(?:src|uri|action|ancestors)\b/i.test(window)) return true;
  if (/add_header\s+Content-Security-Policy|http-equiv\s*=\s*["']?Content-Security-Policy|setHeader\s*\(\s*['"`]Content-Security-Policy/i.test(window)) {
    return true;
  }
  if (/contentSecurityPolicy\s*:\s*\{/i.test(text)) return true;
  return false;
}

/** Bundled or vendored artefacts: long lines, sourcemap comments, minified names. */
function looksVendored(path: string, text: string): boolean {
  if (/(^|\/)(vendor|third[_-]?party|node_modules)\//.test(path)) return true;
  if (/\.min\.(js|css|cjs|mjs)$/.test(path)) return true;
  if (/sourceMappingURL=/.test(text)) return true;
  const longest = text.split('\n').reduce((n, l) => Math.max(n, l.length), 0);
  return longest > 2000;
}

function repoTexts(ctx: ScanContext): Array<[string, string]> {
  const cached = (ctx as ScanContext & { __texts?: Array<[string, string]> }).__texts;
  return cached ?? [];
}

/** Attach the rule-engine texts so verifiers can search the whole repo cheaply. */
export function attachTexts(ctx: ScanContext, texts: Map<string, string>): void {
  (ctx as ScanContext & { __texts?: Array<[string, string]> }).__texts = Array.from(texts.entries());
}

/**
 * A secret is only *committed* if git tracks the file. An untracked or ignored
 * file containing a credential is a different (lesser) finding, and conflating
 * the two is one of the most common ways a secret report loses credibility.
 */
function verifySecretCommitted(input: VerifyInput): VerifyResult {
  const { hits, ctx } = input;
  const checks: VerificationCheck[] = [];
  let trackedCount = 0;
  for (const h of hits.slice(0, 12)) {
    const tracked = git(ctx.root, ['ls-files', '--error-unmatch', h.file]).ok;
    const ignored = git(ctx.root, ['check-ignore', '-q', h.file]).ok;
    if (tracked) trackedCount += 1;
    checks.push({
      description: `git tracking status of ${h.file}`,
      outcome: tracked ? 'pass' : 'fail',
      detail: `${h.file}:${h.line} — ${tracked ? 'tracked by git (the value is in history)' : ignored ? 'git-ignored (present locally, never committed)' : 'untracked'}`,
    });
  }
  const total = Math.min(hits.length, 12);
  return {
    verification: {
      method: 'static-assertion',
      claimType: 'factual',
      performed: total > 0,
      result: trackedCount > 0 ? 'confirmed' : 'refuted',
      checks,
      notes:
        trackedCount > 0
          ? `${trackedCount} of ${total} file(s) holding a credential-shaped value are tracked by git, so the value is in the repository's history and must be rotated, not merely deleted`
          : 'none of the files holding a credential-shaped value are tracked by git — they exist only in this working copy, so the "committed secret" claim is refuted (local hygiene issue, not an exposure)',
    },
    severityHint: trackedCount > 0 ? undefined : 'lower',
    notes: [],
  };
}

/**
 * Re-parse the Dockerfile rather than re-matching one line: "runs as root" is a
 * property of the *final build stage*, and a `USER` in a builder stage does not
 * change it. Checking the cited line alone would get this wrong in both
 * directions.
 */
function verifyDockerRoot(input: VerifyInput): VerifyResult {
  const { ctx, hits } = input;
  const checks: VerificationCheck[] = [];
  let rootCount = 0;
  for (const h of hits.slice(0, 8)) {
    const text = safeRead(join(ctx.root, h.file));
    if (!text) {
      checks.push({ description: `re-read ${h.file}`, outcome: 'skip', detail: `${h.file}:1 — could not be re-read` });
      continue;
    }
    const analysed = analyseDockerfile(h.file, text);
    if (analysed.runsAsRoot) rootCount += 1;
    checks.push({
      description: `re-parsed ${h.file} and resolved the final build stage's user`,
      outcome: analysed.runsAsRoot ? 'pass' : 'fail',
      detail: `${h.file}:${analysed.userLine ?? 1} — final stage user: ${analysed.userLine ? 'explicit USER present' : 'no USER directive, so the process runs as root'}${analysed.runsAsRoot ? '' : ' (non-root, so the claim does not hold for this file)'}`,
    });
  }
  const total = Math.min(hits.length, 8);
  return {
    verification: {
      method: 'static-assertion',
      claimType: 'factual',
      performed: total > 0,
      result: rootCount > 0 ? 'confirmed' : 'refuted',
      checks,
      notes:
        rootCount > 0
          ? `${rootCount} of ${total} Dockerfile(s) were re-parsed at verification time and the final build stage resolves to the root user. A USER directive in an earlier stage was not counted, because it does not affect the runtime container.`
          : 'every Dockerfile was re-parsed and the final stage sets a non-root user, so the claim is refuted',
    },
    severityHint: rootCount > 0 ? undefined : 'lower',
    notes: [],
  };
}

/**
 * A third-party scanner's count is tool output, not something Sentinel checked.
 * It is reported as `plausible` on purpose: presenting another tool's result as
 * Sentinel-verified would be borrowing credibility we did not earn.
 */
function verifyExternalScanner(input: VerifyInput): VerifyResult {
  const external = input.ctx.secrets.externalScanner;
  return {
    verification: {
      method: 'tool-output',
      claimType: 'factual',
      performed: true,
      result: 'plausible',
      checks: [
        {
          description: `ran ${external.name} over the repository`,
          outcome: 'pass',
          detail: `${external.name}: ${external.note}`,
        },
      ],
      notes: `The count comes from ${external.name}, which Sentinel executed but whose individual results it does not re-derive. Reported as plausible rather than confirmed: Sentinel verified that the scanner ran and what it returned, not that each result is a live credential. Run the scanner directly to triage them.`,
    },
    notes: [],
  };
}

function verifyCiGate(input: VerifyInput): VerifyResult {
  const { ctx } = input;
  const checks: VerificationCheck[] = [];
  const gates = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  const missing: string[] = [];
  for (const gate of gates) {
    const ok = gateSatisfied(ctx.ci, gate);
    if (!ok) missing.push(gate);
    checks.push({
      description: `a PR-triggered workflow fails the build on ${gate}`,
      outcome: ok ? 'fail' : 'pass', // "pass" = the finding's claim holds
      detail: ok
        ? `${ctx.ci.workflows.find((w) => w.gates[gate])?.file ?? 'workflow'} — ${gate} gate present`
        : `${ctx.ci.workflows.length} workflow file(s) parsed; none run a blocking ${gate} step`,
    });
  }
  const parseFailures = ctx.ci.workflows.filter((w) => w.parseError);
  for (const w of parseFailures) {
    checks.push({
      description: `workflow parsed cleanly: ${w.file}`,
      outcome: 'skip',
      detail: `${w.file}:1 — parser fell back to text scanning (${w.parseError})`,
    });
  }
  return {
    verification: {
      method: 'static-assertion',
      claimType: 'factual',
      performed: true,
      result: missing.length > 0 ? 'confirmed' : 'refuted',
      checks,
      notes:
        missing.length > 0
          ? `re-parsed ${ctx.ci.workflows.length} workflow file(s) at verification time; no blocking step exists for: ${missing.join(', ')}. Steps marked continue-on-error or suffixed with "|| true" were treated as non-gating, because they are.${parseFailures.length > 0 ? ' Files our YAML reader could not parse were text-scanned instead, which is recorded above.' : ''}`
          : 'every checked gate is present in a PR-triggered workflow, so the finding is refuted',
    },
    notes: [],
  };
}

/**
 * Advisory verification is where most dependency reports overstate themselves.
 * `npm audit` reports on the dependency *graph*; what ships is the *installed
 * tree*. An override, a resolution, or a hoisted newer copy means the advisory
 * can be reported and still not apply. So: read the installed version and test
 * it against the advisory's own range.
 */
function verifyAdvisory(input: VerifyInput): VerifyResult {
  const { ctx, hits } = input;
  const checks: VerificationCheck[] = [];
  const moduleName = String(hits[0]?.meta?.module ?? '');
  const range = String(hits[0]?.meta?.range ?? '');
  const copies = resolveInstalledVersions(ctx.root, moduleName);

  if (copies.length === 0) {
    checks.push({
      description: `locate an installed copy of ${moduleName}`,
      outcome: 'skip',
      detail: `no installed copy of ${moduleName} found under node_modules (hoisted, pnpm virtual store, or nested) — the tree may not be installed`,
    });
    return {
      verification: {
        method: 'tool-output',
        claimType: 'factual',
        performed: true,
        result: 'plausible',
        checks,
        notes: `the advisory comes from the package manager's audit output; Sentinel could not read an installed copy of ${moduleName} to confirm the shipped version falls in the vulnerable range, so the finding is reported as plausible rather than confirmed`,
      },
      notes: [],
    };
  }

  const evaluated = copies.map((c) => ({ ...c, inRange: range ? satisfies(c.version, range) : null }));
  for (const c of evaluated) {
    checks.push({
      description: `installed ${moduleName}@${c.version} falls in the advisory's vulnerable range`,
      outcome: c.inRange === true ? 'pass' : c.inRange === false ? 'fail' : 'skip',
      detail: `${c.location} — installed ${c.version}, advisory range "${range || 'unspecified'}"${c.inRange === null ? ' (range syntax not implemented by the built-in comparator, so not evaluated)' : ''}`,
    });
  }

  const vulnerable = evaluated.filter((c) => c.inRange === true);
  const clear = evaluated.filter((c) => c.inRange === false);
  const undecided = evaluated.filter((c) => c.inRange === null);

  if (vulnerable.length > 0) {
    return {
      verification: {
        method: 'static-assertion',
        claimType: 'factual',
        performed: true,
        result: 'confirmed',
        checks,
        notes: `the vulnerable version is installed: ${vulnerable.map((c) => `${moduleName}@${c.version}`).join(', ')} satisfies "${range}"${clear.length > 0 ? `, alongside ${clear.length} already-patched cop${clear.length === 1 ? 'y' : 'ies'}` : ''}. The advisory applies to what this repository ships. Whether the vulnerable code path is reachable from application code is a separate question Sentinel does not answer — see COVERAGE.md.`,
      },
      notes: [],
    };
  }

  if (clear.length > 0 && undecided.length === 0) {
    return {
      verification: {
        method: 'static-assertion',
        claimType: 'factual',
        performed: true,
        result: 'refuted',
        checks,
        notes: `the package manager reported this advisory against the dependency graph, but every installed copy is outside the vulnerable range (${clear.map((c) => `${c.version}`).join(', ')} vs "${range}"). The advisory does not apply to what this repository actually ships — usually because an override, resolution or a newer hoisted copy already carries the fix. Listed rather than dropped so a future dependency change that reintroduces it is visible.`,
      },
      severityHint: 'lower',
      notes: [],
    };
  }

  return {
    verification: {
      method: 'tool-output',
      claimType: 'factual',
      performed: true,
      result: 'plausible',
      checks,
      notes: `${copies.length} installed cop${copies.length === 1 ? 'y' : 'ies'} of ${moduleName} were read (${copies.map((c) => c.version).join(', ')}), but the advisory range "${range}" uses syntax the built-in comparator does not implement, so applicability was not decided. Deliberately reported as plausible rather than cleared — an unparsed range must never clear an advisory.`,
    },
    notes: [],
  };
}

// ---------------------------------------------------------------------------
// proof execution
// ---------------------------------------------------------------------------

function executeProof(spec: ProofSpec, input: VerifyInput): ProofRun | null {
  ensureDir(input.proofDir);
  const scriptPath = join(input.proofDir, spec.filename);
  writeFileEnsured(scriptPath, spec.source);
  const started = Date.now();
  const res = run(process.execPath, [scriptPath], {
    cwd: input.ctx.root,
    timeoutMs: 60_000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
  });
  const parsed = parseProofOutput(res.stdout);
  const durationMs = Date.now() - started;
  const relPath = `proofs/${spec.filename}`;
  if (!parsed) {
    return {
      path: relPath,
      command: `node ${relPath}`,
      exitCode: res.code,
      durationMs,
      predicted: spec.predicted,
      observed: `the proof produced no verdict line (exit ${res.code}). ${excerpt(res.stderr || res.stdout, 300)}`,
      verdict: 'error',
      stdoutExcerpt: excerpt(res.stdout, 1500),
      stderrExcerpt: excerpt(res.stderr, 600),
    };
  }
  return {
    path: relPath,
    command: `node ${relPath}`,
    exitCode: res.code,
    durationMs,
    predicted: spec.predicted,
    observed: `${parsed.detail}${parsed.stubbedModules.length > 0 ? ` [stubbed unresolvable modules: ${parsed.stubbedModules.join(', ')}]` : ''}`,
    verdict: parsed.verdict,
    stdoutExcerpt: excerpt(`${parsed.detail} | ${parsed.observations.slice(0, 8).join(' | ')}`, 1800),
    stderrExcerpt: excerpt(res.stderr, 600),
  };
}

/**
 * Turn a proof verdict into a verification result, applying the stub asymmetry:
 * a `vulnerable` verdict obtained with stubbed modules is downgraded, because
 * one of the stubs might have been the sanitiser.
 */
function finaliseProof(
  base: VerifyResult,
  proof: ProofRun,
  opts: { vulnerableNote: string; safeNote: string; stubSensitive: boolean; claimType: 'factual' | 'behavioral' },
): VerifyResult {
  const stubbed = /stubbed unresolvable modules:/.test(proof.observed);
  const checks = [...base.verification.checks];
  checks.push({
    description: `generated and executed a proof script (${proof.command})`,
    outcome: proof.verdict === 'vulnerable' ? 'pass' : proof.verdict === 'safe' ? 'fail' : 'skip',
    detail: `${proof.path} — verdict "${proof.verdict}" in ${proof.durationMs}ms: ${excerpt(proof.observed, 220)}`,
  });

  if (proof.verdict === 'vulnerable' && stubbed && opts.stubSensitive) {
    return {
      verification: {
        method: 'proof-executed',
        claimType: opts.claimType,
        performed: true,
        result: 'plausible',
        checks,
        proof: { ...proof, verdict: 'inconclusive' },
        notes: `a proof ran and ${opts.vulnerableNote}, but loading the target required substituting unresolvable modules (${proof.observed.replace(/^.*stubbed unresolvable modules: /, '')}). Because one of those could have been the sanitiser, the vulnerable verdict is downgraded to inconclusive and the finding stays plausible. Re-run the proof inside the project's own test runner to settle it.`,
      },
      notes: [],
    };
  }

  if (proof.verdict === 'vulnerable') {
    return {
      verification: {
        method: 'proof-executed',
        claimType: opts.claimType,
        performed: true,
        result: 'confirmed',
        checks,
        proof,
        notes: `an executed proof demonstrated the behaviour: ${opts.vulnerableNote}. The script is saved alongside this report and can be re-run unchanged.`,
      },
      notes: [],
    };
  }

  if (proof.verdict === 'safe') {
    return {
      verification: {
        method: 'proof-executed',
        claimType: opts.claimType,
        performed: true,
        result: 'refuted',
        checks,
        proof,
        notes: `an executed proof disproved the exploitability claim: ${opts.safeNote}. The static pattern that raised it is real — the consequence is not. Kept in the report so the same pattern is not re-reported as a finding next quarter.${stubbed ? ' Unresolvable modules were substituted during loading; that can only remove behaviour, never add escaping, so a safe verdict remains meaningful.' : ''}`,
      },
      severityHint: 'lower',
      notes: [],
    };
  }

  return {
    verification: {
      method: 'proof-executed',
      claimType: opts.claimType,
      performed: true,
      result: 'plausible',
      checks,
      proof,
      notes: `a proof was generated and executed but reached no verdict (${excerpt(proof.observed, 200)}), so the finding remains unproven rather than being presented as verified.`,
    },
    notes: [],
  };
}

function safeRead(abs: string): string | null {
  try {
    return readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

export function advisoryMeta(a: AdvisoryRecord): Record<string, string | number | boolean> {
  return {
    module: a.module,
    range: a.vulnerableVersions ?? '',
    severity: a.severity,
    path: a.path,
    isDev: a.isDev,
  };
}
