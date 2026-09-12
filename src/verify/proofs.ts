import { join } from 'node:path';
import { exists } from '../util/fsx.js';
import {
  HARNESS_PREAMBLE,
  EXECUTABLE_HTML_PATTERNS,
  XSS_PAYLOADS,
  TRAVERSAL_PAYLOADS,
} from './harness.js';

/**
 * Proof generators.
 *
 * Each generator returns a complete Node script, or null when it cannot build a
 * meaningful proof for this particular hit. Returning null is the honest
 * outcome: the finding then stays `plausible` with a note saying why no proof
 * could be produced, rather than being dressed up as verified.
 */

export interface ProofSpec {
  /** Filename (no directory) for the generated script. */
  filename: string;
  source: string;
  /** Human statement of what a "vulnerable" verdict would mean. */
  predicted: string;
  /** Short description of the technique, for the report. */
  technique: string;
}

export interface ProducerRef {
  /** Identifier called to produce the value, e.g. `renderMarkdownToHtml`. */
  identifier: string;
  /** Module specifier it is imported from, or null when locally defined. */
  specifier: string | null;
  /** Resolved absolute path when the specifier is repo-local. */
  localPath: string | null;
}

/**
 * Given the source of a file and a line containing a raw-HTML sink, work out
 * which function produced the assigned value and where it comes from.
 *
 * This is deliberately shallow — one hop. If the value is not a direct call to
 * an imported/local function we return null rather than guessing.
 */
export function findHtmlProducer(src: string, line: number, root: string, file: string): ProducerRef | null {
  const lines = src.split('\n');
  const text = lines[line - 1] ?? '';
  const rhs =
    /(?:innerHTML|outerHTML)\s*=\s*([A-Za-z_$][\w$]*)\s*\(/.exec(text)?.[1] ??
    /__html\s*:\s*([A-Za-z_$][\w$]*)\s*\(/.exec(text)?.[1] ??
    /insertAdjacentHTML\s*\([^,]+,\s*([A-Za-z_$][\w$]*)\s*\(/.exec(text)?.[1] ??
    null;
  if (!rhs) return null;
  return resolveIdentifier(src, rhs, root, file);
}

/** Find where `identifier` comes from: an import, or this module itself. */
export function resolveIdentifier(src: string, identifier: string, root: string, file: string): ProducerRef | null {
  const importRe = new RegExp(
    `import\\s*(?:\\{[^}]*\\b${escapeRe(identifier)}\\b[^}]*\\}|${escapeRe(identifier)})\\s*from\\s*['"\`]([^'"\`]+)['"\`]`,
  );
  const m = importRe.exec(src);
  if (m?.[1]) {
    const specifier = m[1];
    const localPath = specifier.startsWith('.') ? resolveRelative(root, file, specifier) : null;
    return { identifier, specifier, localPath };
  }
  const declared = new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${escapeRe(identifier)}\\b|(?:export\\s+)?const\\s+${escapeRe(identifier)}\\s*=`).test(src);
  if (declared) {
    return { identifier, specifier: null, localPath: join(root, file) };
  }
  return null;
}

function resolveRelative(root: string, fromFile: string, specifier: string): string | null {
  const dir = join(root, fromFile, '..');
  const base = join(dir, specifier);
  // TypeScript's ESM output convention is to import `./x.js` from `x.ts`, so the
  // specifier on disk frequently does not exist under the name it is written
  // with. Missing this rewrite means no proof can ever be built for a modern
  // TS ESM project — which is most of them.
  const rewritten = base.replace(/\.(js|mjs|cjs|jsx)$/, '');
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.mjs`,
    `${rewritten}.ts`,
    `${rewritten}.tsx`,
    `${rewritten}.mts`,
    join(base, 'index.ts'),
    join(base, 'index.tsx'),
    join(base, 'index.js'),
    join(rewritten, 'index.ts'),
  ];
  return candidates.find((c) => exists(c) && !c.endsWith('/')) ?? null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Proof for a raw-HTML sink: load the producing function and run the payload
 * corpus through it, then look for constructs that can execute.
 *
 * A `safe` verdict here is a genuine refutation of "this sink renders attacker
 * markup", which is why it is worth generating even when we expect the sink to
 * be fine.
 */
export function buildHtmlSinkProof(opts: {
  root: string;
  findingId: string;
  producer: ProducerRef;
  sinkFile: string;
  sinkLine: number;
}): ProofSpec | null {
  const { root, findingId, producer, sinkFile, sinkLine } = opts;
  const specifier = producer.localPath ?? producer.specifier;
  if (!specifier) return null;
  const source = `${HARNESS_PREAMBLE}
// Proof for ${findingId}
// Sink: ${sinkFile}:${sinkLine} assigns the result of ${producer.identifier}() to a raw-HTML sink.
// Question: does ${producer.identifier}() ever emit markup that can execute?
const REPO_ROOT = ${JSON.stringify(root)};
const SPECIFIER = ${JSON.stringify(specifier)};
const EXPORT_NAME = ${JSON.stringify(producer.identifier)};
const PAYLOADS = ${JSON.stringify(XSS_PAYLOADS, null, 2)};
const DANGEROUS = ${EXECUTABLE_HTML_PATTERNS};

const loaded = await loadTarget(REPO_ROOT, SPECIFIER, EXPORT_NAME);
if (typeof loaded.fn !== 'function') {
  emit({
    verdict: 'inconclusive',
    detail: 'could not load ' + EXPORT_NAME + ' from ' + SPECIFIER + ' outside its bundler',
    observations: loaded.attempts,
  });
  process.exit(0);
}

const observations = [];
let vulnerable = 0;
for (const payload of PAYLOADS) {
  let out;
  try {
    out = String(loaded.fn(payload));
  } catch (err) {
    observations.push(JSON.stringify(payload) + ' -> threw ' + (err && err.message ? String(err.message).slice(0, 120) : 'error'));
    continue;
  }
  const matched = DANGEROUS.filter((d) => d.re.test(out));
  if (matched.length > 0) {
    vulnerable += 1;
    observations.push(JSON.stringify(payload) + ' -> SURVIVED as ' + matched.map((d) => d.name).join(', ') + ' :: ' + JSON.stringify(out.slice(0, 160)));
  } else {
    observations.push(JSON.stringify(payload) + ' -> neutralised :: ' + JSON.stringify(out.slice(0, 120)));
  }
}

emit({
  verdict: vulnerable > 0 ? 'vulnerable' : 'safe',
  detail:
    vulnerable > 0
      ? vulnerable + ' of ' + PAYLOADS.length + ' payloads produced executable markup from ' + EXPORT_NAME + '()'
      : 'all ' + PAYLOADS.length + ' payloads were neutralised by ' + EXPORT_NAME + '() (loaded via ' + loaded.via + ')',
  payloadCount: PAYLOADS.length,
  survivingCount: vulnerable,
  loadedVia: loaded.via,
  observations,
});
`;
  return {
    filename: `${findingId}-html-sink.proof.mjs`,
    source,
    predicted: `at least one of ${XSS_PAYLOADS.length} XSS payloads passed through ${producer.identifier}() emerges as executable markup (script element, inline handler, javascript: URL, iframe/object, srcdoc, or data:text/html)`,
    technique: `load ${producer.identifier} from ${specifier} with the repository's own installed dependencies and run a ${XSS_PAYLOADS.length}-payload corpus through it`,
  };
}

/**
 * Proof for path confinement: load the function that builds the path and feed
 * it traversal payloads, checking whether the result escapes the root.
 */
export function buildPathTraversalProof(opts: {
  root: string;
  findingId: string;
  target: ProducerRef;
  rootArgName: string;
}): ProofSpec | null {
  const { root, findingId, target } = opts;
  const specifier = target.localPath ?? target.specifier;
  if (!specifier) return null;
  const source = `${HARNESS_PREAMBLE}
import { resolve, sep } from 'node:path';
// Proof for ${findingId}
// Question: does ${target.identifier}() confine its result to the supplied root?
const REPO_ROOT = ${JSON.stringify(root)};
const SPECIFIER = ${JSON.stringify(specifier)};
const EXPORT_NAME = ${JSON.stringify(target.identifier)};
const PAYLOADS = ${JSON.stringify(TRAVERSAL_PAYLOADS, null, 2)};

const loaded = await loadTarget(REPO_ROOT, SPECIFIER, EXPORT_NAME);
if (typeof loaded.fn !== 'function') {
  emit({ verdict: 'inconclusive', detail: 'could not load ' + EXPORT_NAME, observations: loaded.attempts });
  process.exit(0);
}

const jail = resolve(REPO_ROOT, 'sentinel-jail');
const observations = [];
let escapes = 0;
for (const payload of PAYLOADS) {
  try {
    const out = String(await loaded.fn(jail, payload));
    const resolved = resolve(out);
    const inside = resolved === jail || resolved.startsWith(jail + sep);
    if (!inside) {
      escapes += 1;
      observations.push(JSON.stringify(payload) + ' -> ESCAPED to ' + resolved);
    } else {
      observations.push(JSON.stringify(payload) + ' -> contained at ' + resolved);
    }
  } catch (err) {
    observations.push(JSON.stringify(payload) + ' -> rejected (' + (err && err.message ? String(err.message).slice(0, 100) : 'throw') + ')');
  }
}

emit({
  verdict: escapes > 0 ? 'vulnerable' : 'safe',
  detail: escapes > 0 ? escapes + ' payload(s) escaped the root' : 'every traversal payload was contained or rejected',
  observations,
});
`;
  return {
    filename: `${findingId}-traversal.proof.mjs`,
    source,
    predicted: `at least one traversal payload passed to ${target.identifier}() resolves outside the supplied root directory`,
    technique: `call ${target.identifier} with a synthetic root and ${TRAVERSAL_PAYLOADS.length} traversal payloads, then check containment with path.resolve`,
  };
}

/**
 * Proof that a credential-shaped value reaches web storage: load the module
 * that owns the storage access against an instrumented storage double and
 * record the keys it writes.
 *
 * This proves the data-flow claim (a token, not a preference, lands in
 * localStorage) rather than the mere presence of a call.
 */
export function buildWebStorageProof(opts: {
  root: string;
  findingId: string;
  module: ProducerRef;
  setterExport: string;
  sampleValue: string;
}): ProofSpec | null {
  const { root, findingId, module: mod, setterExport, sampleValue } = opts;
  const specifier = mod.localPath ?? mod.specifier;
  if (!specifier) return null;
  const source = `${HARNESS_PREAMBLE}
// Proof for ${findingId}
// Question: when the application stores a session, does a credential-shaped key
// land in a storage area that page script can read?
const REPO_ROOT = ${JSON.stringify(root)};
const SPECIFIER = ${JSON.stringify(specifier)};
const EXPORT_NAME = ${JSON.stringify(mod.identifier)};
const SETTER = ${JSON.stringify(setterExport)};
const SAMPLE = ${JSON.stringify(sampleValue)};

const writes = [];
class InstrumentedStorage {
  constructor(name) { this.name = name; this.map = new Map(); }
  setItem(k, v) { writes.push({ store: this.name, key: String(k), length: String(v).length }); this.map.set(String(k), String(v)); }
  getItem(k) { return this.map.has(String(k)) ? this.map.get(String(k)) : null; }
  removeItem(k) { this.map.delete(String(k)); }
  clear() { this.map.clear(); }
  key(i) { return Array.from(this.map.keys())[i] ?? null; }
  get length() { return this.map.size; }
}
// Node 22+ defines some of these as getter-only on globalThis, so every
// definition goes through defineProperty and tolerates failure.
function define(name, value) {
  try {
    Object.defineProperty(globalThis, name, { value, writable: true, configurable: true, enumerable: true });
  } catch {
    /* a global we cannot override is not fatal: the target module may not need it */
  }
}
define('localStorage', new InstrumentedStorage('localStorage'));
define('sessionStorage', new InstrumentedStorage('sessionStorage'));
define('window', globalThis);
define('document', {
  cookie: '',
  createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, remove() {} }),
  addEventListener() {},
  removeEventListener() {},
  body: { appendChild() {}, removeChild() {} },
});
if (typeof globalThis.navigator === 'undefined') define('navigator', { userAgent: 'sentinel-proof' });
define('location', { href: 'https://sentinel-proof.invalid/', origin: 'https://sentinel-proof.invalid', search: '', hash: '', pathname: '/' });

const loaded = await loadTarget(REPO_ROOT, SPECIFIER, EXPORT_NAME);
const target = loaded.fn;
if (!target) {
  emit({ verdict: 'inconclusive', detail: 'could not load ' + EXPORT_NAME + ' from ' + SPECIFIER, observations: loaded.attempts });
  process.exit(0);
}
const setter = typeof target === 'function' ? target : target[SETTER];
if (typeof setter !== 'function') {
  emit({ verdict: 'inconclusive', detail: 'no callable ' + SETTER + ' on the loaded module', observations: loaded.attempts });
  process.exit(0);
}
try {
  setter.call(target, SAMPLE);
} catch (err) {
  emit({ verdict: 'inconclusive', detail: 'calling ' + SETTER + ' threw: ' + (err && err.message ? String(err.message).slice(0, 160) : 'error'), observations: loaded.attempts });
  process.exit(0);
}

const credentialKeys = writes.filter((w) => /token|jwt|secret|password|credential|bearer|session/i.test(w.key));
emit({
  verdict: credentialKeys.length > 0 ? 'vulnerable' : 'safe',
  detail:
    credentialKeys.length > 0
      ? 'calling ' + SETTER + '() wrote ' + credentialKeys.map((w) => w.store + '[' + w.key + ']').join(', ') + ' — readable by any script in the origin'
      : 'calling ' + SETTER + '() wrote no credential-shaped key to web storage',
  observations: writes.map((w) => w.store + '.setItem(' + JSON.stringify(w.key) + ', <' + w.length + ' chars>)'),
});
`;
  return {
    filename: `${findingId}-webstorage.proof.mjs`,
    source,
    predicted: `calling the application's own session-storing function writes a credential-shaped key into localStorage or sessionStorage, both of which are readable by any script in the origin`,
    technique: `load the module against an instrumented storage double, invoke ${setterExport}, and record every key written`,
  };
}

/**
 * Generic "does this exported guard actually reject X" proof: used for SSRF and
 * allowlist-style claims where the repository has a named guard function.
 */
export function buildGuardRejectionProof(opts: {
  root: string;
  findingId: string;
  guard: ProducerRef;
  payloads: string[];
  /** A guard is expected to reject (throw or return falsy) for these inputs. */
  expectation: 'reject';
}): ProofSpec | null {
  const { root, findingId, guard, payloads } = opts;
  const specifier = guard.localPath ?? guard.specifier;
  if (!specifier) return null;
  const source = `${HARNESS_PREAMBLE}
// Proof for ${findingId}
// Question: does ${guard.identifier}() reject destinations it is supposed to reject?
const REPO_ROOT = ${JSON.stringify(root)};
const SPECIFIER = ${JSON.stringify(specifier)};
const EXPORT_NAME = ${JSON.stringify(guard.identifier)};
const PAYLOADS = ${JSON.stringify(payloads, null, 2)};

const loaded = await loadTarget(REPO_ROOT, SPECIFIER, EXPORT_NAME);
if (typeof loaded.fn !== 'function') {
  emit({ verdict: 'inconclusive', detail: 'could not load ' + EXPORT_NAME, observations: loaded.attempts });
  process.exit(0);
}

const observations = [];
let accepted = 0;
for (const payload of PAYLOADS) {
  try {
    const out = await loaded.fn(payload);
    if (out === false || out === null || out === undefined) {
      observations.push(JSON.stringify(payload) + ' -> rejected (falsy return)');
    } else {
      accepted += 1;
      observations.push(JSON.stringify(payload) + ' -> ACCEPTED (' + JSON.stringify(String(out).slice(0, 80)) + ')');
    }
  } catch (err) {
    observations.push(JSON.stringify(payload) + ' -> rejected (threw)');
  }
}

emit({
  verdict: accepted > 0 ? 'vulnerable' : 'safe',
  detail: accepted > 0 ? accepted + ' of ' + PAYLOADS.length + ' destinations were accepted by the guard' : 'the guard rejected every destination in the corpus',
  observations,
});
`;
  return {
    filename: `${findingId}-guard.proof.mjs`,
    source,
    predicted: `${guard.identifier}() accepts at least one destination from a corpus of private/metadata addresses, including numeric and IPv6-mapped encodings`,
    technique: `call ${guard.identifier} with ${payloads.length} destinations that a correct guard must refuse`,
  };
}
