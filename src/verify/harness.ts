/**
 * Proof-script harness.
 *
 * A proof is a standalone Node script that exercises the *real* code in the
 * audited repository and prints one machine-readable line:
 *
 *   SENTINEL_PROOF {"verdict":"vulnerable|safe|inconclusive|error", ...}
 *
 * Two design rules make the verdicts trustworthy:
 *
 * 1. **Nothing is mocked on purpose.** The script imports the repository's own
 *    modules with the repository's own installed dependencies.
 *
 * 2. **Unresolvable imports are stubbed, recorded, and treated asymmetrically.**
 *    Real application modules often cannot be loaded outside their bundler
 *    (path aliases, CSS imports, broken transitive packaging). Rather than give
 *    up, the harness substitutes an inert object for any specifier that fails
 *    to resolve and lists what it replaced. Because a stub can only ever
 *    *remove* behaviour, never add it:
 *      - `safe` with stubs is still meaningful — a stub cannot have added the
 *        escaping we observed;
 *      - `vulnerable` with stubs is downgraded to `inconclusive` by the
 *        verifier, since one of the stubbed modules might have been the
 *        sanitiser.
 *    That asymmetry is enforced in src/verify/index.ts, not here.
 */

export const HARNESS_PREAMBLE = `import Module from 'node:module';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const __stubbed = [];
const __origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  try {
    return __origLoad.call(this, request, parent, isMain);
  } catch (err) {
    const code = err && err.code;
    if (code === 'MODULE_NOT_FOUND' || code === 'ERR_MODULE_NOT_FOUND' || code === 'ERR_UNKNOWN_FILE_EXTENSION') {
      __stubbed.push(String(request));
      return new Proxy(
        {},
        {
          get: (_t, key) => (key === '__esModule' ? true : undefined),
          apply: () => undefined,
        },
      );
    }
    throw err;
  }
};

function emit(payload) {
  process.stdout.write('SENTINEL_PROOF ' + JSON.stringify({ ...payload, stubbedModules: __stubbed }) + '\\n');
}

async function loadTarget(repoRoot, specifier, exportName) {
  const attempts = [];
  // 1. ESM import (works for local .ts via Node type stripping, and for ESM packages)
  try {
    const url = specifier.startsWith('.') || specifier.startsWith('/') ? pathToFileURL(specifier).href : specifier;
    const mod = await import(url);
    const fn = exportName ? (mod[exportName] ?? mod.default?.[exportName]) : mod.default;
    if (fn) return { fn, via: 'esm-import', attempts };
    attempts.push('esm import resolved but export "' + exportName + '" was absent');
  } catch (err) {
    attempts.push('esm import failed: ' + (err && err.message ? String(err.message).slice(0, 200) : String(err)));
  }
  // 2. CJS require from the repository root, so the repo's own node_modules wins
  try {
    const req = createRequire(repoRoot.endsWith('/') ? repoRoot + 'package.json' : repoRoot + '/package.json');
    const mod = req(specifier);
    const fn = exportName ? (mod[exportName] ?? (mod.default && mod.default[exportName])) : mod;
    if (fn) return { fn, via: 'cjs-require', attempts };
    attempts.push('cjs require resolved but export "' + exportName + '" was absent');
  } catch (err) {
    attempts.push('cjs require failed: ' + (err && err.message ? String(err.message).slice(0, 200) : String(err)));
  }
  return { fn: null, via: 'none', attempts };
}
`;

/**
 * Constructs that mean "this HTML can execute" if they survive a renderer.
 *
 * Every pattern is anchored on a real, *unescaped* tag (`<tag ...`). This is not
 * a style preference — an earlier version matched the bare token `srcdoc=` and
 * reported a correctly-escaping renderer as vulnerable, because the escaped
 * output still contained the literal text `srcdoc=&quot;`. A proof engine that
 * can be fooled by escaped text is worse than no proof engine, since its
 * verdicts are what everything else in the report leans on.
 */
export const EXECUTABLE_HTML_PATTERNS = `[
  { name: 'script element', re: /<script[\\s>/]/i },
  { name: 'inline event handler', re: /<[a-z][^<>]*\\son[a-z]+\\s*=/i },
  { name: 'javascript: URL in an attribute', re: /<[a-z][^<>]*\\s(?:href|src|action|formaction|data)\\s*=\\s*["']?\\s*javascript:/i },
  { name: 'iframe element', re: /<iframe[\\s>/]/i },
  { name: 'object/embed element', re: /<(?:object|embed)[\\s>/]/i },
  { name: 'srcdoc attribute', re: /<[a-z][^<>]*\\ssrcdoc\\s*=/i },
  { name: 'data:text/html URL in an attribute', re: /<[a-z][^<>]*\\s(?:href|src)\\s*=\\s*["']?\\s*data:text\\/html/i },
  { name: 'base element', re: /<base[\\s>/]/i },
  { name: 'style with expression()', re: /<[a-z][^<>]*\\sstyle\\s*=\\s*["'][^"']*expression\\s*\\(/i },
  { name: 'style/link injection', re: /<(?:style|link)[\\s>/][^<>]*(?:javascript:|expression\\s*\\()/i }
]`;

/** Payload corpus used by HTML-sink proofs. */
export const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<a href="javascript:alert(1)">click</a>',
  '[click](javascript:alert(1))',
  '<iframe src="javascript:alert(1)"></iframe>',
  '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  '<details open ontoggle=alert(1)>',
  '<input autofocus onfocus=alert(1)>',
  '![x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
  '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
  '<object data="javascript:alert(1)">',
  '<base href="javascript:">',
  '<form action="javascript:alert(1)"><button>go</button></form>',
  '<p style="background:url(javascript:alert(1))">x</p>',
];

/** Path-traversal payload corpus. */
export const TRAVERSAL_PAYLOADS = [
  '../../../../etc/passwd',
  '..\\..\\..\\..\\windows\\win.ini',
  '/etc/passwd',
  '....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  'subdir/../../../etc/passwd',
];

/** SSRF destination corpus, including the encodings naive guards miss. */
export const SSRF_PAYLOADS = [
  'http://169.254.169.254/latest/meta-data/',
  'http://127.0.0.1:8080/admin',
  'http://localhost/admin',
  'http://2130706433/', // decimal 127.0.0.1
  'http://0x7f000001/', // hex 127.0.0.1
  'http://0177.0.0.1/', // octal 127.0.0.1
  'http://[::1]/',
  'http://[::ffff:127.0.0.1]/',
  'http://0.0.0.0/',
  'http://10.0.0.1/',
  'http://192.168.1.1/',
  'http://metadata.google.internal/computeMetadata/v1/',
];

export const PROOF_MARKER = 'SENTINEL_PROOF ';

export interface ParsedProofOutput {
  verdict: 'vulnerable' | 'safe' | 'inconclusive' | 'error';
  detail: string;
  stubbedModules: string[];
  observations: string[];
  raw: Record<string, unknown>;
}

export function parseProofOutput(stdout: string): ParsedProofOutput | null {
  const lines = stdout.split('\n').filter((l) => l.startsWith(PROOF_MARKER));
  const last = lines[lines.length - 1];
  if (!last) return null;
  try {
    const doc = JSON.parse(last.slice(PROOF_MARKER.length)) as Record<string, unknown>;
    const verdict = String(doc.verdict ?? 'error');
    return {
      verdict: verdict === 'vulnerable' || verdict === 'safe' || verdict === 'inconclusive' ? verdict : 'error',
      detail: String(doc.detail ?? ''),
      stubbedModules: Array.isArray(doc.stubbedModules) ? doc.stubbedModules.map(String) : [],
      observations: Array.isArray(doc.observations) ? doc.observations.map(String) : [],
      raw: doc,
    };
  } catch {
    return null;
  }
}
