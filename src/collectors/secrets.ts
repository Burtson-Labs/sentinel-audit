import { join } from 'node:path';
import { readTextSafe, type RepoFile } from '../util/fsx.js';
import { maskSecret, shannonEntropy } from '../util/hash.js';
import { maskSource } from '../util/lex.js';
import { commandExists, run } from '../util/exec.js';
import { isTestOrFixturePath } from '../util/testpaths.js';
import type { CollectorRun, SecretCandidate, SecretResult } from '../types.js';

/**
 * Secret scanning: high-precision provider patterns first, generic
 * assignment + entropy second.
 *
 * Every candidate carries a heuristic pre-triage verdict with a reason. The
 * point is that noise is *labelled and kept*, not silently dropped — a reader
 * can audit our suppressions, which is not true of a scanner that only prints
 * what it believes.
 */

interface SecretRule {
  id: string;
  description: string;
  re: RegExp;
  /** Index of the capture group holding the secret material. */
  group: number;
  minEntropy?: number;
  /** High-precision patterns are never auto-suppressed by entropy. */
  precise: boolean;
}

export const SECRET_RULES: SecretRule[] = [
  { id: 'aws-access-key-id', description: 'AWS access key id', re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, group: 1, precise: true },
  { id: 'aws-secret-access-key', description: 'AWS secret access key', re: /aws_?secret_?access_?key["'\s:=]+([A-Za-z0-9/+=]{40})\b/gi, group: 1, precise: true },
  { id: 'github-pat', description: 'GitHub personal access token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, group: 1, precise: true },
  { id: 'github-app-token', description: 'GitHub app installation token', re: /\b(ghs_[A-Za-z0-9]{36,255})\b/g, group: 1, precise: true },
  { id: 'slack-token', description: 'Slack token', re: /\b(xox[abpsr]-[A-Za-z0-9-]{10,})\b/g, group: 1, precise: true },
  { id: 'slack-webhook', description: 'Slack webhook URL', re: /(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,})/g, group: 1, precise: true },
  { id: 'stripe-key', description: 'Stripe secret/restricted key', re: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g, group: 1, precise: true },
  { id: 'openai-key', description: 'OpenAI API key', re: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b/g, group: 1, precise: true },
  { id: 'anthropic-key', description: 'Anthropic API key', re: /\b(sk-ant-[A-Za-z0-9_-]{32,})\b/g, group: 1, precise: true },
  { id: 'google-api-key', description: 'Google API key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1, precise: true },
  { id: 'gcp-service-account', description: 'GCP service-account private key', re: /("type"\s*:\s*"service_account")/g, group: 1, precise: true },
  { id: 'private-key-block', description: 'PEM private key block', re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g, group: 1, precise: true },
  { id: 'npm-token', description: 'npm access token', re: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1, precise: true },
  { id: 'sendgrid-key', description: 'SendGrid API key', re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, group: 1, precise: true },
  { id: 'twilio-key', description: 'Twilio API key', re: /\b(SK[0-9a-fA-F]{32})\b/g, group: 1, precise: true },
  { id: 'jwt-literal', description: 'Hard-coded JWT', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, group: 1, precise: true },
  { id: 'connection-string', description: 'Database/queue connection string with inline credentials', re: /\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|mssql):\/\/[^\s"'<>]*:[^\s"'<>@]+@[^\s"'<>]+)/gi, group: 1, precise: true },
  { id: 'basic-auth-url', description: 'URL with embedded basic-auth credentials', re: /\b(https?:\/\/[A-Za-z0-9._%-]+:[^\s"'<>@/]{4,}@[A-Za-z0-9.-]+)/g, group: 1, precise: true },
  {
    id: 'generic-assigned-secret',
    description: 'Generic high-entropy value assigned to a secret-shaped name',
    re: /\b([A-Za-z0-9_]*(?:secret|passwd|password|token|api[_-]?key|apikey|auth[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_]*)\s*[:=]\s*["'`]([^"'`\n]{12,200})["'`]/gi,
    group: 2,
    minEntropy: 3.3,
    precise: false,
  },
];

/** Values that look secret-shaped but are structurally not secrets. */
const PLACEHOLDER = /^(?:x{3,}|y{3,}|\*{3,}|\.{3,}|<.*>|\$\{.*\}|%.*%|\{\{.*\}\}|#\{.*\}|__.*__)$/i;
/**
 * A variable reference *anywhere* in the matched value means the credential is
 * injected at run time, not embedded. This is the single highest-yield
 * suppression: `https://user:${TOKEN}@host` is correct code, and a scanner that
 * reports it has just taught its reader to ignore secret findings.
 */
const CONTAINS_INTERPOLATION = /\$\{[^}]*\}|\$\([^)]*\)|\{\{[^}]*\}\}|%[A-Za-z_][A-Za-z0-9_]*%|\$[A-Z_][A-Z0-9_]{2,}|<[A-Za-z_-]+>|#\{[^}]*\}/;
/**
 * The *opening* of a shell substitution or a variable reference, with no closing
 * delimiter required.
 *
 * Needed because the capture stops at the first quote: a documented
 * `export API_KEY="$(python3 -c 'import secrets; print(...)')"` yields the value
 * `$(python3 -c ` — a command substitution that `CONTAINS_INTERPOLATION` cannot
 * see because its `\$\([^)]*\)` never finds the closing paren. Sentinel reported
 * that line, three times, as a committed credential.
 */
const SHELL_SUBSTITUTION_FRAGMENT = /\$\(|\$\{|`[^`]*\$/;
/**
 * Dotted / camel / snake identifier with no random-looking segment: a storage
 * key, an env var name, a config path. Never a credential.
 */
const IDENTIFIER_SHAPED = /^[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*$/;
/** Assignment targets that hold the *name* of a secret, not the secret. */
const NAME_HOLDER = /(?:_KEY|_NAME|_ID|_FIELD|_HEADER|_PARAM|_PREFIX|_LABEL|Key|Name|Id|Field|Header|Param|Prefix|Label)$/;
const PLACEHOLDER_WORDS = /(example|sample|placeholder|dummy|changeme|change_me|your[_-]?|my[_-]?secret|redacted|xxxx|todo|fixme|notasecret|test[_-]?(key|token|secret)|fake|mock|lorem|password123|s3cret|secret123|abc123|\bnull\b|\bundefined\b|\bnone\b)/i;
const TYPE_LIKE = /^(?:string|number|boolean|any|unknown|null|undefined|Record<|Array<|Promise<)/;
const SAFE_PATH = /(^|\/)(\.env\.example|\.env\.sample|\.env\.template|example\.env|README|CHANGELOG|LICENSE|SECURITY|CONTRIBUTING)/i;
/**
 * Documentation and example directories. Test/fixture/mock paths come from the
 * shared, profile-configurable predicate instead, so "what counts as a test
 * path" is decided in one place for the whole tool.
 */
const DOC_SAMPLE_PATH = /(^|\/)(examples?|docs?|samples?)(\/|$)/i;
/** Prose file types, where a credential-shaped token is usually an instruction. */
const PROSE_FILE = /\.(md|mdx|markdown|rst|adoc|asciidoc|txt)$/i;
/**
 * Placeholder shapes specific to documentation: angle brackets, x-runs, ellipses
 * and the standard "put yours here" words. Narrower than a blanket "ignore
 * markdown", because a real key pasted into a README is a real leak — the precise
 * provider patterns still fire there.
 */
const DOC_PLACEHOLDER =
  /<[^>]*>|\bx{3,}\b|\.\.\.|…|\b(?:changeme|change[_-]me|replace[_-]?me|replace[_-]?this|your[_-]?\w+|insert[_-]?\w+|paste[_-]?\w+|\w*[_-]?here|abc123|foo|bar|baz)\b/i;
/**
 * An explicit, committed "this is fine" annotation, in the spelling the major
 * scanners use. Honoured because it is auditable: the suppression is published
 * with the annotation as its reason, so a reader can disagree with the author
 * rather than never learning the line exists.
 */
const ALLOW_ANNOTATION = /\b(?:gitleaks:allow|sentinel:allow|pragma:\s*allowlist\s+secret|nosec\b|noqa:\s*S\d|trufflehog:ignore|detect-secrets:allow)/i;
/** JS/TS-family files, where `maskSource` is an accurate comment lexer. */
const JS_FAMILY = /\.[cm]?[jt]sx?$/i;
/**
 * Everything before the match on its own line, when that prefix is a comment
 * opener or a docblock continuation. Language-agnostic fallback for the files
 * `maskSource` does not lex.
 */
const COMMENT_LINE_PREFIX = /^\s*(?:\/\/|\/\*|\*|#|--|;|%|<!--|"""|''')/;

/**
 * Keys whose provider publishes them *on purpose*: they ship in client bundles,
 * are visible in DevTools to every visitor, and rotating one fixes nothing.
 *
 * Reporting these as committed credentials is the single fastest way to lose a
 * reader's trust in a secret section — Sentinel led a High "13 credential-shaped
 * values" finding with a PostHog project key whose own source comment explained
 * it is designed to ship in client code.
 *
 * `context` is a window of lines around the match. Two entries need it, because
 * the value alone is genuinely ambiguous: a Google `AIza…` key is a browser key
 * or a server key depending on how it is restricted, and only the surrounding
 * config says which.
 */
interface PublishableKeyRule {
  id: string;
  /** Completed as "publishable by design: <why>". */
  why: string;
  matches: (input: { value: string; assignedTo?: string; lineText: string; context: string }) => boolean;
}

const NAME_SUGGESTS_PUBLIC_ANALYTICS =
  /(?:mixpanel|segment|amplitude|posthog|heap|plausible|fathom|umami|matomo|hotjar|logrocket|fullstory)[_.\- ]?(?:public|project|write|client|browser|api|site|instrumentation)?[_.\- ]?(?:api[_-]?key|write[_-]?key|write[_-]?token|site[_-]?id|token|key|id)\b/i;
const CLIENT_BUILD_PREFIX = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|VUE_APP)_/;

export const PUBLISHABLE_KEY_RULES: PublishableKeyRule[] = [
  {
    id: 'posthog-project-key',
    why: 'a PostHog project API key (`phc_…`). PostHog documents it as safe to expose; it can only write events, not read data',
    matches: ({ value }) => /^phc_[A-Za-z0-9]{20,}$/.test(value),
  },
  {
    id: 'stripe-publishable-key',
    why: 'a Stripe *publishable* key (`pk_live_`/`pk_test_`), which identifies the account to the browser and cannot move money. The secret key is `sk_`/`rk_`, and that one is still reported',
    matches: ({ value }) => /^pk_(?:live|test)_[A-Za-z0-9]{10,}$/.test(value),
  },
  {
    id: 'sentry-dsn',
    why: 'a Sentry DSN, which is an ingest endpoint the client must know. It accepts events; it cannot read them',
    matches: ({ value }) => /^https:\/\/[0-9a-f]{16,}@[A-Za-z0-9.-]*sentry\.io\/\d+$/i.test(value),
  },
  {
    id: 'google-browser-key',
    why: 'a Google browser API key used from client code (Maps/Places or a Firebase web config). It is meant to ship; the control is an HTTP-referrer and API restriction in the provider console, not secrecy',
    matches: ({ value, assignedTo, lineText, context }) =>
      /^AIza[0-9A-Za-z_-]{35}$/.test(value) &&
      (/maps\.googleapis\.com|googlemaps|google[_-]?maps|places|firebase|authDomain|storageBucket|messagingSenderId|measurementId|appId/i.test(context) ||
        /maps|firebase/i.test(assignedTo ?? '') ||
        CLIENT_BUILD_PREFIX.test(lineText)),
  },
  {
    id: 'public-analytics-write-key',
    why: 'a write-only analytics key (Mixpanel/Segment/Amplitude and similar). These are embedded in the page by design — they can send events and cannot read them',
    matches: ({ assignedTo, lineText, context }) =>
      NAME_SUGGESTS_PUBLIC_ANALYTICS.test(assignedTo ?? '') ||
      NAME_SUGGESTS_PUBLIC_ANALYTICS.test(lineText) ||
      (CLIENT_BUILD_PREFIX.test(lineText) && NAME_SUGGESTS_PUBLIC_ANALYTICS.test(context)),
  },
];

/** The first publishable-key rule that claims this value, if any. */
export function publishableKeyMatch(input: {
  value: string;
  assignedTo?: string;
  lineText: string;
  context?: string;
}): PublishableKeyRule | undefined {
  const ctx = input.context ?? input.lineText;
  return PUBLISHABLE_KEY_RULES.find((r) => r.matches({ ...input, context: ctx }));
}
const LOCKFILE = /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock|go\.sum)$/;
const MIN_SCAN_EXT = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.json', '.yml', '.yaml',
  '.env', '.sh', '.bash', '.zsh', '.toml', '.ini', '.cfg', '.conf', '.properties', '.xml',
  '.py', '.go', '.rs', '.rb', '.java', '.kt', '.cs', '.php', '.tf', '.tfvars', '.md', '.txt',
  '.html', '.dockerfile', '',
]);

export interface SecretOutput {
  secrets: SecretResult;
  run: CollectorRun;
}

export function collectSecrets(
  root: string,
  files: RepoFile[],
  options: {
    useExternalScanner?: boolean;
    gitignored?: (p: string) => boolean;
    /** Profile-configured test/fixture predicate; defaults to the built-in set. */
    isTest?: (p: string) => boolean;
  } = {},
): SecretOutput {
  const started = Date.now();
  const candidates: SecretCandidate[] = [];
  let filesScanned = 0;
  const notExamined: string[] = ['binary files and lockfiles'];

  for (const f of files) {
    if (f.binary) continue;
    if (LOCKFILE.test(f.path)) continue;
    const name = f.path.split('/').pop() ?? '';
    const ext = f.ext || (name.startsWith('.env') ? '.env' : '');
    if (!MIN_SCAN_EXT.has(ext)) continue;
    const text = readTextSafe(f.absolute, 1_000_000);
    if (text === null) continue;
    filesScanned += 1;
    scanText(f.path, text, candidates, { gitignored: options.gitignored, isTest: options.isTest });
  }

  const external = probeExternalScanner(root, options.useExternalScanner ?? true);
  // Only one of these two statements can be true, and the coverage report must
  // not print both: either a history-aware scanner ran, or it did not.
  if (external.available) {
    notExamined.push(
      `individual ${external.name} results are not re-derived as Sentinel findings — it reported ${external.findings}, and the tool should be run directly for the details`,
    );
  } else {
    notExamined.push(
      `git history — only the working tree was scanned. No history-aware scanner (${external.name}) was installed, so a credential that was committed and later deleted would not be found`,
    );
  }

  return {
    secrets: { candidates, filesScanned, externalScanner: external },
    run: {
      name: 'secrets',
      ok: true,
      durationMs: Date.now() - started,
      note: `${filesScanned} files scanned, ${candidates.length} candidates (${candidates.filter((c) => !c.likelyFalsePositive).length} after heuristic triage)`,
      notExamined,
    },
  };
}

export function scanText(
  path: string,
  text: string,
  out: SecretCandidate[],
  options: { gitignored?: (p: string) => boolean; isTest?: (p: string) => boolean } = {},
): void {
  const { gitignored, isTest = isTestOrFixturePath } = options;
  const isExample = SAFE_PATH.test(path) || /\.example$|\.sample$|\.template$/.test(path);
  const inTestPath = isTest(path);
  const isDocPath = DOC_SAMPLE_PATH.test(path);
  const lines = text.split('\n');
  // Comments blanked, string bodies kept — the right search space for *values*.
  // Only for JS/TS, where this lexer is accurate; other languages fall back to
  // the line-prefix check below.
  const commentMask = JS_FAMILY.test(path) ? maskSource(text).codeAndStrings : null;

  for (const rule of SECRET_RULES) {
    const rx = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      const value = m[rule.group];
      if (!value) continue;
      const line = text.slice(0, m.index).split('\n').length;
      const lineText = lines[line - 1] ?? '';
      // Prose inside a comment is not a credential. A docblock sentence —
      // "its display tokens: `[{ title, tokens }]`" — parses as
      // `tokens: "<19 chars>"` and was the *entire* content of a High "credential
      // present in the working tree" finding. Generic matches only: a real
      // `ghp_…` pasted into a comment is still committed, so the precise
      // provider patterns keep firing there.
      if (!rule.precise && inComment(text, m.index, lineText, commentMask)) {
        if (m.index === rx.lastIndex) rx.lastIndex += 1;
        continue;
      }
      const entropy = shannonEntropy(value);
      // group 1 of the generic rule is the assignment target; for precise rules
      // fall back to reading an assignment off the line.
      const assignedTo =
        (rule.group > 1 ? m[1] : undefined) ??
        /(?:const|let|var|readonly)?\s*([A-Za-z_$][\w$]*)\s*[:=]/.exec(lineText)?.[1];
      // A few lines either side, so a value whose meaning lives in its
      // neighbours (a Firebase web config, a maps script tag) can be classified.
      const context = lines.slice(Math.max(0, line - 5), line + 4).join('\n');
      const triage = triageCandidate({ rule, value, lineText, context, entropy, isExample, isFixture: inTestPath, isDocPath, path, assignedTo });
      out.push({
        file: path,
        line,
        ruleId: `SECRET-${rule.id}`,
        description: rule.description,
        masked: maskSecret(value),
        entropy: Number(entropy.toFixed(2)),
        likelyFalsePositive: triage.suppress,
        falsePositiveReason: triage.reason,
        inGitignoredPath: gitignored ? gitignored(path) : false,
        isExampleFile: isExample,
        inTestPath,
      });
      if (m.index === rx.lastIndex) rx.lastIndex += 1;
    }
  }
}

/**
 * Is the match at `index` inside a comment?
 *
 * Two mechanisms, strongest first: the JS/TS lexer when we have it (it knows a
 * `//` inside a string literal is not a comment), then the line prefix, which
 * covers `#`, `--`, `;`, docblock `*` continuations and `"""` blocks in the
 * languages the lexer does not lex.
 */
export function inComment(text: string, index: number, lineText: string, commentMask: string | null): boolean {
  if (commentMask && commentMask.length === text.length) {
    // the lexer blanked this offset, so it is a comment (or a regex body)
    if (commentMask[index] === ' ' && text[index] !== ' ') return true;
  }
  const lineStart = text.lastIndexOf('\n', index - 1) + 1;
  const prefix = text.slice(lineStart, index);
  return COMMENT_LINE_PREFIX.test(prefix) || COMMENT_LINE_PREFIX.test(lineText);
}

interface TriageInput {
  rule: SecretRule;
  value: string;
  lineText: string;
  entropy: number;
  isExample: boolean;
  /** A test, spec, fixture or mock path. */
  isFixture: boolean;
  /** A documentation, example or sample path. */
  isDocPath?: boolean;
  path: string;
  /** The identifier the value was assigned to, when the rule captured one. */
  assignedTo?: string;
  /** A few lines around the match, for values whose meaning is contextual. */
  context?: string;
}

/**
 * Heuristic pre-triage. Returns a *reason* in every case — the report shows
 * suppressed items with the reason so a reviewer can disagree.
 */
/**
 * For URL-shaped matches, narrow to the part that is actually the credential.
 *
 * Without this, a host like `cluster.example.net` makes the placeholder-word
 * check fire on the word "example" and a genuine connection-string leak gets
 * suppressed. Triage has to look at the secret, not at its neighbours.
 */
export function credentialPart(value: string): string {
  const url = /^[a-z+]+:\/\/(?:[^:/@\s]+):([^@\s]+)@/i.exec(value);
  return url?.[1] ?? value;
}

export function triageCandidate(input: TriageInput): { suppress: boolean; reason: string } {
  const { rule, value, lineText, entropy, isExample, isFixture, isDocPath, path, assignedTo, context } = input;
  const credential = credentialPart(value);

  // A key the provider publishes on purpose is checked first, because it is the
  // most informative verdict available: not "this looks like a placeholder" but
  // "this is a real key, and it is supposed to be here".
  const publishable = publishableKeyMatch({ value, assignedTo, lineText, context });
  if (publishable) {
    return {
      suppress: true,
      reason: `publishable by design — ${publishable.why}. Rotating it achieves nothing, so it is not reported as a credential (rule: ${publishable.id})`,
    };
  }

  // Interpolation is checked next because it is a more precise diagnosis than
  // "placeholder-shaped": a `${TOKEN}` is a run-time reference, and the reason a
  // reader gets should say which.
  const interpolation = CONTAINS_INTERPOLATION.exec(credential);
  if (interpolation) {
    return {
      suppress: true,
      reason: `the credential portion is a variable reference (${interpolation[0].slice(0, 40)}) resolved at run time, so nothing secret is embedded here`,
    };
  }
  const shellFragment = SHELL_SUBSTITUTION_FRAGMENT.exec(credential);
  if (shellFragment) {
    return {
      suppress: true,
      reason: `the value opens a shell substitution or variable reference (${shellFragment[0].slice(0, 24)}) — the credential is generated or injected when the command runs, and the capture merely stopped at the next quote`,
    };
  }
  if (ALLOW_ANNOTATION.test(lineText)) {
    return {
      suppress: true,
      reason: `the line carries an explicit scanner allow annotation (${ALLOW_ANNOTATION.exec(lineText)![0]}). Honoured because it is committed and reviewable — published here rather than applied silently, so you can disagree with the author`,
    };
  }
  if (PROSE_FILE.test(path) && !rule.precise && DOC_PLACEHOLDER.test(value)) {
    return {
      suppress: true,
      reason: `${path} is prose and the value is a documentation placeholder ("${credential.slice(0, 24)}") telling the reader what to substitute. Provider-specific patterns still fire in prose files, so a real key pasted into a document is still reported`,
    };
  }
  if (PLACEHOLDER.test(credential.trim())) {
    return { suppress: true, reason: `value is a placeholder token ("${credential.slice(0, 24)}"), not a credential` };
  }
  // Never for a precise provider pattern. `sk_live_…` is identifier-shaped and
  // `stripeApiKey` ends in `Key`, so this branch was silently dismissing real
  // Stripe, GitHub and Google credentials whenever they were assigned to a
  // `*Key`/`*_KEY` name — a false negative hiding inside a false-positive filter.
  // When the *value* identifies the provider, the variable name is irrelevant.
  if (!rule.precise && assignedTo && NAME_HOLDER.test(assignedTo) && IDENTIFIER_SHAPED.test(value.trim()) && value.trim().length < 64) {
    return {
      suppress: true,
      reason: `"${assignedTo}" holds the *name* of a credential (value "${value.slice(0, 40)}" is an identifier, not random material) — a storage key or header name rather than a secret`,
    };
  }
  if (PLACEHOLDER_WORDS.test(credential)) {
    return { suppress: true, reason: `value contains a placeholder word, so it is documentation rather than a live credential` };
  }
  if (TYPE_LIKE.test(value.trim())) {
    return { suppress: true, reason: 'value is a TypeScript type annotation, not a literal' };
  }
  if (isExample && !rule.precise) {
    return { suppress: true, reason: `${path} is an example/template file and the match is a generic pattern` };
  }
  if (/process\.env|import\.meta\.env|os\.environ|getenv|System\.getenv|Deno\.env/.test(lineText)) {
    return { suppress: true, reason: 'value is read from the environment at this line, not embedded' };
  }
  if (!rule.precise) {
    if (rule.minEntropy !== undefined && entropy < rule.minEntropy) {
      return { suppress: true, reason: `entropy ${entropy.toFixed(2)} below the ${rule.minEntropy} threshold for generic matches` };
    }
    if (IDENTIFIER_SHAPED.test(value.trim()) && !/\d{4,}/.test(value) && value.trim().length < 48) {
      return {
        suppress: true,
        reason: `value "${value.slice(0, 40)}" is a dotted/camel/snake identifier with no random-looking segment — a key or config name, not a credential`,
      };
    }
    if (/^(?:https?|file|ws|wss):\/\//.test(value)) {
      return { suppress: true, reason: 'value is a URL with no embedded credential' };
    }
    if (/^[\d.]+$/.test(value)) {
      return { suppress: true, reason: 'value is numeric/version-like' };
    }
    if (isFixture) {
      return { suppress: true, reason: `${path} is a test/fixture path and the match is a generic pattern` };
    }
    if (isDocPath) {
      return { suppress: true, reason: `${path} is a documentation/example path and the match is a generic pattern` };
    }
  }
  return { suppress: false, reason: '' };
}

function probeExternalScanner(root: string, enabled: boolean): SecretResult['externalScanner'] {
  if (!enabled) {
    return { name: 'gitleaks|trufflehog', available: false, findings: 0, note: 'external scanners disabled for this run' };
  }
  if (commandExists('gitleaks')) {
    const res = run('gitleaks', ['detect', '--no-banner', '--report-format', 'json', '--report-path', '/dev/stdout', '--source', root], {
      cwd: root,
      timeoutMs: 180_000,
    });
    const findings = countJsonArray(res.stdout);
    return {
      name: 'gitleaks',
      available: true,
      findings,
      note: `gitleaks detect over the working tree and git history reported ${findings} finding(s); exit ${res.code}`,
    };
  }
  if (commandExists('trufflehog')) {
    const res = run('trufflehog', ['filesystem', root, '--json', '--no-update'], { cwd: root, timeoutMs: 180_000 });
    const findings = res.stdout.split('\n').filter((l) => l.trim().startsWith('{')).length;
    return {
      name: 'trufflehog',
      available: true,
      findings,
      note: `trufflehog filesystem scan reported ${findings} result line(s); exit ${res.code}`,
    };
  }
  return {
    name: 'gitleaks|trufflehog',
    available: false,
    findings: 0,
    note: 'neither gitleaks nor trufflehog is on PATH — Sentinel used its built-in regex + entropy scanner only, which does not cover git history',
  };
}

function countJsonArray(text: string): number {
  const trimmed = text.trim();
  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed) as unknown[];
      return Array.isArray(arr) ? arr.length : 0;
    } catch {
      return 0;
    }
  }
  return trimmed.split('\n').filter((l) => l.trim().startsWith('{')).length;
}

/** Build a predicate for "is this path gitignored" using one git call. */
export function gitignoredPredicate(root: string, paths: string[]): (p: string) => boolean {
  if (paths.length === 0) return () => false;
  const res = run('git', ['-C', root, 'check-ignore', '--stdin'], { input: `${paths.join('\n')}\n`, timeoutMs: 20_000 });
  const ignored = new Set(res.stdout.split('\n').map((l) => l.trim()).filter(Boolean));
  return (p: string) => ignored.has(p);
}

export function envFileInventory(root: string, files: RepoFile[]): Array<{ path: string; tracked: boolean; keys: number }> {
  const out: Array<{ path: string; tracked: boolean; keys: number }> = [];
  for (const f of files) {
    const name = f.path.split('/').pop() ?? '';
    if (!/^\.env(\.|$)/.test(name)) continue;
    const text = readTextSafe(f.absolute, 200_000) ?? '';
    const keys = text.split('\n').filter((l) => /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l)).length;
    const tracked = run('git', ['-C', root, 'ls-files', '--error-unmatch', f.path], { timeoutMs: 10_000 }).ok;
    out.push({ path: f.path, tracked, keys });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

export function gitignoreMentions(root: string, needle: RegExp): boolean {
  const text = readTextSafe(join(root, '.gitignore'), 200_000);
  if (!text) return false;
  return text.split('\n').some((l) => !l.trim().startsWith('#') && needle.test(l.trim()));
}
