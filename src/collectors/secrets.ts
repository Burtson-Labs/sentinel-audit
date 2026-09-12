import { join } from 'node:path';
import { readTextSafe, type RepoFile } from '../util/fsx.js';
import { maskSecret, shannonEntropy } from '../util/hash.js';
import { commandExists, run } from '../util/exec.js';
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
 * Dotted / camel / snake identifier with no random-looking segment: a storage
 * key, an env var name, a config path. Never a credential.
 */
const IDENTIFIER_SHAPED = /^[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*$/;
/** Assignment targets that hold the *name* of a secret, not the secret. */
const NAME_HOLDER = /(?:_KEY|_NAME|_ID|_FIELD|_HEADER|_PARAM|_PREFIX|_LABEL|Key|Name|Id|Field|Header|Param|Prefix|Label)$/;
const PLACEHOLDER_WORDS = /(example|sample|placeholder|dummy|changeme|change_me|your[_-]?|my[_-]?secret|redacted|xxxx|todo|fixme|notasecret|test[_-]?(key|token|secret)|fake|mock|lorem|password123|s3cret|secret123|abc123|\bnull\b|\bundefined\b|\bnone\b)/i;
const TYPE_LIKE = /^(?:string|number|boolean|any|unknown|null|undefined|Record<|Array<|Promise<)/;
const SAFE_PATH = /(^|\/)(\.env\.example|\.env\.sample|\.env\.template|example\.env|README|CHANGELOG|LICENSE|SECURITY|CONTRIBUTING)/i;
const TEST_FIXTURE_PATH = /(^|\/)(test|tests|__tests__|__fixtures__|fixtures|spec|e2e|mocks?|examples?|docs?|samples?)(\/|$)/i;
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
  options: { useExternalScanner?: boolean; gitignored?: (p: string) => boolean } = {},
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
    scanText(f.path, text, candidates, options.gitignored);
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
  gitignored?: (p: string) => boolean,
): void {
  const isExample = SAFE_PATH.test(path) || /\.example$|\.sample$|\.template$/.test(path);
  const isFixture = TEST_FIXTURE_PATH.test(path);
  const lines = text.split('\n');

  for (const rule of SECRET_RULES) {
    const rx = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      const value = m[rule.group];
      if (!value) continue;
      const line = text.slice(0, m.index).split('\n').length;
      const lineText = lines[line - 1] ?? '';
      const entropy = shannonEntropy(value);
      // group 1 of the generic rule is the assignment target; for precise rules
      // fall back to reading an assignment off the line.
      const assignedTo =
        (rule.group > 1 ? m[1] : undefined) ??
        /(?:const|let|var|readonly)?\s*([A-Za-z_$][\w$]*)\s*[:=]/.exec(lineText)?.[1];
      const triage = triageCandidate({ rule, value, lineText, entropy, isExample, isFixture, path, assignedTo });
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
      });
      if (m.index === rx.lastIndex) rx.lastIndex += 1;
    }
  }
}

interface TriageInput {
  rule: SecretRule;
  value: string;
  lineText: string;
  entropy: number;
  isExample: boolean;
  isFixture: boolean;
  path: string;
  /** The identifier the value was assigned to, when the rule captured one. */
  assignedTo?: string;
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
  const { rule, value, lineText, entropy, isExample, isFixture, path, assignedTo } = input;
  const credential = credentialPart(value);

  // Interpolation is checked first because it is the more precise diagnosis: a
  // `${TOKEN}` is not merely placeholder-shaped, it is a run-time reference, and
  // the reason a reader gets should say which.
  const interpolation = CONTAINS_INTERPOLATION.exec(credential);
  if (interpolation) {
    return {
      suppress: true,
      reason: `the credential portion is a variable reference (${interpolation[0].slice(0, 40)}) resolved at run time, so nothing secret is embedded here`,
    };
  }
  if (PLACEHOLDER.test(credential.trim())) {
    return { suppress: true, reason: `value is a placeholder token ("${credential.slice(0, 24)}"), not a credential` };
  }
  if (assignedTo && NAME_HOLDER.test(assignedTo) && IDENTIFIER_SHAPED.test(value.trim()) && value.trim().length < 64) {
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
