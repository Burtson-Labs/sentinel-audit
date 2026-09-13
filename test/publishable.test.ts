import { describe, it, expect } from 'vitest';
import { scanText, triageCandidate, publishableKeyMatch, PUBLISHABLE_KEY_RULES, SECRET_RULES } from '../src/collectors/secrets.js';
import { SECURITY_RULES } from '../src/rules/security.js';
import { maskSource } from '../src/util/lex.js';
import type { RuleFileContext } from '../src/rules/types.js';
import type { RuleHit, SecretCandidate, Severity } from '../src/types.js';

/**
 * Publishable-by-design keys are not leaks.
 *
 * The regression: a High "13 credential-shaped value(s) present in the working
 * tree" finding led with a PostHog project key — 48 characters, high entropy, and
 * documented by its own provider as safe to ship in client code — followed by
 * `$(python3 -c ` captured three times out of a `docker run` example in a
 * markdown file. Neither is a credential, and putting them at the top of a secret
 * finding teaches the reader to skip the section.
 *
 * The fixtures below are the real lines from that scan.
 */

const run = (path: string, text: string): SecretCandidate[] => {
  const out: SecretCandidate[] = [];
  scanText(path, text, out);
  return out;
};

const live = (candidates: SecretCandidate[]): SecretCandidate[] => candidates.filter((c) => !c.likelyFalsePositive);
const reasons = (candidates: SecretCandidate[]): string => candidates.map((c) => c.falsePositiveReason ?? '').join(' | ');

describe('publishable-by-design keys', () => {
  it('does not report a PostHog project key as a credential', () => {
    // verbatim from backend/core/analytics.py in the audited repository
    const hits = run(
      'backend/core/analytics.py',
      '_PUBLIC_PROJECT_TOKEN = "phc_1aVTBknGsk01feeKT0Ooi4Jqf0K8rZqgLVuvmFzD3Gcp"\n',
    );
    expect(hits.length).toBeGreaterThan(0);
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/^publishable by design/);
    expect(reasons(hits)).toMatch(/PostHog/);
  });

  it('does not report a Stripe publishable key — but still reports the secret one', () => {
    // assigned to a secret-shaped name, so the generic rule really does match and
    // the allowlist is what clears it
    const publishableHits = run('src/pay.ts', `const stripeApiKey = 'pk_live_${'A1b2C3d4'.repeat(4)}';\n`);
    expect(publishableHits.length).toBeGreaterThan(0);
    expect(live(publishableHits)).toEqual([]);
    expect(reasons(publishableHits)).toMatch(/publishable by design/);

    const secretHits = run('src/pay.ts', `const stripeApiKey = 'sk_live_${'A1b2C3d4'.repeat(4)}';\n`);
    expect(live(secretHits).length, 'a Stripe secret key must still be reported').toBeGreaterThan(0);
  });

  it('does not report a Sentry DSN', () => {
    const hits = run('src/monitoring.ts', `const SENTRY_TOKEN = 'https://${'a1b2c3d4'.repeat(4)}@o4507.ingest.us.sentry.io/4507123';\n`);
    expect(hits.length).toBeGreaterThan(0);
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/publishable by design/);
  });

  it('does not report a Firebase web config apiKey', () => {
    const hits = run(
      'src/firebase.ts',
      [
        'export const firebaseConfig = {',
        `  apiKey: 'AIza${'Bc3dEf4gHi5jKl6mNo7pQr8sTu9vWx0yZ12'}',`,
        "  authDomain: 'demo.firebaseapp.com',",
        "  projectId: 'demo',",
        "  storageBucket: 'demo.appspot.com',",
        '};',
        '',
      ].join('\n'),
    );
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/publishable by design/);
  });

  it('does not report a Google Maps browser key', () => {
    const hits = run(
      'frontend/src/map.ts',
      [
        'const src = `https://maps.googleapis.com/maps/api/js?key=${MAPS_KEY}`;',
        `const MAPS_API_KEY = 'AIza${'Zy9xWv8uTs7rQp6oNm5lKj4iHg3fEd2cBa1'}';`,
        '',
      ].join('\n'),
    );
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/publishable by design/);
  });

  it('does not report a write-only analytics key', () => {
    for (const line of [
      "const MIXPANEL_TOKEN = 'a3f91c4e7b2d8650af13c9e4b7d206fa';",
      "const amplitudeApiKey = 'c7e2a94f16b3d8057e91c4a6b2f8d035';",
      "const SEGMENT_WRITE_API_KEY = 'QfT8mZ2vL9pR4wX7cB1nK6sD3yH5jG0a';",
    ]) {
      const hits = run('frontend/src/analytics.ts', `${line}\n`);
      expect(hits.length, line).toBeGreaterThan(0);
      expect(live(hits), line).toEqual([]);
      expect(reasons(hits), line).toMatch(/publishable by design/);
    }
  });

  it('recognises a Segment write key by name even when no rule would have matched it', () => {
    // `SEGMENT_WRITE_KEY` is not secret-shaped enough for the generic rule, so
    // nothing reports it today — the allowlist entry still has to know it, for
    // the day a provider pattern or an external scanner feeds it in
    const value = 'QfT8mZ2vL9pR4wX7cB1nK6sD3yH5jG0a';
    const lineText = `const SEGMENT_WRITE_KEY = '${value}';`;
    expect(publishableKeyMatch({ value, assignedTo: 'SEGMENT_WRITE_KEY', lineText })).toBeDefined();
  });

  it('does not let a *Key variable name silence a real provider credential', () => {
    // regression: `NAME_HOLDER` dismissed any identifier-shaped value assigned to
    // a `*Key`/`*_KEY` name, and `sk_live_…` is identifier-shaped — so a genuine
    // Stripe secret key was being suppressed by a false-positive filter
    for (const line of [
      `const stripeApiKey = 'sk_live_${'A1b2C3d4'.repeat(4)}';`,
      `STRIPE_SECRET_KEY = "rk_live_${'A1b2C3d4'.repeat(4)}"`,
      `const googleApiKey = 'AIza${'Bc3dEf4gHi5jKl6mNo7pQr8sTu9vWx0yZ12'}';`,
    ]) {
      const hits = run('src/pay.ts', `${line}\n`);
      expect(live(hits).length, line).toBeGreaterThan(0);
    }
  });

  it('still reports a real server-side key that happens to sit near analytics code', () => {
    const hits = run(
      'backend/app.py',
      ['# analytics wiring lives below', `GITHUB_TOKEN = "ghp_${'a'.repeat(36)}"`, ''].join('\n'),
    );
    expect(live(hits).length).toBeGreaterThan(0);
  });

  it('never allowlists a value on entropy or length alone', () => {
    // a 48-character high-entropy value with no publishable prefix stays reported
    const hits = run('src/a.ts', "const apiSecret = 'xQ4$vB9#mL2@pR7!kT5%zW8&nJ3';\n");
    expect(live(hits).length).toBeGreaterThan(0);
  });

  it('exposes the allowlist as data, with a reason per entry', () => {
    expect(PUBLISHABLE_KEY_RULES.length).toBeGreaterThanOrEqual(5);
    for (const r of PUBLISHABLE_KEY_RULES) {
      expect(r.id, 'every entry needs an id a reader can look up').toMatch(/^[a-z0-9-]+$/);
      expect(r.why.length, r.id).toBeGreaterThan(30);
    }
  });

  it('requires context for the genuinely ambiguous Google key, rather than guessing', () => {
    const value = `AIza${'Qw3eRt5yUi7oPa9sDf1gHj3kLz5xCv7bNm0'}`;
    // no maps/firebase context: the key could be an unrestricted server key, so
    // the allowlist must not claim it
    expect(publishableKeyMatch({ value, lineText: `const k = '${value}';`, context: `const k = '${value}';` })).toBeUndefined();
    expect(
      publishableKeyMatch({ value, lineText: `apiKey: '${value}',`, context: `apiKey: '${value}',\nauthDomain: 'x.firebaseapp.com',` }),
    ).toBeDefined();
  });
});

describe('shell placeholders and documentation placeholders', () => {
  it('does not report an unterminated shell substitution from a docs example', () => {
    // verbatim from deploy/dockerhub-overview.md, reported three times
    const hits = run(
      'deploy/dockerhub-overview.md',
      ['```bash', `export OMNIVOICE_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"`, '```', ''].join('\n'),
    );
    expect(hits.length).toBeGreaterThan(0);
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/shell substitution|variable reference/);
  });

  it('covers both `$(...)` and `${...}` openings, closed or not', () => {
    const base = { rule: SECRET_RULES.find((r) => r.id === 'generic-assigned-secret')!, lineText: '', entropy: 4.5, isExample: false, isFixture: false, path: 'src/a.sh' };
    for (const value of ['$(openssl rand -hex 32)', '$(python3 -c ', '${VAULT_TOKEN}', '${VAULT_TOKEN', '$(aws secretsmanager get']) {
      expect(triageCandidate({ ...base, value }).suppress, value).toBe(true);
    }
  });

  it('dismisses doc placeholders in prose files', () => {
    // deploy/dockerhub-overview.md is prose but neither a docs/ directory nor a
    // README, so the only thing that can clear these is the placeholder branch
    for (const line of [
      'Set `API_TOKEN="<your-key-here>"` before starting.',
      'Set `API_TOKEN="xxxxxxxxxxxxxxxx"` before starting.',
      'Set `API_TOKEN="changeme-please-now"` before starting.',
      'Set `API_TOKEN="replace-this-with-token"` before starting.',
      'Set `API_TOKEN="sk-live-abcdefghijkl..."` before starting.',
      'Set `API_TOKEN="the-token-goes-here-ok"` before starting.',
    ]) {
      const hits = run('deploy/dockerhub-overview.md', `${line}\n`);
      expect(hits.length, line).toBeGreaterThan(0);
      expect(live(hits), line).toEqual([]);
    }
    // the three that only the new branch owns say so in the reason
    for (const value of ['replace-this-with-token', 'sk-live-abcdefghijkl...', 'the-token-goes-here-ok']) {
      const hits = run('deploy/dockerhub-overview.md', `Set \`API_TOKEN="${value}"\` before starting.\n`);
      expect(reasons(hits), value).toMatch(/documentation placeholder/);
    }
  });

  it('still reports a real provider key pasted into a markdown file', () => {
    for (const path of ['docs/setup.md', 'deploy/dockerhub-overview.md', 'README.md']) {
      const hits = run(path, `Use \`ghp_${'b'.repeat(36)}\` as the token.\n`);
      expect(live(hits).length, `${path}: prose is not a free pass for a real key`).toBeGreaterThan(0);
    }
  });

  it('names the right category when it dismisses a generic match in a docs path', () => {
    const hits = run('docs/setup.md', "Set `API_SECRET=\"xQ4$vB9#mL2@pR7!kT5%\"` in the environment.\n");
    expect(live(hits)).toEqual([]);
    // it is a documentation path, not a test path, and the published reason has
    // to say which — a wrong reason is a wrong suppression a reader cannot audit
    expect(reasons(hits)).toMatch(/documentation\/example path/);
    expect(reasons(hits)).not.toMatch(/test\/fixture/);
  });

  it('does not treat a prose file as a free pass for a high-entropy literal', () => {
    const hits = run('deploy/dockerhub-overview.md', "Set `API_SECRET=\"xQ4$vB9#mL2@pR7!kT5%\"` in the environment.\n");
    expect(live(hits).length).toBeGreaterThan(0);
  });
});

describe('prose inside a comment is not a credential', () => {
  it('does not report a docblock sentence as a committed credential', () => {
    // verbatim from frontend/src/utils/audiobookLyrics.js — after the first three
    // fixes this docblock was the *entire* content of a High "credential-shaped
    // value present in the working tree" finding
    const hits = run(
      'frontend/src/utils/audiobookLyrics.js',
      [
        '/**',
        ' * Split a script into the chapters the backend parser would render, each with',
        ' * its display tokens: `[{ title, tokens }]`. Control tokens are stripped.',
        ' */',
        'export function splitChapters() {}',
        '',
      ].join('\n'),
    );
    expect(hits).toEqual([]);
  });

  it('covers line comments, docblock continuations and non-JS comment markers', () => {
    const cases: Array<[string, string]> = [
      ['src/a.ts', "// const apiToken = 'xQ4$vB9#mL2@pR7!kT5%';"],
      ['src/a.ts', " * see apiToken: 'xQ4$vB9#mL2@pR7!kT5%' in the old module"],
      ['backend/a.py', "# api_key = 'xQ4$vB9#mL2@pR7!kT5%'"],
      ['infra/a.tf', "# access_key = 'xQ4$vB9#mL2@pR7!kT5%'"],
      ['db/a.sql', "-- password = 'xQ4$vB9#mL2@pR7!kT5%'"],
    ];
    for (const [path, line] of cases) {
      expect(run(path, `${line}\n`), `${path}: ${line}`).toEqual([]);
    }
  });

  it('does not mistake a // inside a string literal for a comment', () => {
    const hits = run('src/a.ts', "const apiToken = 'https://xQ4vB9mL2pR7kT5zW8nJ3cF6';\n");
    expect(hits.length).toBeGreaterThan(0);
  });

  it('still reports a real provider key commented out — it is committed either way', () => {
    const hits = run('src/a.ts', `// const t = 'ghp_${'d'.repeat(36)}';\n`);
    expect(live(hits).length, 'a precise provider pattern fires inside a comment too').toBeGreaterThan(0);
  });
});

describe('committed allow annotations', () => {
  it('honours an explicit annotation and publishes it as the reason', () => {
    const hits = run('src/a.ts', `const apiToken = 'xQ4$vB9#mL2@pR7!kT5%zW8&nJ3'; // gitleaks:allow — rotated, kept for the migration\n`);
    expect(live(hits)).toEqual([]);
    expect(reasons(hits)).toMatch(/explicit scanner allow annotation/);
    expect(reasons(hits)).toMatch(/gitleaks:allow/);
  });

  it('does not let an annotation elsewhere in the file silence a line', () => {
    const hits = run(
      'src/a.ts',
      ['// gitleaks:allow', `const t = 'ghp_${'c'.repeat(36)}';`, ''].join('\n'),
    );
    expect(live(hits).length, 'the annotation must be on the line it excuses').toBeGreaterThan(0);
  });
});

describe('publishable build variables in the client bundle rule', () => {
  const rule = SECURITY_RULES.find((r) => r.id === 'SEC-SECRET-IN-CLIENT-BUNDLE')!;
  const scanFile = (path: string, src: string): RuleHit[] => {
    const ctx: RuleFileContext = {
      file: { path, absolute: `/repo/${path}`, ext: `.${path.split('.').pop()}`, bytes: src.length, binary: false },
      src,
      masked: maskSource(src),
      isTest: false,
      root: '/repo',
    };
    return rule.scan!(ctx);
  };
  const severityOf = (hits: RuleHit[]): Severity => rule.severityFor!(hits);

  it('reports a publishable provider key at Info, not High', () => {
    const hits = scanFile('frontend/src/utils/analytics.ts', "const token = import.meta.env.VITE_POSTHOG_KEY as string;\n");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meta!.benign).toBe(true);
    expect(hits[0]!.message).toMatch(/publishable by design/);
    expect(severityOf(hits)).toBe('Info');
  });

  it('keeps High for a real credential in a public-prefixed variable', () => {
    for (const name of ['VITE_OPENAI_API_KEY', 'NEXT_PUBLIC_DB_PASSWORD', 'VITE_ADMIN_TOKEN']) {
      const hits = scanFile('src/env.ts', `const v = import.meta.env.${name} as string;\n`);
      expect(hits.length, name).toBe(1);
      expect(hits[0]!.meta!.benign, name).toBe(false);
      expect(severityOf(hits), name).toBe('High');
    }
  });

  it('withdraws the provider exemption when the name means a real credential', () => {
    // a Sentry *auth token* uploads source maps; it is not the DSN
    const hits = scanFile('src/env.ts', 'const v = import.meta.env.VITE_SENTRY_AUTH_TOKEN as string;\n');
    expect(hits[0]!.meta!.benign).toBe(false);
    expect(severityOf(hits)).toBe('High');
  });

  it('one real credential among publishable ones keeps the finding at High', () => {
    const hits = scanFile(
      'src/env.ts',
      ['const a = import.meta.env.VITE_POSTHOG_KEY as string;', 'const b = import.meta.env.VITE_STRIPE_SECRET_KEY as string;', ''].join('\n'),
    );
    expect(hits).toHaveLength(2);
    expect(severityOf(hits)).toBe('High');
  });
});
