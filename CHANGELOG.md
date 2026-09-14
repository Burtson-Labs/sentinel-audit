# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semver.

## [Unreleased]

### Sentinel scanned itself and three real repositories; eight defects in its own output

Each of these is a case where the tool was right about the text and wrong about
the finding, or where its own artefacts were the problem.

- **The remote URL was written into every artefact with its userinfo intact.**
  `git remote get-url origin` returned `https://user@github.com/…` and the string
  went verbatim into `REPORT.md`, `CONFIDENCE.md`, `scan-context.json` and the
  SARIF `repositoryUri` — the files the shipped workflow uploads as build
  artefacts. A remote configured as `https://x-access-token:ghp_…@github.com/…`,
  which is how many CI systems and credential helpers write it, would have had
  the scanner publish the token. `redactRepoUrl` strips the userinfo before the
  URL is recorded; the host and path identify the repository. ssh forms keep
  their bare `git@`.
- **Proofs never ran on Node 22.6–22.17.** Proof scripts import the audited
  repository's TypeScript through Node's native type stripping, which is on by
  default only from 22.18 / 23.6. On the rest of the engines range this package
  declares, every proof against a `.ts` module returned "could not load outside
  its bundler" and the headline feature silently degraded to pattern matching.
  The runner now passes `--experimental-strip-types` where
  `process.features.typescript` says stripping is off and the version says the
  flag exists, and the recorded `command` carries the flag so a reader re-runs
  the same thing.
- **Four rules reported their own descriptions.** The self-scan carried a High
  "TLS certificate validation disabled", a High "SubtleCrypto called with a
  broken digest", a Medium "message handling without origin validation" and a
  Medium "weak hash" — each pointing at a sentence *about* the construct, in a
  rule's `why`, `acceptance` or agent instructions, living in a string literal.
  The lexer gains a fourth view, `codeAndValues`: comments blanked, and any
  string literal whose body reads as a sentence (40+ characters, 5+ tokens, 60%
  plain words, and no token that looks like a flag, path, URL, variable or shell
  operator) blanked with them. Every rule that hunts for a *value* — an
  algorithm name, a storage key, a route path, an env override, an endpoint —
  now searches that view. `codeAndStrings` is unchanged, so the secret scanner
  still sees every literal. A shell command in a string is still a value: the
  operational-token veto keeps `NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js`
  reportable.
- **Three "credentials" in Sentinel's own source were a comment, a docblock and
  a gate description.** A connection string whose password component is one of
  the words documentation uses *for* a password (`secret`, `password`, `pass`,
  `changeme`, …) documents a shape, on any host and any path, and is now
  dismissed with that reason; the same URL with a real password on localhost in
  `src/` is still High. A generic match whose value is a sentence — four or more
  spaced tokens, mostly words — is prose assigned to a secret-shaped name, not
  random material. And a PEM header that is a bare string *token*, closed by its
  quote and followed by a delimiter (`.Replace("-----BEGIN PRIVATE KEY-----",
  "")`, `startsWith('-----BEGIN …')`), is delimiter handling: it led a real
  .NET scan's High "33 credential-shaped values" finding, and no key material
  followed it. A header that opens a key block is still reported. Two smaller
  shapes from the same pass: a credential written with an ellipsis
  (`ghp_…`, `wJalrXUtnFEMI...`) is a truncated illustration, and `token` joins
  the placeholder-password words.
- **Gitignored paths were audited as if they were the repository.** Two scans
  cited `dev-dist/workbox-*.js` (a generated service worker) and
  `.bandit/backups/…` (an agent's own copies) for empty catches, missing origin
  checks and oversized modules. Every one was a true match against a file nobody
  committed, reviews or can fix. The rules now run over the non-ignored tree
  only; the coverage report says how many paths were skipped and why. Secret
  scanning keeps the full working tree on purpose — a live credential in an
  untracked file is still worth knowing about — and the gitignore classification
  now covers every walked path rather than the first 5,000.
- **"PR gate does not enforce: audit" on a repository that runs Sentinel on pull
  requests.** The CI collector recognised `sentinel scan` as SAST but not as the
  dependency audit it also is. A `sentinel scan` / `sentinel-audit scan` /
  `dist/cli.js scan` step now satisfies `audit` unless it passes `--offline`,
  which skips advisory lookup. It still does not satisfy `secrets`: without
  gitleaks or trufflehog on the runner the scan does not cover history, and the
  gate's definition says history.
- **A licence finding failed Sentinel's own schema check on every repository
  that had a copyleft dependency.** `DEP-LICENSE` evidence was a list of
  `name@version — licence` pairs with no artefact named, so the semantic
  validator reported "must cite a concrete reference" as a defect in Sentinel's
  output. The evidence now leads with the manifest it was read from.
- **The shipped workflow and the repository's own CI used mutable action tags**,
  which Sentinel's `CICD` rule reports at Medium. Both now pin every action to a
  commit SHA with the release tag alongside.
- **The self-scan's three dependency advisories were real.** `vitest` moves from
  2.x to 4.1 (and its `vite` to 7.x), which clears the critical vitest advisory,
  the high vite advisory and the lower-severity aggregate the scan reported.

Test fixtures no longer carry a live PostHog project key copied from a scanned
public repository, or the name of a private one; the synthetic replacements keep
the same shape and entropy.

### Package name: `@burtson-labs/sentinel-audit`

The package is scoped to Burtson Labs. The workflow template and the README
install it by that name; the command it installs is still `sentinel`, and
reports still identify the tool as `sentinel-audit`.

### Honest verification vocabulary (breaking change to `status` values)

A finding whose only verification was re-running a static assertion used to carry
the same `confirmed` badge as one proven by an executed proof. That oversold the
cheaper check, so the single value is now two:

- `proof-confirmed` — an executed proof exercised the real code and returned a
  `vulnerable` verdict. The only status that claims exploitability.
- `pattern-confirmed` — a static/lexical assertion was re-established from disk.
  The pattern exists; exploitability is unproven. A *behavioural* claim can never
  reach this status and stays `plausible`.
- `plausible`, `refuted` and `triaged-out` are unchanged.

Threaded through every output: the CLI summary, `REPORT.md` (separate sections and
summary rows), `REPORT.html` (separate stat tiles, filter chips and badges),
`CONFIDENCE.md` (separate evidence-quality rows plus a new proven-by-execution
share), SARIF (`precision` `very-high` vs `high`, new `proofConfirmed` /
`patternConfirmed` run counts, `properties.sentinel.statusClass`) and
`findings/*.json`.

**Field-meaning notes, so nothing changes silently:**

- `status` now emits `proof-confirmed` / `pattern-confirmed` where it emitted
  `confirmed`. Consumers matching the literal `"confirmed"` must be updated, or
  read the new coarse field instead.
- `verification.state` (new) repeats the precise status inside the verification
  block; `verification.class` (new) carries the old coarse vocabulary
  (`confirmed | plausible | refuted | triaged-out`). Validation rejects a finding
  whose `state`/`class` disagree with `status`.
- `findings/index.json` and the SARIF run properties keep a `confirmed` count,
  now defined as the sum of the two confirmed states, and add the split alongside.
  `findings/index.json` entries gain `statusClass`.
- `verification.result` and `verification.method` keep their existing meanings.
- Confidence weighting changed: a `static-assertion` base drops from 0.88 to 0.80,
  so a pattern-confirmed finding scores materially below a proof-confirmed one
  instead of within rounding distance of it. In the risk matrix, only
  proof-confirmed findings are Likelihood High; pattern-confirmed are Medium.

### Fixed — six defects found by scanning real repositories

- **A report-only CSP is no longer read as a policy.** `SEC-CSP-MISSING` cleared itself on `/add_header\s+Content-Security-Policy/`, which also matches `Content-Security-Policy-Report-Only` — a header that evaluates the policy, reports what it *would* have blocked, and blocks nothing. An application enforcing no policy at all was reported as having one, which is the worst failure available to a tool whose job is to check: a false reassurance about the one header it was asked about. Only an enforcing header name clears the finding now (the name must end at the name), and **new `SEC-CSP-REPORT-ONLY` (Low)** reports the report-only case in its own words — "CSP is report-only — it reports violations but blocks nothing" — cited at the declaration. Exactly one of the two CSP rules ever fires, and an enforcing header alongside a report-only one is correct staging practice rather than a finding. Verification had the same blind spot: `isPolicyDeclaration()` *refuted* the missing-CSP finding on a report-only directive list, so the fix had to land in both places. Mapped to a control in all three builtin profiles.
- **`token` no longer means "authenticator" on its own.** The stale-async-result idiom — `const token = ++tokenRef.current` … `if (token !== tokenRef.current) return` — is a correctness guard over an integer counter, and it was reported as "Authenticator compared with a short-circuiting operator" at **High**, eight times, in files containing no crypto. `token` was the one ambiguous name applied unconditionally while `signature`/`sig`/`hmac`/`mac` were already gated on crypto context. It now needs that context or a plausibly secret-derived value (from configuration, the environment, a request header, or a string-typed declaration), and a **counter-valued operand is disqualified everywhere** — `++x`, `useRef(0)`, `Date.now()`, a bare integer — including inside a crypto module, because `++seq` is not an authenticator there either. `Buffer.compare`/`.equals` supply the missing context themselves: nobody compares a sequence number byte-wise. A real `providedToken !== SECRET_TOKEN` still reports at High, and so does a bearer token read from a request header in a file with no crypto primitives at all.
- **`rel="noreferrer"` is opener protection.** `SEC-TARGET-BLANK` tested for the literal string `noopener`, so four correctly protected links were reported as missing the control — with the recommendation to add a token that changes nothing, since the HTML spec makes `noreferrer` imply `noopener`. Either token satisfies it; a `rel` carrying neither still reports.
- **A chat message role is not an authorisation role.** `SEC-CLIENT-SIDE-AUTHZ` matched `role ===`, so in an LLM application `if (role === 'assistant')` — a rendering branch over the *author* of a message — was reported as "Authorisation decision made from client-held claims". Comparisons against the chat-role vocabulary (`user`, `assistant`, `system`, `tool`, `model`, `developer`, `function`) no longer count, while `'admin'`, `'owner'` and `'editor'` still do, including when an authorisation role and a chat role share one line. A predicate inside a **sort comparator** is also excluded — `keys.sort((a, b) => (a.isAdmin ? -1 : 1))` orders a list the user already holds and permits nothing — and only when all three comparator signals are present, so a real guard near an unrelated `.sort()` keeps firing.
- **The relayed scanner count goes through triage.** `SEC-SECRET-HISTORY` reported gitleaks' raw count at a hardcoded High with no triage and no path awareness, so one report called the same test fixture `Info` under `SEC-SECRET-IN-TEST` and `High` under this rule — two severities for one value, in one document. gitleaks JSON (and trufflehog JSON-lines) are now parsed into individual hits and run through the existing triage — publishable keys, placeholders, identifier shapes, test paths — keyed on the file path the scanner itself reported. **High survives only for a hit that survives triage**: all-dismissed becomes `triaged-out`, test-path-only becomes `Info` with the usual `— in test code only`, and findings cite the real files instead of `.git`. An unparseable report stays High and says so, because "could not check" is not "clean". Sentinel still does not re-derive another tool's detections — it relays them, and says which is which.
- **A documented loopback connection string is not a credential.** `LOOPBACK_OR_RESERVED` lived in the rules module, so the secrets collector could not consult it, and a README line telling the reader to `export DATABASE_URL=postgres://readonly_user:secret@localhost:5432/appdb` was reported at High with nothing to rotate. Host classification moves to `util/hosts.ts`, shared by the plaintext-endpoint rule and secret triage. A credential-bearing URL whose host is loopback or RFC-2606 reserved, in prose or an example path, is triaged out as a **"documentation example pointing at a loopback host"**. This branch deliberately runs for the `precise` provider patterns, which every existing suppression skipped — the narrowing that makes it safe is the host, not the path. The same line in `src/` or `config/` stays High, and a routable host stays High in documentation.
- **A finding no longer reports what its own evidence calls correct.** `SEC-WEAK-CRYPTO` detected the `getRandomValues(...) ?? Math.random()` shape, said so in its evidence string, and then reported it anyway. New rule hook `triageFor` lets a rule dismiss its own finding with a reason once it has seen every hit together; used when *every* site is a CSPRNG fallback branch. Triaged out rather than dropped, so the dismissal stays reviewable — and one real site keeps the finding.

### Publishable-by-design keys are not leaks

- **A PostHog project key no longer leads a High secret finding.** `SECRET-001` opened with `phc_…` — 48 characters, entropy 4.77, and documented by its own provider as safe to ship in client code. Keys whose provider publishes them on purpose are now triaged out with the reason **"publishable by design"**, naming the provider and why rotation would achieve nothing: PostHog project keys (`phc_`), Stripe publishable keys (`pk_live_`/`pk_test_`), Sentry DSNs, Google browser keys and Firebase web `apiKey` values, and write-only analytics keys (Mixpanel, Segment, Amplitude, Heap, Plausible, Fathom and similar). The allowlist is exported as data (`PUBLISHABLE_KEY_RULES`), one reason per entry.
- Stripe *secret* keys (`sk_`/`rk_`) are explicitly outside the allowlist, and the ambiguous Google `AIza…` shape is only cleared when the surrounding lines show a browser/Maps/Firebase context — a key that might be an unrestricted server key is still reported.
- **Shell substitutions are no longer credentials.** `export API_KEY="$(python3 -c 'import secrets; print(...)')"` in a docs file was reported three times: the capture stops at the first quote, leaving `$(python3 -c `, which the existing interpolation check could not recognise because it requires a closing delimiter. An *opening* `$(` or `${` is now enough.
- **Documentation placeholders in prose files are dismissed** — `<your-key>`, `xxx`, `changeme`, `replace-this`, `…`-truncated values — while the precise provider patterns keep firing there, so a real key pasted into a README is still reported.
- **Committed allow annotations are honoured**: `gitleaks:allow`, `sentinel:allow`, `pragma: allowlist secret`, `nosec`, `trufflehog:ignore`, `detect-secrets:allow`. The annotation must be on the line it excuses, and the suppression is published with the annotation as its reason rather than applied silently.
- A generic match in a `docs/`, `examples/` or `samples/` path now says so, instead of claiming the file "is a test/fixture path".
- **`SEC-SECRET-IN-CLIENT-BUNDLE` knows the same providers.** `VITE_POSTHOG_KEY` was a High "secret-shaped value exposed through a client-inlined build variable" — the rule read the word `KEY` and stopped. A public-prefixed variable naming a provider whose client key is publishable (PostHog, Mixpanel, Segment, Amplitude, Sentry DSN, Firebase, Maps, reCAPTCHA/Turnstile site keys, Supabase anon, Algolia search) now reports at Info with "publishable by design". When the literal is reachable — on the line, or on the identifier's declaration elsewhere in the module — the *value* is classified with the same allowlist, so `const PUBLIC_PROJECT_TOKEN = 'phc_…'` and every reference to it are treated alike. The exemption is withdrawn when the name carries `SECRET`, `PRIVATE`, `AUTH_TOKEN`, `ADMIN`, `PASSWORD` or `SERVICE_ACCOUNT` — `VITE_SENTRY_AUTH_TOKEN` uploads source maps and stays High — and one real credential among publishable ones keeps the whole finding at High.

### Fixed — two more false positives, found by re-scanning the same repository

- **A docblock sentence is no longer a committed credential.** `its display tokens: \`[{ title, tokens }]\`` in a JSDoc comment parses as `tokens: "<19 chars>"`, and after the fixes above it was the *entire* content of a High "credential-shaped value present in the working tree" finding. Generic matches inside comments are now skipped — via the JS/TS comment lexer where it applies, and a line-prefix check (`//`, `*`, `#`, `--`, `;`, `"""`) elsewhere. The precise provider patterns still fire inside comments, because a real `ghp_…` in a comment is committed either way.
- **A dismissal is no longer reported at High.** The profile's severity *floor* (`severityFloor: { Secret: "High" }`) was raising triaged-out findings, so "53 secret-scanner matches triaged out as non-credentials" was published as a High. The floor no longer applies to a finding that is being dismissed.

### Fixed — a false-negative hiding inside a false-positive filter

- **A `*Key`/`*_KEY` variable name could silence a real provider credential.** The "this name holds the *name* of a secret" heuristic fired on any identifier-shaped value, and `sk_live_…`, `AIza…` and `ghp_…` are identifier-shaped — so `const stripeApiKey = 'sk_live_…'` and `STRIPE_SECRET_KEY = "rk_live_…"` were dismissed as storage keys. The heuristic no longer applies to the high-precision provider patterns: when the value itself identifies the provider, the variable name is irrelevant.

### Path-aware severity for credential and auth findings

- **A session-hygiene spec is no longer a High "authentication material written to web storage".** `SEC-TOKEN-WEBSTORAGE` cited `frontend/e2e-prod/admin-session-hygiene.spec.ts` — a test whose purpose is exercising session hygiene — at High severity. The credential/auth family (`SEC-TOKEN-WEBSTORAGE`, `SEC-SECRET-COMMITTED`, `SEC-SECRET-IN-CLIENT-BUNDLE`, `SEC-JWT-CLIENT-TRUST`, `SEC-CLIENT-SIDE-AUTHZ`, `DOCKER-SECRET-ARG`) now reports at `Info` when every cited location is a test, spec or fixture path, with `— in test code only` in the title and an explicit note saying why. The Info ceiling is applied *after* the profile's `severityFloor`, which otherwise dragged `Secret` findings back up to High.
- **Test files are not excluded from every rule.** A swallowed catch, an oversized module or a weak hash in a test still reports at its own severity. Only the credential/auth family is capped.
- **New `SEC-SECRET-IN-TEST` (Info).** Credential-shaped *values* found in test paths get their own finding instead of inflating the High "credential-shaped values in the working tree" count or vanishing — a real production key pasted into a fixture is still committed. Mapped to a control in all three builtin profiles; the production finding links to it in a note.
- **The test-path list is configurable per profile** via `testPaths: { mode: "extend" | "replace", patterns: [...] }`. Built-in coverage: `test`/`tests`/`spec`/`specs`/`e2e`/`e2e-*`/`*-tests`/`cypress`/`playwright`/`fixtures`/`mocks`/`stubs`/`testdata`/`test_data`/`__tests__`/`__mocks__`/`__fixtures__` directories, plus `*.test.*`, `*.spec.*`, `*.fixture.*`, `*.mock.*`, `*_test.go`, `test_*.py`, `conftest.py` and `*Tests.cs`-style filenames. An invalid pattern is reported by profile validation, and ignored rather than fatal at scan time.
- The rule engine and the secret collector now share one notion of "test path", so a repository only has to configure it once. `recon.isTestPath` stays narrower on purpose: it counts test *modules* for the test-to-source ratio, where counting `fixtures/` would flatter the repository.

### Cryptographic-usage rules

- Four rules for the failures that break a signing or verification library, none of which are about an obsolete primitive:
  - `SEC-TIMING-UNSAFE-COMPARE` — a signature, MAC, token, password or API key compared with `===`, `Buffer.compare` or `Buffer.equals`, which return on the first differing byte and leak the value one byte at a time.
  - `SEC-CRYPTO-IV-REUSE` — an encryption nonce/IV that is fixed, zero-filled, clock-derived, or drawn once at module scope and reused on every call, plus ECB.
  - `SEC-WEBCRYPTO-MISUSE` — SubtleCrypto called with a collision-broken digest, a private key marked extractable, a PBKDF2 cost below the modern floor, or a truncated AEAD tag.
  - `SEC-SIGNATURE-VERIFY-DISCARDED` — a verification call used as a bare statement, a `catch` around one that returns success, a runtime switch that skips verification, or `none` accepted as an algorithm.
- Each rule is discriminated rather than broadened: an unkeyed content hash is not a timing oracle and is not reported; `secret.id` and `password !== confirm` are not authentication decisions; `catch { return true }` inside `isTokenExpired()` fails closed; `importKey(…, true, ['verify'])` exports a public key and is fine. Measured at 14/14 on a defect fixture and 0 findings across 1,003 files of correct source.
- Mapped in all three profiles (ASVS 6.2.x/2.4.1/3.5.2, CWE-208/323/329/328/347/252, and the generic enterprise catalogue).

### Fixed

- **Security headers configured at the edge are no longer reported as absent.** The header rules read only nginx configs, static-host files and bundler configs, so an application that sets HSTS through `nginx.ingress.kubernetes.io/hsts` in its Helm chart was told it had no HSTS. Header presence is now checked across Helm values and templates, Kubernetes ingress annotations, Traefik middleware (`stsSeconds`, `contentTypeNosniff`, `referrerPolicy`, `frameDeny`), ingress snippet annotations, and the previously covered surfaces.
- **`RegExp.prototype.exec` is no longer reported as shell execution.** `SEC-CHILD-PROCESS-SHELL` matched any `exec(`, so `FORBIDDEN_KEYWORDS.exec(sql)` in a SQL guard read as `child_process.exec`. A dotted call now only counts when the receiver is a child_process namespace, so `cp.exec(...)` still fires and `/re/.exec(s)` does not.
- **A module constant is no longer mistaken for a client-inlined build variable.** `SEC-SECRET-IN-CLIENT-BUNDLE` matched the `PUBLIC_` prefix on any identifier, reporting `export const PUBLIC_KEY_FILE = 'audit-signing.pub'` in a Node CLI as a published credential. The rule now requires an actual build-variable read (`process.env` / `import.meta.env`) or a config/env file, and treats `_FILE`/`_DIR`/`_EXT` as locator suffixes.
- **An absence claim is downgraded when a surface cannot be read.** A templated ingress snippet, annotations sourced from a values file that is not in the repository, an ingress fed from a ConfigMap, or a Traefik middleware reference that resolves nowhere in-tree now produce `plausible` with a "checked X, could not inspect Y" note, instead of `confirmed`.

## [0.1.0] — 2026-09-12

First release.

### Verified findings

- Every finding carries a `verification` block: method, the individual checks that ran with `file:line` evidence, and a result. Status is one of `confirmed`, `plausible`, `refuted`, `triaged-out` — derived from what the verification did, never asserted.
- Runnable proofs: Sentinel generates a standalone Node script that imports the repository's real modules and exercises them against a payload corpus, runs it, and saves it alongside the report. Proof generators ship for raw-HTML sinks, path confinement, web-storage data flow, and named destination guards.
- A claim about *behaviour* cannot reach `confirmed` without an executed proof. A claim about *code* can, via a re-assertion of the artefact from disk. The distinction is a schema invariant, validated on every run.
- Refuted findings stay in the report with the proof that disproved them, and travel through SARIF as `suppressions` rather than deletions.

### False-positive suppression

- Rules match a lexically masked copy of the source (comments and string bodies blanked, offsets preserved), so a match is real code rather than a code sample in a docblock.
- Vendored and bundled artefacts are excluded from the code rules and named in the coverage report.
- Secret-scanner noise is triaged with a stated reason and a cited location, and published under "triaged out" rather than dropped. An uncited dismissal is rejected by the pipeline.
- Dependency advisories are cross-checked against every installed copy of the package (hoisted, pnpm virtual store, nested). An advisory that does not apply to the installed tree is refuted rather than reported.

### Fix plans and remediation

- Each finding carries a structured fix plan: exact files, the change shape, the acceptance tests to write, a risk rating, and whether an agent can execute it unsupervised — with a stated reason when it cannot.
- `sentinel fix` drives a coding agent to implement the mechanical subset: one branch per finding, the repository's own tests as the gate, one pull request each, human merge required. Never touches the default branch; abandons any fix whose tests fail.

### Standards profiles

- Selectable mapping via `profiles/*.json`: `owasp-asvs`, `cwe-top-25`, `generic-enterprise`, or a path to your own. Profiles declare the rule→control mapping, per-type severity floors, and gate thresholds.

### Honest confidence and coverage

- `CONFIDENCE.md` — overall score, security posture, production readiness, gate decision, risk matrix with likelihood derived from verification strength, signals with interpretation, phased remediation estimate. Severity penalties saturate per class, so a pile of Medium findings cannot outweigh one verified Blocker.
- `COVERAGE.md` — derived from what actually ran: which collectors reported gaps, which external tools were missing, which findings rest on execution versus reasoning.

### Collectors and rules

- Recon, supply chain with licence inventory, secret scanning (19 provider patterns plus entropy, with optional gitleaks/trufflehog), CI gate analysis that treats `continue-on-error` and `|| true` as not gating, Dockerfile analysis that resolves the final build stage's user.
- 26 JS/TS rules across security, quality and tech debt.

### Output

- `REPORT.md`, `REPORT.html` (self-contained, dark/light, zero network requests), `findings/*.json` (superset of the common consultant finding schema), `report.sarif` (2.1.0), `CONFIDENCE.md`, `COVERAGE.md`, `proofs/*.mjs`.
- `sentinel init-workflow` writes a GitHub Actions workflow that self-scans on pull requests and weekly and uploads SARIF to code scanning.

### Model-pass robustness

- Analysis prompts forbid tool use. The provider may be a coding agent rather than a completion endpoint; left to its own devices it explores the repository to answer a review question, burns the per-call budget, and is killed before it answers.
- JSON extraction scans every opening bracket and keeps the last structure that parses, so prose containing brackets (`SEC-001 [High/confirmed]`) no longer swallows the payload.
- A provider that did not answer is reported differently from a provider that answered badly — the two need different remedies.
- `SENTINEL_LLM_DEBUG=<dir>` dumps every prompt/response pair.
- `--llm-timeout` bounds the per-call budget, which dominates scan wall time.

### Engineering

- Zero runtime dependencies. In-tree YAML subset reader, semver comparator, lexical masker, argument parser and schema validator.
- 233 tests, including an end-to-end scan of a synthetic repository that asserts a known non-defect is *refuted* by a real executed proof, and that no artefact embeds the audited source.
- Artefacts never republish the subject: the run record carries findings, provenance and summaries, not a copy of the codebase.
