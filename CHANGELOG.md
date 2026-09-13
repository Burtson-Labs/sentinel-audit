# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semver.

## [Unreleased]

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
