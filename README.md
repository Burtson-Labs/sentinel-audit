<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.burtson.ai/logos/burtson-labs-logo-alt.png" />
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.burtson.ai/logos/burtson-labs-logo.png" />
    <img src="https://cdn.burtson.ai/logos/burtson-labs-logo-alt.png" alt="Burtson Labs" width="180" />
  </picture>

  # Sentinel Audit

  **A repository audit that verifies its own findings — and keeps the ones it disproves.**

  [![CI](https://github.com/Burtson-Labs/sentinel-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Burtson-Labs/sentinel-audit/actions/workflows/ci.yml)
  [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
  [![Docs](https://img.shields.io/badge/docs-profiles-a60ee5)](docs/profiles.md)
  [![Node](https://img.shields.io/badge/node-%E2%89%A5%2022.6-5FA04E?logo=node.js&logoColor=white)](package.json)
  [![Dependencies](https://img.shields.io/badge/runtime%20deps-0-a60ee5)](package.json)

  <sub>A <a href="https://burtson.ai">Burtson Labs</a> open-source project</sub>

</div>

---

Most security reviews — human or AI — hand you a list of assertions. Sentinel hands
you a list of *checked* assertions, each labelled with how it was checked and what
happened: `confirmed`, `plausible`, `refuted`, or `triaged-out`. Where it can, it
writes a runnable proof script, executes it against your real code, and saves the
script next to the report so you can re-run it yourself.

> A refuted finding is a feature. Sentinel keeps them in the report, because "we
> checked this and your protection works" is information you paid for too — and
> because a tool that only ever reports problems cannot be trusted about the
> problems it reports.

```
confirmed    23   (an executed check agreed)
plausible     5   (reasoned, unproven)
refuted       1   (an executed check disproved it)
triaged out   1   (noise, with reasons)

score 5.4/10 (acceptable / moderate) · security 5.7/10 · gate PASS-WITH-CONDITIONS
verified share of live findings: 82%
```

- **Nothing says "confirmed" unless something ran.** Either a generated script
  exercised your real modules and returned a verdict, or the artefact was re-read
  from disk at report time and the factual claim re-established. Everything else
  stays `plausible`, and the report says so next to the finding.
- **The confidence number is derived, not authored.** It comes out of the
  verification record. A model cannot set it, and neither can a reviewer.
- **Zero runtime dependencies.** A tool whose pitch is "your supply chain is the
  attack surface" should not arrive with one. The CLI parses its own arguments.
- **The model pass is additive and never load-bearing.** With no provider
  reachable the scan completes, and every artefact states that it did not run
  along with the coverage cost.

## Quickstart

```bash
# Node >= 22.6 required — the proof runner uses native TypeScript type stripping
git clone https://github.com/Burtson-Labs/sentinel-audit.git
cd sentinel-audit && pnpm install && pnpm build

# audit any repository
node dist/cli.js scan ../some-repo --out ./results

# pick a standards vocabulary and the artefacts you want
node dist/cli.js scan ../some-repo --profile cwe-top-25 --format md,html,json,sarif

# deterministic only: no model calls, seconds rather than minutes
node dist/cli.js scan ../some-repo --no-llm
```

Exit codes: `0` clean · `1` findings at or above the conditional threshold · `2`
the profile gate blocked.

Not on a public registry yet, so there is no `npm i -g` line here. `npm link` in
the checkout puts `sentinel` on your `PATH` if you want the short command.

### Artefacts

| File | What it is |
|---|---|
| `REPORT.md` | Findings with evidence, verification record, standards mapping and a fix plan each |
| `REPORT.html` | Self-contained page, dark/light, filterable by status. No network requests at all |
| `findings/*.json` | One file per finding. Superset of the common consultant finding schema — see below |
| `findings/index.json` | Manifest with counts, provenance, and the schema-validation result |
| `report.sarif` | SARIF 2.1.0 for GitHub code scanning. Refuted findings travel as `suppressions`, not deletions |
| `CONFIDENCE.md` | Scored assessment: overall, security posture, gate decision, risk matrix, remediation phases |
| `COVERAGE.md` | What was **not** examined and why — derived from what actually ran |
| `proofs/*.mjs` | The generated proof scripts. Re-runnable, unchanged, by hand |
| `scan-context.json` | The run record: provenance, collector results, gaps. Summaries only — never a copy of your source |

## Why this is different

| | Consultant-style review (human or LLM) | sentinel-audit |
|---|---|---|
| **Finding status** | Asserted. You cannot tell a demonstration from a suspicion | Every finding carries `status` + a `verification` block stating method, checks run, and result |
| **Exploitability** | "Assessed by code reading" | A generated script runs the real code and returns a verdict; behavioural claims cannot be `confirmed` without one |
| **Wrong findings** | Quietly dropped, or shipped as real | `refuted`, with the proof that disproved them, kept in the report |
| **Scanner noise** | Either all of it or none of it | Triaged out with a reason *and* a cited `file:line`. An uncited dismissal is rejected by the pipeline |
| **Confidence number** | Authored by the reviewer | Derived from the verification record. A model cannot set it |
| **Standards mapping** | One firm's private catalogue | Selectable profile: `owasp-asvs`, `cwe-top-25`, `generic-enterprise`, or your own JSON |
| **Dependency advisories** | Whatever `npm audit` printed | Cross-checked against the **installed** version (pnpm store included); an advisory that does not apply is refuted |
| **Coverage claims** | A paragraph of prose | A table derived from which collectors ran and which tools were missing |
| **Remediation** | A recommendation | A structured fix plan, and for the mechanical subset, `sentinel fix` drives an agent to implement it on a branch and open a PR |
| **Reproducibility** | Re-read everything | Stable fingerprints; a second run over an unchanged tree produces identical ids |

### The verification ladder

A finding earns its status; it is never assigned one.

- **`confirmed`** — something ran and agreed. Two ways to get here:
  - `proof-executed` — a generated script exercised your real modules and returned
    a verdict. **Required** for any claim about *behaviour*.
  - `static-assertion` — the artefact was re-read from disk at report time,
    independently of the rule pass, and the factual claim re-established (the
    construct is at that line; the policy is absent from every file it could live
    in; the vulnerable version is the one installed). Sufficient for claims *about
    the code*.
- **`plausible`** — reasoned from reading. Honest and still useful, but you should
  confirm it before funding the fix. The schema *forbids* promoting a code-read
  finding to confirmed, which is why model-proposed findings top out here.
- **`refuted`** — an executed check disproved it. Kept, with the reason.
- **`triaged-out`** — suppressed as noise, with a reason and a cited location.

Two asymmetries keep the verdicts honest:

1. **Stub asymmetry.** Real application modules often cannot load outside their
   bundler. The proof harness substitutes inert objects for unresolvable imports
   and records what it replaced. A `safe` verdict under stubbing is still
   meaningful — a stub cannot *add* escaping. A `vulnerable` verdict under
   stubbing is downgraded to inconclusive, because one of the stubs might have
   been the sanitiser.
2. **Proofs can only strengthen factual claims.** If a data-flow proof fails to
   reproduce a write that re-assertion already established from the source, the
   finding stands. A proof that cannot load a module is never treated as a
   refutation.

## CLI

```
sentinel scan <repo> [options]
sentinel fix <findings-dir> [options]
sentinel rules [--json]          # list the 30 rules with their claim types
sentinel profiles                # list the standards profiles
sentinel init-workflow           # write .github/workflows/sentinel.yml
```

**Scan options**

```
--profile <id|path>     owasp-asvs | cwe-top-25 | generic-enterprise | ./my-profile.json
--out <dir>             default ./sentinel-results/<repo-name>
--format <list>         md,html,json,sarif
--no-llm                deterministic only
--no-proofs             skip generating and executing proof scripts
--offline               skip anything needing the network (dependency advisories)
--bandit-cli <path>     path to the coding/review agent entrypoint
--max-review-files <n>  how many files the model review pass may read (default 4)
--llm-timeout <ms>      per-call budget for the model pass (default 300000)
--quiet
```

## What it looks at

**Deterministic collectors** (no model involved, always run):

- **Recon** — languages, LOC, frameworks, entrypoints, package manager,
  test-to-source ratio, largest modules, TS strictness, git provenance.
- **Supply chain** — advisories from your own package manager's audit, grouped by
  module, then cross-checked against every installed copy (hoisted, pnpm virtual
  store, nested). Licence inventory with copyleft flagging.
- **Secrets** — 19 provider patterns plus generic assignment + entropy, over the
  working tree. Every candidate gets a triage verdict with a reason.
  `gitleaks`/`trufflehog` are used if present (they cover git history, which the
  built-in scanner does not, and `COVERAGE.md` says so when they are absent).
- **CI** — does the gate actually gate? `continue-on-error: true` and `|| true`
  are treated as not gating, because they are not. Unpinned action references and
  fork-context triggers are flagged.
- **Containers** — base-image pinning, root user (resolved for the **final** build
  stage, so a `USER` in a builder does not count), credential-shaped build args.
- **Edge configuration** — response security headers are checked across every
  surface that can set one: Helm chart values and templates, Kubernetes ingress
  annotations (`nginx.ingress.kubernetes.io/hsts`), Traefik middleware, nginx and
  Caddy configs, static-host header files, and `<meta>` tags. A header set at the
  ingress is set, and a rule that only reads nginx confs would report its own
  blind spot as your defect.
- **30 code rules** for JS/TS — raw-HTML sinks, token storage, client-side
  authorisation, unverified JWT decoding, shell execution, path traversal, SSRF
  shape, dynamic evaluation, TLS overrides, CORS, `postMessage` origin, secrets in
  client bundles, CSP, source maps, the cryptographic-usage set below, plus
  quality signals (swallowed catches, `console` logging, `any` density, file size,
  test thinness, deferred-work markers).

Rules match a **lexically masked** copy of the source — comments and string bodies
blanked, offsets preserved — so a match is real code rather than a code sample in a
docblock. Vendored and bundled artefacts are excluded from the code rules and named
in the coverage report.

### Cryptographic usage

Checking whether a *primitive* is obsolete — MD5, SHA-1, `Math.random()` — is the
easy half, and most scanners stop there. What actually breaks a signing or
verification library is a correct primitive wired up wrongly, so five rules cover
that separately:

| Rule | What it reports |
|---|---|
| `SEC-WEAK-CRYPTO` | Broken hash primitives and non-cryptographic randomness in a security context |
| `SEC-TIMING-UNSAFE-COMPARE` | A signature, MAC, token, password or API key compared with `===`, `Buffer.compare` or `Buffer.equals`, which short-circuit on the first differing byte |
| `SEC-CRYPTO-IV-REUSE` | An encryption nonce/IV that is fixed, zero-filled, clock-derived, or drawn once at module scope and reused on every call — plus ECB, the degenerate case |
| `SEC-WEBCRYPTO-MISUSE` | SubtleCrypto called with a collision-broken digest, an `extractable: true` private key, a PBKDF2 cost below the modern floor, or a truncated AEAD tag |
| `SEC-SIGNATURE-VERIFY-DISCARDED` | A verification call used as a bare statement, a `catch` around one that returns success, a runtime switch that skips verification, or `none` accepted as an algorithm |

Precision is bought with discriminators rather than with a shorter pattern list,
because the naive version of each of these rules is unusable:

- A SHA-256 **content hash** compared with `!==` is not a timing oracle — both
  sides are public. Only a digest the file shows was *keyed* counts.
- `secret.id`, `token.type` and `password !== confirm` are metadata and
  same-origin comparisons, not authentication decisions.
- `isTokenExpired() { … catch { return true } }` fails **closed**. A `catch`
  returning `true` is only a finding inside a positive predicate whose `try` block
  contains a real verification primitive.
- `importKey(…, true, ['verify'])` exports a *public* key, which is fine. The
  extractable flag only matters with private usages.
- The `timingSafeEqual` exemption is scoped to three lines, so importing a safe
  comparator cannot silently disable the rule for the rest of the module.

**Model pass** (optional, additive, and never load-bearing):

Uses the [Bandit CLI](https://github.com/Burtson-Labs/bandit-agent-framework) if it
is installed, otherwise `ANTHROPIC_API_KEY` or any `OPENAI_API_KEY`-compatible
endpoint. Three jobs only:

1. **Triage** — may dismiss or downgrade a deterministic finding, but only by
   citing a `file:line` that justifies it. Uncited dismissals are rejected by the
   pipeline and logged. A model opinion never overturns an executed proof.
2. **Deep review** — reads the highest-signal files for defects the lexical rules
   cannot see. Proposals are marked `source: llm`, `method: code-read`, and
   therefore cannot be `confirmed`.
3. **Fix-plan authoring** — turns recommendations into instructions an agent can
   execute.

With no provider reachable, the scan completes and every artefact says the model
pass did not run, with the coverage cost spelled out. The one failure mode a
security report must not have is quietly producing less while looking the same.

**Wall-clock note:** the deterministic half of a scan takes seconds; the model pass
takes minutes per call and dominates the total. Budget it with `--llm-timeout` and
`--max-review-files`, or run `--no-llm` in CI and the full pass on a schedule.

## Automated remediation

```bash
sentinel fix ./results/findings --repo ../some-repo               # dry run, writes nothing
sentinel fix ./results/findings --repo ../some-repo --only SEC-*  # still a dry run
sentinel fix ./results/findings --repo ../some-repo --apply       # commit on branches
sentinel fix ./results/findings --repo ../some-repo --pr          # push + one PR per finding
```

### Trust model — read this before `--apply` or `--pr`

1. **A human merges. Always.** Sentinel opens pull requests. It never merges, never
   pushes to the default branch, never force-pushes.
2. **Tests are the gate.** Every fix runs on its own branch and the repository's own
   test command must pass. A fix whose tests fail is abandoned and reported as
   failed, not shipped as a PR that breaks the build. With no test command,
   `--apply`/`--pr` refuse to run unless you pass `--no-tests`, and the PR body
   states in bold that the change is unverified.
3. **One finding, one branch, one PR.** No batching, so a bad fix is one revert.
4. **Only `agent-executable` fix plans.** That flag is false by default and false
   for anything needing a policy value, an allowlist, a credential, or a product
   decision. Each finding records *why* it is not automatable.
5. **Refuted and triaged-out findings are never fixed.** Acting on them would undo
   working protections.
6. **A dirty working tree aborts the run.** Sentinel will not mix its changes with
   yours.
7. **Dry run is the default.**

Typically 6–8 of ~30 findings are agent-executable: adding `rel="noopener"`,
converting shell execution to argv form, swapping weak crypto primitives, routing an
authenticator comparison through a constant-time helper, annotating unverified JWT
decodes, gating source maps, validating `postMessage` origins, switching plaintext
endpoints to TLS. The judgement calls stay with you — that is the point. Changing a
nonce scheme, a digest, or a KDF cost is explicitly *not* automatable, because each
one changes data already written.

### CI

```bash
sentinel init-workflow   # writes .github/workflows/sentinel.yml
```

Scans on pull requests and weekly, uploads SARIF to code scanning, publishes the
full artefact set, writes a summary table to the job summary, and re-asserts the
gate after the upload so a blocked gate actually fails the check.

## Standards profiles

Findings map to a selectable profile, not to one company's private catalogue.

| Profile | Use when |
|---|---|
| `owasp-asvs` | The audience expects a recognised application-security baseline |
| `cwe-top-25` | The consumer is a vulnerability-management system keyed on CWE |
| `generic-enterprise` | You want house rules. **Fork this file**, replace the control ids with your own, pass the path |

```bash
sentinel scan . --profile ./my-company-standards.json
```

A profile declares the rule→control mapping, per-type severity floors, and the gate
thresholds. Same findings, different vocabulary — which is the right separation: the
defect does not change because your catalogue does. Full reference in
[docs/profiles.md](docs/profiles.md).

## The finding schema

`findings/*.json` is a **superset** of the common consultant-review record, so a
consumer written against that shape reads Sentinel output unchanged:

```
id · title · type · severity · suggestedLabels · affectedArea · evidence
whyThisMatters · recommendation · acceptanceCriteria · effortEstimate
dependenciesRelated · provenance · standardMapping
```

Everything Sentinel adds is additive:

```jsonc
{
  "status": "refuted",
  "verification": {
    "method": "proof-executed",
    "claimType": "behavioral",
    "performed": true,
    "result": "refuted",
    "checks": [
      { "description": "re-read src/view.ts:4 and re-matched the construct",
        "outcome": "pass", "detail": "src/view.ts:4 — el.innerHTML = safeRender(body);" },
      { "description": "generated and executed a proof script",
        "outcome": "fail", "detail": "proofs/SEC-004-1-html-sink.proof.mjs — verdict \"safe\"" }
    ],
    "proof": {
      "path": "proofs/SEC-004-1-html-sink.proof.mjs",
      "command": "node proofs/SEC-004-1-html-sink.proof.mjs",
      "predicted": "at least one of 15 XSS payloads emerges as executable markup",
      "observed": "all 15 payloads were neutralised by safeRender()",
      "verdict": "safe"
    },
    "notes": "an executed proof disproved the exploitability claim… the static pattern that raised it is real — the consequence is not."
  },
  "fixPlan": { "agentExecutable": false, "strategy": "…", "files": [], "acceptanceTests": [], "risk": "medium" },
  "standards": { "profile": "cwe-top-25", "cwe": ["CWE-79"], "controls": [] },
  "confidence": 0.95,
  "fingerprint": "c1f0a2e9b7d4…"
}
```

Sentinel validates its own output against this schema on every run, **including the
semantic invariants**:

- a `confirmed` behavioural finding must carry an executed proof with a
  `vulnerable` verdict;
- a `refuted` finding must have an executed check;
- a suppression must cite a concrete location;
- a plan claiming `agentExecutable` must carry an agent prompt.

Violations land in `SCHEMA-VALIDATION.md` and are described as bugs in Sentinel, not
in your repository.

## Limits, stated plainly

Sentinel's own `COVERAGE.md` says this per run; here it is in general:

- **Rules are lexical, not full-AST.** No cross-module data-flow tracking. A
  sanitiser or guard called from another module is not seen by a rule — which is
  exactly why the proof stage exists, and why unproven findings stay `plausible`.
- **Crypto rules read names and call shapes, not types.** An authenticator held in
  a variable called `value` is invisible; a keyed digest produced in another module
  is not traced. The trade is deliberate — the alternative is a rule that reports
  every string comparison in the repository.
- **Nothing is executed as a service.** No application is started, no request is
  issued, no load testing. Authorisation correctness beyond code reading needs a
  running instance.
- **Advisory reachability is not proven.** An advisory is matched to the installed
  version; whether the vulnerable function is called from your code is a separate
  question.
- **Secret scanning covers the working tree, not git history,** unless
  `gitleaks`/`trufflehog` is installed.
- **Containers are read, not built.** Base-image CVEs need a container scanner.
- **Infrastructure outside the repository is invisible.** A CSP added by your CDN, a
  WAF, a NetworkPolicy — Sentinel cannot see these and says so rather than claiming
  their absence. Edge config that *is* in the repository but cannot be evaluated
  statically — a templated ingress snippet, a Traefik middleware defined
  elsewhere — downgrades the finding to `plausible` with a "checked X, could not
  inspect Y" note rather than asserting absence.
- **Non-JS/TS languages** get secrets, dependencies, CI and container coverage only.

## Development

```bash
pnpm install
pnpm build          # tsc
pnpm test           # 300 vitest tests incl. an end-to-end scan of a synthetic repo
pnpm lint
pnpm typecheck
pnpm selfscan       # Sentinel audits Sentinel
```

The end-to-end test builds a fixture repository with known defects **and one known
non-defect** (a renderer that escapes correctly), then asserts Sentinel refutes the
non-defect via a real executed proof. A tool that cannot produce a refutation is just
a scanner with better prose.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, and
[SECURITY.md](SECURITY.md) for the threat model of running Sentinel against untrusted
code.

## License

[MIT](LICENSE) © Burtson Labs
