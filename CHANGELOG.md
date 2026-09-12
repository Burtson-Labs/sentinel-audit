# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semver.

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

### Engineering

- Zero runtime dependencies. In-tree YAML subset reader, semver comparator, lexical masker, argument parser and schema validator.
- 225 tests, including an end-to-end scan of a synthetic repository that asserts a known non-defect is *refuted* by a real executed proof.
