# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Burtson-Labs/sentinel-audit/security/advisories/new) on this repository. Please do not open a public issue for a vulnerability.

Include the version, the command you ran, the shape of the repository it ran against (a minimal reproduction is ideal), and what happened. We aim to acknowledge within three working days.

## Threat model

Sentinel reads untrusted source code and, by design, **executes code in the repository under audit**. That is not incidental — it is how a behavioural claim gets verified. Treat `sentinel scan` on an untrusted repository as equivalent to running that repository's test suite.

### What Sentinel does

| Behaviour | Why | How it is constrained |
|---|---|---|
| Reads every text file in the tree | Collectors and rules need the source | Excludes `node_modules`, build output and vendored bundles; never follows symlinks; per-file size cap |
| Runs the repository's package manager audit | Advisory data must come from a live source, not a stale embedded database | `shell: false` with an argv array; timeout; skipped entirely with `--offline` |
| Generates and executes proof scripts that **import modules from the audited repository** | A claim about behaviour can only be verified by running the code | Separate `node` process; 60-second timeout; no arguments derived from repository content reach a shell; disable with `--no-proofs` |
| Invokes a coding/review agent | Triage, deep review, fix plans | Review passes run with the agent's plan/read-only permission mode set; disable with `--no-llm` |
| Writes branches and commits, and opens pull requests | `sentinel fix` | Only with `--apply`/`--pr`; never the default branch; never a merge; never a force-push; aborts on a dirty tree; abandons a fix whose tests fail |

### Running against untrusted code

Importing a module runs its top-level code. If you are auditing a repository you do not trust:

```bash
sentinel scan ./untrusted --no-proofs --offline --no-llm
```

That reduces Sentinel to pure reading. You lose behavioural verification — every affected finding drops to `plausible` and `COVERAGE.md` records it — but nothing from the repository executes. For the full scan on untrusted input, run it in a container or VM with no credentials and no network.

### What Sentinel never does

- **Never prints a secret.** Secret findings carry a masked value (3 leading characters, the length) and never the material. This is enforced at the collector, so it holds in every output format including SARIF and JSON.
- **Never phones home.** No telemetry, no analytics, no update check. The HTML report makes no network requests of any kind — no CDN, no font, no remote image — and a test asserts it.
- **Never interpolates repository content into a shell.** Every subprocess goes through one helper with `shell: false` and an argv array.
- **Never commits to your default branch.**

## Supply chain

Sentinel ships with **zero runtime dependencies**. A tool whose pitch is "your dependency tree is an attack surface" should not arrive with four hundred transitive packages. The YAML reader, the semver comparator, the argument parser and the schema validator are all in-tree and tested, which is the reason they exist rather than an accident.

Development dependencies are TypeScript, vitest and ESLint. `pnpm selfscan` runs Sentinel against itself in CI.

## Interpreting a Sentinel report as a security artefact

Two failure modes to guard against when acting on output:

1. **Do not read `plausible` as `confirmed`.** It means nothing was executed to establish the claim. `CONFIDENCE.md` reports the verified share precisely so that budget follows evidence.
2. **Do not read absence of a finding as absence of a vulnerability.** `COVERAGE.md` lists what was not examined. Notably: no cross-module data-flow analysis, no running service, no advisory-reachability proof, and no visibility into infrastructure outside the repository.
