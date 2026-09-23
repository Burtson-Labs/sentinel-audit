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
| Generates and executes proof scripts that **import modules from the audited repository** | A claim about behaviour can only be verified by running the code | Docker/Podman container by default: `--network none`, read-only root, repository and proofs mounted read-only, `--cap-drop ALL`, `no-new-privileges`, pid/memory/CPU limits, `noexec` `/tmp`, your uid:gid, and an empty environment. 60-second timeout. Never falls back to the host on its own; see below |
| Invokes a coding/review agent | Triage, deep review, fix plans | Review passes run with the agent's plan/read-only permission mode set; disable with `--no-llm` |
| Writes branches and commits, and opens pull requests | `sentinel fix` | Only with `--apply`/`--pr`; never the default branch; never a merge; never a force-push; aborts on a dirty tree; abandons a fix whose tests fail |

### Running against untrusted code

Importing a module runs its top-level code, so every proof runs the audited repository's code. `--proof-sandbox` decides where:

| Mode | Where proofs run | What the proof can reach |
|---|---|---|
| `auto` (default) | a `docker` or `podman` container if one answers; otherwise **not at all** | the repository and the proof scripts, read-only. No network, no environment variables from your shell, no home directory, no writable path except a 64 MB `noexec` `/tmp` |
| `container` | same as `auto` | same |
| `host` | your machine, as you | your files and your network. The environment is still an allowlist (`PATH`, temp dir, locale), so API keys and tokens in your shell are not passed, but this is only for repositories you already trust |
| `off` | nowhere (same as `--no-proofs`) | nothing |

`auto` never falls back to `host`. When no runtime is running, affected findings stay `plausible` and `COVERAGE.md` says why. `test/sandbox.test.ts` runs a hostile proof in the container that tries to read credentials, reach the network, write to the repository and execute from `/tmp`, and fails the build if any of them works.

The first scan pulls `node:24-alpine` once. For an air-gapped machine, pull it (or your own Node 22.18+ image, via `--proof-image` or `SENTINEL_PROOF_IMAGE`) ahead of time. `SENTINEL_CONTAINER_RUNTIME` selects a runtime other than `docker`/`podman`.

The container isolates a proof, not the rest of the scan. The package-manager audit and the model pass run on the host, so for a repository you do not trust at all, add `--offline --no-llm` as well.

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
