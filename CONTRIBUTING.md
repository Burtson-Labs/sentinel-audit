# Contributing

Thanks for looking. The bar here is a little unusual, so it is worth stating up front.

## The one rule

**A finding must be able to survive being checked.** Every contribution is judged against that. A rule that fires on a pattern without a way to verify the consequence is half a contribution; the other half is the verifier, or an honest `claimType: 'behavioral'` so the finding is capped at `plausible` and the report says why.

Concretely, pull requests are expected to:

- keep the semantic invariants in `src/schema.ts` true;
- add tests for both the true positive **and** the false positive you expect people to hit;
- say what the rule cannot see, in the rule's own `why` text.

## Setup

```bash
pnpm install
pnpm build
pnpm test
pnpm lint
pnpm selfscan   # Sentinel audits Sentinel; CI runs this too
```

Node 22.6+ is required: the proof harness relies on native TypeScript type stripping to import a repository's `.ts` modules without a build step.

## Adding a rule

A rule lives in `src/rules/security.ts`, `server.ts`, `quality.ts` or `web.ts` and is registered in `src/rules/index.ts`.

```ts
export const myRule: Rule = {
  id: 'SEC-SOMETHING',          // FAMILY-NAME, stable forever; it is the SARIF ruleId
  title: 'Short, what is wrong — not what to do',
  type: 'Security',
  severity: 'High',             // the worst case; use severityFor() for the case at hand
  area: 'API',
  labels: ['security'],
  claimType: 'behavioral',      // see below — this is the important field
  why: '…',                     // the consequence, concretely. Not "this is bad practice"
  recommendation: '…',
  acceptance: ['…'],
  effort: 'M',
  appliesTo: JS_TS,
  scan: (ctx) => [/* RuleHit[] */],
  fixPlan: (hits) => ({ /* … */ }),
};
```

### `claimType` is not a formality

- **`factual`** — "the code contains / does not contain X". A re-read of the artefact can confirm this outright, so the finding can reach `confirmed` via `static-assertion`.
- **`behavioral`** — "input X causes unsafe behaviour Y". Only an executed proof can confirm this. Getting it wrong is the one mistake that makes the whole tool dishonest, so the schema enforces it and `test/schema.test.ts` asserts the enforcement.

If you are unsure, pick `behavioral`. The cost is a finding that reports as `plausible`; the cost of the other mistake is a report that claims proof it does not have.

### Match against the right view

`ctx.masked` gives three views of the source, all the same length as the original so offsets stay valid:

| View | Contains | Use for |
|---|---|---|
| `masked.code` | Code only; comments **and** string bodies blanked | Constructs: `eval(`, `exec(`, `.innerHTML =` |
| `masked.codeAndStrings` | Comments blanked only | **Values**: URLs, env var names, route paths, algorithm names — anything that lives inside a string literal |
| `masked.strings` | String bodies only | Rare; inspecting literal content directly |

Using `ctx.src` raw is almost always a bug: you will match a URL inside a comment explaining why that URL is wrong. That exact false positive shipped once and is now a regression test (`test/rules.test.ts`, "ignores a URL mentioned only in a comment"). Conversely, matching `createHash('md5')` against `masked.code` finds nothing, because the algorithm name is a blanked string — also a real bug we fixed, also a test now.

### Tests a rule needs

```ts
it('flags the real thing', () => { /* … */ });
it('ignores the obvious false positive', () => { /* … */ });
it('ignores an occurrence inside a comment', () => { /* … */ });
it('stays silent when the mitigating construct is present', () => { /* … */ });
```

The generic registry tests in `test/rules.test.ts` already assert that every rule has a claim type, a substantive `why`, acceptance criteria, and a fix plan that either carries an agent prompt or explains why it cannot. Those will fail on a half-filled rule.

## Adding a verifier

Verifiers live in `src/verify/index.ts`, dispatched by rule id. A verifier either:

- re-asserts a factual claim against the artefact on disk (see `verifyCspAbsence`, `verifyDockerRoot`, `verifyAdvisory` for the shape), or
- builds a proof spec in `src/verify/proofs.ts` and runs it.

Two rules that are not negotiable:

1. **A proof may only strengthen a factual claim.** If a data-flow proof fails to reproduce something re-assertion already established from the source, the finding stands. `verifyWebStorage` carries a long comment about why: an earlier version let a `safe` verdict through from a proof that had invoked the wrong function, and refuted a true finding. Read it before writing a new verifier.
2. **Stub asymmetry.** The harness substitutes inert objects for unresolvable imports and records what it replaced. A `safe` verdict under stubbing is meaningful (a stub cannot add escaping); a `vulnerable` verdict under stubbing is downgraded to inconclusive (a stub might have been the sanitiser). `finaliseProof` implements this; do not bypass it.

## Adding a standards profile

Copy `profiles/generic-enterprise.json`, replace the control ids and titles, keep the rule ids as the keys. `validateProfile` checks the shape and `test/report.test.ts` asserts every builtin profile loads clean and maps the security rules.

Profiles are deliberately data, not code: your catalogue is yours, and it does not belong in this repository.

## Style

- Comments explain **why**, not what. A comment restating the line below it is noise; a comment naming the false positive a check exists to prevent is the most valuable line in the file.
- Finding prose is written for an engineer who has to act on it, and for their manager who has to fund it. State the consequence, not the category.
- No emoji in output or code.
- Evidence is `file:line`. Always.
- British or American spelling, consistently within a file. Do not churn existing text for this.

## What will be declined

- A rule with no way to be wrong (fires on everything, or on nothing real).
- A finding whose `why` is "this is a bad practice" with no stated consequence.
- Any change that lets a `code-read` verification reach `confirmed`.
- A runtime dependency, unless it replaces more in-tree code than it adds and the trade-off is argued in the PR. Zero runtime dependencies is a feature of this project, not an accident.
- Telemetry, update checks, or anything that makes an artefact reach the network.
