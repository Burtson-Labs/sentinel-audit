# Standards profiles

A profile decides **which control vocabulary a finding is expressed in**, and **what the gate blocks on**. It does not decide what is a defect — the rules do that. Keeping the two separate is the point: a cross-site-scripting sink does not stop being one because your catalogue calls it `ENG-SEC-OUTPUT-01` instead of `CWE-79`.

## Builtins

| Id | Title | When to use it |
|---|---|---|
| `owasp-asvs` | OWASP ASVS 4.0.3 (Level 2) | The audience expects a recognised application-security baseline |
| `cwe-top-25` | CWE Top 25 | The consumer is a vulnerability-management system keyed on CWE |
| `generic-enterprise` | Generic enterprise engineering standards | A vendor-neutral stand-in for an internal catalogue — the one to fork |

```bash
sentinel profiles                                  # list them
sentinel scan . --profile cwe-top-25
sentinel scan . --profile ./my-company.json        # your own
```

## Writing your own

Copy `profiles/generic-enterprise.json` and replace the control ids. The keys are Sentinel rule ids (`sentinel rules` lists them all); the values are your controls.

```jsonc
{
  "id": "acme-engineering",
  "title": "ACME Engineering Standards v4",
  "description": "Internal catalogue. Sourced from the engineering handbook, section 7.",
  "reference": "https://handbook.internal.acme/engineering/security",

  // Per finding *type*, never report below this. Useful when your organisation
  // treats a category as categorically serious regardless of instance.
  "severityFloor": {
    "Secret": "High",
    "CI-CD": "Medium"
  },

  // Which paths are test/fixture/mock code. Credential and auth-storage rules
  // report at Info there, with an explicit "in test code" note, because in a
  // test the construct is usually what is being exercised rather than an
  // exposure. `extend` (the default) appends to the built-in list; `replace`
  // uses only what you supply, and `replace` with an empty list turns
  // path-aware severity off. Entries are JavaScript regular-expression sources,
  // matched case-insensitively against the repo-relative POSIX path.
  "testPaths": {
    "mode": "extend",
    "patterns": ["(^|/)acceptance(/|$)", "(^|/)harness(/|$)"]
  },

  // What the gate does. `sentinel scan` exits 2 when a finding at a blockOn
  // severity is confirmed, and 1 when one is merely present or a conditional
  // severity appears.
  "gate": {
    "blockOn": ["Blocker"],
    "conditionalOn": ["High"],
    "note": "Blockers stop the release. Highs need a dated, owned exception."
  },

  "controls": {
    "SEC-TOKEN-WEBSTORAGE": [
      { "id": "ACME-AUTH-04", "title": "Session material is unreadable by page script",
        "url": "https://handbook.internal.acme/engineering/security#auth-04" }
    ],
    "SEC-CHILD-PROCESS-SHELL": [
      { "id": "ACME-INPUT-03", "title": "Process execution uses argv arrays" }
    ]
  }
}
```

### Mapping resolution

For a rule id, Sentinel looks for:

1. an exact key (`SEC-TOKEN-WEBSTORAGE`);
2. then progressively shorter family prefixes (`DEP-ADVISORY-LODASH` → `DEP-ADVISORY` → `DEP`);
3. then nothing — and the finding says so (`"no mapped control (general engineering quality)"`) rather than being mapped to something approximate.

A rule you do not map still appears in the report, with its severity and its verification intact. Omission is how you say "we do not have a control for this", not how you suppress a finding; use the triage path for that.

### Validation

`loadProfile` rejects a malformed profile with the specific problem rather than failing later during rendering. Required: `id`, `title`, `controls` (an object), `gate` with `blockOn` and `conditionalOn` arrays. Every control needs `{ id, title }`; `url` is optional. `testPaths.patterns` must be an array of valid regular expressions and `testPaths.mode` must be `extend` or `replace` — a pattern that does not compile is reported here rather than silently ignored at scan time.

```bash
node -e "import('./dist/profile.js').then(m => console.log(m.validateProfile(require('./my-company.json'))))"
```

An empty array means it is valid.

## Why profiles are data, not code

The benchmark this tool was built against mapped every finding to one firm's private standards catalogue. That makes the review legible to exactly one organisation and illegible — or worse, quietly authoritative — to everyone else. Sentinel ships the mapping as swappable data so that:

- the same scan can be re-expressed for a different audience without re-running it (`--profile` changes the vocabulary, not the findings — there is a test asserting this);
- your internal catalogue stays in your repository, not in ours;
- a finding with no mapped control is visibly unmapped rather than forced into the nearest available control.
