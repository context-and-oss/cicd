# Disclose gitleaks suppressions

## Why

gitleaks has three ways to drop a finding, and none of them leaves a trace in
its report:

- an inline `gitleaks:allow` on the line,
- a fingerprint in `.gitleaksignore` at the root of the scanned tree,
- a `.gitleaks.toml` at the root: an `[allowlist]` entry, or a rule set that
  disables, narrows or does not load a default rule.

Each is written by the repository being graded, and a pass that rests on one
read exactly like a pass on a clean tree. That is the doctrine rule
[An acceptance nobody can read is indistinguishable from a bug](../docs/explanation/doctrine.md#an-acceptance-nobody-can-read-is-indistinguishable-from-a-bug),
which `--vuln-accept` closed for Trivy and nothing had closed for gitleaks.

The worst case was in this repository. Its own `.gitleaks.toml` set only an
`[allowlist]`, with no `[extend] useDefault = true`, so gitleaks replaced its
222 default rules with none. Measured on v8.30.1: **0 rules loaded**, every
scan of this repository "no leaks found". The secrets gate had searched for
nothing since that file landed.

## What changed

**A scan that loaded no rules is a non-run** (`gitleaksRunError`, every leg).
The SARIF's `tool.driver.rules` is gitleaks' own record of what it loaded,
so it is read rather than the config. The error names the cause and the fix
(`[extend] useDefault = true`).

**Every finding a suppression removed is put back, visible and uncounted.**
The tree leg is run twice when a suppression could apply: the real scan, and
a shadow over a copy of the tree with `.gitleaks.toml` and `.gitleaksignore`
removed and `--ignore-gitleaks-allow`, so gitleaks' default rules run with no
suppression at all. A shadow result the real scan did not report is one a
suppression removed. It is appended to the report with a SARIF suppression
(`status: accepted`, the mechanism in `justification`), which every counter
already skips: `gitleaksFindings`, `parseSarifSeverities` and the evidence
aggregator. `warnings[]` gets one line per mechanism, naming each finding as
`"file:line rule"`, capped like the archive list:

```
gitleaks: SUPPRESSED — 2 findings in the source tree were removed by a fingerprint in .gitleaksignore and are not counted: "a.go:2 aws-access-token", "sp ace/e.go:2 aws-access-token"
gitleaks: SUPPRESSED — 2 findings in the source tree were removed by an inline gitleaks:allow and are not counted: "b.go:2 aws-access-token", "k.pem:1 private-key"
gitleaks: SUPPRESSED — 1 finding in the source tree was removed by the scanned tree's .gitleaks.toml (an [allowlist] entry, or a default rule it disables, narrows or does not load) and is not counted: "allowed/d.go:2 aws-access-token"
```

That is the end-to-end run against a fixture with one counted finding and
five suppressed, one per mechanism plus a quoted path and a multi-line key.

**Attribution is measured, never guessed.** In order:

1. **`.gitleaksignore`**: gitleaks logs, at DBG and only there, the
   fingerprint each ignore entry dropped. The tree leg already runs at debug
   (for the unopened-archive list), and `gitleaksScript`'s filter keeps that
   line's fingerprint in `gitleaks.ignored` — only when the line carries
   `finding=REDACTED` as a whole field, so a gitleaks that stopped redacting
   it costs the attribution, never a secret on disk.
2. **`gitleaks:allow`**: `grep -rnoF` lists every mark in the tree. `-o`
   keeps file content out of the output. A mark anywhere in a multi-line
   finding's span counts, because gitleaks honours it there.
3. **`.gitleaks.toml`**: blamed only when the mark list is known and the
   finding is not inside an archive. The shadow and the real scan differ
   only by the three mechanisms, so what is left is the config.
4. **Unidentified**: anything else — a mark inside an archive, which grep
   cannot open, or a tree whose mark list could not be read. The finding is
   still disclosed and still not counted.

**A config that narrows the rules is named.** When the root carries a
`.gitleaks.toml`, the real scan's loaded rule ids are compared to the
shadow's (the defaults), and a missing id adds `gitleaks: NARROWED RULES —
the source tree's .gitleaks.toml loads N rules and leaves out K of gitleaks'
M default rules, which searched for nothing: <ids>`. Rules a config adds are
not a narrowing and are not reported.

**A shadow that could not run fails the row.** It returns the real scan's
report with an error, the shape a failed history leg has: the findings
reported are real, but a pass resting on an acceptance cicd could not read is
not one it can stand behind. `--fail-on NONE` does not forgive it.

**The shadow costs nothing when nothing applies.** The mark grep always runs;
the shadow scan runs only when the root has a config or ignore file, or the
tree has a mark, or the mark list is unknown. It runs beside the real scan,
not after it.

**cicd's own config is fixed.** `.gitleaks.toml` now extends the defaults
(222 rules, measured), allowlists `testdata/`, whose fixtures plant
credentials on purpose, and stops on three synthetic markers. Tree and
history both scan clean under it. `testdata/.gitleaks.toml` is removed:
gitleaks reads only the root config, so it applied to nothing, and every
module-test cell scans a fixture as its own root.

## Trade-offs taken

- **Disclose, don't refuse.** Every mechanism stays honoured: the findings do
  not count and do not gate. Refusing them would turn every consumer with an
  ignore entry red at once with no warning first — the same blast-radius
  reasoning as disclosing `.trivyignore` rather than neutralising it.
- **A narrowed rule set warns; zero rules is a non-run.** A config that drops
  a rule it judged noisy is a choice the warning makes visible. A config that
  drops all of them is a scan of nothing.
- **A second scan, not a config parser.** gitleaks resolves its config with
  extension, defaults and per-rule allowlists; reimplementing that would be a
  second resolver for one question, and one of the two would be wrong. The
  shadow asks gitleaks itself.

## Still open

- **History is not shadowed.** A finding a suppression removed from the
  history leg is not disclosed. Shadowing history doubles its cost, the
  bigger leg, for credentials already rotated or still in the tree, which
  the tree leg does disclose. A suppressed tree result does not hide a
  history result at the same location (`mergeGitleaksSARIF`): history
  reported it, so it counts.
- **A mark inside an archive cannot be attributed.** It is disclosed as
  unidentified.
- **Wording-coupled.** The ignore attribution reads one DBG line's shape. A
  gitleaks bump that rewords it moves those findings to "unidentified" — still
  disclosed, never lost — and `TestGitleaksScriptKeepsTheIgnoredFingerprints`
  is the tripwire.
