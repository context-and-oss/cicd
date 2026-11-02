# Intent: give a finding its line, so two findings stop being one

## Why

`evidence.Finding` carried severity, tool, rule, message and artifact path — and
no line. `dedupeFindings` keys on the whole struct, deliberately: collapsing on
location alone would merge two distinct CVEs in one lockfile, and under-reporting
to tidy a table is not a trade this repository makes. But the same argument runs
backwards. **Two findings that the tool distinguished only by line number were
byte-identical structs here, and the dedupe kept exactly one.**

So a `.env` with three leaked credentials rendered as one row in the PR comment,
under a count of three. The count came from `FindingsBySeverity`, which is
computed separately and stayed right; the table is what a reviewer reads and acts
on. Every producer upstream already emitted the line — eslint, pylint, the dotnet
reports and gitleaks' own SARIF all set `region.startLine` — and `sarifFindings`
read `artifactLocation.uri` and dropped the region on the way in.

TruffleHog was worse, and in two ways found while fixing the first:

- `buildTrufflehogSARIF` emitted results with **no `locations` array at all**, so
  there was no path and no line for the aggregator to extract.
- `parseTrufflehogOutput` set the finding's file to `SourceName`, which is not a
  path: for a filesystem scan it is the literal string `trufflehog - filesystem`,
  identical for every result in the run. So every secret in an image carried the
  same fake location, and any two from one detector deduped into one.

This is the repository's standing failure class in its quietest form. Nothing
errored, no gate flipped, the counts stayed correct — the evidence just described
fewer problems than the tools found, and a shorter findings table reads exactly
like a cleaner tree.

## What changed

**`evidence.Finding` gains `Line int` (`json:"line,omitempty"`)**, synced to all
ten module copies by `make sync-schema`. It is part of a finding's identity, not
decoration, which is why the dedupe comment now says so in both directions.

**`sarifFindings` reads `region.startLine`** (SARIF 2.1.0 §3.30.5) and only when
positive — a zero or absent region means the tool did not say, and 0 is already
the zero value. Never line 1.

**`findingLocation` in `src/notify/render.go`** renders the location cell as
`path:line`, the form an editor or terminal turns into a jump. A line with no path
renders nothing (a bare `42` is not actionable) and `Line <= 0` renders the path
alone rather than `path:0`.

**TruffleHog's pure logic moved to `src/security/trufflehogreport.go`, untagged**,
and now:

- reads the real path and line from `SourceMetadata.Data.Filesystem`, stripping
  the `/target` mount root that only exists inside a Dagger container;
- emits a `locations` array — with a `region` when there is a line, none when
  there is not, and no location at all for a finding with no path, rather than one
  naming nothing;
- treats output it cannot parse as a run error instead of returning the findings
  so far;
- drops `Raw` — the credential itself — from the result struct entirely.

Moving it out from behind `//go:build !unit_test` matters on its own: those tests
now execute in `make test-module-units`, where a green `lint-repo` means they ran.
The existing `TestTruffleHogArgs` had been sitting behind the Dagger tag, proving
nothing about any CI run.

## Proof

**The TruffleHog schema is measured, not assumed.** The pinned image
(`trufflesecurity/trufflehog:3.78.0@sha256:731515da…`) scanning a fixture with
three GitHub tokens at known positions:

| secret on file line | reported |
|---|---|
| 3 | `"line": 2` |
| 7 | `"line": 6` |
| 1 | no `line` key at all |

`line` is a **0-based offset** serialised with `omitempty`, and `SourceName` came
back as `trufflehog - filesystem` on all three — confirming the mislabelled path
directly rather than by inference. `trufflehogLocation` therefore increments the
offset, and reports an absent key as *no line* rather than line 1: omitempty makes
offset 0 indistinguishable from a source that reports no offset, and inventing the
more precise of two readings is how a fabricated location reaches evidence. A
first-line secret arrives with its path and no line.

`TestTruffleHogRealOutput` runs the parser over a verbatim capture of that stdout
(credential-bearing fields dropped rather than neutered — a scanner's own fixture
is no place to commit something shaped like a token), so a hand-built fixture that
drifts from the tool cannot make the rest of the suite agree with itself and be
wrong.

**The infinite loop is measured too.** The `continue`-on-decode-error being
replaced never advanced the decoder: `json.Decoder` does not move past a syntax
error, so `More()` stayed true and `Decode` failed on the same bytes. Reproduced
with the old loop body verbatim — **47,847,656 iterations in two seconds**, one
result decoded, no termination. A hang, not a degradation, and the new test asserts
termination on a 5s deadline rather than trusting the shape of the code.

**What was not run.** The chain has not been driven end to end through a live
gitleaks scan into `evidence.Wrap`. The TruffleHog leg — the only code here whose
input shape was in question — is measured against the real tool; the aggregator's
region parsing and the notify cell are unit-proven against SARIF shaped like the
one gitleaks already emits, and gitleaks itself was not touched. `module-test` and
`composite-smoke` exercise the live path in CI.

**Coverage.** 673 module unit tests (from 660), 419 script tests, `make test`,
`make lint`, `check-surface`, `check-pins`, `check-image-pins`,
`check-ado-templates` all green. The new tests assert what the change is for: two
findings differing only by line survive the merge; an absent region does not
become line 1; the notify table renders `.env:4` and `.env:19` as two rows.

## Decisions

**Line participates in the dedupe key.** It has to — that is the whole change —
but it means the key now widens whenever `Finding` gains a field, and a producer
that leaves that field at its zero value gets no benefit from it. Both directions
are written into the `dedupeFindings` comment, because the next person adding a
field needs to know which failure they are choosing between.

**A missing line is honest; a guessed one is not.** Every path here treats "the
tool did not say" as 0 and renders it as a path with no line. The alternative —
defaulting to 1 — makes every unlocated finding look precisely located, which is
the same species of lie as a scanner that could not run reporting zero findings.

**Trivy findings still have no line, and that is correct.** A CVE is a property of
a package version, not of a source line; `trivyFindingPath` reports the target and
package. Intent findings are likewise file-level by construction (artifact
presence, filename/test coupling), so `IntentFinding` does not follow.

**Parsing that fails is a run error.** This makes TruffleHog stricter: output with
one unreadable line now fails `ScanImage` rather than under-reporting. That is the
documented doctrine, and the tool is invoked with `--json` on a pinned digest, so
non-JSON on stdout is a genuine surprise worth a red build.

## Known residue

The 0-based offset is version-coupled. The digest pin and the Renovate group make
a version move visible, and `src/security/CLAUDE.md` carries the instruction to
re-measure the base when bumping `trufflehogVersion` — but nothing fails
automatically if the base flips, because the check would have to run the scanner.
The captured-stdout test pins the schema, not the semantics.

`src/internal/evidence/schema_test.go` and `src/risk/scanner.go` are unformatted
by `gofmt` on `main`, and remain so — unrelated to this change, and `make lint`
does not cover them (it runs golangci-lint on `src/internal` only). Worth its own
pass.
