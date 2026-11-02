# Couple the edit, not the artifact's history

## Why

A privacy scrub rounds measurements in old specs and capsules because exact
figures can identify a consumer. The intent gate scopes discovery to changed
artifacts, then `checkRefsCoupling` in `src/cross-cutting/intent/rules.go` reads
each artifact's entire history as if it were a new rationale. A numerical edit
therefore fails for naming the implementation the old change touched, not the
files this change touches. Adding a new intent spec alongside the scrub does
not help: each historical artifact independently fails.

Restoring the measurements would undo the privacy fix. Adding irrelevant file
names to historical rationales would rewrite their meaning just to satisfy the
gate. Neither is the change we intend.

## Decision

Only the file-reference coupling rule becomes edit-aware. For an existing
artifact modified in place, judge references present in the new extracted text
but absent from the previous extracted text. Replacing a number or rewrapping
prose can repeat an old reference on a `+` line, so added lines alone do not
express this distinction. Reconstruct the previous document from the diff and
the current artifact, then run the same YAML/Markdown extraction on both.
This preserves block-scalar and frontmatter context rather than grading fragments.

`src/cross-cutting/intent/coupling.go` owns reconstruction and the production
`runArtifactRules` boundary. Its hunk reader consumes file sections resolved by
`parseDiffPaths` in `diffpaths.go`, not another filename parser. That shared
parser remains byte-identical with `src/risk/diffpaths.go`. Round-trip tests
against real Git also exposed its trailing tab delimiter on whitespace-bearing
`---`/`+++` paths; remove that delimiter before unquoting, not a filename's own
escaped tab. The shared parser's test table covers both quoted tabs and
unquoted spaces.

- New, copied and renamed artifacts keep whole-artifact coupling. An unrelated
  rationale copied into place must not inherit an exemption.
- Existing artifacts with no readable textual patch keep whole-artifact
  coupling, never an assumed empty edit. Malformed or truncated textual hunks,
  overlapping/out-of-order ranges and content mismatches are refusals, even at
  `--fail-on NONE`.
- A new unrelated reference still fails. A changed filename mentioned only in
  the old rationale cannot clear it. The literal-name reverse check continues
  to recognise names outside the path tokeniser's extension list.
- Removing references introduces none. Repeating an existing reference is not
  a new reference; changing the claims around that reference remains a human
  review responsibility, not something this deterministic rule can establish.
- Renaming a reference is not a new reference either. A scrub that moves an
  org slug inside every URL and API path (`old-org/tool` to `new-org/tool`)
  changes one segment of each token and keeps the file it names. Measured on
  the preparation change, that was the whole of its remaining coupling failure.
  An introduced token counts as a rename when a token that disappeared from the
  artifact has the same segment count, the same last segment, and differs in
  exactly one other segment. Each disappeared token explains at most one
  introduced token, so one removal cannot launder several additions. Changing
  the last segment names a different file, and changing two segments is not a
  rename this rule can tell from a new reference: both still fail. A directory
  move of a same-named file therefore passes; that is the rename's cost, and
  its claim remains a human review responsibility like any repeated reference.
- Presence and all other prose rules still judge the entire current artifact.
  This is not a blanket exemption for modified specs, and a metadata-only edit
  still cannot make missing intent or placeholder prose disappear.
- Without a diff the documented whole-tree prose audit is unchanged. The
  envelope warns when coupling used the narrower, introduced-reference scope,
  because a clean result must say what was judged.

## Verification

Use synthetic Markdown and capsule YAML, not consumer text. Tests exercise the
production rule boundary, not just a regex: numerical replacements on lines
with file names, reflow, removed references, block scalars and frontmatter,
new unrelated references, inherited coupling witnesses, literal changed names,
one-segment renames against file swaps, two-segment changes and one removal
claimed by two renames, and new/copied/renamed artifacts. Patch tests include multiple hunks, insertions,
deletions, quoted paths, CRLF, missing final newlines and strict refusal of
corruption or a patch that does not match the supplied artifact.

Run the canonical module-unit and repository script suites, surface/pin/format
checks, and a real Dagger `intent check` on the preparation change's full diff.
A negative control must still return a failed envelope for an unrelated new
reference; an unreadable patch must return an error, never a clean envelope.
