# File the BYO test result under its concerns

## Why

A consumer monorepo runs the commit composite in repository mode with a `byo-test` leg. Its
bundle for `main` holds `parts/02-quality-byo-test.json` saying `passed: true`,
`outcome: CLEAN` and a `coveragePercent` of about 90. The same bundle's
`concerns/index.json` lists `tests` and `coverage` under `notAnswered`, and the
row for that envelope sits in `concerns/unclassified.json`. Every consumer that
reads the bundle by concern (a fleet dashboard, the notify table, a customer report)
therefore says the repository has no test evidence, about a run that had just
reported a green suite over ninety percent of the tree.

The cause is in `Test`: it declared `sources[]` rows only in application mode,
because the rows were added for the application report and repository mode was
left on the old path. In repository mode the envelope shipped with no rows, so
cross-cutting/evidence synthesised one from the envelope, and the envelope
names no concern because one `byo-test` envelope answers two questions (tests
and coverage) and the `concern` field can hold one. The synthesised row landed
in unclassified, which is the aggregator doing exactly what it documents: a row
whose producer declared no concern is reported, not guessed at.

## What

`Test` now declares rows in repository mode too, in `byoreport.go`:

- one `tests` row per leg, `tool: byo-test`, `scope: <leg label>`. The tool
  is `byo-test` instead of the label because cicd did not choose the command
  and cannot say what runner it was; the label goes in `scope`, the axis that
  tells two legs apart, since labels are unique per run where languages are
  not. `passed` is `ran && passed`, `outcome` is `byoLegOutcome`, the same
  two verdicts the envelope folds.
- one `coverage` row for the run, `tool: coverage`, `scope: byo-test`, with
  `examined` in coverable lines. One row instead of one per leg because the
  verdict is one: the ratchet (ADR-003) judges the merged figure, and a per-leg
  split would put `CLEAN` on every row of a run the ratchet failed, so the
  rows' AND would stop being the envelope's verdict. A failed ratchet is
  `FAILED`, matching the envelope's own fold; no coverage output is `SKIPPED`
  with the ratchet's warning counted, matching `coverageSource` and the
  module's fail-open rule, so that the row cannot fail a concern the envelope
  passes.

Application mode is unchanged: `appTestStatuses` keeps its per-leg coverage
rows because that mode has no ratchet and treats a missing declared report as
an error.

## Blast radius

Every repository-mode bundle with a `byo-test` leg gains rows under `tests`
and `coverage` and loses its `unclassified.json` entry. `combined-evidence.json`'s
`passed` and `outcome` do not move, because the rows fold to the same two
values the envelope already carried. Consumers keyed on `concerns/unclassified.json`
being present would see it disappear; none is known.

## Provenance

Consumer names and private references in this spec were replaced with neutral
stand-ins because `AGENTS.md` keeps them out of the public tree. The mechanism
and the measured behaviour are unchanged.
