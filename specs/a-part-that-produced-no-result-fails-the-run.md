# A part that produced no result fails the run

## Intent

Every workflow gate reads one field: `combined-evidence.json`'s `passed`.
`buildCombined` set it from each part's own `passed`, so a part that wrote
`passed: true` beside outcome `ERROR` turned the whole run green, with the
reason in `errors[]` where no gate looked.

Measured on the native test legs in `src/quality/test.go`. Go, Node, Python and
.NET computed `passed` as `gatedPassed(ran, subjectPassed, threshold)`, and
`testOutcome` reaches `ERROR` with `ran` still true: a runner that exits
non-zero while its own accounting says no test failed (a build error outside
any package's test, a .NET host that crashed after a green suite). At
`--fail-on NONE` that leg's envelope read `passed: true`, outcome `ERROR`. The
`Check` roll-up already caught it through `anyLegErrored`, so the defect was
in the part a consumer reads when they open `parts/`, and in the aggregator
that would pass the next producer to make the same mistake.

## Chosen approach

Two places, because the second only exists to catch the first:

- **At the source.** `testLegPassed` (`src/quality/legfold.go`) folds
  `testOutcome(...) != ERROR` into the non-run half of `gatedPassed`, and all
  four native legs use it. A real failing suite (`FAILED`) is unchanged and
  still passes at NONE.
- **At the aggregate.** `producedNoResult` (`src/cross-cutting/evidence/main.go`)
  fails the combined verdict for a part whose outcome is `ERROR` *and* whose
  `errors[]` is non-empty, whatever its own `passed` says.

## Rejected

- **Key on `errors[]` alone.** A real failing suite under NONE carries
  `go test failed (exit 1)` in `errors[]`, outcome `FAILED`, `passed: true`.
  That is NONE's documented meaning, and keying on `errors[]` would make NONE
  fail every red suite.
- **Key on `ERROR` alone.** notify reports a Teams card it could not deliver
  as `ERROR` with the reason in `warnings[]`. A lost notification must be
  visible, and must not redden a pipeline whose gates passed.

## Expected result

`src/cross-cutting/evidence/outcome_test.go`:
`TestAPartThatProducedNoResultFailsTheCombinedVerdict` combines
`{passed: true, outcome: ERROR, errors: [x]}` to `passed: false`, with a
failing suite under NONE and a lost card as the green controls.
`src/quality/legfold_test.go` holds `testLegPassed` at every threshold.
