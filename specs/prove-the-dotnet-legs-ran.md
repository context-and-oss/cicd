# Prove the .NET legs ran

## Intent

Both tools the .NET legs invoke exit 0 on work they never performed, and neither
leg distinguished that from a clean tree. Measured against the pinned SDK image:
`dotnet format` returns 1 on a restore failure and 145 when `global.json` names
an absent SDK band, and the leg mapped both onto the clean-run output through
`|| true` plus an `|| echo '[]'` fallback. `dotnet test`, invoked at the source
root, resolves the single project in the working directory without recursing, so
a repository whose root project carries no test reference ran zero tests and
still exited 0. Coverage was never collected at all, because
`--collect:"XPlat Code Coverage"` word-splits inside a `sh -c` body into three
arguments and the collector name degrades to `XPlat`. On top of that the
coverage gate in `src/quality/main.go` skipped a language whose figure was
absent, so `--min-coverage` could not fail for .NET under any input. Four
separate ways to read as verified without verifying anything.

## Chosen approach

Each .NET leg now has to demonstrate that it executed, and a leg that cannot
demonstrate it fails the gate.

- `src/quality/dotnetreport.go` holds the classification: only exit 0 and exit 2
  count as a `dotnet format` run, and a run must have left a non-empty report,
  since a clean run writes `[]` rather than nothing. Test targets are resolved
  explicitly and a project without a test reference is never handed to
  `dotnet test`; a run must produce a parseable `.trx` accounting for at least
  one executed test. `IsTestProject` is matched as `IsTestProject>` followed by
  `true`, because as a bare substring it also matched a project that had
  explicitly opted out.
- `src/quality/dotnetexec.go` performs target discovery in the Alpine image
  instead of the SDK image, given that a question about which files exist must
  not depend on the SDK being usable, and reads the SDK version out of the
  container so the envelope describes the toolchain that ran rather than the
  compile-time pin.
- `src/quality/lint.go` runs `dotnet format` against a solution when exactly one
  is present and otherwise against every project individually, because pointing
  the tool at a directory loads only that directory's project and leaves nested
  sources unchecked.
- `src/quality/test.go` quotes the collector argument as one token, enumerates
  every cobertura report rather than stopping at the first, and collapses
  byte-identical duplicates, since the collector writes its report twice per run.
- `src/quality/main.go` treats a missing coverage figure as an error instead of
  skipping it. `--lint-only` stays exempt because it deliberately never runs the
  test leg.
- `testdata/dotnet-app/tests/dotnet-app.Tests.csproj` gains `coverlet.collector`,
  without which the collector cannot be found and `dotnet test` reports success
  anyway, so the coverage path was not provable from the fixture.

The classification and parsing live in untagged Go so
`src/quality/dotnetreport_test.go` can drive them without a Dagger session, and
`.github/workflows/ci.yml` now asserts on the evidence rather than on the exit
code: `check` returns a file, therefore a false verdict never failed the cell.

## Expected result

A .NET tool that did not run yields `passed=false` with the cause in `errors[]`.
The fixture reports measured coverage where it previously reported none, and a
`--min-coverage` floor above that figure fails. A repository with no test project
is rejected by name instead of being recorded as tested. CI asserts the reported
SDK version has the shape of an observed version, that coverage is above zero,
and that a warning names the test project that executed, so each of the four
observed failures has a cell that fails when it returns. Existing consumers of
the other three languages keep passing, verified by running the coverage gate
against the Go, Node and Python fixtures.
