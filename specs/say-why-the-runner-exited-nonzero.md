# Say why the runner exited non-zero

## Why

One consumer's run, as the evidence reported it:

```json
"testsByLanguage": { "dotnet": { "total": N, "passed": N, "failed": 0, "skipped": 0 } }
"errors": [ "test dotnet: Consumer.slnx: dotnet test failed (exit 1)" ]
```

About a hundred tests, all passing, a `.trx` parsed, coverage measured — and exit 1. The
entire explanation cicd offered was `(exit 1)`.

The cause was not missing. `test.go` runs

```sh
dotnet test "$TARGET" "$@" > /tmp/dotnet-test.out 2>&1
echo $? > /tmp/dotnet-test.exit
```

and reads both files back. The output was in memory, in a variable named `out`,
at the moment the message was written.

It was dropped because of which branch fires. `dotnetTestRunError` calls
`dotnetDiagnosticLine(out)` on every arm that classifies a non-run — no `.trx`,
an unreadable exit status, a refused MTP target, a zero-test report. This run
hits none of them: a `.trx` exists, it parses, and it reports `total > 0`. So the
function returns `""` through its default arm, correctly, and the only remaining
line was:

```go
res.errs = append(res.errs, "dotnet test failed (exit "+code+")")
```

which has never looked at `out` at all.

That is this repository's own failure class, in its cheapest form: a pipeline
built to refuse silent signals shipped a verdict with the explanation still in a
local variable. `testOutcome` already classifies this run `ERROR` rather than
`FAILED` — the *what* has been right since evidence schema 1.2.0. The *why* was
one branch away and never taken.

## What changed

`dotnetTestExitFailure` replaces the bare string. It appends the diagnostic
line, and only in the case that needs it:

| exit | `dotnetTestRunError` | accounting | message |
|---|---|---|---|
| non-zero | classified a non-run | — | unchanged; the diagnostic is already in that message |
| non-zero | `""` | `Failed > 0` | unchanged; a failing suite explains itself |
| non-zero | `""` | `Failed == 0` | **+ "every test reported passing … last diagnostic: `<line>`"** |
| non-zero | `""` | no readable `.trx` | as above — nothing has been reconciled, so nothing is excused |

Two absences are kept distinct, both deliberately:

- **A classified non-run is not explained twice.** `dotnetDiagnosticLine` is
  already inside that message; appending it again would read as two findings
  where there is one.
- **A genuinely failing suite is left alone.** `Failed > 0` and a non-zero exit
  agree with each other. Attaching cicd's guesswork there would bury the real
  result under a hint about something that is not wrong.

`parsed > 0` — not `sum.Failed == 0` — is what proves the accounting is an
accounting. An unparsed `.trx` sums to `Failed: 0`, which must never be read as
"no test failed", so a run with no readable results takes the explained branch
rather than the excused one.

The message is never empty and never silently equivalent to the old string. A
non-zero exit with a green suite and *no output at all* says exactly that,
because "cicd had nothing to add" and "the runner said nothing" are different
facts and only one of them is about cicd.

`dotnetreport.go` is untagged, so the decision is reachable under
`-tags unit_test`. The same reason `coverageglob.go` keeps its decisions out of
the Dagger entrypoint, and the same reason the last two bugs in this area were
unreachable by a test until they were moved.

## What this does not do

**It does not say what actually went wrong on that run.** Nobody knows yet,
because the output has never been printed. The standing hypothesis — a solution
of some twenty projects, VSTest exiting 1 on `No test is available in <assembly>.dll`
while the assemblies that do carry tests run all green — is a hypothesis. The
point of this change is that the next run answers the question instead of posing
it again.
