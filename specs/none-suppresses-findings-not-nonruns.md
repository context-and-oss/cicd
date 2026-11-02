# NONE suppresses findings, not non-runs

## Intent

Every scanner and linter in this repository classifies its own exit status so a
tool that could not run is recorded as a failure rather than as zero findings.
`gatedPassed` then discarded that work. It checked the threshold first and
returned true unconditionally for `NONE`, so the verdict a consumer reads —
`passed` — could not distinguish a clean tree from a tool that examined nothing.
The cause was written into `errors[]` and nothing looked at it: the reusable
workflows' gate step keys on `passed`, and when it does trip it printed
`findings` only, which a non-run leaves empty.

That put the false pass back one layer above the classification built to prevent
it, and it landed on the worst possible setting. `NONE` is what a team is told to
use for a first rollout, in `docs/how-to-guides/use-complete-pipeline.md` and in
`cicd-prepush`'s advisory mode — precisely when nobody yet knows what a working
run looks like, so a scanner that never started is indistinguishable from a
repository with nothing to find. Every non-run this repository has already paid
for was reachable this way: Semgrep unable to build a config under
`--metrics=off`, Trivy dropping vulnerability scanning without `--scanners vuln`,
ESLint unresolvable outside a package root, `dotnet format` exiting 145 on an SDK
band mismatch, `dotnet test` producing no `.trx`.

## Chosen approach

`gatedPassed` takes the two signals separately, in both copies
(`src/quality/gating.go`, `src/security/gating.go`):

```go
func gatedPassed(ran, severityOK bool, threshold Severity) bool {
	if !ran {
		return false
	}
	if threshold == SeverityNone {
		return true
	}
	return severityOK
}
```

`ran=false` fails at every threshold. `severityOK` carries the findings verdict
and is the only thing `NONE` suppresses.

Splitting the signal at each call site is the actual work, because the two were
conflated differently in each leg:

- The lint legs and `dotnet format` collect **only** non-run causes in `errs` —
  findings live in `bySeverity` — so `len(errs) == 0` is the ran verdict directly.
- `runGoTest`, `runVitest`, `runPytest` and `quality.Test` conflated them in one
  expression: a Dagger error means the exit sentinel never came out and there is
  no result, whereas a non-zero exit *is* a result. `ran` is now the first term
  alone.
- `runDotnetTest` mixes both classes in one `errs` slice, so
  `dotnetTestResult.ran` carries the verdict explicitly: false for an unreadable
  exit status, an unparseable `.trx` or any `dotnetTestRunError`, and true when
  the tests merely failed.
- `Check`'s aggregate needs its own `allRan`, because `lintEnv.Passed` and
  `testEnv.Passed` already have the threshold applied — under `NONE` a leg with
  findings and a leg that never executed both arrive as passed. `lintLanguage`
  and `testLanguage` therefore return `(*envelope, bool, error)`. The verdict
  travels beside the envelope rather than inside it because `schema.go` is a
  verbatim copy shared across every module, and widening the wire format is a
  change worth making on its own terms, not as a side effect of a gate fix.
- The coverage gate's "no coverage was measured" case is a gate that could not
  run, not a threshold verdict, so it clears `allRan` too.

Two consumers of the old behaviour had to change with it, and both were asserting
the defect:

- `src/security/archive_test.go` contained a subtest named "tool error with
  failOn NONE still passes". It is now "scanner error fails even at NONE".
- `.github/workflows/ci.yml`'s `scan-web` cell asserted `passed == True` up front
  and separately tolerated an unreachable target as an expected outcome, so it
  relied on `NONE` to paper over a DAST scan that never reached the host. The
  assertion moved into the branches: `passed` must be false when the target was
  unreachable and true when ZAP produced a report.

The reusable workflows' gate step now prints `errors[]` alongside `findings`.
Without that, this change would turn a non-run into a red gate annotated with
nothing at all, since a non-run produces no findings to list.

## Expected result

A `NONE` run reporting `passed: true` means the pipeline did the work and the
consumer chose not to gate on what it found. A `NONE` run reporting
`passed: false` means part of the pipeline could not do the work, and the gate
step names which part. Findings-based gating at `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`
is unchanged: for every one of those thresholds `gatedPassed` returns the
severity verdict exactly as before, which `gating_test.go` pins in both modules
alongside a case proving a non-run fails at all five thresholds including `NONE`.
