# Intent: a policy engine that did not run must not be reported as a policy violation

## Why

`src/risk/opa.go` handled a conftest that could not start like this:

```go
out, err := ctr.WithExec(execArgs).Stdout(ctx)
if err != nil {
	allViolations = append(allViolations, reportViol{
		Msg: fmt.Sprintf("  - conftest exec failed: %v", err), Severity: string(SeverityHigh)})
	bySeverity[SeverityHigh]++
	continue
}
```

and computed its verdict as `passed := !shouldFail(bySeverity, threshold)`.

Three defects compounding into one:

**A non-run was laundered into a finding.** The evidence reported a HIGH *policy
violation* — with a severity, counted in `findingsCount`, rendered in the PR comment
alongside real violations — when no policy had produced anything. A consumer reading
that envelope, or a dashboard counting it, learns the opposite of the truth: the
policy engine's silence is recorded as its verdict.

**`--fail-on NONE` then suppressed it.** Because the verdict was the severity check
alone, a synthetic HIGH at threshold NONE returned `passed=true`. So the failure mode
was: policy engine never ran → invented a violation → suppressed the invented
violation → reported clean. This is the exact defect `gatedPassed` was introduced for
in `src/quality` (`none-suppresses-findings-not-nonruns.md`); `src/risk` never got it.

**Unparseable output was laundered the same way.** `parseConftestViolations` returned
`[{Msg: "  - Failed to parse conftest JSON output", Severity: "high"}]` for anything
it could not decode — including empty stdout. Same shape, same suppression, and it
applied to both passes.

The asymmetry inside one function is what makes this hard to defend as intentional:
**pass 1** (the findings/decisions gate) returns a hard Go error for an identical
conftest exec failure, at `opa.go:127`. Same tool, same failure, two treatments,
twenty lines apart.

## What changed

- **`ran` is tracked separately from the violation counts**, and the verdict is
  `gatedPassed(ran, !shouldFail(bySeverity, threshold), threshold)` — a verbatim copy
  of `src/quality/gating.go`, because Dagger modules are isolated and the rule is one
  sentence. `ran=false` fails at every threshold, NONE included.
- **A conftest that could not run lands in `errors[]`, not in the violations.**
  `findingsCount` counts findings again, and the envelope carries the cause.
- **`parseConftestViolations` returns `([]ParsedViolation, error)`.** No synthetic
  violation is ever fabricated. Empty stdout is separated from a decode failure,
  because conftest `--output json` always writes a document, so nothing at all means
  the tool produced no output and the remedy differs.
- **The message names the cause.** `err.Error()` alone renders as
  `exit code: 1` — measured, and useless. `execStderr` unwraps `*dagger.ExecError` so
  the entry carries `exec: "conftest": executable file not found in $PATH`, bounded to
  400 bytes with newlines collapsed (a raw newline silently truncates a markdown list
  item, which is how this evidence is rendered). Each entry names its parser and
  namespace, and says outright that the line is *not a policy verdict* — a reader who
  has seen the old evidence would otherwise read it as one.
- **Pass 1's hard Go error stays a hard Go error.** It fails before there is anything
  to put in an envelope; the pass-2 group loop can still emit evidence saying exactly
  what broke, so there it is evidence plus a failed gate. That is the line: a failure
  that can be reported as evidence is; one that cannot stays an error.

## Proof

Unit tests cover the classification and the gating. Behaviour was then measured with
real `dagger call validate` runs, including one that forces the exec failure by
pointing `conftestImage` at an image with no conftest binary:

| Run | Result |
| --- | --- |
| `testdata/go-app`, real conftest, `--fail-on NONE` | `passed=true`, 0 findings, 4 infra files scanned, no `errors[]` — unchanged from before |
| `testdata/go-app` with a `FROM alpine:latest` / no-`USER` Dockerfile, `--fail-on HIGH` | `passed=false`, 2 findings (`DOCKER-001` HIGH, `DOCKER-002` MEDIUM) — the policy leg genuinely evaluates |
| conftest image swapped for one without the binary, `--fail-on NONE` | **`passed=false`**, **0 findings**, two `errors[]` entries naming parser, namespace and `exec: "conftest": executable file not found in $PATH` |

The third row is the fix. Before: `passed=true` with two fabricated violations
(one per file group) at the same threshold.

## Decisions

**`errors[]` and a failed gate, rather than a hard Go error, for pass 2.** A hard
error is louder but produces no envelope, so nothing records what happened — and this
module's whole contract is evidence. The chosen shape keeps the audit trail and still
cannot be forgiven by a threshold. The cost is that `dagger call validate` still exits
0, so a caller that ignores `passed` sees nothing; that is a pre-existing property of
every module here, not something this change introduces.

**Version reporting is left wrong on purpose, and recorded below.** Fixing it in the
same change would mean either an extra container exec per group or a wire-format
change to `tool.version`, and neither belongs in a gating fix.

## Known residue

**`Tool.Version` is the hardcoded string `"conftest:v0.58.0"`.** It describes the pin,
not what ran — the same defect the .NET leg had (`prove-the-dotnet-legs-ran.md`) and
the Go lint leg had (`prove-the-go-lint-leg-ran.md`). If the image is ever repointed,
or a future run resolves a different binary, the evidence will confidently name the
wrong version. Fixing it means probing `conftest --version` inside the container and
reporting `unknown` when it cannot be read, plus a decision about what to report when
*no* container ran at all (a repo with no infra files) — currently there is no
observation to report and `unknown` would be the honest answer.

**A repository with no risk files still passes with a warning.** `errNoRiskFiles`
records "no risk files found — run … scan to initialise" and pass 1 is skipped
entirely, so the findings-review half of this gate reports clean on a repository that
has never been scanned. That is documented intent (`src/risk/CLAUDE.md`), and changing
it would fail every consumer who has not adopted `risk.Scan` — but it is the same
"could not run reads as clean" shape, and the honest fix is the *skipped* concept the
evidence schema still does not have (see `lint-what-the-consumer-configured.md`).

**`src/risk/scanner.go` has pre-existing gofmt drift**, untouched here because CI's
`make lint` only covers `src/internal` and mixing a formatting sweep into a gating fix
obscures both. It is real, and it is one of the 33 findings the Go lint blind spot in
`prove-the-go-lint-leg-ran.md` describes.
