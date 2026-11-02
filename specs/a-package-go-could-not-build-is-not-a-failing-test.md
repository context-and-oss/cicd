# A package go could not build is not a failing test

## Intent

`go test` exits 1 for three different things: a test that failed, a package it
could not compile or set up, and a go command that stopped before reaching any
package (a toolchain it could not download, a `go.mod` it could not parse).
`foldTestLeg` read every one as `go test failed (exit 1)`, a failing suite, which
`--fail-on NONE` passes. Measured with go1.26.3 over a three-package module:

```
FAIL	ex/b	0.185s
FAIL	ex/c [build failed]
```

with `ex/b` holding a real failing test. The leg reported FAILED, NONE passed
it, and the evidence never said `ex/c` was not tested at all. The failing test
hid the build error. A toolchain that could not be fetched printed two `go:`
lines, no package verdict, and read the same way.

## Chosen approach

`goTestNonRun` (`src/quality/testlegrun.go`) runs after `foldTestLeg` on a
non-zero exit:

- Any `FAIL\t<pkg> [build failed]` or `[setup failed]` line makes the leg a
  non-run that names the packages (sorted, deduplicated, first ten by name with
  the rest counted). Measured: a syntax error, an unused variable in a `_test.go`,
  a vet printf error and a missing import all print that line, so the `# <pkg>`
  compile blocks are not parsed separately.
- The counts from the packages that did build are quoted in the reason and
  withheld from `tests`: a count beside the word total would claim the whole
  suite.
- Native leg only: a non-zero exit with no package verdict and no `=== RUN`
  line is `go test: did not run (exit N)`, quoting a bounded, credential-scrubbed
  tail of the output. cicd chose `go test -v`, so a verdict line is guaranteed
  whenever anything ran.
- The BYO Go leg applies the build-verdict rule only. A caller's command may
  print gotestsum's format or a Makefile's, so a missing package line there
  proves nothing, and treating it as a non-run would fail a real failing suite at
  NONE.

## Rejected

- **Keep the partial counts in `tests`.** The aggregate would publish them as
  the language's total.
- **Parse `# <pkg>` headers too.** Every measured case already prints the
  verdict line; a second parser for the same fact is one that can disagree.
- **Switch to `go test -json`.** It reports `"Action":"build-fail"` cleanly, but
  it is a different invocation with its own uncountable-run failure mode; see
  the comment above `goRunLine` in `testcounts.go`.

## Expected result

`src/quality/nonrun_matrix_test.go`: build failed beside a failing test, setup
failed, build failed alone and a toolchain download failure each fail at every
threshold with no exit code; a failing suite stays `go test failed (exit 1)`, a
gotestsum-shaped BYO failure stays a failure, and disabling the rule turns the
matrix red. `scripts/smoke/non-run-matrix.sh` copies `testdata/go-app`, adds a
package with a syntax error, and requires `passed: false` at NONE naming
`<module>/broken (build failed)`, beside `testdata/go-app` as the control.
