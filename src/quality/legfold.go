// How a BYO leg's own errors and the aggregate fold read back into a verdict.
//
// Untagged (no //go:build !unit_test) for the reason gating.go gives: byotest.go
// carries the Dagger build tag, so a rule declared there is unreachable from the
// unit suite. gating.go itself holds only gatedPassed, byte-identical across
// three modules and guarded as such, which is why these quality-only helpers
// live here and not beside it.
package main

// prefixErrors qualifies each entry with a label so sub-envelope errors
// remain identifiable after being merged into the aggregate envelope
// (e.g., "lint go: eslint failed"). Returns nil for empty input.
func prefixErrors(prefix string, errs []string) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, prefix+": "+e)
	}
	return out
}

// byoLegOutcome is runOutcome plus the errors that happen after the exit code.
//
// A leg's exit status is settled the moment its command returns, and the
// coverage harvest runs afterwards — a glob that matched documents the parser
// could not read, a container file read that errored. Those append to Errors
// with Ran and Passed already true, and the caller folds them into allErrs,
// which fails the envelope. So the leg reported CLEAN inside an envelope its own
// errors had just failed: the gate blocking while the outcome says nothing
// happened. That is this field's whole failure mode running backwards, and it
// shipped in the change that introduced the field.
//
// Only a CLEAN is downgraded, the same rule skippedIfNothingExamined follows.
// A leg that genuinely failed its command stays FAILED even when the harvest
// errored too: the failing command is the actionable result and the harvest
// error is noise stacked on top of it.
//
// Plain values rather than the legOutcome it reads from: byotest.go carries the
// Dagger build tag, so a helper declared there cannot be reached by a unit test
// at all — the same reason coverageglob.go keeps its decisions out here.
func byoLegOutcome(ran, passed bool, errs []string) Outcome {
	o := runOutcome(ran, passed)
	if o == OutcomeClean && len(errs) > 0 {
		return OutcomeError
	}
	return o
}

// byoTestLegOutcome is byoLegOutcome with the runner's accounting available.
// Counts sharpen a non-zero exit the same way they do for native runners: a
// reported failed test is FAILED, while an exit that contradicts an all-green
// accounting is ERROR. Errors added after the command (coverage harvest, for
// example) still downgrade only an otherwise-clean result.
func byoTestLegOutcome(ran, passed bool, errs []string, counts *TestCounts) Outcome {
	o := testOutcome(ran, passed, counts)
	if o == OutcomeClean && len(errs) > 0 {
		return OutcomeError
	}
	return o
}

// anyLegErrored reports whether some leg's outcome says it produced no usable
// result. The schema defines ERROR as "the ran=false of gatedPassed", and
// testOutcome reaches it with ran still true: a runner that exits non-zero
// while its own accounting says no test failed (pytest's exit 5, no tests
// collected; a .NET host that crashed after a green suite). Folding only the
// ran flags passed that leg at `--fail-on NONE`, measured end to end as
// passed:true beside outcome:ERROR, so both folds take the outcomes into the
// non-run half of the verdict as well.
func anyLegErrored(outcomes []Outcome) bool {
	for _, o := range outcomes {
		if o == OutcomeError {
			return true
		}
	}
	return false
}

// testLegPassed is the verdict of one native test leg, and it takes the
// leg's outcome into the non-run half for the reason anyLegErrored gives: a
// runner that exits non-zero while its own accounting says nothing failed
// reaches OutcomeError with ran still true, and gatedPassed(ran, false, NONE)
// would pass it. The leg's own envelope said passed:true beside ERROR, and a
// consumer who read the parts rather than the Check roll-up saw a green leg
// that had produced no result.
func testLegPassed(ran, subjectPassed bool, counts *TestCounts, threshold Severity) bool {
	return gatedPassed(ran && testOutcome(ran, subjectPassed, counts) != OutcomeError, subjectPassed, threshold)
}
