package main

// Per-tool verdicts for the BYO test envelope in repository mode.
//
// Test used to declare rows only in application mode. In repository mode the
// envelope shipped with no sources[] at all, so cross-cutting/evidence
// synthesised one row from the envelope — and the envelope names no concern,
// because one envelope answers two questions (tests and coverage) and cannot
// name both. The row landed in concerns/unclassified.json, and every consumer
// reading the bundle by concern saw "tests: not answered" and "coverage: not
// answered" about a run that had just reported 90% coverage over a green
// suite. The same shape legSource fixed for the native runners.

// byoTestSource is the row for one leg's command.
//
// The tool is byo-test rather than the label: cicd did not choose the command
// and cannot say what runner it was. The label goes in Scope, the axis that
// tells two legs apart — labels are unique per run (see parseTestLegs) where
// languages are not.
//
// ran and passed are legOutcome's two verdicts, taken apart for the reason
// that type keeps them apart: a container that never ran is an ERROR no
// threshold forgives. When counts are present they distinguish a failed test
// from a runner error whose exit status contradicts an all-green accounting.
func byoTestSource(label string, ran, passed bool, counts *TestCounts, errs, warnings []string) SourceStatus {
	row := SourceStatus{
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          "byo-test",
		Scope:         label,
		Concern:       ConcernTests,
		Passed:        ran && passed,
		Outcome:       byoTestLegOutcome(ran, passed, errs, counts),
		ErrorsCount:   len(errs),
		WarningsCount: len(warnings),
	}
	if counts != nil {
		row.Examined = &Examined{Unit: "tests", Count: counts.Total}
	}
	return row
}

// byoCoverageSource is the one coverage row for the run.
//
// One row rather than one per leg, because the verdict is one: the ratchet
// (ADR-003) judges the merged figure against the baseline, and the envelope's
// Passed carries that judgement once. A per-leg split would put a CLEAN on
// every row of a run the ratchet failed, and the rows' AND would no longer be
// the envelope's verdict.
//
// No coverage at all is SKIPPED, not ERROR, matching coverageSource and the
// ratchet's own fail-open rule: a declared report that was not written is a
// warning in this module, and a row that called it an error would fail a
// concern the envelope passes. The ratchet warning is counted on the row so a
// reader sees the skip was said, not silent.
func byoCoverageSource(ratchet ratchetOutcome, lines *int) SourceStatus {
	row := SourceStatus{
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          "coverage",
		Scope:         "byo-test",
		Concern:       ConcernCoverage,
		Passed:        true,
		Outcome:       OutcomeClean,
		ErrorsCount:   len(ratchet.Errors),
		WarningsCount: len(ratchet.Warnings),
	}
	if lines != nil {
		// The denominator the percentage needs; see coverageSource.
		row.Examined = &Examined{Unit: "coverable lines", Count: *lines}
	}
	switch ratchet.Verdict {
	case ratchetSkipNoCoverage:
		row.Outcome = OutcomeSkipped
	case ratchetFail:
		// A measured figure that came out wrong, the same class as a failing
		// leg — the fold in Test uses FAILED for it too.
		row.Passed = false
		row.Outcome = OutcomeFailed
	}
	return row
}
