package main

import "testing"

func TestByoTestSourceReportsTheLegNotTheCommand(t *testing.T) {
	row := byoTestSource("unit", true, true, nil, nil, []string{"w"})
	if row.Tool != "byo-test" || row.Scope != "unit" || row.Concern != ConcernTests {
		t.Fatalf("row = %+v, want byo-test row scoped to the leg label under tests", row)
	}
	if !row.Passed || row.Outcome != OutcomeClean || row.WarningsCount != 1 || row.ErrorsCount != 0 {
		t.Errorf("green leg = %+v, want passed CLEAN with its warning counted", row)
	}

	row = byoTestSource("unit", true, false, nil, nil, nil)
	if row.Passed || row.Outcome != OutcomeFailed {
		t.Errorf("failing command = %+v, want FAILED, not passed", row)
	}

	row = byoTestSource("unit", false, false, nil, []string{"container did not start"}, nil)
	if row.Passed || row.Outcome != OutcomeError || row.ErrorsCount != 1 {
		t.Errorf("non-run = %+v, want ERROR with the error counted", row)
	}
}

func TestByoTestSourceCarriesTestDenominator(t *testing.T) {
	// Synthetic mixed-status counts: 3200 + 3 + 21 = 3224 tests.
	counts := &TestCounts{Total: 3224, Passed: 3200, Failed: 3, Skipped: 21}
	row := byoTestSource("all", true, false, counts, []string{"test command failed (exit 1)"}, nil)
	if row.Examined == nil || row.Examined.Unit != "tests" || row.Examined.Count != 3224 {
		t.Fatalf("Examined = %+v, want 3224 tests", row.Examined)
	}
	if row.Outcome != OutcomeFailed {
		t.Fatalf("Outcome = %q, want FAILED from the runner's own failed-test count", row.Outcome)
	}
}

func TestByoCoverageSourceFollowsTheRatchet(t *testing.T) {
	// Synthetic coverable-line denominator, shared by the ratchet cases.
	lines := 6400
	row := byoCoverageSource(ratchetOutcome{Verdict: ratchetPass}, &lines)
	if row.Concern != ConcernCoverage || !row.Passed || row.Outcome != OutcomeClean {
		t.Fatalf("passing ratchet = %+v, want passed CLEAN under coverage", row)
	}
	if row.Examined == nil || row.Examined.Unit != "coverable lines" || row.Examined.Count != 6400 {
		t.Errorf("examined = %+v, want the coverable-line denominator", row.Examined)
	}

	row = byoCoverageSource(ratchetOutcome{Verdict: ratchetSkipNoBaseline, Warnings: []string{"seeds"}}, &lines)
	if !row.Passed || row.Outcome != OutcomeClean || row.WarningsCount != 1 {
		t.Errorf("no baseline = %+v, want CLEAN: the figure was measured, only the comparison was skipped", row)
	}

	row = byoCoverageSource(ratchetOutcome{Verdict: ratchetFail, Errors: []string{"fell below"}}, &lines)
	if row.Passed || row.Outcome != OutcomeFailed || row.ErrorsCount != 1 {
		t.Errorf("regression = %+v, want FAILED with the violation counted", row)
	}

	row = byoCoverageSource(ratchetOutcome{Verdict: ratchetSkipNoCoverage, Warnings: []string{"no report"}}, nil)
	if !row.Passed || row.Outcome != OutcomeSkipped || row.Examined != nil || row.WarningsCount != 1 {
		t.Errorf("no coverage = %+v, want SKIPPED with no denominator and the skip counted", row)
	}
}
