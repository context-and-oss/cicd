package main

import "testing"

// The verdict this module used to compute was `!shouldFail(bySeverity, threshold)`
// and nothing else, so `--fail-on NONE` returned true unconditionally. A conftest
// that could not start therefore reported passed=true — and on the way there it
// was counted as a HIGH policy violation, so the evidence also claimed a policy
// failure no policy had produced. A non-run is not a finding and no threshold may
// suppress it.
func TestGatedPassed_nonRunFailsAtEveryThreshold(t *testing.T) {
	for _, threshold := range []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone,
	} {
		if gatedPassed(false, true, threshold) {
			t.Errorf("ran=false must fail at threshold %s even with a clean violation verdict", threshold)
		}
		if gatedPassed(false, false, threshold) {
			t.Errorf("ran=false must fail at threshold %s", threshold)
		}
	}
}

// The other half: NONE still means "collect violations, do not fail me over
// them". That behaviour is the documented migration path and must not change.
func TestGatedPassed_noneSuppressesTheViolationVerdictOnly(t *testing.T) {
	if !gatedPassed(true, false, SeverityNone) {
		t.Fatal("NONE must report passed=true when conftest ran and found violations")
	}
	if !gatedPassed(true, true, SeverityNone) {
		t.Fatal("NONE with a clean result must still report true")
	}
}

// A real threshold still gates on severity when the engine ran.
func TestGatedPassed_ranDefersToSeverity(t *testing.T) {
	if gatedPassed(true, false, SeverityHigh) {
		t.Fatal("a HIGH threshold with violations at or above it must fail")
	}
	if !gatedPassed(true, true, SeverityHigh) {
		t.Fatal("a HIGH threshold with a clean verdict must pass")
	}
}

// A policy engine with nothing in scope has not cleared the repository. On this
// repository's own shadow run, risk reported infraFilesScanned:0, zero
// violations and passed:true, so scanOutcome called it CLEAN and a report would
// have shown a green tick beside "no risk files found".
func TestAnEvaluationOverNothingIsNotClean(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       Outcome
		ran      bool
		examined int
		want     Outcome
	}{
		{"clean over nothing", OutcomeClean, true, 0, OutcomeSkipped},
		{"clean over real files stays clean", OutcomeClean, true, 12, OutcomeClean},
		// A tool that produced any other result plainly examined something,
		// so nothing below CLEAN is second-guessed by a file count.
		{"findings are never downgraded", OutcomeFindings, true, 0, OutcomeFindings},
		{"failures are never downgraded", OutcomeFailed, true, 0, OutcomeFailed},
		{"an error is not a skip", OutcomeError, false, 0, OutcomeError},
		{"unset stays unset", "", true, 0, ""},
	} {
		if got := skippedIfNothingExamined(tc.in, tc.ran, tc.examined); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
