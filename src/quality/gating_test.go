package main

import (
	"reflect"
	"testing"
)

// `fail-on NONE` opts out of failing over findings. Test runners used to compute
//
//	passed := err == nil && exitCode == "0"
//
// without consulting the threshold, so a failing test flipped passed=false even
// when the caller asked for NONE, and the PR comment rendered "❌ Failed" over a
// gate the user had opted out of.
func TestGatedPassed_noneSuppressesTheSeverityVerdict(t *testing.T) {
	if !gatedPassed(true, false, SeverityNone) {
		t.Fatalf("threshold NONE must report passed=true when the tool ran and found problems")
	}
	if !gatedPassed(true, true, SeverityNone) {
		t.Fatalf("threshold NONE with a clean result must still report true")
	}
}

// The other half of the contract, and the reason gatedPassed takes two signals.
// NONE used to be checked first and return true unconditionally, so a linter or
// test runner that could not execute at all reported passed=true with the cause
// sitting unread in errors[] — "clean tree" and "tool never ran" became the same
// verdict, which is the failure class the run-error classification in
// eslintreport.go / dotnetreport.go exists to prevent. A non-run is not a
// finding and no threshold may suppress it.
func TestGatedPassed_nonRunFailsAtEveryThreshold(t *testing.T) {
	for _, threshold := range []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone,
	} {
		if gatedPassed(false, true, threshold) {
			t.Errorf("ran=false must fail at threshold %s even with a clean severity verdict", threshold)
		}
		if gatedPassed(false, false, threshold) {
			t.Errorf("ran=false must fail at threshold %s", threshold)
		}
	}
}

func TestGatedPassed_otherThresholdsPreserveTheSeverityVerdict(t *testing.T) {
	for _, threshold := range []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow,
	} {
		for _, severityOK := range []bool{true, false} {
			if got := gatedPassed(true, severityOK, threshold); got != severityOK {
				t.Errorf("gatedPassed(true, %v, %s) = %v, want %v",
					severityOK, threshold, got, severityOK)
			}
		}
	}
}

// Regression for Check's previous behaviour of silently dropping sub-envelope
// Errors[] when the per-language call returned no infra error — users saw
// passed=false with no breadcrumb pointing at which step actually failed.
func TestPrefixErrors_qualifiesEach(t *testing.T) {
	got := prefixErrors("lint go", []string{"eslint failed", "npm install failed"})
	want := []string{"lint go: eslint failed", "lint go: npm install failed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixErrors mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPrefixErrors_emptyInputReturnsNil(t *testing.T) {
	if got := prefixErrors("lint go", nil); got != nil {
		t.Fatalf("expected nil for empty input, got %#v", got)
	}
	if got := prefixErrors("lint go", []string{}); got != nil {
		t.Fatalf("expected nil for zero-length input, got %#v", got)
	}
}
