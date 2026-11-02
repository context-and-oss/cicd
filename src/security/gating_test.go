package main

import "testing"

// `fail-on NONE` opts out of failing over findings. ScanSource/ScanImage/ScanWeb
// used to compute passed without consulting the threshold, so any finding
// flipped passed=false even at NONE and the PR comment rendered "❌ Failed" over
// a gate the user had opted out of.
//
// Mirrors quality/gating_test.go.
func TestGatedPassed_noneSuppressesTheSeverityVerdict(t *testing.T) {
	if !gatedPassed(true, false, SeverityNone) {
		t.Fatalf("threshold NONE must report passed=true when the scanners ran and found something")
	}
	if !gatedPassed(true, true, SeverityNone) {
		t.Fatalf("threshold NONE with a clean report must still report true")
	}
}

// The other half, and the reason gatedPassed takes two signals. NONE used to be
// checked first and return true unconditionally, so a Semgrep that could not
// build a config, a Trivy that could not reach its database, or a ZAP that never
// started reported passed=true with the cause sitting unread in errors[]. That
// makes "nothing to find" and "nothing was looked at" the same verdict, which is
// exactly what semgrepRunError and friends exist to prevent. A non-run is not a
// finding and no threshold may suppress it.
func TestGatedPassed_nonRunFailsAtEveryThreshold(t *testing.T) {
	for _, threshold := range []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone,
	} {
		if gatedPassed(false, true, threshold) {
			t.Errorf("ran=false must fail at threshold %s even with an empty report", threshold)
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
