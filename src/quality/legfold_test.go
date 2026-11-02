package main

import "testing"

// A native leg whose runner exited non-zero with its own accounting green is
// ERROR, and its envelope must not say passed beside that at any threshold,
// --fail-on NONE included. A real failing suite stays a failure NONE suppresses.
func TestTestLegPassedFoldsAnErroredLegIntoTheNonRunHalf(t *testing.T) {
	green := &TestCounts{Total: 100, Passed: 100}
	red := &TestCounts{Total: 100, Passed: 97, Failed: 3}
	for _, th := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone} {
		if testLegPassed(true, false, green, th) {
			t.Errorf("exit non-zero, 100/100 green: passed at --fail-on %s", th)
		}
		if testLegPassed(false, false, nil, th) {
			t.Errorf("did not run: passed at --fail-on %s", th)
		}
		if !testLegPassed(true, true, green, th) {
			t.Errorf("control: a green leg failed at --fail-on %s", th)
		}
	}
	if !testLegPassed(true, false, red, SeverityNone) {
		t.Error("a failing suite must stay a failure --fail-on NONE suppresses")
	}
	if testLegPassed(true, false, red, SeverityHigh) {
		t.Error("a failing suite passed at --fail-on HIGH")
	}
}
