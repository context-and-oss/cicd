package main

import (
	"testing"
	"time"
)

// TestParseFailOn covers both the intent gate's native vocabulary
// (error|warn|never) and the standard workflow severity vocabulary
// (NONE|LOW|MEDIUM|HIGH|CRITICAL) that every other gate accepts. An
// unrecognized or empty value must still gate at HIGH so a typo never
// silently passes.
func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in   string
		want Severity
	}{
		// Native vocabulary.
		{"error", SeverityHigh},
		{"warn", SeverityMedium},
		{"never", SeverityNone},
		// Standard workflow vocabulary.
		{"none", SeverityNone},
		{"NONE", SeverityNone},
		{"low", SeverityLow},
		{"LOW", SeverityLow},
		{"medium", SeverityMedium},
		{"MEDIUM", SeverityMedium},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"critical", SeverityHigh},
		{"CRITICAL", SeverityHigh},
		// Surrounding whitespace is tolerated.
		{"  none  ", SeverityNone},
		// Unrecognized / empty values must still gate at HIGH.
		{"", SeverityHigh},
		{"bogus", SeverityHigh},
	}
	for _, tt := range tests {
		if got := parseFailOn(tt.in); got != tt.want {
			t.Errorf("parseFailOn(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestParseFailOnGateOutcome proves the passed flag responds to the threshold
// while the finding is always recorded: fail-on NONE keeps an error-severity
// (HIGH) finding report-only (passed true), and the default HIGH still gates
// (passed false) — preserving today's behavior.
func TestParseFailOnGateOutcome(t *testing.T) {
	highFinding := []IntentFinding{{
		Rule:     "presence",
		Severity: RuleSeverityError, // maps to SeverityHigh
		Message:  "no intent artifact for this change",
	}}

	t.Run("NONE suppresses the gate but still records the finding", func(t *testing.T) {
		env := buildEnvelope("sha", "main", "https://example.com", highFinding, "NONE", time.Second)
		if !env.Passed {
			t.Errorf("passed = false, want true when fail-on is NONE")
		}
		if got := env.FindingsBySeverity[SeverityHigh]; got != 1 {
			t.Errorf("findingsBySeverity[HIGH] = %d, want 1 (finding must still be recorded)", got)
		}
	})

	t.Run("default HIGH still gates on an error-severity finding", func(t *testing.T) {
		env := buildEnvelope("sha", "main", "https://example.com", highFinding, "HIGH", time.Second)
		if env.Passed {
			t.Errorf("passed = true, want false at default fail-on HIGH")
		}
		if got := env.FindingsBySeverity[SeverityHigh]; got != 1 {
			t.Errorf("findingsBySeverity[HIGH] = %d, want 1", got)
		}
	})
}
