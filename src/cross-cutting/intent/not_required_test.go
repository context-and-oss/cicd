package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestNotRequiredEnvelopeIsDistinguishable is the whole point of the opt-in
// gate's evidence: a gate nobody asked to run produces the same zero findings
// as a gate that ran clean, so the envelope has to separate the two by itself.
// Both a human reading the rendered warnings and a machine reading
// genericReport must be able to tell which one they are looking at.
func TestNotRequiredEnvelopeIsDistinguishable(t *testing.T) {
	notRequired := buildNotRequiredEnvelope("sha", "main", "https://example.com", "error", time.Second)
	checked := buildEnvelope("sha", "main", "https://example.com", nil, "error", time.Second)

	// Neither fails the pipeline, and neither reports a finding — which is
	// exactly why the fields below have to carry the difference.
	for name, env := range map[string]*envelope{"not-required": notRequired, "checked-clean": checked} {
		if !env.Passed {
			t.Errorf("%s: passed = false, want true", name)
		}
		if env.FindingsCount != 0 {
			t.Errorf("%s: findingsCount = %d, want 0", name, env.FindingsCount)
		}
		if env.ModuleName != "intent" {
			t.Errorf("%s: moduleName = %q, want intent — the module must stay in the audit trail", name, env.ModuleName)
		}
	}

	// Human channel: the PR comment renders warnings verbatim.
	if len(notRequired.Warnings) != 1 || !strings.Contains(notRequired.Warnings[0], "NOT REQUIRED") {
		t.Errorf("not-required warnings = %v, want one warning naming the state", notRequired.Warnings)
	}
	if !strings.Contains(notRequired.Warnings[0], "--require-intent") {
		t.Errorf("not-required warning does not say how to turn the gate on: %q", notRequired.Warnings[0])
	}

	// Machine channel: genericReport.required.
	for name, env := range map[string]*envelope{"not-required": notRequired, "checked-clean": checked} {
		var report struct {
			Tool     string          `json:"tool"`
			Required *bool           `json:"required"`
			Findings []IntentFinding `json:"findings"`
		}
		if err := json.Unmarshal(env.GenericReport, &report); err != nil {
			t.Fatalf("%s: genericReport does not parse: %v", name, err)
		}
		if report.Tool != "intent-gate" {
			t.Errorf("%s: genericReport.tool = %q, want intent-gate", name, report.Tool)
		}
		if report.Required == nil {
			t.Fatalf("%s: genericReport omits `required` — the only machine-readable "+
				"signal separating a skipped gate from a clean one", name)
		}
		if want := name == "checked-clean"; *report.Required != want {
			t.Errorf("%s: genericReport.required = %v, want %v", name, *report.Required, want)
		}
		if len(report.Findings) != 0 {
			t.Errorf("%s: genericReport.findings = %v, want empty", name, report.Findings)
		}
	}
}

// The distinction this file's other test asserts for the payload, asserted for
// the field a consumer that knows nothing about intent-gate's format actually
// reads. An opt-in gate that is off produces exactly what a gate that passed
// produces — no findings — so both folded to CLEAN and a report rendered a
// green tick for a check that was never consulted.
func TestNotRequiredIsSkippedNotClean(t *testing.T) {
	notRequired := buildNotRequiredEnvelope("sha", "main", "https://example.com", "error", time.Second)
	checked := buildEnvelope("sha", "main", "https://example.com", nil, "error", time.Second)

	if notRequired.Outcome != OutcomeSkipped {
		t.Errorf("not-required outcome = %q, want %q", notRequired.Outcome, OutcomeSkipped)
	}
	if checked.Outcome != OutcomeClean {
		t.Errorf("checked-and-clean outcome = %q, want %q", checked.Outcome, OutcomeClean)
	}
	if notRequired.Outcome == checked.Outcome {
		t.Error("a gate that was never consulted and a gate that passed report the same outcome — the exact conflation this envelope exists to prevent")
	}
	if !notRequired.Passed {
		t.Error("passed must stay true: the gate is opt-in and this is not a gate change")
	}
}
