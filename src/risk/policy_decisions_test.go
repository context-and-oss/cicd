package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplyPolicyDecisionsExactOverrideSuppressesOnlyMatchingFinding(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	file := ".github/workflows/triage.yml"
	resource := "example-org/triage-action@v1"
	decisions := map[string]Decision{
		policyDecisionKey("PIPE-003", file, resource): validPolicyDecision(),
	}
	violations := []ParsedViolation{
		pipeViolation(file, resource),
		pipeViolation(file, "actions/checkout@v6"),
		pipeViolation(".github/workflows/other.yml", resource),
	}

	remaining, overridden := applyPolicyDecisions(violations, decisions, now)
	if len(overridden) != 1 {
		t.Fatalf("expected 1 overridden violation, got %d: %#v", len(overridden), overridden)
	}
	if overridden[0].DecisionKey != policyDecisionKey("PIPE-003", file, resource) {
		t.Fatalf("override key = %q", overridden[0].DecisionKey)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining violations, got %d: %#v", len(remaining), remaining)
	}
	if remaining[0].Resource != "actions/checkout@v6" {
		t.Fatalf("changed resource was suppressed: %#v", remaining)
	}
	if remaining[1].Filename != ".github/workflows/other.yml" {
		t.Fatalf("same policy/resource in another file was suppressed: %#v", remaining)
	}
}

func TestApplyPolicyDecisionsInvalidOverrideDoesNotSuppress(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	file := ".github/workflows/triage.yml"
	resource := "example-org/triage-action@v1"
	key := policyDecisionKey("PIPE-003", file, resource)
	violation := pipeViolation(file, resource)

	cases := []struct {
		name     string
		decision Decision
	}{
		{"missing status", Decision{Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23"}},
		{"missing justification", Decision{Status: "accepted_risk", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23"}},
		{"missing reviewed_by", Decision{Status: "accepted_risk", Justification: "Internal action", ReviewedAt: "2026-06-23"}},
		{"missing reviewed_at", Decision{Status: "accepted_risk", Justification: "Internal action", ReviewedBy: "reviewer"}},
		{"invalid reviewed_at", Decision{Status: "accepted_risk", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "today"}},
		{"approved", Decision{Status: "approved", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23"}},
		{"needs_review", Decision{Status: "needs_review", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23"}},
		{"rejected", Decision{Status: "rejected", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23"}},
		{"expired", Decision{Status: "accepted_risk", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23", ExpiresAt: "2026-06-22"}},
		{"invalid expires_at", Decision{Status: "accepted_risk", Justification: "Internal action", ReviewedBy: "reviewer", ReviewedAt: "2026-06-23", ExpiresAt: "not-a-date"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remaining, overridden := applyPolicyDecisions([]ParsedViolation{violation}, map[string]Decision{key: tc.decision}, now)
			if len(overridden) != 0 {
				t.Fatalf("expected no override, got %#v", overridden)
			}
			if len(remaining) != 1 {
				t.Fatalf("expected violation to remain, got %#v", remaining)
			}
		})
	}
}

func TestApplyPolicyDecisionsDateOnlyExpiresAtIsValidThroughThatDate(t *testing.T) {
	now := time.Date(2026, 6, 23, 23, 59, 0, 0, time.UTC)
	file := ".github/workflows/triage.yml"
	resource := "example-org/triage-action@v1"
	key := policyDecisionKey("PIPE-003", file, resource)
	decision := validPolicyDecision()
	decision.ExpiresAt = "2026-06-23"

	remaining, overridden := applyPolicyDecisions([]ParsedViolation{pipeViolation(file, resource)}, map[string]Decision{key: decision}, now)
	if len(remaining) != 0 {
		t.Fatalf("expected date-only expires_at to remain valid through the date, got %#v", remaining)
	}
	if len(overridden) != 1 {
		t.Fatalf("expected one override, got %#v", overridden)
	}
}

func TestApplyPolicyDecisionsDoesNotTreatAIFindingDecisionAsPolicyOverride(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	var decisions map[string]Decision
	if err := json.Unmarshal([]byte(`{"abc123":{"status":"approved"}}`), &decisions); err != nil {
		t.Fatalf("unmarshal AI decisions: %v", err)
	}

	remaining, overridden := applyPolicyDecisions(
		[]ParsedViolation{pipeViolation(".github/workflows/triage.yml", "example-org/triage-action@v1")},
		decisions,
		now,
	)
	if len(overridden) != 0 {
		t.Fatalf("AI finding decision unexpectedly suppressed policy finding: %#v", overridden)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected policy finding to remain, got %#v", remaining)
	}
	if decisions["abc123"].Status != "approved" {
		t.Fatalf("AI decision status changed: %#v", decisions["abc123"])
	}
}

func TestApplyPolicyDecisionsIgnoresBroadPolicyKey(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	remaining, overridden := applyPolicyDecisions(
		[]ParsedViolation{pipeViolation(".github/workflows/triage.yml", "example-org/triage-action@v1")},
		map[string]Decision{"policy:PIPE-003": validPolicyDecision()},
		now,
	)
	if len(overridden) != 0 {
		t.Fatalf("broad policy key unexpectedly suppressed policy finding: %#v", overridden)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected policy finding to remain, got %#v", remaining)
	}
}

func TestResolveConftestFilenameMapsMountedInputToRepoPath(t *testing.T) {
	mounts := map[string]string{"/inputs/f0001": ".github/workflows/triage.yml"}
	got := resolveConftestFilename("/inputs/f0001", mounts)
	if got != ".github/workflows/triage.yml" {
		t.Fatalf("resolved filename = %q", got)
	}
}

func pipeViolation(file, resource string) ParsedViolation {
	return ParsedViolation{
		Msg:      "  - PIPE-003: Action \"" + resource + "\" is not pinned to a commit SHA",
		Severity: "medium",
		PolicyID: "PIPE-003",
		Filename: file,
		Resource: resource,
	}
}

func validPolicyDecision() Decision {
	return Decision{
		Status:        "accepted_risk",
		Justification: "Internal action owned by our org; v1 is the supported package channel.",
		ReviewedBy:    "reviewer",
		ReviewedAt:    "2026-06-23",
		ExpiresAt:     "2026-09-23",
	}
}
