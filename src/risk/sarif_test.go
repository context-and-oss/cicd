package main

import (
	"encoding/json"
	"testing"
)

func TestBuildRiskSARIFCarriesPolicyIdentitySeverityAndLocation(t *testing.T) {
	raw, err := buildRiskSARIF([]reportViol{
		{Msg: "  - DOCKER-001: runs as root", Severity: "HIGH", PolicyID: "DOCKER-001", File: "Dockerfile"},
		{Msg: "  - PIPE-003: action is not pinned", Severity: "MEDIUM", PolicyID: "PIPE-003", File: ".github/workflows/ci.yml"},
		{Msg: "  - TAG-001: owner tag missing", Severity: "LOW", PolicyID: "TAG-001", File: "main.tf"},
		{Msg: "  - critical review finding", Severity: "CRITICAL"},
	}, true, nil)
	if err != nil {
		t.Fatalf("build SARIF: %v", err)
	}

	var doc riskSARIFDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("unexpected SARIF root: %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != riskToolName || run.Tool.Driver.Version != riskToolVersion {
		t.Errorf("tool = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %d, want one per policy plus review fallback", len(run.Tool.Driver.Rules))
	}

	want := []struct {
		rule, level, severity, file, message string
	}{
		{"DOCKER-001", "error", "HIGH", "Dockerfile", "DOCKER-001: runs as root"},
		{"PIPE-003", "warning", "MEDIUM", ".github/workflows/ci.yml", "PIPE-003: action is not pinned"},
		{"TAG-001", "note", "LOW", "main.tf", "TAG-001: owner tag missing"},
		{riskReviewRule, "error", "CRITICAL", "", "critical review finding"},
	}
	for i, expected := range want {
		result := run.Results[i]
		if result.RuleID != expected.rule || result.Level != expected.level ||
			result.Properties.CICDSeverity != expected.severity || result.Message.Text != expected.message {
			t.Errorf("result %d = %+v, want rule=%s level=%s severity=%s message=%q",
				i, result, expected.rule, expected.level, expected.severity, expected.message)
		}
		if expected.file == "" {
			if len(result.Locations) != 0 {
				t.Errorf("result %d locations = %+v, want none", i, result.Locations)
			}
		} else if len(result.Locations) != 1 ||
			result.Locations[0].PhysicalLocation.ArtifactLocation.URI != expected.file {
			t.Errorf("result %d location = %+v, want %q", i, result.Locations, expected.file)
		}
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Errorf("successful invocation not recorded: %+v", run.Invocations)
	}
}

func TestBuildRiskSARIFCleanRunUsesEmptyArrays(t *testing.T) {
	raw, err := buildRiskSARIF(nil, true, nil)
	if err != nil {
		t.Fatalf("build SARIF: %v", err)
	}
	var rawDoc map[string]any
	if err := json.Unmarshal(raw, &rawDoc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	runs, ok := rawDoc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %#v, want one risk-validate run", rawDoc["runs"])
	}
	run := runs[0].(map[string]any)
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Errorf("results = %#v, want []", run["results"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if rules, ok := driver["rules"].([]any); !ok || len(rules) != 0 {
		t.Errorf("rules = %#v, want []", driver["rules"])
	}
}

func TestBuildRiskSARIFRecordsPolicyEngineNonRun(t *testing.T) {
	raw, err := buildRiskSARIF(nil, false, []string{"conftest yaml pass failed", "conftest docker pass failed"})
	if err != nil {
		t.Fatalf("build SARIF: %v", err)
	}
	var doc riskSARIFDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	invocation := doc.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("a policy-engine non-run must not be recorded as successful")
	}
	if len(invocation.ToolExecutionNotifications) != 2 {
		t.Fatalf("notifications = %+v", invocation.ToolExecutionNotifications)
	}
	for _, notification := range invocation.ToolExecutionNotifications {
		if notification.Level != "error" {
			t.Errorf("notification level = %q, want error", notification.Level)
		}
	}
}

func TestBuildRiskSARIFDeduplicatesRules(t *testing.T) {
	raw, err := buildRiskSARIF([]reportViol{
		{Msg: "first", Severity: "MEDIUM", PolicyID: "PIPE-003", File: "one.yml"},
		{Msg: "second", Severity: "MEDIUM", PolicyID: "PIPE-003", File: "two.yml"},
	}, true, nil)
	if err != nil {
		t.Fatalf("build SARIF: %v", err)
	}
	var doc riskSARIFDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if got := len(doc.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Errorf("rules = %d, want one declaration for repeated PIPE-003", got)
	}
	if got := len(doc.Runs[0].Results); got != 2 {
		t.Errorf("results = %d, want both findings", got)
	}
}
