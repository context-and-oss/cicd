package sarif_test

import (
	"encoding/json"
	"testing"

	"github.com/context-and-oss/cicd/internal/sarif"
)

func TestNewDocument(t *testing.T) {
	doc := sarif.NewDocument()
	doc.AddRun("golangci-lint", "1.57.0", []sarif.Result{
		{RuleID: "errcheck", Level: "error", Message: sarif.Message{Text: "unchecked error"}},
		{RuleID: "unused", Level: "warning", Message: sarif.Message{Text: "unused variable"}},
	})

	data, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if raw["version"] != "2.1.0" {
		t.Errorf("version: got %v, want 2.1.0", raw["version"])
	}

	runs, ok := raw["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run")
	}
}

// TestEmptyArraysNeverMarshalAsNull pins both halves of the null/[] rule. A nil
// Go slice marshals to null, and SARIF 2.1.0 §3.14.23 allows run.results to be
// absent but requires an array when the property is present — so a null is both
// schema-invalid and semantically wrong: "ran, found nothing" is an empty list,
// not missing information.
func TestEmptyArraysNeverMarshalAsNull(t *testing.T) {
	empty, err := sarif.NewDocument().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var emptyDoc map[string]any
	if err := json.Unmarshal(empty, &emptyDoc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if runs, ok := emptyDoc["runs"].([]any); !ok || len(runs) != 0 {
		t.Errorf("empty document runs: got %#v, want an empty array", emptyDoc["runs"])
	}

	doc := sarif.NewDocument()
	doc.AddRun("golangci-lint", "2.12.2", nil) // a clean run reports no results
	data, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed struct {
		Runs []map[string]json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
	}
	results, present := parsed.Runs[0]["results"]
	if !present {
		t.Fatalf("results property is missing: %s", data)
	}
	if string(results) != "[]" {
		t.Errorf("clean run results: got %s, want []", results)
	}
}

func TestCountBySeverity(t *testing.T) {
	results := []sarif.Result{
		{Level: "error"},
		{Level: "error"},
		{Level: "warning"},
		{Level: "note"},
	}
	counts := sarif.CountBySeverity(results)
	if counts["HIGH"] != 2 {
		t.Errorf("HIGH: got %d, want 2", counts["HIGH"])
	}
	if counts["MEDIUM"] != 1 {
		t.Errorf("MEDIUM: got %d, want 1", counts["MEDIUM"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("LOW: got %d, want 1", counts["LOW"])
	}
}
