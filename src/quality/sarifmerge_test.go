//go:build unit_test

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMergeSARIFReports(t *testing.T) {
	a := json.RawMessage(`{"$schema":"https://sarif/2.1.0","version":"2.1.0","runs":[{"tool":{"driver":{"name":"a"}}}]}`)
	b := json.RawMessage(`{"$schema":"https://sarif/2.1.0","version":"2.1.0","runs":[{"tool":{"driver":{"name":"b"}}},{"tool":{"driver":{"name":"c"}}}]}`)

	if got := mergeSARIFReports(nil); got != nil {
		t.Fatalf("no reports must stay nil so the field is omitted, got %s", got)
	}
	if got := mergeSARIFReports([]json.RawMessage{a}); string(got) != string(a) {
		t.Fatalf("one report is returned as it is, got %s", got)
	}

	var merged struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(mergeSARIFReports([]json.RawMessage{a, b}), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Schema != "https://sarif/2.1.0" || merged.Version != "2.1.0" {
		t.Fatalf("header must come from the first document, got %+v", merged)
	}
	if len(merged.Runs) != 3 {
		t.Fatalf("runs are concatenated in order, got %d", len(merged.Runs))
	}
	if !strings.Contains(string(merged.Runs[2]), `"c"`) {
		t.Fatalf("run order lost: %s", merged.Runs[2])
	}

	// A document that is not SARIF is skipped, and when every document is
	// skipped the result says "no runs" rather than null.
	out := mergeSARIFReports([]json.RawMessage{json.RawMessage(`not json`), json.RawMessage(`{`)})
	if !strings.Contains(string(out), `"runs":[]`) {
		t.Fatalf("every report unreadable must marshal runs as [], got %s", out)
	}
}
