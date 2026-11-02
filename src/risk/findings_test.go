package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHashFinding_deterministic(t *testing.T) {
	a := hashFinding("data_exposure", "src/user.go", 42)
	b := hashFinding("data_exposure", "src/user.go", 42)
	if a != b {
		t.Fatalf("hash not deterministic: %q vs %q", a, b)
	}
	if len(a) != 8 {
		t.Fatalf("expected 8 hex chars, got %q (len %d)", a, len(a))
	}
}

func TestHashFinding_distinct(t *testing.T) {
	a := hashFinding("data_exposure", "src/user.go", 42)
	b := hashFinding("data_exposure", "src/user.go", 43)
	c := hashFinding("identity_access", "src/user.go", 42)
	if a == b || a == c || b == c {
		t.Fatalf("expected distinct hashes: %q %q %q", a, b, c)
	}
}

func TestScaffoldDecisions(t *testing.T) {
	findings := []Finding{
		{ID: "abc123", Title: "Test finding"},
		{ID: "def456", Title: "Another finding"},
	}
	decisions := scaffoldDecisions(findings)
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
	for id, d := range decisions {
		if d.Status != "needs_review" {
			t.Fatalf("decision %q: expected needs_review, got %q", id, d.Status)
		}
	}
}

func TestFindingsFile_roundtrip(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	f := FindingsFile{
		SchemaVersion: "1.0",
		ScannedAt:     now,
		Findings: []Finding{
			{
				ID: "a1b2c3", Category: "data_exposure", Severity: "high",
				Confidence: 0.85, Title: "Test", Description: "Desc",
				Evidence: Evidence{File: "src/main.go", StartLine: 10, EndLine: 12, Snippet: "log(email)"},
			},
		},
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FindingsFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Findings[0].ID != "a1b2c3" {
		t.Fatalf("got %q", got.Findings[0].ID)
	}
}
