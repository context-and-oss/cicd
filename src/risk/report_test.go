package main

import (
	"strings"
	"testing"
)

func TestRenderReport_groupsByStatus(t *testing.T) {
	findings := []Finding{
		{ID: "aaa", Title: "A finding", Category: "data_exposure", Severity: "high",
			Confidence: 0.9, Evidence: Evidence{File: "src/main.go", StartLine: 10, EndLine: 12, Snippet: "log(email)"}},
		{ID: "bbb", Title: "B finding", Category: "infrastructure", Severity: "low",
			Confidence: 0.7, Evidence: Evidence{File: "Dockerfile", StartLine: 1, EndLine: 1}},
	}
	decisions := map[string]Decision{
		"aaa": {Status: "approved", Justification: "Expected use", ReviewedBy: "reviewer@example.com", ReviewedAt: "2026-04-26T10:00:00Z"},
		"bbb": {Status: "needs_review"},
	}
	md := renderReport(findings, decisions)
	if !strings.Contains(md, "## needs review") {
		t.Error("expected 'needs review' section")
	}
	if !strings.Contains(md, "## approved") {
		t.Error("expected 'approved' section")
	}
	if !strings.Contains(md, "Expected use") {
		t.Error("expected justification for approved finding")
	}
}

func TestRenderReport_emptyFindings(t *testing.T) {
	md := renderReport(nil, nil)
	if !strings.Contains(md, "# Risk Report") {
		t.Error("expected header even with no findings")
	}
	if !strings.Contains(md, "No findings") {
		t.Error("expected 'No findings' message")
	}
}
