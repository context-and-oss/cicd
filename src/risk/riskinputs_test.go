package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRiskInputs(t *testing.T) {
	findings := `{"findings":[{"id":"abc","title":"PII in logs","category":"data_governance"}]}`
	decisions := `{"abc":{"status":"needs_review"}}`
	in, err := parseRiskInputs(findings, decisions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(in.findings.Findings) != 1 || in.findings.Findings[0].ID != "abc" {
		t.Errorf("findings = %#v", in.findings.Findings)
	}
	if in.decisions["abc"].Status != "needs_review" {
		t.Errorf("decisions = %#v", in.decisions)
	}
	var merged struct {
		Findings  []Finding           `json:"findings"`
		Decisions map[string]Decision `json:"decisions"`
	}
	if err := json.Unmarshal(in.merged, &merged); err != nil {
		t.Fatalf("merged is not JSON: %v\n%s", err, in.merged)
	}
	if len(merged.Findings) != 1 || merged.Decisions["abc"].Status != "needs_review" {
		t.Errorf("merged document lost content: %s", in.merged)
	}
}

func TestParseRiskInputsNamesTheFileItRefuses(t *testing.T) {
	cases := []struct {
		name, findings, decisions, want string
	}{
		{"bad findings", `{"findings":[`, `{}`, "parse findings.json:"},
		{"bad decisions", `{"findings":[]}`, `[]`, "parse decisions.json:"},
		{"empty findings", ``, `{}`, "parse findings.json:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRiskInputs(tc.findings, tc.decisions)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Errorf("err = %v, want prefix %q", err, tc.want)
			}
		})
	}
}

func TestParseRiskInputsEmptyDecisionsIsAMap(t *testing.T) {
	in, err := parseRiskInputs(`{"findings":[]}`, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if in.decisions == nil {
		t.Error("decisions must be an empty map, not nil, so lookups and the merged document behave")
	}
	if !strings.Contains(string(in.merged), `"decisions":{}`) {
		t.Errorf("merged = %s", in.merged)
	}
}
