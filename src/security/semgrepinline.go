package main

import (
	_ "embed"
	"encoding/json"
)

const (
	semgrepInlinePath     = "/" + semgrepCicdRuleDir + "/semgrep_inline.py"
	semgrepInlinePlanPath = "/" + semgrepCicdRuleDir + "/inline-plan.json"
	semgrepInlineWarnings = "/tmp/semgrep.inline-warnings.json"
)

//go:embed semgrep_inline.py
var semgrepInlineScript string

// The adapter receives only the selected pinned membership, not arbitrary
// consumer configs. Their path restrictions cannot be replayed on synthetic
// filenames without changing what the caller asked to scan.
func semgrepInlinePlan(plan semgrepPlan) string {
	data, _ := json.Marshal(struct {
		Files []string `json:"files"`
		Floor []string `json:"floor"`
	}{plan.Files, append(append([]string(nil), plan.Floor...), semgrepDOMRule.LoadedID())})
	return string(data)
}
