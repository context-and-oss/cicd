// Pure findings/severity helpers shared by the scan entry points.
//
// src/risk/findings.go shares the name and nothing else: it declares the
// findings.json / decisions.json types the AI scan commits to a repository,
// while this file reads scanner output into the evidence envelope.
//
// Deliberately untagged (no //go:build !unit_test): these have no Dagger
// dependency, so the unit_test-tagged tests (gating_test.go, archive_test.go,
// findings_test.go) can compile against them with `go test -tags unit_test ./...`.
package main

import (
	"encoding/json"
	"fmt"
)

// finding represents a secrets detection result (used by both Gitleaks and TruffleHog).
type finding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	Line        int    `json:"Line"`
}

// bySeverityFromFindings converts a findings slice (all treated as HIGH) to a severity map.
func bySeverityFromFindings(findings []finding) map[Severity]int {
	if len(findings) == 0 {
		return nil
	}
	return map[Severity]int{SeverityHigh: len(findings)}
}

// mergeSeverity sums counts across multiple bySeverity maps.
func mergeSeverity(maps ...map[Severity]int) map[Severity]int {
	out := map[Severity]int{}
	for _, m := range maps {
		for sev, cnt := range m {
			out[sev] += cnt
		}
	}
	return out
}

// --- SARIF severity -------------------------------------------------------

type sarifDocRule struct {
	ID                   string `json:"id"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sarifDocResult struct {
	RuleID       string                `json:"ruleId"`
	RuleIndex    *int                  `json:"ruleIndex"`
	Level        string                `json:"level"`
	Kind         string                `json:"kind"`
	Suppressions []sarifDocSuppression `json:"suppressions"`
}

type sarifDocSuppression struct {
	Status string `json:"status"`
}

type sarifDocRun struct {
	Tool struct {
		Driver struct {
			Rules []sarifDocRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifDocResult `json:"results"`
}

type sarifDoc struct {
	Runs []sarifDocRun `json:"runs"`
}

// lookupSARIFRule resolves the rule a result was produced by, preferring
// ruleId and falling back to the ruleIndex into the run's rule array.
func lookupSARIFRule(r sarifDocResult, rules []sarifDocRule) (sarifDocRule, bool) {
	if r.RuleID != "" {
		for _, rule := range rules {
			if rule.ID == r.RuleID {
				return rule, true
			}
		}
	}
	if r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(rules) {
		return rules[*r.RuleIndex], true
	}
	return sarifDocRule{}, false
}

// resolveSARIFLevel returns the effective level for one SARIF result.
//
// SARIF 2.1.0 §3.27.10 makes result.level optional: when it is absent the
// level is inherited from the producing rule's defaultConfiguration.level, and
// only falls back to "warning" when the rule says nothing either. Semgrep OSS
// omits result.level entirely and carries severity solely on
// rules[].defaultConfiguration.level, so reading result.level alone silently
// collapsed *every* SAST finding into one bucket — a repo's genuine
// error-level findings could never trip a HIGH gate.
func resolveSARIFLevel(r sarifDocResult, rules []sarifDocRule) string {
	if r.Level != "" {
		return r.Level
	}
	// §3.27.9: a result whose kind is anything other than "fail" does not
	// represent a failure, so its level is "none" whatever the rule configures.
	if r.Kind != "" && r.Kind != "fail" {
		return "none"
	}
	if rule, ok := lookupSARIFRule(r, rules); ok && rule.DefaultConfiguration.Level != "" {
		return rule.DefaultConfiguration.Level
	}
	return "warning"
}

// severityFromSARIFLevel maps a resolved SARIF level onto a canonical severity.
// Kept identical to cross-cutting/evidence's copy so the aggregate counts and
// the per-finding detail rows in combined-evidence.json cannot disagree.
func severityFromSARIFLevel(level string) Severity {
	switch level {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note", "none":
		return SeverityLow
	}
	return SeverityMedium
}

// sarifResultIsSuppressed reports whether a result has an accepted suppression.
//
// SARIF 2.1.0 §3.35.3 defines a suppression with no status as accepted. An
// explicit "accepted" has the same meaning; "underReview" and "rejected" do
// not remove the result from either the gate or the findings report. Semgrep
// writes rule-specific nosemgrep decisions in exactly this array.
func sarifResultIsSuppressed(r sarifDocResult) bool {
	for _, suppression := range r.Suppressions {
		if suppression.Status == "" || suppression.Status == "accepted" {
			return true
		}
	}
	return false
}

// parseSarifSeverities counts results in a SARIF document by canonical severity.
func parseSarifSeverities(raw json.RawMessage) map[Severity]int {
	var doc sarifDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	counts := map[Severity]int{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if sarifResultIsSuppressed(r) {
				continue
			}
			counts[severityFromSARIFLevel(resolveSARIFLevel(r, run.Tool.Driver.Rules))]++
		}
	}
	return counts
}

// sarifSuppressionWarning discloses accepted source suppressions while keeping
// them out of the severity counts and gate. The native SARIF remains untouched,
// so an auditor can still inspect the rule, location and suppression metadata.
func sarifSuppressionWarning(tool string, raw json.RawMessage) string {
	var doc sarifDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	count := 0
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if sarifResultIsSuppressed(r) {
				count++
			}
		}
	}
	if count == 0 {
		return ""
	}
	noun := "finding"
	if count != 1 {
		noun = "findings"
	}
	return fmt.Sprintf("%s: %d %s suppressed in source", tool, count, noun)
}

// stampSARIFLevel rewrites result.level on every result in a SARIF document,
// preserving all other fields.
//
// cicd classifies every secrets finding as HIGH (see CLAUDE.md), and counts
// them that way via bySeverityFromFindings. Gitleaks' native SARIF, however,
// sets no level on results and no defaultConfiguration on its rules, so the
// document alone resolves to the spec default ("warning" → MEDIUM). Left
// unstamped, a leaked credential renders as MEDIUM in combined-evidence.json
// and in any SARIF viewer while the envelope counts it HIGH.
func stampSARIFLevel(raw json.RawMessage, level string) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return raw
	}
	for _, run := range runs {
		runMap, ok := run.(map[string]any)
		if !ok {
			continue
		}
		results, ok := runMap["results"].([]any)
		if !ok {
			continue
		}
		for _, res := range results {
			if resMap, ok := res.(map[string]any); ok {
				resMap["level"] = level
			}
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// Vulnerability severities are no longer derived from CycloneDX. The parser that
// used to live here read `vulnerabilities[].ratings[0].severity` — the first
// vendor opinion the advisory database happened to serialise — and measurement
// against trivy 0.70.0 showed it under-reported 34 of debian:11.6's 205
// vulnerabilities and found 3 of the 9 CRITICALs. Counts now come from Trivy's
// own resolved verdict; see trivyreport.go for the full measurement and why
// neither CycloneDX nor SARIF can carry it.
