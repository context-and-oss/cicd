package main

import (
	"encoding/json"
	"testing"
)

// TestParseSarifSeveritiesRuleLevelInheritance is the regression guard for the
// false pass this file's resolver exists to close: Semgrep OSS emits results
// with no `level`, carrying severity only on rules[].defaultConfiguration.level.
// Reading result.level alone bucketed every SAST finding at the default, so a
// repo's genuine error-level findings could never trip a HIGH gate.
func TestParseSarifSeveritiesRuleLevelInheritance(t *testing.T) {
	// Shaped exactly like real Semgrep output: no level on any result.
	doc := `{
      "runs": [{
        "tool": {"driver": {"name": "Semgrep OSS", "rules": [
          {"id": "csharp.lang.security.sqli", "defaultConfiguration": {"level": "error"}},
          {"id": "typescript.react.dangerouslysetinnerhtml", "defaultConfiguration": {"level": "warning"}},
          {"id": "generic.style.nit", "defaultConfiguration": {"level": "note"}}
        ]}},
        "results": [
          {"ruleId": "csharp.lang.security.sqli"},
          {"ruleId": "csharp.lang.security.sqli"},
          {"ruleId": "typescript.react.dangerouslysetinnerhtml"},
          {"ruleId": "generic.style.nit"}
        ]
      }]
    }`

	got := parseSarifSeverities(json.RawMessage(doc))
	want := map[Severity]int{SeverityHigh: 2, SeverityMedium: 1, SeverityLow: 1}
	assertSeverities(t, got, want)

	if got[SeverityHigh] == 0 {
		t.Fatal("error-level Semgrep rules resolved to no HIGH findings: a HIGH gate would pass on real SAST hits")
	}
}

func TestResolveSARIFLevel(t *testing.T) {
	rules := []sarifDocRule{
		{ID: "explicit-error"},
		{ID: "rule-warn"},
	}
	rules[0].DefaultConfiguration.Level = "error"
	rules[1].DefaultConfiguration.Level = "warning"

	idx := func(i int) *int { return &i }

	cases := []struct {
		name   string
		result sarifDocResult
		want   string
	}{
		{"explicit level wins over rule", sarifDocResult{RuleID: "rule-warn", Level: "error"}, "error"},
		{"inherits rule level when absent", sarifDocResult{RuleID: "explicit-error"}, "error"},
		{"resolves by ruleIndex when ruleId is unknown", sarifDocResult{RuleIndex: idx(1)}, "warning"},
		{"unknown rule falls back to spec default", sarifDocResult{RuleID: "nope"}, "warning"},
		{"no rule reference at all", sarifDocResult{}, "warning"},
		{"non-fail kind is not a failure", sarifDocResult{RuleID: "explicit-error", Kind: "informational"}, "none"},
		{"kind fail still inherits", sarifDocResult{RuleID: "explicit-error", Kind: "fail"}, "error"},
		{"out-of-range ruleIndex is ignored", sarifDocResult{RuleIndex: idx(99)}, "warning"},
		{"negative ruleIndex is ignored", sarifDocResult{RuleIndex: idx(-1)}, "warning"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveSARIFLevel(c.result, rules); got != c.want {
				t.Fatalf("resolveSARIFLevel = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSeverityFromSARIFLevel(t *testing.T) {
	cases := map[string]Severity{
		"error":     SeverityHigh,
		"warning":   SeverityMedium,
		"note":      SeverityLow,
		"none":      SeverityLow,
		"":          SeverityMedium,
		"gibberish": SeverityMedium,
	}
	for level, want := range cases {
		if got := severityFromSARIFLevel(level); got != want {
			t.Errorf("severityFromSARIFLevel(%q) = %v, want %v", level, got, want)
		}
	}
}

func TestParseSarifSeveritiesMalformed(t *testing.T) {
	if got := parseSarifSeverities(json.RawMessage(`not json`)); got != nil {
		t.Fatalf("malformed SARIF should yield nil counts, got %v", got)
	}
	if got := parseSarifSeverities(json.RawMessage(`{"runs":[]}`)); len(got) != 0 {
		t.Fatalf("empty SARIF should yield no counts, got %v", got)
	}
}

func TestParseSarifSeveritiesOmitsAcceptedSuppressions(t *testing.T) {
	doc := json.RawMessage(`{
      "runs": [{
        "tool": {"driver": {"rules": [
          {"id": "semgrep.high", "defaultConfiguration": {"level": "error"}}
        ]}},
        "results": [
          {"ruleId": "semgrep.high"},
          {"ruleId": "semgrep.high", "suppressions": [{"kind": "inSource"}]},
          {"ruleId": "semgrep.high", "suppressions": [{"kind": "inSource", "status": "accepted"}]},
          {"ruleId": "semgrep.high", "suppressions": [{"kind": "inSource", "status": "underReview"}]},
          {"ruleId": "semgrep.high", "suppressions": [{"kind": "inSource", "status": "rejected"}]},
          {"ruleId": "semgrep.high", "suppressions": [
            {"kind": "external", "status": "rejected"},
            {"kind": "inSource", "status": "accepted"}
          ]}
        ]
      }]
    }`)

	assertSeverities(t, parseSarifSeverities(doc), map[Severity]int{SeverityHigh: 3})
	if got, want := sarifSuppressionWarning(doc), "semgrep: 3 findings suppressed in source"; got != want {
		t.Errorf("sarifSuppressionWarning = %q, want %q", got, want)
	}
}

func TestSarifSuppressionWarningSingularAndInvalidInput(t *testing.T) {
	one := json.RawMessage(`{"runs":[{"results":[{"suppressions":[{}]}]}]}`)
	if got, want := sarifSuppressionWarning(one), "semgrep: 1 finding suppressed in source"; got != want {
		t.Errorf("sarifSuppressionWarning = %q, want %q", got, want)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`not json`),
		json.RawMessage(`{"runs":[{"results":[{"suppressions":[{"status":"rejected"}]}]}]}`),
	} {
		if got := sarifSuppressionWarning(raw); got != "" {
			t.Errorf("sarifSuppressionWarning(%s) = %q, want empty", raw, got)
		}
	}
}

// TestStampSARIFLevel proves the secrets SARIF is made to agree with the HIGH
// counts the envelope reports, without losing any other field.
func TestStampSARIFLevel(t *testing.T) {
	in := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},
      "results":[{"ruleId":"generic-api-key","message":{"text":"secret"}},
                 {"ruleId":"aws-key","level":"note"}]}]}`

	out := stampSARIFLevel(json.RawMessage(in), "error")

	var doc sarifDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("stamped SARIF does not parse: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("stamping changed the document shape: %s", out)
	}
	for i, r := range doc.Runs[0].Results {
		if r.Level != "error" {
			t.Errorf("result %d level = %q, want error", i, r.Level)
		}
	}
	// Counts derived from the stamped document must now read HIGH, matching
	// bySeverityFromFindings' classification of the same findings.
	assertSeverities(t, parseSarifSeverities(out), map[Severity]int{SeverityHigh: 2})

	// Sibling fields survive.
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["version"] != "2.1.0" {
		t.Errorf("version field lost: %v", raw["version"])
	}
	results := raw["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if msg := results[0].(map[string]any)["message"]; msg == nil {
		t.Error("message field lost during stamping")
	}
}

func TestStampSARIFLevelLeavesBadInputAlone(t *testing.T) {
	for _, in := range []string{``, `not json`, `{"runs":"nope"}`, `{}`} {
		if got := string(stampSARIFLevel(json.RawMessage(in), "error")); got != in {
			t.Errorf("stampSARIFLevel(%q) = %q, want it returned unchanged", in, got)
		}
	}
}

// Vulnerability severity counting moved to trivyreport_test.go along with the
// parser. The test that used to sit here asserted the defect as the contract: it
// fed `ratings:[{"critical"},{"medium"}]` and `ratings:[{"high"},{"medium"}]` and
// expected one CRITICAL and one HIGH from taking entry zero, and it expected an
// `unknown` rating and a vulnerability with no ratings at all to be counted
// nowhere. All four expectations were wrong about what a gate needs.

func assertSeverities(t *testing.T, got, want map[Severity]int) {
	t.Helper()
	for sev, n := range want {
		if got[sev] != n {
			t.Errorf("%s = %d, want %d (full: %v)", sev, got[sev], n, got)
		}
	}
	for sev, n := range got {
		if n != 0 && want[sev] == 0 {
			t.Errorf("unexpected %s = %d (full: %v)", sev, n, got)
		}
	}
}
