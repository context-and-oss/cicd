package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestMergeFindings verifies the aggregator preserves human-readable detail
// from each finding-bearing payload shape (SARIF, intent-gate, risk-validate),
// maps severities correctly, and sorts CRITICAL→LOW so gate-tripping findings
// render first.
func TestMergeFindings(t *testing.T) {
	sarif := json.RawMessage(`{
	  "runs": [{
	    "tool": {"driver": {"name": "trivy"}},
	    "results": [
	      {"ruleId": "CVE-2024-1", "level": "error", "message": {"text": "critical-ish vuln"},
	       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.mod"}}}]},
	      {"ruleId": "GO-2", "level": "note", "message": {"text": "informational"}}
	    ]
	  }]
	}`)
	intent := json.RawMessage(`{
	  "tool": "intent-gate",
	  "findings": [
	    {"rule": "min-causal-language", "severity": "error", "artifactPath": ".capsules/x.yaml", "message": "no causal language"},
	    {"rule": "no-weasel-words", "severity": "warn", "artifactPath": ".capsules/x.yaml", "message": "uses robust"}
	  ]
	}`)
	risk := json.RawMessage(`{
	  "violations": [
	    {"msg": "- Dockerfile runs as root", "severity": "CRITICAL"},
	    {"msg": "weird severity", "severity": "bogus"}
	  ],
	  "infraFilesScanned": 3
	}`)

	envs := []*envelope{
		{ModuleName: "security", SARIFReport: sarif},
		{ModuleName: "intent", GenericFormat: "intent-gate", GenericReport: intent},
		{ModuleName: "risk", GenericFormat: "ctx-risk-validate/1.0", GenericReport: risk},
		{ModuleName: "quality"}, // no findings payload — must be skipped cleanly
	}

	got := mergeFindings(envs)

	if len(got) != 6 {
		t.Fatalf("expected 6 findings, got %d: %+v", len(got), got)
	}

	// Sorted CRITICAL→LOW. First must be the CRITICAL risk violation.
	if got[0].Severity != SeverityCritical {
		t.Errorf("expected first finding CRITICAL, got %s", got[0].Severity)
	}
	if last := got[len(got)-1].Severity; last != SeverityLow {
		t.Errorf("expected last finding LOW, got %s", last)
	}
	// Non-increasing severity order.
	for i := 1; i < len(got); i++ {
		if severityOrder(got[i-1].Severity) < severityOrder(got[i].Severity) {
			t.Errorf("findings not sorted descending at %d: %s before %s", i, got[i-1].Severity, got[i].Severity)
		}
	}

	bySource := map[string]Finding{}
	for _, f := range got {
		bySource[findingKey(f)] = f
	}

	// SARIF error → HIGH, with tool + rule + location.
	if f, ok := bySource["trivy/CVE-2024-1"]; !ok {
		t.Error("missing SARIF finding CVE-2024-1")
	} else {
		if f.Severity != SeverityHigh {
			t.Errorf("SARIF error level should map to HIGH, got %s", f.Severity)
		}
		if f.ArtifactPath != "go.mod" {
			t.Errorf("SARIF location not extracted, got %q", f.ArtifactPath)
		}
	}
	// SARIF note → LOW.
	if f := bySource["trivy/GO-2"]; f.Severity != SeverityLow {
		t.Errorf("SARIF note level should map to LOW, got %s", f.Severity)
	}
	// intent error → HIGH, warn → MEDIUM.
	if f := bySource["intent-gate/min-causal-language"]; f.Severity != SeverityHigh || f.ArtifactPath != ".capsules/x.yaml" {
		t.Errorf("intent error mapping wrong: %+v", f)
	}
	if f := bySource["intent-gate/no-weasel-words"]; f.Severity != SeverityMedium {
		t.Errorf("intent warn should map to MEDIUM, got %s", f.Severity)
	}
	// risk: canonical severity preserved, leading "- " stripped from message.
	// There are two risk-validate findings and bySource keeps one, so both are
	// asserted below by walking the slice instead of through the map.
	var critRisk, fallbackRisk *Finding
	for i := range got {
		if got[i].Tool == "risk-validate" {
			if got[i].Severity == SeverityCritical {
				critRisk = &got[i]
			} else {
				fallbackRisk = &got[i]
			}
		}
	}
	if critRisk == nil || critRisk.Message != "Dockerfile runs as root" {
		t.Errorf("expected CRITICAL risk finding with trimmed message, got %+v", critRisk)
	}
	if fallbackRisk == nil || fallbackRisk.Severity != SeverityHigh {
		t.Errorf("unparseable risk severity should fall back to HIGH, got %+v", fallbackRisk)
	}
}

// TestMergeFindingsEmpty ensures no findings payloads yields a nil slice (so
// the combined envelope omits the field) rather than panicking.
func TestMergeFindingsEmpty(t *testing.T) {
	if got := mergeFindings([]*envelope{{ModuleName: "quality"}}); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", got)
	}
}

func TestMergeFindingsPrefersRiskSARIFOverDuplicateGenericReport(t *testing.T) {
	sarif := json.RawMessage(`{
	  "runs": [{
	    "tool": {"driver": {"name": "risk-validate"}},
	    "results": [{
	      "ruleId": "DOCKER-001",
	      "level": "error",
	      "properties": {"cicdSeverity": "CRITICAL"},
	      "message": {"text": "container runs as root"},
	      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}}}]
	    }]
	  }]
	}`)
	generic := json.RawMessage(`{
	  "violations": [{
	    "msg": "  - container runs as root",
	    "severity": "CRITICAL",
	    "policyId": "DOCKER-001",
	    "file": "Dockerfile"
	  }]
	}`)

	got := mergeFindings([]*envelope{{
		ModuleName: "risk", GenericFormat: "ctx-risk-validate/1.0",
		SARIFReport: sarif, GenericReport: generic,
	}})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want one SARIF-backed row rather than a duplicate: %+v", len(got), got)
	}
	finding := got[0]
	if finding.Severity != SeverityCritical || finding.Tool != "risk-validate" ||
		finding.Rule != "DOCKER-001" || finding.ArtifactPath != "Dockerfile" {
		t.Errorf("finding lost canonical risk detail: %+v", finding)
	}
}

func TestRiskGenericFallbackPreservesPolicyIdentityAndLocation(t *testing.T) {
	raw := json.RawMessage(`{"violations":[{
	  "msg":"  - action is not pinned", "severity":"MEDIUM",
	  "policyId":"PIPE-003", "file":".github/workflows/ci.yml"
	}]}`)
	got := riskFindings(raw)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Rule != "PIPE-003" || got[0].ArtifactPath != ".github/workflows/ci.yml" {
		t.Errorf("generic fallback lost policy identity or location: %+v", got[0])
	}
}

// TestMergeFindingsReadsModuleStatedFindings is the regression guard for
// vulnerability rows reaching the detail list at all. The security module states
// them in envelope.Findings because neither payload it ships can carry Trivy's
// resolved severity: CycloneDX has per-vendor ratings and no verdict, and SARIF
// collapses critical and high onto level "error". Before this, a run whose only
// failure was a CRITICAL CVE rendered a findings count with an empty table.
func TestMergeFindingsReadsModuleStatedFindings(t *testing.T) {
	stated := Finding{
		Severity: SeverityCritical, Tool: "trivy", Rule: "CVE-2023-45853",
		Message: "zlib1g@1:1.2.11.dfsg-2 — no fix available", ArtifactPath: "debian:11.6",
	}
	got := mergeFindings([]*envelope{{ModuleName: "security", Findings: []Finding{stated}}})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want the module's own: %+v", len(got), got)
	}
	if !reflect.DeepEqual(got[0], stated) {
		t.Errorf("finding = %+v, want it carried through verbatim (%+v)", got[0], stated)
	}
	// Severity must survive as CRITICAL. Routing this through SARIF is what would
	// have demoted it to HIGH.
	if got[0].Severity != SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", got[0].Severity)
	}
}

// TestMergeFindingsSortsStatedFindingsWithTheRest checks a stated finding is not
// merely appended: the list is what a reader scans top-down, so a CRITICAL
// vulnerability has to outrank a lint error from another envelope.
func TestMergeFindingsSortsStatedFindingsWithTheRest(t *testing.T) {
	lint := json.RawMessage(`{"runs":[{"tool":{"driver":{"name":"eslint"}},
	  "results":[{"ruleId":"no-undef","level":"error","message":{"text":"undef"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"}}}]}]}]}`)
	got := mergeFindings([]*envelope{
		{ModuleName: "quality", SARIFReport: lint},
		{ModuleName: "security", Findings: []Finding{
			{Severity: SeverityCritical, Tool: "trivy", Rule: "CVE-1", Message: "x"},
		}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("first row is %s from %s, want the CRITICAL vulnerability first",
			got[0].Severity, got[0].Tool)
	}
}

// TestMergeFindingsDeduplicates covers a module that both states a finding and
// ships a payload describing it. A row shown twice is indistinguishable from two
// genuine findings at one site.
func TestMergeFindingsDeduplicates(t *testing.T) {
	sarif := json.RawMessage(`{"runs":[{"tool":{"driver":{"name":"gitleaks"}},
	  "results":[{"ruleId":"aws-key","level":"error","message":{"text":"leak"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":".env"}}}]}]}]}`)
	dup := Finding{
		Severity: SeverityHigh, Tool: "gitleaks", Rule: "aws-key",
		Message: "leak", ArtifactPath: ".env",
	}
	got := mergeFindings([]*envelope{
		{ModuleName: "security", Findings: []Finding{dup}, SARIFReport: sarif},
	})
	if len(got) != 1 {
		t.Errorf("got %d findings, want 1 after dedupe: %+v", len(got), got)
	}

	// Two genuinely different findings at the same location must both survive.
	twoAtOneSite := mergeFindings([]*envelope{{ModuleName: "security", Findings: []Finding{
		{Severity: SeverityHigh, Tool: "trivy", Rule: "CVE-1", Message: "a", ArtifactPath: "go.sum"},
		{Severity: SeverityHigh, Tool: "trivy", Rule: "CVE-2", Message: "b", ArtifactPath: "go.sum"},
	}}})
	if len(twoAtOneSite) != 2 {
		t.Errorf("got %d findings, want both CVEs in the same file: %+v", len(twoAtOneSite), twoAtOneSite)
	}
}

// TestSarifFindingsRuleLevelInheritance is the regression guard for the detail
// list agreeing with the counts. Semgrep OSS sets no level on any result and
// carries severity only on rules[].defaultConfiguration.level, so reading
// result.level alone rendered every SAST row at the bare default — a genuine
// error-level SQL-injection hit displayed identically to a style nit.
func TestSarifFindingsRuleLevelInheritance(t *testing.T) {
	raw := json.RawMessage(`{
	  "runs": [{
	    "tool": {"driver": {"name": "Semgrep OSS", "rules": [
	      {"id": "csharp.sqli", "defaultConfiguration": {"level": "error"}},
	      {"id": "ts.innerhtml", "defaultConfiguration": {"level": "warning"}},
	      {"id": "style.nit", "defaultConfiguration": {"level": "note"}}
	    ]}},
	    "results": [
	      {"ruleId": "csharp.sqli", "message": {"text": "sqli"},
	       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Db.cs"}}}]},
	      {"ruleId": "ts.innerhtml", "message": {"text": "xss"}},
	      {"ruleId": "style.nit", "message": {"text": "nit"}},
	      {"ruleIndex": 0, "message": {"text": "by index"}},
	      {"ruleId": "csharp.sqli", "level": "note", "message": {"text": "explicit wins"}},
	      {"ruleId": "csharp.sqli", "kind": "informational", "message": {"text": "not a failure"}},
	      {"ruleId": "unknown-rule", "message": {"text": "no rule entry"}}
	    ]
	  }]
	}`)

	got := sarifFindings(raw)
	if len(got) != 7 {
		t.Fatalf("expected 7 findings, got %d: %+v", len(got), got)
	}

	want := []Severity{
		SeverityHigh,   // inherits error
		SeverityMedium, // inherits warning
		SeverityLow,    // inherits note
		SeverityHigh,   // resolved via ruleIndex
		SeverityLow,    // explicit note beats the rule's error
		SeverityLow,    // non-fail kind => level "none"
		SeverityMedium, // unresolvable rule => spec default "warning"
	}
	for i, w := range want {
		if got[i].Severity != w {
			t.Errorf("finding %d (%q) severity = %s, want %s", i, got[i].Message, got[i].Severity, w)
		}
	}

	if got[0].Tool != "Semgrep OSS" || got[0].Rule != "csharp.sqli" || got[0].ArtifactPath != "Db.cs" {
		t.Errorf("finding metadata lost: %+v", got[0])
	}
}

func TestSarifFindingsOmitsAcceptedSuppressions(t *testing.T) {
	raw := json.RawMessage(`{
      "runs": [{
        "tool": {"driver": {"name": "Semgrep OSS"}},
        "results": [
          {"ruleId":"active", "level":"warning", "message":{"text":"active"}},
          {"ruleId":"implicit-accepted", "level":"error", "suppressions":[{"kind":"inSource"}], "message":{"text":"suppressed"}},
          {"ruleId":"accepted", "level":"error", "suppressions":[{"kind":"inSource", "status":"accepted"}], "message":{"text":"suppressed"}},
          {"ruleId":"under-review", "level":"error", "suppressions":[{"kind":"inSource", "status":"underReview"}], "message":{"text":"pending"}},
          {"ruleId":"rejected", "level":"error", "suppressions":[{"kind":"inSource", "status":"rejected"}], "message":{"text":"rejected"}},
          {"ruleId":"any-accepted", "level":"error", "suppressions":[{"status":"rejected"},{"status":"accepted"}], "message":{"text":"suppressed"}}
        ]
      }]
    }`)

	got := sarifFindings(raw)
	if len(got) != 3 {
		t.Fatalf("got %d findings, want active, underReview and rejected: %+v", len(got), got)
	}
	wantRules := map[string]bool{"active": true, "under-review": true, "rejected": true}
	for _, finding := range got {
		if !wantRules[finding.Rule] {
			t.Errorf("suppressed result reached findings table: %+v", finding)
		}
	}
}

// TestSarifFindingsBadInput pins the skip-don't-panic contract: an unparseable
// payload contributes no detail, and the per-module counts still carry the gate
// signal.
func TestSarifFindingsBadInput(t *testing.T) {
	for _, raw := range []string{``, `not json`, `{}`, `{"runs":[]}`, `{"runs":[{"results":[]}]}`} {
		if got := sarifFindings(json.RawMessage(raw)); len(got) != 0 {
			t.Errorf("sarifFindings(%q) = %+v, want none", raw, got)
		}
	}
}

func findingKey(f Finding) string {
	return f.Tool + "/" + f.Rule
}

// TestSarifFindingsCarryTheLine is the regression guard for the detail table
// under-reporting. Before Finding had a Line, two findings that differed only
// by line number were byte-identical structs here, and dedupeFindings — which
// keys on the whole struct — kept exactly one. A .env with three leaked
// credentials rendered as one row under a count of three, and the row is what a
// reviewer acts on.
func TestSarifFindingsCarryTheLine(t *testing.T) {
	raw := json.RawMessage(`{
	  "runs": [{
	    "tool": {"driver": {"name": "gitleaks"}},
	    "results": [
	      {"ruleId": "aws-key", "level": "error", "message": {"text": "leak"},
	       "locations": [{"physicalLocation": {
	         "artifactLocation": {"uri": ".env"}, "region": {"startLine": 4}}}]},
	      {"ruleId": "aws-key", "level": "error", "message": {"text": "leak"},
	       "locations": [{"physicalLocation": {
	         "artifactLocation": {"uri": ".env"}, "region": {"startLine": 19}}}]},
	      {"ruleId": "aws-key", "level": "error", "message": {"text": "leak"},
	       "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".env"}}}]},
	      {"ruleId": "aws-key", "level": "error", "message": {"text": "leak"},
	       "locations": [{"physicalLocation": {
	         "artifactLocation": {"uri": ".env"}, "region": {"startLine": 0}}}]}
	    ]
	  }]
	}`)

	got := sarifFindings(raw)
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(got), got)
	}
	if got[0].Line != 4 || got[1].Line != 19 {
		t.Errorf("startLine lost: %+v", got[:2])
	}
	// An absent region and an explicit 0 both mean "the tool did not say", and
	// neither may become line 1 — an invented location reads as precise.
	if got[2].Line != 0 || got[3].Line != 0 {
		t.Errorf("a line was invented where the tool reported none: %+v", got[2:])
	}
	for i, f := range got {
		if f.ArtifactPath != ".env" {
			t.Errorf("finding %d lost its path: %+v", i, f)
		}
	}

	// The end-to-end consequence: the two located leaks must both survive the
	// dedupe, and the two unlocated ones are genuine exact repeats.
	merged := mergeFindings([]*envelope{{ModuleName: "security", SARIFReport: raw}})
	if len(merged) != 3 {
		t.Fatalf("got %d findings after dedupe, want 3 (lines 4, 19 and one unlocated): %+v",
			len(merged), merged)
	}
	lines := map[int]bool{}
	for _, f := range merged {
		lines[f.Line] = true
	}
	for _, want := range []int{4, 19, 0} {
		if !lines[want] {
			t.Errorf("line %d did not survive the merge: %+v", want, merged)
		}
	}
}

// TestSarifFindingsKeepSameNamedFilesApart is the folder half of the argument
// above. dotnet format's report names a file twice — a bare FileName and an
// absolute FilePath — and quality used to put the bare name in the uri. Two
// same-named files in different folders holding the same violation on the same
// line were then byte-identical here, and the dedupe collapsed distinct
// locations in the combined table. The producer fix is in quality (the uri is
// now the path relative to the source root); this pins the aggregator side — a folder in the uri is a
// distinct identity, and the bare name is shown to collapse so the reason the
// producer must carry it is on record.
func TestSarifFindingsKeepSameNamedFilesApart(t *testing.T) {
	doc := func(a, b string) json.RawMessage {
		return json.RawMessage(`{
		  "runs": [{
		    "tool": {"driver": {"name": "dotnet-format"}},
		    "results": [
		      {"ruleId": "WHITESPACE", "level": "warning",
		       "message": {"text": "Fix whitespace formatting. Delete 1 characters."},
		       "locations": [{"physicalLocation": {
		         "artifactLocation": {"uri": "` + a + `"},
		         "region": {"startLine": 5, "startColumn": 19}}}]},
		      {"ruleId": "WHITESPACE", "level": "warning",
		       "message": {"text": "Fix whitespace formatting. Delete 1 characters."},
		       "locations": [{"physicalLocation": {
		         "artifactLocation": {"uri": "` + b + `"},
		         "region": {"startLine": 5, "startColumn": 19}}}]}
		    ]
		  }]
		}`)
	}

	withFolder := doc("Controllers/OrderController.cs", "Api/Controllers/OrderController.cs")
	merged := mergeFindings([]*envelope{{ModuleName: "quality", SARIFReport: withFolder}})
	if len(merged) != 2 {
		t.Fatalf("two same-named files in different folders must stay two findings, got %d: %+v",
			len(merged), merged)
	}
	paths := map[string]bool{}
	for _, f := range merged {
		paths[f.ArtifactPath] = true
		if f.Line != 5 {
			t.Errorf("line lost: %+v", f)
		}
	}
	if !paths["Controllers/OrderController.cs"] || !paths["Api/Controllers/OrderController.cs"] {
		t.Errorf("a folder was lost on the way in: %+v", merged)
	}

	// Negative control: the shape quality used to emit. This collapse is the
	// aggregator working as designed over an under-specified location, which is
	// exactly why the producer must never send one.
	bare := doc("OrderController.cs", "OrderController.cs")
	if got := mergeFindings([]*envelope{{ModuleName: "quality", SARIFReport: bare}}); len(got) != 1 {
		t.Errorf("the bare-name shape should collapse to 1 (this documents the defect), got %d", len(got))
	}
}
