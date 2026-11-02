package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMergeSARIFWithoutProducerRunsIsAnEmptyArray covers DAST-only bundles:
// ZAP findings live in genericReport, so no producer contributes a SARIF run.
// The bundle must still contain an iterable runs array for GitHub Code Scanning.
func TestMergeSARIFWithoutProducerRunsIsAnEmptyArray(t *testing.T) {
	doc := mergeSARIF([]*envelope{{ModuleName: "security", GenericReport: json.RawMessage(`{"scanner":"zap"}`)}})
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if !strings.Contains(string(raw), `"runs":[]`) {
		t.Fatalf("empty merged SARIF must encode runs as an array, got %s", raw)
	}
}

// A risk envelope used to carry its policy violations only in genericReport,
// which mergeSARIF deliberately does not reinterpret. This pins the producer
// contract at the aggregation seam: once risk supplies its native SARIF, the
// run and every result reach the file uploaded to Code Scanning.
func TestRiskValidateRunReachesMergedSARIF(t *testing.T) {
	riskReport := json.RawMessage(`{"version":"2.1.0","runs":[{
	  "tool":{"driver":{"name":"risk-validate"}},
	  "results":[{"ruleId":"DOCKER-001"},{"ruleId":"PIPE-003"}]
	}]}`)
	doc := mergeSARIF([]*envelope{{ModuleName: "risk", SARIFReport: riskReport}})
	if len(doc.Runs) != 1 {
		t.Fatalf("risk run was lost: got %d merged runs", len(doc.Runs))
	}
	tool, _, results := identityOf(t, doc.Runs[0])
	if tool != "risk-validate" || results != 2 {
		t.Errorf("merged risk run = tool %q, %d results; want risk-validate, 2", tool, results)
	}
}

func run(tool, id string) json.RawMessage {
	m := map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": tool}},
		"results": []any{map[string]any{"ruleId": "r1"}},
	}
	if id != "" {
		m["automationDetails"] = map[string]any{"id": id}
	}
	raw, _ := json.Marshal(m)
	return raw
}

func identityOf(t *testing.T, raw json.RawMessage) (tool, id string, results int) {
	t.Helper()
	var probe struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Results []any `json:"results"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("run is not valid JSON: %v\n%s", err, raw)
	}
	return probe.Tool.Driver.Name, probe.AutomationDetails.ID, len(probe.Results)
}

// TestUniqueRunIdentitiesDisambiguatesCollisions is the backstop guard for
// GitHub's 2025-07-22 rule: two runs sharing (tool driver name, category) fail
// the whole upload. Two eslint runs with no automationDetails are exactly that
// once the workflow's category input fills them identically.
func TestUniqueRunIdentitiesDisambiguatesCollisions(t *testing.T) {
	out := uniqueRunIdentities([]json.RawMessage{
		run("eslint", ""),
		run("eslint", ""),
		run("gitleaks", ""),
	})
	if len(out) != 3 {
		t.Fatalf("want 3 runs out, got %d", len(out))
	}

	// First run of the identity keeps its bytes — its alerts stay keyed as
	// they always were.
	if _, id, _ := identityOf(t, out[0]); id != "" {
		t.Errorf("first eslint run was rewritten: id=%q", id)
	}
	tool, id, results := identityOf(t, out[1])
	if tool != "eslint" || id != "cicd/eslint/2" {
		t.Errorf("second eslint run: tool=%q id=%q, want eslint / cicd/eslint/2", tool, id)
	}
	if results != 1 {
		t.Errorf("rewrite cost a finding: %d results, want 1", results)
	}
	if _, id, _ := identityOf(t, out[2]); id != "" {
		t.Errorf("gitleaks run was rewritten despite a unique identity: id=%q", id)
	}
}

// TestUniqueRunIdentitiesSuffixesExplicitIDs: producers that stamped the same
// id twice collide just the same; the suffix hangs off their id, and bumping
// continues past an id a producer already owns.
func TestUniqueRunIdentitiesSuffixesExplicitIDs(t *testing.T) {
	out := uniqueRunIdentities([]json.RawMessage{
		run("golangci-lint", "cicd/golangci-lint/mod"),
		run("golangci-lint", "cicd/golangci-lint/mod"),
		run("golangci-lint", "cicd/golangci-lint/mod/2"), // occupies the first suffix
		run("golangci-lint", "cicd/golangci-lint/mod"),
	})
	var ids []string
	for _, r := range out {
		_, id, _ := identityOf(t, r)
		ids = append(ids, id)
	}
	want := []string{
		"cicd/golangci-lint/mod",
		"cicd/golangci-lint/mod/2",
		"cicd/golangci-lint/mod/2/2",
		"cicd/golangci-lint/mod/3",
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("run %d: id=%q, want %q (all: %v)", i, ids[i], want[i], ids)
		}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate identity survived: %q (all: %v)", id, ids)
		}
		seen[id] = true
	}
}

// TestUniqueRunIdentitiesSameToolDifferentIDsUntouched: distinct identities are
// not a collision — nothing may be rewritten.
func TestUniqueRunIdentitiesSameToolDifferentIDsUntouched(t *testing.T) {
	in := []json.RawMessage{
		run("eslint", "cicd/eslint/Client"),
		run("eslint", "cicd/eslint/Server"),
	}
	out := uniqueRunIdentities(in)
	for i := range in {
		if string(out[i]) != string(in[i]) {
			t.Errorf("run %d was rewritten without a collision:\n in: %s\nout: %s", i, in[i], out[i])
		}
	}
}

// TestUniqueRunIdentitiesUnparseableRunPassesThrough: rewriting is cosmetic and
// must never cost a finding — bytes we cannot parse ship as they are.
func TestUniqueRunIdentitiesUnparseableRunPassesThrough(t *testing.T) {
	junk := json.RawMessage(`"not a run object"`)
	out := uniqueRunIdentities([]json.RawMessage{run("eslint", ""), junk})
	if string(out[1]) != string(junk) {
		t.Errorf("unparseable run was rewritten: %s", out[1])
	}
}

// TestMergeSARIFAppliesUniqueness proves the backstop sits on the real path:
// two envelopes whose reports both carry an eslint run come out of mergeSARIF
// with distinct identities.
func TestMergeSARIFAppliesUniqueness(t *testing.T) {
	report := func(runs ...json.RawMessage) json.RawMessage {
		doc, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": runs})
		return doc
	}
	doc := mergeSARIF([]*envelope{
		{ModuleName: "quality", SARIFReport: report(run("eslint", ""))},
		{ModuleName: "quality-2", SARIFReport: report(run("eslint", ""))},
	})
	if len(doc.Runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(doc.Runs))
	}
	_, firstID, _ := identityOf(t, doc.Runs[0])
	_, secondID, _ := identityOf(t, doc.Runs[1])
	if firstID == secondID {
		t.Fatalf("merged document still collides: %q vs %q", firstID, secondID)
	}
	if !strings.HasPrefix(secondID, "cicd/eslint/") {
		t.Errorf("second run's id = %q, want a cicd/eslint/ suffix", secondID)
	}
}

func runWithResults(results ...map[string]any) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "gitleaks"}},
		"results": results,
	})
	return raw
}

func suppressed(rule string, statuses ...string) map[string]any {
	var sups []any
	for _, s := range statuses {
		if s == "" {
			sups = append(sups, map[string]any{"kind": "external"})
			continue
		}
		sups = append(sups, map[string]any{"kind": "external", "status": s})
	}
	r := map[string]any{"ruleId": rule}
	if sups != nil {
		r["suppressions"] = sups
	}
	return r
}

func ruleIDs(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var probe struct {
		Results []struct {
			RuleID string `json:"ruleId"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("run is not valid JSON: %v\n%s", err, raw)
	}
	ids := []string{}
	for _, r := range probe.Results {
		ids = append(ids, r.RuleID)
	}
	return ids
}

// TestWithoutAcceptedResultsKeepsAcceptedOutOfCodeScanning: GitHub ignores
// result.suppressions on upload, so an accepted result in findings.sarif is an
// open alert. Accepted (explicit or absent status) is dropped; a decision still
// under review, or rejected, is a live finding and stays.
func TestWithoutAcceptedResultsKeepsAcceptedOutOfCodeScanning(t *testing.T) {
	in := runWithResults(
		suppressed("live"),
		suppressed("explicit", "accepted"),
		suppressed("implicit", ""),
		suppressed("pending", "underReview"),
		suppressed("rejected", "rejected"),
		suppressed("mixed", "rejected", "accepted"),
	)
	got := strings.Join(ruleIDs(t, withoutAcceptedResults(in)), ",")
	if got != "live,pending,rejected" {
		t.Fatalf("kept %q, want live,pending,rejected", got)
	}
}

func TestWithoutAcceptedResultsLeavesUntouchedRunBytes(t *testing.T) {
	in := runWithResults(suppressed("live"), suppressed("pending", "underReview"))
	if out := withoutAcceptedResults(in); string(out) != string(in) {
		t.Fatalf("run with nothing to drop was rewritten:\n%s\n%s", in, out)
	}
	bad := json.RawMessage(`{"results": "not an array"}`)
	if out := withoutAcceptedResults(bad); string(out) != string(bad) {
		t.Fatalf("unparseable results were rewritten: %s", out)
	}
}

// TestWithoutAcceptedResultsEmptiesRunToResultsArray: a run whose every result
// was accepted must still upload with results: [], so the alerts an earlier
// upload opened are closed rather than left standing.
func TestWithoutAcceptedResultsEmptiesRunToResultsArray(t *testing.T) {
	out := withoutAcceptedResults(runWithResults(suppressed("a", "accepted")))
	if !strings.Contains(string(out), `"results":[]`) {
		t.Fatalf("want results: [], got %s", out)
	}
	if tool, _, _ := identityOf(t, out); tool != "gitleaks" {
		t.Fatalf("filtering lost the run's tool: %s", out)
	}
}

func TestMergeSARIFDropsAcceptedResults(t *testing.T) {
	report, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []json.RawMessage{
		runWithResults(suppressed("live"), suppressed("fixture", "accepted")),
	}})
	doc := mergeSARIF([]*envelope{{ModuleName: "security", SARIFReport: report}})
	if got := strings.Join(ruleIDs(t, doc.Runs[0]), ","); got != "live" {
		t.Fatalf("findings.sarif carries %q, want live only", got)
	}
}
