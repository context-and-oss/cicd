//go:build unit_test

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// resultsOf returns the results value of the document's first run exactly as it
// survives a JSON round trip: a []any for an array, nil for a null or a missing
// property. The two are told apart by the second return value.
func resultsOf(t *testing.T, raw []byte) (results []any, present bool) {
	t.Helper()
	var doc struct {
		Runs []map[string]json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("document is not valid JSON: %v\n%s", err, raw)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("want exactly 1 run, got %d\n%s", len(doc.Runs), raw)
	}
	rawResults, ok := doc.Runs[0]["results"]
	if !ok {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(rawResults, &v); err != nil {
		t.Fatalf("results is not valid JSON: %v", err)
	}
	arr, isArray := v.([]any)
	if !isArray {
		// A present-but-not-an-array results is the defect this file guards.
		t.Fatalf("results is present but not an array: %s", rawResults)
	}
	return arr, true
}

// TestSingleRunSARIFResultsIsAlwaysAnArray is the regression guard for
// `"results": null`. Every parser here declared `var results []map[string]any`
// and marshalled the nil slice, so a clean run — the common case — emitted a
// null. That is schema-invalid under SARIF 2.1.0 §3.14.23 (present means array)
// and it erases the distinction this module is built to preserve: an empty array
// is "ran, found nothing", a null is "no information".
func TestSingleRunSARIFResultsIsAlwaysAnArray(t *testing.T) {
	for _, in := range [][]map[string]any{
		nil,
		{},
		{{"ruleId": "no-undef", "level": "error"}},
	} {
		raw, err := json.Marshal(singleRunSARIF("tool", "1.2.3", in))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(raw), `"results":null`) {
			t.Fatalf("emitted a null results array: %s", raw)
		}
		results, present := resultsOf(t, raw)
		if !present {
			t.Fatalf("results property is missing: %s", raw)
		}
		if len(results) != len(in) {
			t.Fatalf("results has %d entries, want %d: %s", len(results), len(in), raw)
		}
	}
}

func TestSingleRunSARIFShape(t *testing.T) {
	raw, err := json.Marshal(singleRunSARIF("eslint", "9.39.5", nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"version":"2.1.0"`,
		`"$schema":"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"`,
		`"name":"eslint"`,
		`"version":"9.39.5"`,
		`"results":[]`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("document is missing %s: %s", want, raw)
		}
	}
}

// TestStampSARIFAutomationID covers the run-identity stamp that keeps a
// multi-project leg's same-named runs distinct under Code Scanning's
// (tool, category) identity — two runs colliding on it fail the whole upload.
func TestStampSARIFAutomationID(t *testing.T) {
	doc, err := json.Marshal(singleRunSARIF("eslint", "9.39.5", []map[string]any{
		{"ruleId": "no-undef", "level": "error"},
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	stamped := stampSARIFAutomationID(doc, "eslint", "Client")
	var got struct {
		Runs []struct {
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stamped, &got); err != nil {
		t.Fatalf("stamped document is not valid JSON: %v\n%s", err, stamped)
	}
	if len(got.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(got.Runs))
	}
	if got.Runs[0].AutomationDetails.ID != "cicd/eslint/Client" {
		t.Errorf("automationDetails.id = %q, want %q", got.Runs[0].AutomationDetails.ID, "cicd/eslint/Client")
	}
	// The stamp is metadata only — it must never cost a finding.
	if len(got.Runs[0].Results) != 1 {
		t.Errorf("stamping changed the results array: %d results, want 1", len(got.Runs[0].Results))
	}
}

// TestStampSARIFAutomationIDPreservesExistingDetails: a run that already
// carries automationDetails keeps its other properties; only id is written.
func TestStampSARIFAutomationIDPreservesExistingDetails(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"golangci-lint"}},"automationDetails":{"id":"old","description":{"text":"keep me"}},"results":[]}]}`)
	stamped := stampSARIFAutomationID(doc, "golangci-lint", "src/internal")
	s := string(stamped)
	if !strings.Contains(s, `"id":"cicd/golangci-lint/src/internal"`) {
		t.Errorf("id was not restamped: %s", s)
	}
	if !strings.Contains(s, `"keep me"`) {
		t.Errorf("sibling automationDetails property was dropped: %s", s)
	}
}

// TestStampSARIFAutomationIDTolerance: malformed input comes back untouched —
// same contract as stampSARIFDriverVersion, because a cosmetic stamp must never
// turn a readable report into nothing.
func TestStampSARIFAutomationIDTolerance(t *testing.T) {
	for name, in := range map[string][]byte{
		"not json":       []byte(`{"version":`),
		"runs not array": []byte(`{"version":"2.1.0","runs":{}}`),
	} {
		out := stampSARIFAutomationID(in, "eslint", "Client")
		if string(out) != string(in) {
			t.Errorf("%s: input was rewritten: %s", name, out)
		}
	}
}

// TestSARIFAutomationIDNamesTheRoot: "." is the mount root; as a category
// segment it would read as noise, so it gets a name.
func TestSARIFAutomationIDNamesTheRoot(t *testing.T) {
	for in, want := range map[string]string{
		".":                    "cicd/golangci-lint/root",
		"":                     "cicd/golangci-lint/root",
		"src/internal":         "cicd/golangci-lint/src/internal",
		"Server/Server.csproj": "cicd/golangci-lint/Server/Server.csproj",
	} {
		if got := sarifAutomationID("golangci-lint", in); got != want {
			t.Errorf("sarifAutomationID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCleanRunsEmitEmptyResults drives the three real parsers on their clean
// inputs, because the invariant is only worth anything where the documents are
// actually produced. Each tool's "no problems" payload is its own shape: ESLint
// writes an empty array of files, dotnet format writes an empty array of
// changes, pylint writes an empty array of messages.
func TestCleanRunsEmitEmptyResults(t *testing.T) {
	eslint, _ := parseEslintJSON([]byte("[]"), "9.39.5")
	if eslint == nil {
		t.Fatal("clean ESLint run produced no document")
	}
	dotnet, _, _ := parseDotnetFormatReport([]byte("[]"), "10.0.100", dotnetSrcMount)
	if dotnet == nil {
		t.Fatal("clean dotnet format run produced no document")
	}
	pylint, err := json.Marshal(buildPylintSarif(nil))
	if err != nil {
		t.Fatalf("marshal pylint document: %v", err)
	}

	for name, raw := range map[string][]byte{
		"eslint":        eslint,
		"dotnet-format": dotnet,
		"pylint":        pylint,
	} {
		if strings.Contains(string(raw), `"results":null`) {
			t.Errorf("%s clean run emitted a null results array: %s", name, raw)
		}
		results, present := resultsOf(t, raw)
		if !present {
			t.Errorf("%s clean run omitted the results property: %s", name, raw)
			continue
		}
		if len(results) != 0 {
			t.Errorf("%s clean run reported %d results, want 0: %s", name, len(results), raw)
		}
	}
}
