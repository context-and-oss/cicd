package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPinnedSemgrepMetadataReachesCombinedEvidence(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fixture := filepath.Join(root, "testdata", "semgrep-finding-metadata")
	raw, err := os.ReadFile(filepath.Join(fixture, "native.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("python3", "-B", filepath.Join(root, "src", "security", "semgrep_metadata.py"), "--json", filepath.Join(fixture, "native.json"), "--sarif", path).CombinedOutput(); err != nil {
		t.Fatalf("enrich: %v\n%s", err, output)
	}
	enriched, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	part := &envelope{
		ModuleName: "security", Stage: "stage-2", Passed: true, Outcome: OutcomeFindings,
		FindingsCount: 3, FindingsBySeverity: map[Severity]int{SeverityHigh: 3},
		SARIFReport: enriched,
		Sources:     []SourceStatus{{Tool: "semgrep", Concern: ConcernSAST, Outcome: OutcomeFindings, FindingsCount: 3}},
	}
	combined := buildCombined("evidence", "cross-cutting", repoContext{}, []*envelope{part}, time.Now())
	if !combined.Passed || combined.FindingsCount != 3 || combined.FindingsBySeverity[SeverityHigh] != 3 || len(combined.Findings) != 3 {
		t.Fatalf("classification changed counts/gate: %+v", combined)
	}
	var security, style, unknown Finding
	for _, f := range combined.Findings {
		switch f.Rule {
		case "synthetic-security-audit":
			security = f
		case "synthetic-style":
			style = f
		case "synthetic-unknown":
			unknown = f
		}
	}
	if security.Concern != ConcernSAST || security.Category != "security" || security.Confidence != "LOW" ||
		!reflect.DeepEqual(security.Subcategories, []string{"audit"}) || !reflect.DeepEqual(security.WeaknessIDs, []string{"CWE-79"}) ||
		security.ClassificationSource != "scanner-metadata" || security.Severity != SeverityHigh || security.Line != 2 {
		t.Fatalf("security metadata missing or changed: %+v", security)
	}
	if style.Category != "style" || style.Confidence != "HIGH" || style.Concern != ConcernSAST {
		t.Fatalf("style was inferred as security: %+v", style)
	}
	if unknown.Category != "" || unknown.Confidence != "" || unknown.ClassificationSource != "" || unknown.Concern != ConcernSAST {
		t.Fatalf("ERROR/very-high precision invented classification: %+v", unknown)
	}
	// The exact classified row can appear in both a producer's explicit list
	// and its native payload. It must not be rendered twice.
	part.Findings = []Finding{security}
	if got := mergeFindings([]*envelope{part}); len(got) != 3 {
		t.Fatalf("duplicate classified row: %+v", got)
	}
	bytes, err := marshalBundleDoc("combined-evidence.json", combined)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip envelope
	if err := json.Unmarshal(bytes, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip.Findings, combined.Findings) {
		t.Fatalf("bundle lost metadata: %v", err)
	}
}

func TestOptionalFindingMetadataDoesNotDiscardFindings(t *testing.T) {
	for _, metadata := range []string{`null`, `[]`, `"invalid"`, `{"category":false}`, `{"confidence":3}`} {
		raw := json.RawMessage(`{"runs":[{"tool":{"driver":{"name":"custom"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"},"properties":{"cicdFindingMetadata":` + metadata + `}}]}]}`)
		got := sarifFindings(raw)
		if len(got) != 1 || got[0].Severity != SeverityHigh || got[0].Category != "" || got[0].Confidence != "" {
			t.Fatalf("optional metadata %s changed finding: %+v", metadata, got)
		}
	}
}

func TestFindingClassificationIsAllowlistedAndNotSeverity(t *testing.T) {
	f := Finding{Severity: SeverityLow, Rule: "r", Message: "m"}
	applyFindingMetadata(&f, json.RawMessage(`{"concern":"sast","category":"security","confidence":"LOW","subcategories":["audit","audit","confirmed"],"weaknessIds":["CWE-89","CWE-79","CWE-79","not-a-weakness"],"classificationSource":"scanner-metadata","severity":"CRITICAL","confirmed":true}`))
	if f.Severity != SeverityLow || f.Confidence != "LOW" || !reflect.DeepEqual(f.Subcategories, []string{"audit"}) ||
		!reflect.DeepEqual(f.WeaknessIDs, []string{"CWE-79", "CWE-89"}) {
		t.Fatalf("metadata changed severity or copied unapproved fields: %+v", f)
	}
	unknown := Finding{}
	applyFindingMetadata(&unknown, json.RawMessage(`{"concern":"unknown-new-concern","category":"security","confidence":"HIGH","classificationSource":"guess"}`))
	if !reflect.DeepEqual(unknown, Finding{}) {
		t.Fatalf("unrecognised provenance became an assertion: %+v", unknown)
	}
}

func TestOldEvidenceStillReadsWithoutClassification(t *testing.T) {
	var old envelope
	if err := json.Unmarshal([]byte(`{"schemaVersion":"1.6.0","findings":[{"severity":"HIGH","tool":"custom","rule":"r","message":"m"}]}`), &old); err != nil {
		t.Fatal(err)
	}
	got := mergeFindings([]*envelope{&old})
	if len(got) != 1 || got[0].Category != "" || got[0].Confidence != "" || got[0].Concern != "" {
		t.Fatalf("old finding acquired invented metadata: %+v", got)
	}
	wire, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"category", "confidence", "concern", "subcategories", "weaknessIds", "classificationSource"} {
		if strings.Contains(string(wire), `"`+field+`"`) {
			t.Errorf("absent metadata was emitted as %s", field)
		}
	}
}

func TestMetadataDoesNotUnsuppressResults(t *testing.T) {
	raw := json.RawMessage(`{"runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"},"suppressions":[{"status":"accepted"}],"properties":{"cicdFindingMetadata":{"category":"security","confidence":"HIGH","classificationSource":"scanner-metadata"}}}]}]}`)
	if got := sarifFindings(raw); len(got) != 0 {
		t.Fatalf("classification revived an accepted suppression: %+v", got)
	}
}

func TestClassificationSurvivesTheDetailCap(t *testing.T) {
	security := Finding{
		Severity: SeverityMedium, Tool: "semgrep", Rule: "synthetic", Message: "m",
		Concern: ConcernSAST, Category: "security", Subcategories: []string{"audit"},
		Confidence: "LOW", WeaknessIDs: []string{"CWE-79"}, ClassificationSource: "scanner-metadata",
	}
	merged := mergeFindings([]*envelope{
		{ModuleName: "quality", Findings: styleRows(maxCombinedFindings + 10)},
		{ModuleName: "security", Findings: []Finding{security}},
	})
	kept, warning := capFindings(merged)
	if warning == "" || len(kept) != maxCombinedFindings || !reflect.DeepEqual(kept[0], security) {
		t.Fatalf("detail cap lost classification: warning=%q first=%+v", warning, kept[0])
	}
}

func TestMetadataParticipatesInTotalOrderAndDedupe(t *testing.T) {
	base := Finding{Severity: SeverityHigh, Tool: "custom", Rule: "r", Message: "m", ArtifactPath: "a.js", Line: 3}
	var rows []classedFinding
	add := func(f Finding) { rows = append(rows, classedFinding{Finding: f, class: classSecurity}) }
	add(base)
	f := base
	f.Category = "security"
	add(f)
	f = base
	f.Subcategories = []string{"audit"}
	add(f)
	f = base
	f.WeaknessIDs = []string{"CWE-79"}
	add(f)
	f = base
	f.Confidence = "LOW"
	add(f)
	f = base
	f.Concern = ConcernSAST
	add(f)
	f = base
	f.ClassificationSource = "scanner-metadata"
	add(f)
	rows = append(rows, rows...) // exact duplicates, including list fields
	want := orderFindings(append([]classedFinding{}, rows...))
	if len(want) != 7 {
		t.Fatalf("metadata collapsed or duplicated rows: %+v", want)
	}
	rng := rand.New(rand.NewSource(17))
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
		if got := orderFindings(append([]classedFinding{}, rows...)); !reflect.DeepEqual(got, want) {
			t.Fatal("optional metadata broke deterministic total ordering")
		}
	}
}
