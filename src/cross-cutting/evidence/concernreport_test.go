package main

import (
	"encoding/json"
	"testing"
	"time"
)

// TestTheEnvelopeAndTheBundleAgreeAboutEveryConcern is the whole reason the
// fold lives in the aggregator instead of in notify. concerns/index.json and
// the pull request comment are read by the same person in the same sitting; if
// they can disagree, they eventually will, and neither document will fail.
func TestTheEnvelopeAndTheBundleAgreeAboutEveryConcern(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName: "security", Stage: "domain", Passed: false,
			Sources: []SourceStatus{
				{ModuleName: "security", Tool: "semgrep", Concern: ConcernSAST, Passed: true, Outcome: OutcomeClean,
					Examined: &Examined{Count: 40, Unit: "files"}},
				{ModuleName: "security", Tool: "trivy", Concern: ConcernSCA, Passed: false, Outcome: OutcomeFindings,
					FindingsCount: 7, Examined: &Examined{Count: 900, Unit: "packages"}},
			},
		},
		{
			ModuleName: "quality", Stage: "domain", Passed: true, Outcome: OutcomeClean,
			Concern: ConcernCoverage, Tool: toolInfo{Name: "go test"},
		},
	}

	_, idx := buildConcerns(envs, []string{"01-security.json", "02-quality.json"})
	rep := concernReport(envs)

	if len(rep.Answered) != len(idx.Concerns) {
		t.Fatalf("envelope reports %d concerns, bundle index reports %d", len(rep.Answered), len(idx.Concerns))
	}
	// Compared as wire bytes, not as structs: the claim is that the two
	// documents SAY the same thing, and Examined is a pointer that is
	// separately allocated on each side.
	for i, got := range rep.Answered {
		gotJSON := mustJSON(t, got)
		wantJSON := mustJSON(t, idx.Concerns[i].ConcernRollup)
		if gotJSON != wantJSON {
			t.Errorf("concern %d:\n  envelope     %s\n  bundle index %s", i, gotJSON, wantJSON)
		}
	}
	if len(rep.NotAnswered) != len(idx.NotAnswered) {
		t.Errorf("notAnswered: envelope %v, bundle %v", rep.NotAnswered, idx.NotAnswered)
	}
}

// TestCombineAlwaysFoldsTheConcerns pins the field onto the combined envelope
// itself, which is the only copy notify ever sees.
func TestCombineAlwaysFoldsTheConcerns(t *testing.T) {
	got := buildCombined("evidence", "cross-cutting", repoContext{}, []*envelope{{
		ModuleName: "risk", Stage: "domain", Passed: true, Outcome: OutcomeClean,
		Concern: ConcernIaC, Tool: toolInfo{Name: "conftest"},
	}}, time.Now())
	if got.Concerns == nil {
		t.Fatal("combined envelope carries no concern report")
	}
	if len(got.Concerns.Answered) != 1 || got.Concerns.Answered[0].Concern != ConcernIaC {
		t.Fatalf("answered = %+v, want one IaC rollup", got.Concerns.Answered)
	}
	if got.Concerns.Answered[0].Tools != 1 {
		t.Errorf("Tools = %d, want 1", got.Concerns.Answered[0].Tools)
	}
	if len(got.Concerns.NotAnswered) != len(concernOrder)-1 {
		t.Errorf("notAnswered = %v, want the other nine", got.Concerns.NotAnswered)
	}
}

// TestARunThatDeclaredNothingStillSaysSo. An empty Answered beside a full
// NotAnswered is the honest report of an unconverted pipeline. Returning nil
// would say "nobody folded this", which would be untrue and would make the
// section vanish from the comment.
func TestARunThatDeclaredNothingStillSaysSo(t *testing.T) {
	got := buildCombined("evidence", "cross-cutting", repoContext{}, []*envelope{{
		ModuleName: "legacy", Stage: "domain", Passed: true, Tool: toolInfo{Name: "something"},
	}}, time.Now())
	if got.Concerns == nil {
		t.Fatal("a run that declared no concern must still report that it declared none")
	}
	if len(got.Concerns.Answered) != 1 {
		t.Fatalf("answered = %+v, want the unclassified rollup", got.Concerns.Answered)
	}
	if got.Concerns.Answered[0].Concern != "" {
		t.Errorf("unclassified rollup names concern %q", got.Concerns.Answered[0].Concern)
	}
	if len(got.Concerns.NotAnswered) != len(concernOrder) {
		t.Errorf("notAnswered = %v, want all ten", got.Concerns.NotAnswered)
	}
}

// TestAnUnclassifiedRowIsAnsweredNotAbsent. A tool that ran and reported is
// not a missing leg, and filing it under notAnswered would hide an unconverted
// producer behind a list that reads as "these were not run".
func TestAnUnclassifiedRowIsAnsweredNotAbsent(t *testing.T) {
	rep := concernReport([]*envelope{{
		ModuleName: "security", Stage: "domain", Passed: false,
		Sources: []SourceStatus{
			{ModuleName: "security", Tool: "mystery", Passed: false, Outcome: OutcomeFindings, FindingsCount: 3},
		},
	}})
	for _, c := range rep.NotAnswered {
		if c == "" {
			t.Fatal("the unclassified group was filed as not answered")
		}
	}
	if len(rep.Answered) != 1 || rep.Answered[0].FindingsCount != 3 {
		t.Fatalf("answered = %+v, want the unclassified rollup carrying 3 findings", rep.Answered)
	}
}

// TestTheRollupDoesNotCarryTheRows keeps the envelope from doubling. The rows
// are already in Sources; a second copy is bytes that can disagree with the
// first.
func TestTheRollupDoesNotCarryTheRows(t *testing.T) {
	rep := concernReport([]*envelope{{
		ModuleName: "security", Stage: "domain", Passed: true,
		Sources: []SourceStatus{
			{ModuleName: "security", Tool: "gitleaks", Concern: ConcernSecrets, Passed: true, Outcome: OutcomeClean},
		},
	}})
	b, err := json.Marshal(rep.Answered[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["tools"].(float64); !ok {
		t.Fatalf("tools is %T, want a count", m["tools"])
	}
	for _, banned := range []string{"sources", "part", "moduleName", "findings"} {
		if _, ok := m[banned]; ok {
			t.Errorf("rollup carries %q; the rows belong in sources[] only", banned)
		}
	}
}

// TestTheConcernOrderIsTheSameInBothDocuments. A reader diffing the comment
// against the bundle should not have to re-sort either one.
func TestTheConcernOrderIsTheSameInBothDocuments(t *testing.T) {
	envs := []*envelope{{
		ModuleName: "security", Stage: "domain", Passed: true,
		Sources: []SourceStatus{
			{ModuleName: "security", Tool: "t", Concern: ConcernCoverage, Passed: true, Outcome: OutcomeClean},
			{ModuleName: "security", Tool: "u", Concern: ConcernSAST, Passed: true, Outcome: OutcomeClean},
			{ModuleName: "security", Tool: "v", Concern: ConcernSBOM, Passed: true, Outcome: OutcomeClean},
		},
	}}
	rep := concernReport(envs)
	want := []Concern{ConcernSAST, ConcernSBOM, ConcernCoverage}
	if len(rep.Answered) != len(want) {
		t.Fatalf("answered = %+v", rep.Answered)
	}
	for i, c := range want {
		if rep.Answered[i].Concern != c {
			t.Errorf("position %d is %q, want %q", i, rep.Answered[i].Concern, c)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
