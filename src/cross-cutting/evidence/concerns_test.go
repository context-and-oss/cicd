package main

import (
	"encoding/json"
	"testing"
)

// env builds an envelope with per-tool rows, the shape a fused module produces.
func env(module string, rows ...SourceStatus) *envelope {
	return &envelope{ModuleName: module, Stage: "domain", Sources: rows}
}

func row(tool string, c Concern, o Outcome, findings int) SourceStatus {
	return SourceStatus{
		ModuleName:    "security",
		Stage:         "domain",
		Tool:          tool,
		Concern:       c,
		Passed:        o != OutcomeFailed && o != OutcomeError,
		Outcome:       o,
		FindingsCount: findings,
	}
}

// TestAConcernGathersItsToolsFromEveryModule is the whole point of the
// directory: the question "what about secrets?" is answered by two tools in two
// different envelopes, and no reader should have to know that.
func TestAConcernGathersItsToolsFromEveryModule(t *testing.T) {
	envs := []*envelope{
		env("security",
			row("semgrep", ConcernSAST, OutcomeClean, 0),
			row("gitleaks", ConcernSecrets, OutcomeFindings, 2),
		),
		env("security", row("trufflehog", ConcernSecrets, OutcomeFindings, 1)),
	}
	files, idx := buildConcerns(envs, []string{"01-security.json", "02-security.json"})

	secrets, ok := files["secrets.json"]
	if !ok {
		t.Fatalf("no secrets.json; got %v", keys(files))
	}
	if len(secrets.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(secrets.Tools))
	}
	if secrets.FindingsCount != 3 {
		t.Errorf("findings = %d, want 3", secrets.FindingsCount)
	}
	if secrets.Tools[0].Part != "parts/01-security.json" ||
		secrets.Tools[1].Part != "parts/02-security.json" {
		t.Errorf("rows must point at the part they came from: %q, %q",
			secrets.Tools[0].Part, secrets.Tools[1].Part)
	}
	// The pointer is the design: a row must not carry the evidence itself.
	if len(idx.Concerns) != 2 {
		t.Fatalf("index lists %d concerns, want sast and secrets", len(idx.Concerns))
	}
}

// TestAConcernNobodyAnsweredGetsNoFile is the failure class this directory
// could otherwise introduce. An empty concerns/sast.json is a document saying
// SAST ran and found nothing.
func TestAConcernNobodyAnsweredGetsNoFile(t *testing.T) {
	envs := []*envelope{env("security", row("semgrep", ConcernSAST, OutcomeClean, 0))}
	files, idx := buildConcerns(envs, []string{"01-security.json"})

	if _, ok := files["dast.json"]; ok {
		t.Fatal("wrote a dast.json for a run with no DAST leg")
	}
	if len(files) != 1 {
		t.Fatalf("wrote %d files, want only sast.json: %v", len(files), keys(files))
	}
	var found bool
	for _, c := range idx.NotAnswered {
		if c == ConcernDAST {
			found = true
		}
	}
	if !found {
		t.Errorf("dast must appear in notAnswered, else a missing section reads as a clean one; got %v", idx.NotAnswered)
	}
	if len(idx.NotAnswered) != len(concernOrder)-1 {
		t.Errorf("notAnswered = %d, want every concern but sast", len(idx.NotAnswered))
	}
}

// TestAnUndeclaredConcernIsReportedNotDropped: a producer that gains a tool
// without saying what question it answers must be loud.
func TestAnUndeclaredConcernIsReportedNotDropped(t *testing.T) {
	envs := []*envelope{env("security",
		row("semgrep", ConcernSAST, OutcomeClean, 0),
		row("newtool", "", OutcomeFindings, 7),
	)}
	files, idx := buildConcerns(envs, []string{"01-security.json"})

	un, ok := files["unclassified.json"]
	if !ok {
		t.Fatalf("undeclared row vanished; files = %v", keys(files))
	}
	if un.FindingsCount != 7 || len(un.Tools) != 1 || un.Tools[0].Tool != "newtool" {
		t.Errorf("unclassified = %+v, want the newtool row intact", un)
	}
	if un.Concern != "" {
		t.Errorf("unclassified must name no concern, got %q", un.Concern)
	}
	// It is listed, not just written — an unopened file is not a report.
	var listed bool
	for _, e := range idx.Concerns {
		if e.File == "concerns/unclassified.json" {
			listed = true
		}
	}
	if !listed {
		t.Error("unclassified.json missing from index")
	}
}

// TestTheConcernVerdictCannotDisagreeWithItsRows pins the two folds to the
// rules the combined envelope uses.
func TestTheConcernVerdictCannotDisagreeWithItsRows(t *testing.T) {
	envs := []*envelope{env("security",
		row("trivy", ConcernSCA, OutcomeClean, 0),
		row("trivy", ConcernSCA, OutcomeError, 0),
	)}
	files, _ := buildConcerns(envs, []string{"01-security.json"})
	sca := files["sca.json"]

	if sca.Passed {
		t.Error("passed must be the AND: one row failed")
	}
	if sca.Outcome != OutcomeError {
		t.Errorf("outcome = %q, want ERROR — not knowing outranks knowing", sca.Outcome)
	}
}

// TestOneSilentToolCollapsesTheConcernOutcome: worstOutcome's rule has to
// survive the re-index, or a concern reports CLEAN because a leg declined to
// answer.
func TestOneSilentToolCollapsesTheConcernOutcome(t *testing.T) {
	envs := []*envelope{env("security",
		row("trivy", ConcernSCA, OutcomeClean, 0),
		row("other", ConcernSCA, "", 0),
	)}
	files, _ := buildConcerns(envs, []string{"01-security.json"})
	if got := files["sca.json"].Outcome; got != "" {
		t.Errorf("outcome = %q, want unset: a tool that did not say must not be folded in as CLEAN", got)
	}
}

// TestADenominatorIsOnlySummedWhenTheSumMeansSomething.
func TestADenominatorIsOnlySummedWhenTheSumMeansSomething(t *testing.T) {
	mk := func(ex ...*Examined) []concernRow {
		out := make([]concernRow, 0, len(ex))
		for _, e := range ex {
			out = append(out, concernRow{Examined: e})
		}
		return out
	}
	pkgs := func(n int) *Examined { return &Examined{Unit: "resolved packages", Count: n} }

	if got := foldExamined(mk(pkgs(96), pkgs(4))); got == nil || got.Count != 100 {
		t.Errorf("same unit must sum: %+v", got)
	}
	if got := foldExamined(mk(pkgs(96), &Examined{Unit: "coverable lines", Count: 50000})); got != nil {
		t.Errorf("mixed units must not sum, got %+v — that number is about nothing", got)
	}
	if got := foldExamined(mk(pkgs(96), nil)); got != nil {
		t.Errorf("a silent tool must suppress the sum, got %+v — an understated denominator flatters the findings", got)
	}
	if got := foldExamined(mk(&Examined{Count: 3})); got != nil {
		t.Errorf("a count with no unit cannot be reported, got %+v", got)
	}
	if got := foldExamined(nil); got != nil {
		t.Errorf("no rows, no denominator, got %+v", got)
	}
	// Partial IS folded: each is a subset of its own row's Count, so the sum
	// stays bounded by the folded Count. Dropping it would let a concern row
	// read as fully examined while one of its tools said otherwise.
	if got := foldExamined(mk(&Examined{Unit: "files", Count: 300, Partial: 7}, &Examined{Unit: "files", Count: 50})); got == nil || got.Partial != 7 || got.Count != 350 {
		t.Errorf("partial must survive the fold: %+v", got)
	}
	// Total is deliberately not folded: two tools' scopes overlap invisibly.
	withTotal := mk(&Examined{Unit: "files", Count: 3, Total: 10}, &Examined{Unit: "files", Count: 4, Total: 10})
	if got := foldExamined(withTotal); got == nil || got.Total != 0 {
		t.Errorf("total must stay unset, got %+v", got)
	}
}

// TestAFusedModuleIsCountedOnce guards the seam envelopeRows exists to close:
// an envelope declaring rows must not also contribute a row for itself.
func TestAFusedModuleIsCountedOnce(t *testing.T) {
	fused := env("security",
		row("semgrep", ConcernSAST, OutcomeClean, 0),
		row("trivy", ConcernSCA, OutcomeFindings, 5),
	)
	fused.FindingsCount = 5
	fused.Concern = ConcernSCA

	files, _ := buildConcerns([]*envelope{fused}, []string{"01-security.json"})
	if got := files["sca.json"].FindingsCount; got != 5 {
		t.Errorf("sca findings = %d, want 5 — the envelope must not be counted alongside its own rows", got)
	}
	if n := len(files["sca.json"].Tools); n != 1 {
		t.Errorf("sca tools = %d, want 1", n)
	}
}

// TestAModuleWithNoRowsStillReachesItsConcern: risk, build and the ZAP scan
// declare at envelope level and have no Sources.
func TestAModuleWithNoRowsStillReachesItsConcern(t *testing.T) {
	e := &envelope{
		ModuleName: "risk", Stage: "cross-cutting",
		Tool: toolInfo{Name: "risk-validate"}, Concern: ConcernIaC,
		Passed: true, Outcome: OutcomeSkipped,
		Examined: &Examined{Unit: "infrastructure files", Count: 0},
	}
	files, _ := buildConcerns([]*envelope{e}, []string{"01-risk.json"})
	iac, ok := files["iac.json"]
	if !ok {
		t.Fatalf("envelope-level concern lost; files = %v", keys(files))
	}
	if iac.Outcome != OutcomeSkipped || iac.Tools[0].Tool != "risk-validate" {
		t.Errorf("iac = %+v", iac)
	}
	if iac.Examined == nil || iac.Examined.Count != 0 {
		t.Errorf("a present zero is a claim and must survive: %+v", iac.Examined)
	}
}

// TestTheIndexOrderIsStableAcrossRuns — a report diffed week to week must not
// move because a scanner found something.
func TestTheIndexOrderIsStableAcrossRuns(t *testing.T) {
	build := func(findings int) []string {
		envs := []*envelope{env("q",
			row("coverage", ConcernCoverage, OutcomeClean, 0),
			row("semgrep", ConcernSAST, OutcomeFindings, findings),
			row("trivy", ConcernSCA, OutcomeClean, 0),
		)}
		_, idx := buildConcerns(envs, []string{"01-q.json"})
		out := []string{}
		for _, e := range idx.Concerns {
			out = append(out, e.File)
		}
		return out
	}
	a, b := build(0), build(999)
	if len(a) != 3 {
		t.Fatalf("got %v", a)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("order moved with findings: %v vs %v", a, b)
		}
	}
	// concernOrder, not alphabetical: sast before sca before coverage.
	want := []string{"concerns/sast.json", "concerns/sca.json", "concerns/coverage.json"}
	for i := range want {
		if a[i] != want[i] {
			t.Fatalf("order = %v, want %v", a, want)
		}
	}
}

// TestTheIndexIsJSONAConsumerCanRead — notAnswered must serialise as a present
// empty array rather than null when everything was answered, so a consumer
// reading it does not have to special-case nil.
func TestTheIndexIsJSONAConsumerCanRead(t *testing.T) {
	envs := []*envelope{env("security", row("semgrep", ConcernSAST, OutcomeClean, 0))}
	_, idx := buildConcerns(envs, []string{"01-security.json"})
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Concerns    []concernEntry `json:"concerns"`
		NotAnswered []Concern      `json:"notAnswered"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Concerns) != 1 || back.Concerns[0].File != "concerns/sast.json" {
		t.Errorf("round-trip lost the index: %s", b)
	}
	if back.Concerns[0].Tools != 1 {
		t.Errorf("tools count = %d, want 1", back.Concerns[0].Tools)
	}
}

// TestEveryIndexedConcernResolvesToAFile pins the lookup the bundle writer
// makes. Wrap iterates index entries and fetches each one from the files map
// by its basename; if the two ever key differently, the writer emits an index
// naming files it never wrote, and the failure is silent — a reader opens
// concerns/index.json, follows a path, and gets nothing. wrap.go carries the
// Dagger build tag and no test can reach it, so the correspondence is pinned
// here instead.
func TestEveryIndexedConcernResolvesToAFile(t *testing.T) {
	envs := []*envelope{env("security",
		row("semgrep", ConcernSAST, OutcomeClean, 0),
		row("trivy", ConcernSCA, OutcomeFindings, 3),
		row("mystery", "", OutcomeFindings, 1),
	)}
	files, idx := buildConcerns(envs, []string{"01-security.json"})

	if len(idx.Concerns) != len(files) {
		t.Fatalf("index lists %d, map holds %d: %v vs %v", len(idx.Concerns), len(files), idx.Concerns, keys(files))
	}
	for _, e := range idx.Concerns {
		base := e.File[len("concerns/"):]
		sum, ok := files[base]
		if !ok {
			t.Fatalf("index names %q but no such file was built; have %v", e.File, keys(files))
		}
		// The entry is a summary OF that file, so the two must agree.
		if sum.FindingsCount != e.FindingsCount || sum.Passed != e.Passed ||
			sum.Outcome != e.Outcome || len(sum.Tools) != e.Tools {
			t.Errorf("index row %q disagrees with its file: %+v vs %+v", e.File, e, sum)
		}
	}
}

func keys(m map[string]concernSummary) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
