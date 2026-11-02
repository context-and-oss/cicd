package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A synthetic failing-suite scenario, end to end through the aggregator.
//
// A quality envelope built under `fail-on: NONE` reports passed=true over a
// failed .NET suite — the documented gate contract — and until Outcome existed
// the only record of the failure was English prose in errors[]. This pins that
// the un-gated result survives the trip into combined-evidence.json, both on
// the source row a report generator reads and on the combined envelope.
func TestAFailedSuiteSurvivesTheAggregator(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName: "quality",
			Stage:      "domain",
			Tool:       toolInfo{Name: "quality"},
			Passed:     true,
			Outcome:    OutcomeFailed,
			Errors:     []string{"test dotnet: dotnet test failed (exit 1)"},
		},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if !combined.Passed {
		t.Fatal("combined.Passed = false: the gate contract must not change with this field")
	}
	if got := combined.Sources[0].Outcome; got != OutcomeFailed {
		t.Errorf("Sources[0].Outcome = %q, want FAILED", got)
	}
	if got := combined.Outcome; got != OutcomeFailed {
		t.Errorf("combined.Outcome = %q, want FAILED — passed=true and outcome=FAILED are both true at once", got)
	}
}

// A module that fuses several scanners declares its own rows, and those rows —
// not a synthesised one for the envelope — are what the combined outcome folds.
func TestPerToolRowsAreWhatTheCombinedOutcomeFolds(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName: "security",
			Stage:      "domain",
			Tool:       toolInfo{Name: "security-source"},
			Passed:     true,
			Outcome:    OutcomeFindings,
			Sources: []SourceStatus{
				{ModuleName: "security", Tool: "semgrep", Scope: "security-source", Passed: true, Outcome: OutcomeFindings, FindingsCount: 9},
				{ModuleName: "security", Tool: "gitleaks", Scope: "security-source", Passed: true, Outcome: OutcomeClean},
			},
		},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if len(combined.Sources) != 2 {
		t.Fatalf("Sources length = %d, want 2 — the declared rows replace the envelope, they do not add to it", len(combined.Sources))
	}
	if got := combined.Outcome; got != OutcomeFindings {
		t.Errorf("combined.Outcome = %q, want FINDINGS", got)
	}
}

// One module that states no outcome must not be summarised as if it had. The
// alternative is a combined envelope reporting CLEAN over a run where a module
// never said what it found — the failure class this repository exists to catch.
func TestOneSilentModuleLeavesTheCombinedOutcomeUnset(t *testing.T) {
	envs := []*envelope{
		{ModuleName: "quality", Stage: "domain", Passed: true, Outcome: OutcomeClean},
		{ModuleName: "risk", Stage: "cross-cutting", Passed: true},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if got := combined.Outcome; got != "" {
		t.Fatalf("combined.Outcome = %q, want unset", got)
	}
	if got := combined.Sources[0].Outcome; got != OutcomeClean {
		t.Errorf("the converted module's own row lost its outcome: %q", got)
	}
}

// Both properties are omitempty, so an unconverted producer emits no key at all
// rather than a wrong one. A consumer can tell "did not say" from any verdict,
// which is what makes a staged rollout safe.
func TestAnUnsetOutcomeIsAbsentFromTheWire(t *testing.T) {
	data, err := json.Marshal(&envelope{ModuleName: "risk", Passed: true, Sources: []SourceStatus{{ModuleName: "risk"}}})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["outcome"]; ok {
		t.Errorf("envelope emitted an outcome key with nothing to say: %s", data)
	}
	row := back["sources"].([]any)[0].(map[string]any)
	if _, ok := row["outcome"]; ok {
		t.Errorf("source row emitted an outcome key with nothing to say: %s", data)
	}
}

// A run with no source envelopes at all folds to unset, not CLEAN. combine.yml
// can produce one: every module skipped, nothing to aggregate. Reporting CLEAN
// there is the "absent evidence read as clean evidence" defect exactly.
func TestNoSourcesIsNotACleanRun(t *testing.T) {
	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, nil, time.Now())
	if got := combined.Outcome; got != "" {
		t.Fatalf("combined.Outcome = %q over zero envelopes, want unset", got)
	}
	if !combined.Passed {
		t.Fatal("combined.Passed changed for the empty case; this field must not move the gate")
	}
}

// A synthetic mixed run combines invented scanner counts with a runner error
// and three skipped checks: risk with no risk files, intent not required, and
// build under --artifact none. Skips must not fold to CLEAN, and findings must
// not hide the .NET leg that exited 1 without a result.
func TestTheWholeRunReportsWhatItActuallyDid(t *testing.T) {
	envs := []*envelope{
		// passed:false, as the fixed producer now emits it: the leg produced no
		// result, and that is the half of the verdict NONE never suppresses.
		{ModuleName: "quality", Stage: "domain", Tool: toolInfo{Name: "quality"}, Passed: false, Outcome: OutcomeError,
			Errors: []string{"test dotnet: dotnet test failed (exit 1)"}},
		{ModuleName: "security", Stage: "domain", Tool: toolInfo{Name: "security-source"}, Passed: true, Outcome: OutcomeFindings,
			Sources: []SourceStatus{
				{ModuleName: "security", Tool: "semgrep", Scope: "security-source", Passed: true, Outcome: OutcomeFindings, FindingsCount: 9},
				{ModuleName: "security", Tool: "gitleaks", Scope: "security-source", Passed: true, Outcome: OutcomeFindings, FindingsCount: 2},
				{ModuleName: "security", Tool: "trivy", Scope: "security-source", Passed: true, Outcome: OutcomeClean},
			}},
		{ModuleName: "security", Stage: "domain", Tool: toolInfo{Name: "security-license"}, Passed: true, Outcome: OutcomeClean,
			Examined: &Examined{Unit: "licence declarations", Count: 248},
			Sources: []SourceStatus{
				{ModuleName: "security", Tool: "trivy-license", Scope: "security-license", Passed: true, Outcome: OutcomeClean,
					Examined: &Examined{Unit: "licence declarations", Count: 248}},
			}},
		{ModuleName: "risk", Stage: "domain", Tool: toolInfo{Name: "risk-validate"}, Passed: true, Outcome: OutcomeSkipped,
			Examined: &Examined{Unit: "infrastructure files", Count: 0}},
		{ModuleName: "intent", Stage: "cross-cutting", Tool: toolInfo{Name: "intent-gate"}, Passed: true, Outcome: OutcomeSkipped},
		{ModuleName: "build", Stage: "domain", Tool: toolInfo{Name: "artifact-attestation"}, Passed: true, Outcome: OutcomeSkipped},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.Passed {
		t.Fatal("combined.Passed = true over a run whose .NET leg produced no result")
	}
	// ERROR, because the .NET leg's runner exited non-zero with every
	// test green and nothing in the run can say why.
	if got := combined.Outcome; got != OutcomeError {
		t.Errorf("combined.Outcome = %q, want ERROR", got)
	}

	want := map[string]Outcome{
		"quality":              OutcomeError,
		"semgrep":              OutcomeFindings,
		"gitleaks":             OutcomeFindings,
		"trivy":                OutcomeClean,
		"trivy-license":        OutcomeClean,
		"risk-validate":        OutcomeSkipped,
		"intent-gate":          OutcomeSkipped,
		"artifact-attestation": OutcomeSkipped,
	}
	if len(combined.Sources) != len(want) {
		t.Fatalf("got %d source rows, want %d", len(combined.Sources), len(want))
	}
	for _, row := range combined.Sources {
		w, ok := want[row.Tool]
		if !ok {
			t.Errorf("unexpected row %q", row.Tool)
			continue
		}
		if row.Outcome != w {
			t.Errorf("%s: outcome = %q, want %q", row.Tool, row.Outcome, w)
		}
		if wantPassed := row.Tool != "quality"; row.Passed != wantPassed {
			t.Errorf("%s: passed = %v, want %v", row.Tool, row.Passed, wantPassed)
		}
	}
}

// A part that wrote passed:true beside ERROR, with its reason in errors[],
// fails the combined verdict. Every workflow gate reads only combined.passed,
// so this is the one place a producer that got the fold wrong is still caught.
// The controls are the two cases that look alike and must stay green: a real
// failing suite under --fail-on NONE (FAILED, reason in errors[]) and a Teams
// card notify could not deliver (ERROR, reason in warnings[]).
func TestAPartThatProducedNoResultFailsTheCombinedVerdict(t *testing.T) {
	errored := &envelope{ModuleName: "quality", Tool: toolInfo{Name: "go-test"}, Passed: true, Outcome: OutcomeError,
		Errors: []string{"go test: go test failed (exit 1)"}}
	failingSuite := &envelope{ModuleName: "quality", Tool: toolInfo{Name: "go-test"}, Passed: true, Outcome: OutcomeFailed,
		FailOnSeverity: SeverityNone, Errors: []string{"go test: go test failed (exit 1)"}}
	lostCard := &envelope{ModuleName: "notify", Tool: toolInfo{Name: "teams"}, Passed: true, Outcome: OutcomeError,
		Warnings: []string{"teams: card not delivered"}}

	if got := buildCombined("x", "cross-cutting", repoContext{}, []*envelope{errored}, time.Now()); got.Passed {
		t.Error("passed:true + ERROR + errors[] combined to passed:true")
	}
	if got := buildCombined("x", "cross-cutting", repoContext{}, []*envelope{failingSuite, lostCard}, time.Now()); !got.Passed {
		t.Errorf("control: a failing suite under NONE and a lost card must stay green; errors=%q", got.Errors)
	}
}

// Three skipped checks must not average out into a clean headline, and a real
// finding must still beat them to it.
func TestSkippedChecksDegradeTheHeadlineButFindingsStillWinIt(t *testing.T) {
	skippedOnly := buildCombined("x", "cross-cutting", repoContext{}, []*envelope{
		{ModuleName: "risk", Tool: toolInfo{Name: "risk-validate"}, Passed: true, Outcome: OutcomeSkipped},
		{ModuleName: "quality", Tool: toolInfo{Name: "quality"}, Passed: true, Outcome: OutcomeClean},
	}, time.Now())
	if got := skippedOnly.Outcome; got != OutcomeSkipped {
		t.Errorf("outcome = %q, want SKIPPED — one check did not run, so the run is not clean", got)
	}

	withFindings := buildCombined("x", "cross-cutting", repoContext{}, []*envelope{
		{ModuleName: "risk", Tool: toolInfo{Name: "risk-validate"}, Passed: true, Outcome: OutcomeSkipped},
		{ModuleName: "security", Tool: toolInfo{Name: "semgrep"}, Passed: true, Outcome: OutcomeFindings},
	}, time.Now())
	if got := withFindings.Outcome; got != OutcomeFindings {
		t.Errorf("outcome = %q, want FINDINGS — an absence must never bury a finding", got)
	}
}

// examined is propagated, never derived, for the same reason outcome is: this
// layer cannot reconstruct how much a scanner looked at.
func TestExaminedSurvivesTheAggregatorAndTheWire(t *testing.T) {
	combined := buildCombined("x", "cross-cutting", repoContext{}, []*envelope{
		{ModuleName: "security", Tool: toolInfo{Name: "security-license"}, Passed: true, Outcome: OutcomeClean,
			Examined: &Examined{Unit: "licence declarations", Count: 248}},
		{ModuleName: "intent", Tool: toolInfo{Name: "intent-gate"}, Passed: true, Outcome: OutcomeSkipped},
	}, time.Now())

	var licence, intent SourceStatus
	for _, r := range combined.Sources {
		switch r.Tool {
		case "security-license":
			licence = r
		case "intent-gate":
			intent = r
		}
	}
	if licence.Examined == nil {
		t.Fatal("licence row lost its examined count")
	}
	if licence.Examined.Count != 248 || licence.Examined.Unit != "licence declarations" {
		t.Errorf("examined = %+v, want 248 licence declarations", *licence.Examined)
	}
	if licence.Examined.Total != 0 {
		t.Errorf("total = %d, want 0 — this scan cannot see its own denominator and must not imply one", licence.Examined.Total)
	}
	if intent.Examined != nil {
		t.Errorf("intent row invented an examined count: %+v", *intent.Examined)
	}

	// A producer that did not say must put nothing on the wire, so a consumer
	// cannot read a confident zero where there was no claim.
	blob, err := json.Marshal(intent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "examined") {
		t.Errorf("unset examined reached the wire: %s", blob)
	}
}
