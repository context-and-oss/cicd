//go:build unit_test

package main

import "testing"

// TestTheCoverageGateIsFinallyReachableByATest covers the decision that used to
// sit inline in Check, behind the Dagger build tag.
//
// It is worth stating why that matters. The gate once `continue`d on a missing
// figure, so --min-coverage passed for any language whose coverage report never
// appeared — which, for .NET, was every run: the collector name was word-split
// by the shell, no cobertura report was produced, and the gate was structurally
// unfailable. Nothing could reach it to notice.
func TestTheCoverageGateIsFinallyReachableByATest(t *testing.T) {
	cases := []struct {
		name        string
		pct         float64
		measured    bool
		lines       int
		minCoverage float64
		minLines    int

		wantOutcome  Outcome
		wantPassed   bool
		wantRan      bool
		wantErr      bool
		wantWarning  bool
		wantExamined bool
	}{
		{
			name: "no gate, no measurement: coverage this run does not have",
			// SKIPPED and not CLEAN: the test leg ran and produced no figure,
			// so there is nothing to be clean about. Absent coverage reading as
			// fine is the whole failure class.
			wantOutcome: OutcomeSkipped, wantPassed: true, wantRan: true,
		},
		{
			name: "no gate, a measurement: nothing to violate",
			pct:  2.5, measured: true, lines: 50000,
			wantOutcome: OutcomeClean, wantPassed: true, wantRan: true, wantExamined: true,
		},
		{
			name:        "the .NET bug: a gate that could not measure",
			minCoverage: 60,
			// Not SKIPPED. A configured gate that could not run is a non-run,
			// and gatedPassed fails a non-run at every threshold including NONE.
			wantOutcome: OutcomeError, wantPassed: false, wantRan: false, wantErr: true,
		},
		{
			name: "measured and over the bar",
			pct:  81.3, measured: true, lines: 12000, minCoverage: 60,
			wantOutcome: OutcomeClean, wantPassed: true, wantRan: true, wantExamined: true,
		},
		{
			name: "measured and under the bar: a real result that failed",
			pct:  2.5, measured: true, lines: 50000, minCoverage: 60,
			wantOutcome: OutcomeFailed, wantPassed: false, wantRan: true, wantErr: true, wantExamined: true,
		},
		{
			name: "too few lines to judge: a threshold exists and was declined",
			pct:  0, measured: true, lines: 12, minCoverage: 60, minLines: 100,
			// SKIPPED, not CLEAN. The bar was not cleared, it was not applied,
			// and a report must not render the two the same way.
			wantOutcome: OutcomeSkipped, wantPassed: true, wantRan: true, wantWarning: true, wantExamined: true,
		},
		{
			name: "the min-lines waiver does not rescue a failure above it",
			pct:  2.5, measured: true, lines: 50000, minCoverage: 60, minLines: 100,
			wantOutcome: OutcomeFailed, wantPassed: false, wantRan: true, wantErr: true, wantExamined: true,
		},
		{
			name: "zero measured lines is still a measurement, and still below the bar",
			pct:  0, measured: true, lines: 0, minCoverage: 60,
			wantOutcome: OutcomeFailed, wantPassed: false, wantRan: true, wantErr: true, wantExamined: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := coverageSource("dotnet", tc.pct, tc.measured, tc.lines, tc.minCoverage, tc.minLines)

			if v.Source.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q", v.Source.Outcome, tc.wantOutcome)
			}
			if v.Source.Passed != tc.wantPassed {
				t.Errorf("passed = %v, want %v", v.Source.Passed, tc.wantPassed)
			}
			if v.Ran != tc.wantRan {
				t.Errorf("ran = %v, want %v", v.Ran, tc.wantRan)
			}
			if (v.Err != "") != tc.wantErr {
				t.Errorf("err = %q, want error: %v", v.Err, tc.wantErr)
			}
			if (v.Warning != "") != tc.wantWarning {
				t.Errorf("warning = %q, want warning: %v", v.Warning, tc.wantWarning)
			}
			if (v.Source.Examined != nil) != tc.wantExamined {
				t.Errorf("examined = %v, want present: %v", v.Source.Examined, tc.wantExamined)
			}
			if v.Source.Examined != nil {
				if v.Source.Examined.Count != tc.lines {
					t.Errorf("examined.count = %d, want %d", v.Source.Examined.Count, tc.lines)
				}
				if v.Source.Examined.Unit != "coverable lines" {
					t.Errorf("examined.unit = %q", v.Source.Examined.Unit)
				}
			}
			if v.Source.Tool != "coverage" || v.Source.Scope != "dotnet" {
				t.Errorf("row identity = %q/%q, want coverage/dotnet", v.Source.Tool, v.Source.Scope)
			}
			// A row that reports an error or a warning must say so in its
			// counts, or a consumer summing the list sees a quieter run than
			// the envelope does.
			wantErrCount := 0
			if tc.wantErr {
				wantErrCount = 1
			}
			if v.Source.ErrorsCount != wantErrCount {
				t.Errorf("errorsCount = %d, want %d", v.Source.ErrorsCount, wantErrCount)
			}
		})
	}
}

// TestTheUngatedPathStaysSilent pins the compatibility promise that let the
// coverage row be emitted on every run rather than only gated ones: with no
// threshold configured, nothing reaches errs, warnings or allRan.
func TestTheUngatedPathStaysSilent(t *testing.T) {
	for _, measured := range []bool{true, false} {
		v := coverageSource("node", 7.5, measured, 30000, 0, 0)
		if v.Err != "" || v.Warning != "" || !v.Ran {
			t.Fatalf("measured=%v: ungated run must be silent, got err=%q warning=%q ran=%v",
				measured, v.Err, v.Warning, v.Ran)
		}
	}
}

// TestALegRowRepeatsItsSubEnvelopeRatherThanReinterpretingIt.
//
// The leg already decided its own verdict and stated its own outcome. A second
// derivation up here could only disagree with it, and the row a report reads
// would then say something the evidence it came from does not.
func TestALegRowRepeatsItsSubEnvelopeRatherThanReinterpretingIt(t *testing.T) {
	sub := &envelope{
		Tool:          toolInfo{Name: "dotnet-format", Version: "10.0.400"},
		Passed:        true, // fail-on: NONE
		Outcome:       OutcomeFindings,
		FindingsCount: 123456,
		Errors:        []string{"one"},
		Warnings:      []string{"a", "b"},
	}

	row := legSource("dotnet", ConcernLint, sub)

	if row.Tool != "dotnet-format" || row.Scope != "dotnet" {
		t.Fatalf("identity = %q/%q", row.Tool, row.Scope)
	}
	if row.ModuleName != moduleName || row.Stage != moduleStage {
		t.Fatalf("module identity = %q/%q", row.ModuleName, row.Stage)
	}
	// The case the whole outcome field exists for: passed says nothing under
	// NONE, and the row must still report what the linter found.
	if !row.Passed || row.Outcome != OutcomeFindings {
		t.Fatalf("passed=%v outcome=%q, want true/FINDINGS", row.Passed, row.Outcome)
	}
	if row.FindingsCount != 123456 || row.ErrorsCount != 1 || row.WarningsCount != 2 {
		t.Fatalf("counts = %d/%d/%d", row.FindingsCount, row.ErrorsCount, row.WarningsCount)
	}
}

// TestALegThatBrokeStillGetsARow.
//
// Dropping it would shorten sources[] rather than fail it, and a consumer
// counting rows would see a smaller, cleaner-looking run than actually
// happened.
func TestALegThatBrokeStillGetsARow(t *testing.T) {
	row := brokenLegSource("test", "node", ConcernTests)

	if row.Outcome != OutcomeError || row.Passed {
		t.Fatalf("outcome=%q passed=%v, want ERROR/false", row.Outcome, row.Passed)
	}
	if row.Tool != "test" || row.Scope != "node" {
		t.Fatalf("identity = %q/%q", row.Tool, row.Scope)
	}
	if row.ErrorsCount != 1 {
		t.Fatalf("errorsCount = %d, want 1", row.ErrorsCount)
	}
	// No outcome to read means no findings figure to claim either.
	if row.FindingsCount != 0 || row.Examined != nil {
		t.Fatalf("a broken leg must claim nothing: findings=%d examined=%v", row.FindingsCount, row.Examined)
	}
}

// TestTheRunThatMotivatedThisSplit replays the shape of the consumer's shadow
// run's quality envelope, with rounded synthetic figures, and asserts the rows a
// report would now read.
//
// Before the split this was one row: `tool: "quality", findingsCount: 123456`.
// Almost all of those findings are ENDOFLINE — a CRLF-versus-LF disagreement in
// one .NET tree — and eslint's genuine zero was inside the same number.
func TestTheRunThatMotivatedThisSplit(t *testing.T) {
	rows := []SourceStatus{
		legSource("node", ConcernLint, &envelope{
			Tool: toolInfo{Name: "eslint"}, Passed: true, Outcome: OutcomeClean,
		}),
		legSource("dotnet", ConcernLint, &envelope{
			Tool: toolInfo{Name: "dotnet-format"}, Passed: true,
			Outcome: OutcomeFindings, FindingsCount: 123456,
		}),
		legSource("dotnet", ConcernTests, &envelope{
			// Every test passed, and the runner exited 1 anyway.
			Tool: toolInfo{Name: "dotnet-test"}, Passed: true, Outcome: OutcomeError,
			Errors: []string{"dotnet test failed (exit 1)"},
		}),
		coverageSource("dotnet", 2.5, true, 50000, 0, 0).Source,
		coverageSource("node", 7.5, true, 30000, 0, 0).Source,
	}

	// Every row reports passed=true — the run was `fail-on: NONE` — and the
	// outcomes are the only thing that distinguishes them.
	for _, r := range rows {
		if !r.Passed {
			t.Fatalf("%s/%s: expected passed=true under NONE", r.Tool, r.Scope)
		}
	}

	want := map[string]Outcome{
		"eslint/node":          OutcomeClean,
		"dotnet-format/dotnet": OutcomeFindings,
		"dotnet-test/dotnet":   OutcomeError,
		"coverage/dotnet":      OutcomeClean,
		"coverage/node":        OutcomeClean,
	}
	for _, r := range rows {
		key := r.Tool + "/" + r.Scope
		if want[key] != r.Outcome {
			t.Errorf("%s outcome = %q, want %q", key, r.Outcome, want[key])
		}
	}

	// And the fold: one ERROR row drags the envelope to ERROR, which the single
	// lump row could never have said while passed was true.
	if got := sourcesOutcome(rows); got != OutcomeError {
		t.Fatalf("envelope outcome = %q, want ERROR", got)
	}

	// The coverage denominators a customer report needs, and the reason the
	// percentages alone are not enough.
	byKey := map[string]SourceStatus{}
	for _, r := range rows {
		byKey[r.Tool+"/"+r.Scope] = r
	}
	if e := byKey["coverage/dotnet"].Examined; e == nil || e.Count != 50000 {
		t.Fatalf("dotnet coverage denominator = %v", e)
	}
	if e := byKey["coverage/node"].Examined; e == nil || e.Count != 30000 {
		t.Fatalf("node coverage denominator = %v", e)
	}
}

// TestTheEnvelopeOutcomeAndItsRowsCannotDisagree.
//
// cross-cutting/evidence propagates a module's own rows INSTEAD OF a row for
// its envelope, and folds the combined outcome from whatever rows it received.
// So the moment quality started declaring rows, any gap between its envelope
// outcome and the worst of those rows became a way for the combined verdict to
// silently improve. Check appends to legOutcomes and sources in lockstep to
// close that; this is the assertion that says so out loud.
func TestTheEnvelopeOutcomeAndItsRowsCannotDisagree(t *testing.T) {
	rows := []SourceStatus{
		legSource("go", ConcernLint, &envelope{Tool: toolInfo{Name: "golangci-lint"}, Outcome: OutcomeClean, Passed: true}),
		legSource("go", ConcernTests, &envelope{Tool: toolInfo{Name: "go-test"}, Outcome: OutcomeFailed}),
		coverageSource("go", 40, true, 900, 60, 0).Source,
		brokenLegSource("lint", "python", ConcernLint),
	}

	var legOutcomes []Outcome
	for _, r := range rows {
		legOutcomes = append(legOutcomes, r.Outcome)
	}

	if worstOutcome(legOutcomes) != sourcesOutcome(rows) {
		t.Fatalf("envelope fold %q != row fold %q", worstOutcome(legOutcomes), sourcesOutcome(rows))
	}
	if got := sourcesOutcome(rows); got != OutcomeError {
		t.Fatalf("fold = %q, want ERROR (the broken python lint leg)", got)
	}
}
