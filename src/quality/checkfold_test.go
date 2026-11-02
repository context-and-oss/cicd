//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func checkRepo() repoContext {
	return repoContext{RepoURL: "https://example.com/r", CommitSHA: "abc", Branch: "main"}
}

func legEnvelope(tool string, passed bool, outcome Outcome) *envelope {
	return &envelope{Tool: toolInfo{Name: tool}, Passed: passed, Outcome: outcome}
}

// A tree with no marker file lints nothing and tests nothing. That is
// disclosed in warnings[] and the envelope passes with no outcome at all —
// not CLEAN, which would be the claim that every leg ran and found nothing.
func TestCheckFoldNoLanguageIsAWarnedPassWithNoOutcome(t *testing.T) {
	f := newCheckFold(nil, []string{"detect: looked at 3 levels"})
	if len(f.Warnings) != 2 || f.Warnings[0] != "detect: looked at 3 levels" {
		t.Fatalf("detection warnings are seeded first, then the no-language disclosure: %v", f.Warnings)
	}
	if !strings.Contains(f.Warnings[1], "NO LANGUAGE DETECTED") {
		t.Fatalf("no-language disclosure missing: %v", f.Warnings)
	}
	f.foldCoverage(nil, false, 80, 0)
	env := buildCheckEnvelope(f, nil, checkRepo(), SeverityHigh, time.Now())
	if !env.Passed {
		t.Fatalf("no work is a disclosed pass, got errors %v", env.Errors)
	}
	if env.Outcome != "" {
		t.Fatalf("no leg means no outcome, got %q", env.Outcome)
	}
	if len(env.Sources) != 0 || len(env.Languages) != 0 {
		t.Fatalf("no rows and no languages, got %+v / %v", env.Sources, env.Languages)
	}
	if env.SARIFReport != nil {
		t.Fatalf("no SARIF document must stay omitted, got %s", env.SARIFReport)
	}
}

// A leg that returned an error has no envelope. It is a broken row, an ERROR
// outcome and a non-run, and `--fail-on NONE` does not clear it.
func TestCheckFoldLegThatCouldNotRunFailsAtEveryThreshold(t *testing.T) {
	f := newCheckFold([]string{"go"}, nil)
	f.addLint("go", nil, false, errors.New("golangci-lint: image pull failed"))
	if f.AllRan || f.LintPassed {
		t.Fatalf("a broken lint leg is a non-run: ran=%v lintPassed=%v", f.AllRan, f.LintPassed)
	}
	if len(f.Errs) != 1 || f.Errs[0] != "lint go: golangci-lint: image pull failed" {
		t.Fatalf("the error names the leg and the language: %v", f.Errs)
	}
	if len(f.Sources) != 1 || f.Sources[0].Tool != "lint" || f.Sources[0].Outcome != OutcomeError || f.Sources[0].Concern != ConcernLint {
		t.Fatalf("broken row: %+v", f.Sources)
	}
	for _, th := range []Severity{SeverityHigh, SeverityNone} {
		env := buildCheckEnvelope(f, []string{"go"}, checkRepo(), th, time.Now())
		if env.Passed {
			t.Fatalf("a non-run must fail at %s", th)
		}
		if env.Outcome != OutcomeError {
			t.Fatalf("outcome at %s: %q", th, env.Outcome)
		}
	}
}

// A leg that ran (ran=true) but handed back no envelope has no tool for this
// language: no row, no outcome, nothing invented.
func TestCheckFoldNilEnvelopeWithoutErrorIsNoRow(t *testing.T) {
	f := newCheckFold([]string{"go"}, nil)
	f.addLint("go", nil, true, nil)
	f.addTest("go", nil, true, nil)
	if len(f.Sources) != 0 || len(f.LegOutcomes) != 0 || !f.AllRan || !f.LintPassed || !f.TestPassed {
		t.Fatalf("nothing was asked of a tool, so nothing is recorded: %+v", f)
	}
}

// Findings fail the gate at HIGH and are collected at NONE; the outcome says
// FINDINGS either way, and the leg's own errors and warnings arrive prefixed.
func TestCheckFoldFindingsAreGatedByThresholdOnly(t *testing.T) {
	lint := legEnvelope("eslint", false, OutcomeFindings)
	lint.FindingsCount = 3
	lint.FindingsBySeverity = map[Severity]int{SeverityHigh: 2, SeverityLow: 1}
	lint.SARIFReport = json.RawMessage(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"eslint"}}}]}`)
	lint.Warnings = []string{"a rule was skipped"}

	cov := 81.5
	lines := 2000
	test := legEnvelope("vitest", true, OutcomeClean)
	test.CoveragePercent = &cov
	test.CoverageLines = &lines
	test.Tests = &TestCounts{Total: 12, Passed: 12}
	test.GenericReport = json.RawMessage(`{"tail":"x"}`)
	test.GenericFormat = "dotnet-test-output/1.0"

	f := newCheckFold([]string{"node"}, nil)
	f.addLint("node", lint, true, nil)
	f.addTest("node", test, true, nil)
	f.foldCoverage([]string{"node"}, false, 50, 0)

	if !f.AllRan {
		t.Fatal("both legs ran")
	}
	if f.Warnings[0] != "lint node: a rule was skipped" {
		t.Fatalf("leg warnings are prefixed with the leg and language: %v", f.Warnings)
	}
	if len(f.Sources) != 3 {
		t.Fatalf("lint, test and coverage rows: %+v", f.Sources)
	}

	high := buildCheckEnvelope(f, []string{"node"}, checkRepo(), SeverityHigh, time.Now())
	if high.Passed {
		t.Fatal("a failed lint leg fails the gate at HIGH")
	}
	none := buildCheckEnvelope(f, []string{"node"}, checkRepo(), SeverityNone, time.Now())
	if !none.Passed {
		t.Fatalf("NONE collects findings without failing: %v", none.Errors)
	}
	for _, env := range []*envelope{high, none} {
		if env.Outcome != OutcomeFindings {
			t.Fatalf("the ungated outcome is FINDINGS, got %q", env.Outcome)
		}
		if env.FindingsCount != 3 || env.FindingsBySeverity[SeverityHigh] != 2 {
			t.Fatalf("findings are summed: %d %v", env.FindingsCount, env.FindingsBySeverity)
		}
		if env.CoverageByLanguage["node"] != 81.5 || env.CoverageLinesByLanguage["node"] != 2000 || env.TestsByLanguage["node"].Total != 12 {
			t.Fatalf("coverage and counts travel per language: %+v", env)
		}
		if env.GenericFormat != qualityDiagnosticsFormat || !strings.Contains(string(env.GenericReport), "dotnet-test-output/1.0") {
			t.Fatalf("leg diagnostics are wrapped under their format: %s %s", env.GenericFormat, env.GenericReport)
		}
		if env.SARIFReport == nil || env.Languages[0] != "node" || env.Tool.Name != "quality" {
			t.Fatalf("envelope shape: %+v", env)
		}
	}
}

// A configured coverage gate over a language that produced no figure is a
// gate that could not run: an error, a non-run, and a failure at NONE too.
// lintOnly never runs the test leg, so it has no figure to have missed.
func TestCheckFoldCoverageGateThatCouldNotMeasureIsANonRun(t *testing.T) {
	f := newCheckFold([]string{"dotnet"}, nil)
	f.addLint("dotnet", legEnvelope("dotnet-format", true, OutcomeClean), true, nil)
	f.addTest("dotnet", legEnvelope("dotnet-test", true, OutcomeClean), true, nil)
	f.foldCoverage([]string{"dotnet"}, false, 60, 0)
	if f.AllRan {
		t.Fatal("an unmeasured gate is a non-run")
	}
	if len(f.Errs) != 1 || !strings.Contains(f.Errs[0], "coverage gate requires 60.0%") {
		t.Fatalf("the gate names what it needed: %v", f.Errs)
	}
	env := buildCheckEnvelope(f, []string{"dotnet"}, checkRepo(), SeverityNone, time.Now())
	if env.Passed || env.Outcome != OutcomeError {
		t.Fatalf("NONE must not clear a gate that could not run: passed=%v outcome=%q", env.Passed, env.Outcome)
	}

	lintOnly := newCheckFold([]string{"dotnet"}, nil)
	lintOnly.addLint("dotnet", legEnvelope("dotnet-format", true, OutcomeClean), true, nil)
	lintOnly.foldCoverage([]string{"dotnet"}, true, 60, 0)
	if !lintOnly.AllRan || len(lintOnly.Errs) != 0 || len(lintOnly.Sources) != 1 {
		t.Fatalf("lint-only has no coverage row: %+v", lintOnly)
	}
	if got := buildCheckEnvelope(lintOnly, []string{"dotnet"}, checkRepo(), SeverityHigh, time.Now()); !got.Passed || got.Outcome != OutcomeClean {
		t.Fatalf("lint-only clean run: passed=%v outcome=%q", got.Passed, got.Outcome)
	}
}

// One leg's non-run and another leg's findings: the non-run wins the outcome
// and the gate fails at every threshold.
func TestCheckFoldWorstOutcomeWins(t *testing.T) {
	f := newCheckFold([]string{"go", "node"}, nil)
	lint := legEnvelope("golangci-lint", false, OutcomeFindings)
	lint.FindingsCount = 1
	f.addLint("go", lint, true, nil)
	f.addTest("go", legEnvelope("go-test", true, OutcomeClean), true, nil)
	f.addLint("node", nil, false, errors.New("eslint: not installed"))
	f.addTest("node", legEnvelope("vitest", true, OutcomeClean), true, nil)
	f.foldCoverage([]string{"go", "node"}, false, 0, 0)
	env := buildCheckEnvelope(f, []string{"go", "node"}, checkRepo(), SeverityNone, time.Now())
	if env.Passed || env.Outcome != OutcomeError {
		t.Fatalf("passed=%v outcome=%q errors=%v", env.Passed, env.Outcome, env.Errors)
	}
	if len(env.Sources) != 6 {
		t.Fatalf("two lint, two test, two coverage rows: %d", len(env.Sources))
	}
}

// A runner that exited non-zero while its own accounting says no test failed
// is ERROR (testOutcome), and ERROR is the ran=false of gatedPassed. Both
// folds used to read only the legs' ran flags, so the leg passed at `--fail-on
// NONE`: measured end to end as passed:true beside outcome:ERROR for pytest's
// exit 5 (no tests collected). The control is a suite with a failing test,
// which is a result NONE may suppress.
func TestNonRunMatrixErroredTestLegFailsTheAggregate(t *testing.T) {
	exit5 := TestCounts{}
	failing := TestCounts{Total: 2, Passed: 1, Failed: 1}
	cases := []struct {
		name     string
		counts   *TestCounts
		wantNone bool
	}{
		{"exit 5, nothing collected", &exit5, false},
		{"control: one test failed", &failing, true},
	}
	for _, c := range cases {
		outcome := testOutcome(true, false, c.counts)
		for _, th := range allThresholds {
			f := newCheckFold([]string{"python"}, nil)
			f.addTest("python", &envelope{
				Tool:    toolInfo{Name: "pytest"},
				Passed:  gatedPassed(true, false, th),
				Outcome: outcome,
				Errors:  []string{"pytest failed (exit 5)"},
				Tests:   c.counts,
			}, true, nil)
			env := buildCheckEnvelope(f, []string{"python"}, checkRepo(), th, time.Now())
			if want := c.wantNone && th == SeverityNone; env.Passed != want {
				t.Errorf("check %s at --fail-on %s: passed=%v, want %v (outcome %s)", c.name, th, env.Passed, want, env.Outcome)
			}

			code := 5
			bf := oneLegFold(legacyTestLeg("pytest", "", "", []string{"python"}), false)
			bf.addLeg(0, legOutcome{Ran: true, ExitCode: &code, Counts: c.counts, Errors: []string{"test command failed (exit 5)"}})
			benv, err := buildTestEnvelope(bf, []string{"python"}, baselineDoc{}, 1.0, false, testRepo(), th, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if want := c.wantNone && th == SeverityNone; benv.Passed != want {
				t.Errorf("byo %s at --fail-on %s: passed=%v, want %v (outcome %s)", c.name, th, benv.Passed, want, benv.Outcome)
			}
		}
	}
}
