//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testRepo() repoContext {
	return repoContext{RepoURL: "https://example.com", CommitSHA: "abc", Branch: "main"}
}

func oneLegFold(leg testLeg, appMode bool) *byoTestFold {
	return newByoTestFold([]testLeg{leg}, []string{"golang:1.26"}, []ToolchainResolution{{Image: "golang:1.26", From: ToolchainFromDefault}}, appMode, nil)
}

func buildEnv(t *testing.T, f *byoTestFold, detected []string, baseline baselineDoc, warnMode bool) *envelope {
	t.Helper()
	env, err := buildTestEnvelope(f, detected, baseline, 1.0, warnMode, testRepo(), SeverityHigh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func TestBuildTestEnvelopeSingleLegClean(t *testing.T) {
	leg := legacyTestLeg("go test ./...", "cover.out", "", []string{"go"})
	f := oneLegFold(leg, false)
	exit := 0
	f.addLeg(0, legOutcome{Ran: true, Passed: true, ExitCode: &exit, Output: "ok", Counts: &TestCounts{Total: 3, Passed: 3}, Coverage: &nodeCoverage{Percent: 81.5, Lines: 400}})
	env := buildEnv(t, f, []string{"go"}, baselineDoc{}, false)

	if !env.Passed || env.Outcome != OutcomeClean || env.Tool.Name != "byo-test" {
		t.Fatalf("passed=%v outcome=%s tool=%s", env.Passed, env.Outcome, env.Tool.Name)
	}
	if env.CoveragePercent == nil || *env.CoveragePercent != 81.5 || env.CoverageByLanguage["go"] != 81.5 || env.CoverageLinesByLanguage["go"] != 400 {
		t.Fatalf("coverage = %v %v %v", env.CoveragePercent, env.CoverageByLanguage, env.CoverageLinesByLanguage)
	}
	if env.TestsByLanguage["go"].Total != 3 {
		t.Fatalf("tests = %+v", env.TestsByLanguage)
	}
	if env.CoverageRatchet != ratchetSkipNoBaseline {
		t.Fatalf("ratchet = %q", env.CoverageRatchet)
	}
	if len(env.Languages) != 1 || env.Languages[0] != "go" {
		t.Fatalf("languages = %v", env.Languages)
	}
	if env.RawOutputRef != "ok" {
		t.Fatalf("one leg keeps its raw output unlabelled, got %q", env.RawOutputRef)
	}
	// One test row and the coverage row, nothing from application mode.
	if len(env.Sources) != 2 || env.Sources[1].Concern != ConcernCoverage {
		t.Fatalf("sources = %+v", env.Sources)
	}
	if env.GenericFormat != legsReportFormat {
		t.Fatalf("generic format = %q", env.GenericFormat)
	}
	var report legsReport
	if err := json.Unmarshal(env.GenericReport, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Legs) != 1 || report.Legs[0].Image != "golang:1.26" || !report.Legs[0].CoverageMeasured {
		t.Fatalf("legs report = %+v", report)
	}
}

func TestBuildTestEnvelopeNonRunFailsAndNamesTheLeg(t *testing.T) {
	leg := legacyTestLeg("go test ./...", "", "", []string{"go"})
	f := oneLegFold(leg, false)
	f.addLeg(0, legOutcome{Ran: false, Passed: false, Errors: []string{"container exec failed: image pull failed"}})
	env := buildEnv(t, f, []string{"go"}, baselineDoc{}, false)

	if env.Passed || env.Outcome != OutcomeError {
		t.Fatalf("passed=%v outcome=%s", env.Passed, env.Outcome)
	}
	if len(env.Errors) == 0 || env.Errors[0] != "byo-test: container exec failed: image pull failed" {
		t.Fatalf("errors = %q", env.Errors)
	}
	if !hasLine(env.Warnings, "coverage ratchet skipped") {
		t.Fatalf("warnings = %q", env.Warnings)
	}
}

func TestBuildTestEnvelopeFailingCommandIsFailedNotError(t *testing.T) {
	leg := legacyTestLeg("go test ./...", "", "", []string{"go"})
	f := oneLegFold(leg, false)
	exit := 1
	f.addLeg(0, legOutcome{Ran: true, Passed: false, ExitCode: &exit, Counts: &TestCounts{Total: 4, Passed: 3, Failed: 1}, Errors: []string{"test command exited 1"}})
	env := buildEnv(t, f, []string{"go"}, baselineDoc{}, false)
	if env.Passed || env.Outcome != OutcomeFailed {
		t.Fatalf("passed=%v outcome=%s", env.Passed, env.Outcome)
	}
}

func TestAddLegPrefixesLinesOnlyWithSeveralLegs(t *testing.T) {
	legs := []testLeg{
		{Label: "api", Language: "go", Cmd: "go test", CoveragePath: "cover.out"},
		{Label: "web", Language: "node", Cmd: "npm test"},
	}
	f := newByoTestFold(legs, []string{"golang:1.26", "node:22"}, []ToolchainResolution{{Image: "golang:1.26"}, {Image: "node:22"}}, false, []string{"detect: --include narrowed"})
	f.addLeg(0, legOutcome{Ran: true, Passed: true, Output: "go ok", Coverage: &nodeCoverage{Percent: 50, Lines: 10}, Warnings: []string{"slow"}})
	f.addLeg(1, legOutcome{Ran: true, Passed: false, Output: "node failed", Errors: []string{"test command exited 1"}})

	if f.Warnings[0] != "detect: --include narrowed" {
		t.Fatalf("seed warnings must come first: %q", f.Warnings)
	}
	if !hasLine(f.Warnings, "test-leg api: slow") {
		t.Fatalf("leg warning not prefixed: %q", f.Warnings)
	}
	if !hasLine(f.Errs, "test-leg web: test command exited 1") {
		t.Fatalf("leg error not prefixed: %q", f.Errs)
	}
	if !hasLine(f.Warnings, "test-leg web: no coverage-path configured") {
		t.Fatalf("a silent sibling leg must be named: %q", f.Warnings)
	}
	if !strings.HasPrefix(f.RawOutputs[1], "===== test-leg web (node:22) =====\n") {
		t.Fatalf("raw output = %q", f.RawOutputs[1])
	}
	if !f.AllRan || f.AllPassed {
		t.Fatalf("both legs ran and one failed, got allRan=%v allPassed=%v", f.AllRan, f.AllPassed)
	}
	if len(f.RepoRows) != 2 || len(f.LegOutcomes) != 2 {
		t.Fatalf("rows=%d outcomes=%d", len(f.RepoRows), len(f.LegOutcomes))
	}

	env := buildEnv(t, f, []string{"go", "node"}, baselineDoc{}, false)
	if env.Passed || env.Outcome != OutcomeFailed {
		t.Fatalf("passed=%v outcome=%s", env.Passed, env.Outcome)
	}
	if env.CoverageByLanguage["go"] != 50 || len(env.CoverageByLanguage) != 1 {
		t.Fatalf("coverage = %v", env.CoverageByLanguage)
	}
}

func TestAddLegCoverageMissingIsNamedWithSeveralLegs(t *testing.T) {
	legs := []testLeg{
		{Label: "api", Language: "go", Cmd: "go test", CoveragePath: "cover.out"},
		{Label: "web", Language: "node", Cmd: "npm test", CoveragePath: "cov/summary.json"},
	}
	f := newByoTestFold(legs, []string{"a", "b"}, make([]ToolchainResolution, 2), false, nil)
	f.addLeg(0, legOutcome{Ran: true, Passed: true, Coverage: &nodeCoverage{Percent: 70, Lines: 100}})
	f.addLeg(1, legOutcome{Ran: true, Passed: true, CoverageMissing: true})
	if !hasLine(f.Warnings, "test-leg web: no coverage report found at cov/summary.json") {
		t.Fatalf("warnings = %q", f.Warnings)
	}
}

func TestBuildTestEnvelopeAppModeRequiresDeclaredCoverageAndWitnessedLanguages(t *testing.T) {
	leg := testLeg{Label: "api", Language: "go", Cmd: "go test", CoveragePath: "cover.out"}
	f := oneLegFold(leg, true)
	f.addLeg(0, legOutcome{Ran: true, Passed: true})
	env := buildEnv(t, f, []string{"go", "node"}, baselineDoc{}, false)

	if env.Passed || env.Outcome != OutcomeError {
		t.Fatalf("passed=%v outcome=%s", env.Passed, env.Outcome)
	}
	if !hasLine(env.Errors, "declared application coverage output was missing or unusable") {
		t.Fatalf("errors = %q", env.Errors)
	}
	if !hasLine(env.Errors, "application languages lack test legs: node") {
		t.Fatalf("errors = %q", env.Errors)
	}
	if !hasLine(env.Warnings, "coverage totals do not prove complete application coverage") {
		t.Fatalf("warnings = %q", env.Warnings)
	}
	// Application rows only: the test row, the coverage row, and the
	// unwitnessed-languages row. No repository coverage row.
	if len(env.Sources) != 3 || env.Sources[2].Tool != "unwitnessed-languages" {
		t.Fatalf("sources = %+v", env.Sources)
	}
	if len(env.Languages) != 1 || env.Languages[0] != "go" {
		t.Fatalf("languages must be the witnessed set, got %v", env.Languages)
	}
}

func TestBuildTestEnvelopeUnwitnessedLanguageWarnsInRepositoryMode(t *testing.T) {
	leg := testLeg{Label: "api", Language: "go", Cmd: "go test"}
	f := oneLegFold(leg, false)
	f.addLeg(0, legOutcome{Ran: true, Passed: true})
	env := buildEnv(t, f, []string{"go", "python"}, baselineDoc{}, false)
	if !env.Passed {
		t.Fatalf("an unwitnessed language is a warning, not a failure: %q", env.Errors)
	}
	if !hasLine(env.Warnings, "python") {
		t.Fatalf("warnings = %q", env.Warnings)
	}
}

func TestBuildTestEnvelopeRatchet(t *testing.T) {
	leg := legacyTestLeg("go test ./...", "cover.out", "", []string{"go"})
	measured := legOutcome{Ran: true, Passed: true, Coverage: &nodeCoverage{Percent: 70, Lines: 100}}

	t.Run("regression fails the gate and folds in as FAILED", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.addLeg(0, measured)
		env := buildEnv(t, f, []string{"go"}, baselineDoc{Present: true, Raw: `{"coverageByLanguage":{"go":80}}`}, false)
		if env.Passed || env.Outcome != OutcomeFailed || env.CoverageRatchet != ratchetFail {
			t.Fatalf("passed=%v outcome=%s ratchet=%s errors=%q", env.Passed, env.Outcome, env.CoverageRatchet, env.Errors)
		}
		if env.CoverageBaselineByLanguage["go"] != 80 {
			t.Fatalf("baseline = %v", env.CoverageBaselineByLanguage)
		}
		if last := env.Sources[len(env.Sources)-1]; last.Concern != ConcernCoverage || last.Passed {
			t.Fatalf("coverage row = %+v", last)
		}
	})

	t.Run("warn mode keeps the run green", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.addLeg(0, measured)
		env := buildEnv(t, f, []string{"go"}, baselineDoc{Present: true, Raw: `{"coverageByLanguage":{"go":80}}`}, true)
		if !env.Passed || env.Outcome != OutcomeClean || len(env.Errors) != 0 {
			t.Fatalf("passed=%v outcome=%s errors=%q", env.Passed, env.Outcome, env.Errors)
		}
	})

	t.Run("unreadable baseline is a warning and a skipped ratchet", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.addLeg(0, measured)
		env := buildEnv(t, f, []string{"go"}, baselineDoc{Present: true, ReadErr: errors.New("boom")}, false)
		if !env.Passed || env.CoverageRatchet != ratchetSkipNoBaseline || !hasLine(env.Warnings, "baseline file unreadable: boom") {
			t.Fatalf("passed=%v ratchet=%s warnings=%q", env.Passed, env.CoverageRatchet, env.Warnings)
		}
		if env.CoverageBaselineByLanguage != nil {
			t.Fatalf("no baseline must be recorded: %v", env.CoverageBaselineByLanguage)
		}
	})

	t.Run("unusable baseline is a warning and a skipped ratchet", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.addLeg(0, measured)
		env := buildEnv(t, f, []string{"go"}, baselineDoc{Present: true, Raw: "not json"}, false)
		if !env.Passed || env.CoverageRatchet != ratchetSkipNoBaseline || !hasLine(env.Warnings, "baseline unusable:") {
			t.Fatalf("passed=%v ratchet=%s warnings=%q", env.Passed, env.CoverageRatchet, env.Warnings)
		}
	})
}

func TestAddLegDotnetScope(t *testing.T) {
	leg := testLeg{Label: "test-cmd", Language: "dotnet", Cmd: "dotnet test", CoveragePath: "**/coverage.cobertura.xml"}

	t.Run("a failed sweep is said, not an empty tree", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.setDotnetScope(nil, errors.New("find: permission denied"))
		f.addLeg(0, legOutcome{Ran: true, Passed: true})
		if !hasLine(f.Warnings, "permission denied") {
			t.Fatalf("warnings = %q", f.Warnings)
		}
		if f.LegReports[0].ProjectsDiscovered != nil {
			t.Fatal("no sweep, no project count")
		}
	})

	t.Run("the sweep's numbers reach the leg report", func(t *testing.T) {
		f := oneLegFold(leg, false)
		f.setDotnetScope(&dotnetDiscovery{Projects: []string{"a.csproj", "b.csproj", "c.csproj"}, TestProjects: []string{"b.csproj", "c.csproj"}}, nil)
		f.addLeg(0, legOutcome{Ran: true, Passed: true, Coverage: &nodeCoverage{Percent: 60, Lines: 50}, CoverageSet: &coverageSet{Matched: 1, Parsed: 1}})
		r := f.LegReports[0]
		if r.ProjectsDiscovered == nil || *r.ProjectsDiscovered != 3 || *r.TestProjectsDiscovered != 2 || r.CoverageDocumentsMerged == nil || *r.CoverageDocumentsMerged != 1 {
			t.Fatalf("report = %+v", r)
		}
	})
}

func TestAddLegUnknownLanguageKeysCoverageAsUnknown(t *testing.T) {
	// Nothing detected plus an explicit image: the run is real and the
	// language genuinely is not known.
	leg := legacyTestLeg("make test", "cov.json", "busybox", nil)
	f := oneLegFold(leg, false)
	f.addLeg(0, legOutcome{Ran: true, Passed: true, Coverage: &nodeCoverage{Percent: 10, Lines: 5}, Counts: &TestCounts{Total: 1, Passed: 1}})
	if _, ok := f.ReadingsByLang["unknown"]; !ok {
		t.Fatalf("readings = %v", f.ReadingsByLang)
	}
	if _, ok := f.TestCountsByLang["unknown"]; !ok {
		t.Fatalf("counts = %v", f.TestCountsByLang)
	}
}
