package main

import (
	"testing"
	"time"
)

// buildCombined collapses every source envelope into one AND — Sources is the
// only place the combined document keeps WHICH gate produced the verdict, so
// these tests pin that the list is complete, ordered, and truthful about a
// failed source.
func TestBuildCombinedSources(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName:    "quality",
			Stage:         "domain",
			Tool:          toolInfo{Name: "eslint"},
			Passed:        true,
			FindingsCount: 2,
			Warnings:      []string{"quality: NO LANGUAGE DETECTED in ./docs"},
		},
		{
			ModuleName:    "security",
			Stage:         "domain",
			Tool:          toolInfo{Name: "trivy"},
			Passed:        false,
			FindingsCount: 5,
			Errors:        []string{"trivy: report contains no scan results"},
		},
		{
			ModuleName: "cross-cutting/intent",
			Stage:      "cross-cutting",
			Passed:     true,
		},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.Passed {
		t.Fatalf("combined.Passed = true with a failed source envelope")
	}
	if len(combined.Sources) != len(envs) {
		t.Fatalf("Sources length = %d, want %d — every input envelope must appear", len(combined.Sources), len(envs))
	}
	want := []SourceStatus{
		{ModuleName: "quality", Stage: "domain", Tool: "eslint", Passed: true, FindingsCount: 2, WarningsCount: 1},
		{ModuleName: "security", Stage: "domain", Tool: "trivy", Passed: false, FindingsCount: 5, ErrorsCount: 1},
		{ModuleName: "cross-cutting/intent", Stage: "cross-cutting", Passed: true},
	}
	for i, w := range want {
		if combined.Sources[i] != w {
			t.Errorf("Sources[%d] = %+v, want %+v", i, combined.Sources[i], w)
		}
	}
}

func TestBuildCombinedSourcesAllGreen(t *testing.T) {
	envs := []*envelope{
		{ModuleName: "quality", Stage: "domain", Passed: true},
		{ModuleName: "build", Stage: "domain", Passed: true, FindingsCount: 0},
	}
	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())
	if !combined.Passed {
		t.Fatalf("combined.Passed = false with only passing sources")
	}
	for i, s := range combined.Sources {
		if !s.Passed {
			t.Errorf("Sources[%d].Passed = false, want true", i)
		}
		if s.ErrorsCount != 0 || s.WarningsCount != 0 {
			t.Errorf("Sources[%d] counts = %d errors / %d warnings, want 0/0 — a zero count is a claim, not an omission", i, s.ErrorsCount, s.WarningsCount)
		}
	}
}

// A module that fuses several scanners under one verdict declares its own
// Sources, and those rows must REPLACE the row the aggregator would have
// synthesised for the envelope — not join it. Both describe the same findings,
// so emitting both doubles every count for a consumer that sums the list.
func TestBuildCombinedPropagatesDeclaredSources(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName:    "quality",
			Stage:         "domain",
			Tool:          toolInfo{Name: "eslint"},
			Passed:        true,
			FindingsCount: 2,
		},
		{
			ModuleName:    "security",
			Stage:         "domain",
			Tool:          toolInfo{Name: "security-source"},
			Passed:        false,
			FindingsCount: 7,
			Errors:        []string{"gitleaks: exit 1"},
			Sources: []SourceStatus{
				{ModuleName: "security", Stage: "domain", Tool: "semgrep", Scope: "security-source", Passed: true, FindingsCount: 2},
				{ModuleName: "security", Stage: "domain", Tool: "gitleaks", Scope: "security-source", Passed: false, FindingsCount: 0, ErrorsCount: 1},
				{ModuleName: "security", Stage: "domain", Tool: "trivy", Scope: "security-source", Passed: false, FindingsCount: 5},
			},
		},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if len(combined.Sources) != 4 {
		t.Fatalf("Sources length = %d, want 4 (one for quality, three for the fused security envelope)", len(combined.Sources))
	}
	for _, s := range combined.Sources {
		if s.Tool == "security-source" {
			t.Fatalf("the fused envelope's own row survived alongside its constituents — counts are now doubled")
		}
	}

	// The declared rows must sum to what the envelope claimed, or replacing one
	// row with three silently changed the total a consumer reads.
	sum := 0
	for _, s := range combined.Sources {
		if s.ModuleName == "security" {
			sum += s.FindingsCount
		}
	}
	if sum != envs[1].FindingsCount {
		t.Errorf("propagated rows sum to %d, envelope claimed %d", sum, envs[1].FindingsCount)
	}

	// The split must not change the combined verdict — it only says which of
	// the three produced it.
	if combined.Passed {
		t.Errorf("combined.Passed = true with a failed constituent")
	}

	// Scope has to survive the hop, or one scanner over two scopes is
	// indistinguishable in the combined document.
	if combined.Sources[1].Scope != "security-source" {
		t.Errorf("Sources[1].Scope = %q, want security-source", combined.Sources[1].Scope)
	}
}

// The ordinary case is unchanged: an envelope declaring no Sources still gets
// exactly one synthesised row. Without this the propagation branch could be
// widened to swallow every envelope and the suite would not notice.
func TestBuildCombinedSynthesisesWhenNoSourcesDeclared(t *testing.T) {
	envs := []*envelope{
		{ModuleName: "risk", Stage: "cross-cutting", Tool: toolInfo{Name: "risk"}, Passed: true, FindingsCount: 3},
	}
	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())
	want := SourceStatus{ModuleName: "risk", Stage: "cross-cutting", Tool: "risk", Passed: true, FindingsCount: 3}
	if len(combined.Sources) != 1 || combined.Sources[0] != want {
		t.Fatalf("Sources = %+v, want exactly [%+v]", combined.Sources, want)
	}
}

// Coverage merge. The aggregator used to drop CoverageLinesByLanguage even
// though quality emits it and schema.go claimed the combined envelope carried
// it, so no consumer could derive a repo-wide figure and an unweighted average
// of the per-language percentages was the only thing available — a fabricated
// number. These tests pin the counts through, pin the weighting, and pin the
// refusals, because the refusals are the part a well-meaning simplification
// would delete.
func TestBuildCombinedMergesCoverageLineCounts(t *testing.T) {
	envs := []*envelope{{
		ModuleName:              "quality",
		Stage:                   "domain",
		Passed:                  true,
		CoverageByLanguage:      map[string]float64{"go": 100, "node": 50},
		CoverageLinesByLanguage: map[string]int{"go": 10, "node": 1000},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if got := combined.CoverageLinesByLanguage["node"]; got != 1000 {
		t.Fatalf("CoverageLinesByLanguage[node] = %d, want 1000 — quality's counts must survive aggregation", got)
	}
	if combined.CoveragePercent == nil {
		t.Fatal("CoveragePercent = nil, want a weighted figure when every language brought its line count")
	}
	// 10 covered of 10 in go, 500 of 1000 in node = 510/1010.
	if want := 510.0 / 1010 * 100; *combined.CoveragePercent != want {
		t.Fatalf("CoveragePercent = %v, want %v — weighted by coverable lines, not averaged", *combined.CoveragePercent, want)
	}
	// The unweighted mean is 75%, and it is the number this test exists to
	// prevent: it is 24 points higher than the truth and looks entirely normal.
	if *combined.CoveragePercent > 74 {
		t.Fatalf("CoveragePercent = %v — that is the unweighted average, not a weighted figure", *combined.CoveragePercent)
	}
	// A percentage without its denominator cannot be contextualised: 50% of
	// 1010 lines and 50% of 10 are the same number and not the same claim.
	if combined.CoverageLines == nil {
		t.Fatal("CoverageLines = nil, want the total the percentage is of")
	}
	if *combined.CoverageLines != 1010 {
		t.Fatalf("CoverageLines = %d, want 1010 — the total must be the denominator of the reported percentage", *combined.CoverageLines)
	}
}

func TestBuildCombinedWithholdsCoveragePercentWhenALanguageHasNoLineCount(t *testing.T) {
	envs := []*envelope{{
		ModuleName:              "quality",
		Stage:                   "domain",
		Passed:                  true,
		CoverageByLanguage:      map[string]float64{"go": 90, "dotnet": 10},
		CoverageLinesByLanguage: map[string]int{"go": 1000},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.CoveragePercent != nil {
		t.Fatalf("CoveragePercent = %v, want nil — weighting only the languages that reported lines makes the figure describe part of the repo while presenting it as the whole", *combined.CoveragePercent)
	}
	if got := combined.CoverageByLanguage["dotnet"]; got != 10 {
		t.Fatalf("CoverageByLanguage[dotnet] = %v, want 10 — a per-language percentage is honest on its own and must still be reported", got)
	}
	// Summing only go's 1000 lines would publish a denominator for part of the
	// repo. Multiplied by any percentage presented as the whole it yields a
	// covered-line count about nothing, so the total goes when the figure goes.
	if combined.CoverageLines != nil {
		t.Fatalf("CoverageLines = %d, want nil — a total over only the languages that reported counts is not the repo's total", *combined.CoverageLines)
	}
}

func TestBuildCombinedWithholdsCoveragePercentWhenNoLinesAreCoverable(t *testing.T) {
	envs := []*envelope{{
		ModuleName:              "quality",
		Stage:                   "domain",
		Passed:                  true,
		CoverageByLanguage:      map[string]float64{"go": 0},
		CoverageLinesByLanguage: map[string]int{"go": 0},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.CoveragePercent != nil {
		t.Fatalf("CoveragePercent = %v, want nil — 0%% of nothing reads as 'measured, nothing covered'", *combined.CoveragePercent)
	}
	if combined.CoverageLines != nil {
		t.Fatalf("CoverageLines = %d, want nil — a zero total is not a measurement", *combined.CoverageLines)
	}
}

func TestBuildCombinedNeverPairsOneEnvelopesPercentWithAnothersLineCount(t *testing.T) {
	// Two envelopes both report node. Both maps are last-writer-wins, so a
	// version that merged them in separate loops would keep the first
	// envelope's 1000-line count next to the second's 50% — a weighted figure
	// about a run that never happened.
	envs := []*envelope{
		{
			ModuleName:              "quality",
			Stage:                   "domain",
			Passed:                  true,
			CoverageByLanguage:      map[string]float64{"node": 90},
			CoverageLinesByLanguage: map[string]int{"node": 1000},
		},
		{
			ModuleName:         "quality-rerun",
			Stage:              "domain",
			Passed:             true,
			CoverageByLanguage: map[string]float64{"node": 50},
		},
	}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if _, ok := combined.CoverageLinesByLanguage["node"]; ok {
		t.Fatalf("CoverageLinesByLanguage[node] = %d survived an envelope that redefined node's percentage without a count — the pair is now mismatched", combined.CoverageLinesByLanguage["node"])
	}
	if combined.CoveragePercent != nil {
		t.Fatalf("CoveragePercent = %v, want nil — the surviving percentage has no count to weight it", *combined.CoveragePercent)
	}
}

// The percentage and its denominator are one claim, and the danger is that they
// drift apart: two functions sharing a withholding predicate is two places to
// change, and the failure mode of changing one is a plausible-looking number.
// weightedCoverage returns both so that cannot happen; this pins the contract at
// the boundary where neither is derivable.
func TestBuildCombinedWithholdsBothCoverageFiguresWhenNothingReportsCoverage(t *testing.T) {
	envs := []*envelope{{
		ModuleName: "quality",
		Stage:      "domain",
		Passed:     true,
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.CoveragePercent != nil {
		t.Fatalf("CoveragePercent = %v, want nil — no language measured coverage", *combined.CoveragePercent)
	}
	if combined.CoverageLines != nil {
		t.Fatalf("CoverageLines = %d, want nil — a total with no percentage to be the denominator of is a number with no claim attached", *combined.CoverageLines)
	}
}

// Test counts. The mirror image of the coverage merge above: counts sum
// honestly where percentages do not, so there is no weighting — but the refusal
// to publish a partial figure as a whole one carries over unchanged.
func TestBuildCombinedTotalsTestCountsAcrossLanguages(t *testing.T) {
	envs := []*envelope{{
		ModuleName: "quality",
		Stage:      "domain",
		Passed:     true,
		Languages:  []string{"go", "dotnet"},
		TestsByLanguage: map[string]TestCounts{
			"go":     {Total: 980, Passed: 979, Failed: 0, Skipped: 1, DurationMS: 2400},
			"dotnet": {Total: 431, Passed: 426, Failed: 2, Skipped: 3, DurationMS: 8100},
		},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if got := combined.TestsByLanguage["dotnet"].Failed; got != 2 {
		t.Fatalf("TestsByLanguage[dotnet].Failed = %d, want 2 — the per-language accounting must survive aggregation", got)
	}
	if combined.Tests == nil {
		t.Fatal("Tests = nil, want a total when every tested language was counted")
	}
	want := TestCounts{Total: 1411, Passed: 1405, Failed: 2, Skipped: 4, DurationMS: 10500}
	if *combined.Tests != want {
		t.Fatalf("Tests = %+v, want %+v", *combined.Tests, want)
	}
}

func TestBuildCombinedWithholdsTheTestTotalWhenATestedLanguageWasNotCounted(t *testing.T) {
	// node was tested and produced no accounting. "980 tests" is then a total
	// for part of the run printed beside the word total, and nothing in the
	// output says which part — so it goes, and go's own honest entry stays.
	envs := []*envelope{{
		ModuleName: "quality",
		Stage:      "domain",
		Passed:     true,
		Languages:  []string{"go", "node"},
		TestsByLanguage: map[string]TestCounts{
			"go": {Total: 980, Passed: 980},
		},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.Tests != nil {
		t.Fatalf("Tests = %+v, want nil — node was tested and never counted", *combined.Tests)
	}
	if got := combined.TestsByLanguage["go"].Total; got != 980 {
		t.Fatalf("TestsByLanguage[go].Total = %d, want 980 — a counted suite is honest on its own", got)
	}
}

func TestBuildCombinedWithholdsTheTestTotalWhenNothingWasCounted(t *testing.T) {
	envs := []*envelope{{
		ModuleName: "quality",
		Stage:      "domain",
		Passed:     true,
		Languages:  []string{"node"},
	}}

	combined := buildCombined("cross-cutting/evidence", "cross-cutting", repoContext{}, envs, time.Now())

	if combined.Tests != nil {
		t.Fatalf("Tests = %+v, want nil — nothing reported an accounting", *combined.Tests)
	}
}
