package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// checkFold is what Check's legs fold into: one lint and one test leg per
// detected language, then one coverage row per language, and out of it the
// aggregate envelope.
//
// Untagged. The fold used to be inline in Check behind the Dagger build tag,
// which is how the coverage gate stayed structurally unfailable for every .NET
// run (sources.go tells that story) and how a nil envelope from a leg with no
// linter was one line away from a panic: nothing here could be reached by a
// test. Check keeps the container work and hands each leg's result in.
type checkFold struct {
	LintPassed bool
	TestPassed bool
	// AllRan is the aggregate non-run verdict. It must be tracked separately
	// from LintPassed/TestPassed: those already have the threshold applied, so
	// under `fail-on NONE` a leg that found problems and a leg that never
	// executed both arrive here as passed. Only the second may fail the gate
	// at NONE.
	AllRan bool
	// LegOutcomes collects what each leg FOUND, as opposed to what its gate
	// decided. It is a slice rather than a running fold because worstOutcome
	// has to see the whole set: one leg that reports no outcome must collapse
	// the aggregate to none, and a pairwise accumulator cannot stay collapsed.
	LegOutcomes []Outcome
	// One row per tool that ran, replacing the single synthesised row that
	// cross-cutting/evidence used to invent for this envelope. See sources.go.
	Sources             []SourceStatus
	TotalFindings       int
	Errs                []string
	Warnings            []string
	SARIFReports        []json.RawMessage
	Combined            map[Severity]int
	CoverageByLang      map[string]float64
	CoverageLinesByLang map[string]int
	TestsByLang         map[string]TestCounts
	// Diagnostics collects each leg's genericReport payload, keyed by the
	// leg's genericFormat, for qualityDiagnosticsReport to wrap. Today only
	// the .NET test leg writes one (dotnet-test-output/1.0, the bounded output
	// kept when an exit is not explained by a failing test).
	Diagnostics map[string]json.RawMessage
}

// newCheckFold starts the fold over the languages detection resolved to.
//
// The detection warnings are seeded, not appended later: every warning
// detectLanguages produced is about work this run is not going to do, and a
// reader needs it before the findings.
//
// A language set that resolves to zero entries runs no leg at all, so AllRan
// stays vacuously true, Errs stays empty, and gatedPassed(true, true, …)
// returns passed=true over a repository where nothing was linted and no test
// ran — an envelope indistinguishable from one where every leg ran and found
// nothing. It cannot be a caller mistake any more (resolveIncludeNames makes
// an unrecognised --include name a hard error, so a non-empty include always
// resolves to at least one language), which is exactly why it is disclosed
// rather than failed: what is left is auto-detection on a tree with no marker
// file, which is a legitimate state for a documentation-only repository or
// one written in a language this module does not lint. See include.go for the
// argument, and intent.Check's `intent-gate: NOT REQUIRED …` for the precedent.
func newCheckFold(langs []string, detectWarnings []string) *checkFold {
	f := &checkFold{
		LintPassed:          true,
		TestPassed:          true,
		AllRan:              true,
		Warnings:            detectWarnings,
		Combined:            map[Severity]int{},
		CoverageByLang:      map[string]float64{},
		CoverageLinesByLang: map[string]int{},
		TestsByLang:         map[string]TestCounts{},
		Diagnostics:         map[string]json.RawMessage{},
	}
	if len(langs) == 0 {
		f.Warnings = append(f.Warnings, noLanguageDetectedWarning())
	}
	return f
}

// foldLeg records what every leg shares — the non-run verdict, the outcome,
// the sources[] row and the prefixed diagnostics — and reports whether env
// carries a result the caller should read further.
//
// A leg that returned an error has no envelope, so there is no outcome to
// read from one and no tool name either — the row says which leg and which
// language, which is what is actually known.
//
// A nil envelope with no error is the leg's "no tool for this language":
// nothing was asked of a tool, so there is no outcome and no row, and adding
// either would be an invention. Skipping it keeps the aggregate a fold over
// the legs that actually ran. The whole of the caller's branch is guarded,
// not just the outcome: lintLanguage's default arm says "Check skips a nil
// envelope" and Check did not — the nil test guarded one line and
// lintEnv.Passed was dereferenced on the next. Unreachable today because all
// four detected languages have a linter, and one detector away from a panic.
func (f *checkFold) foldLeg(tool, lang string, concern Concern, env *envelope, ran bool, err error) bool {
	if !ran {
		f.AllRan = false
	}
	if err != nil {
		f.Errs = append(f.Errs, fmt.Sprintf("%s %s: %v", tool, lang, err))
		f.AllRan = false
		f.LegOutcomes = append(f.LegOutcomes, OutcomeError)
		f.Sources = append(f.Sources, brokenLegSource(tool, lang, concern))
		return false
	}
	if env == nil {
		return false
	}
	f.LegOutcomes = append(f.LegOutcomes, env.Outcome)
	f.Sources = append(f.Sources, legSource(lang, concern, env))
	// Surface sub-envelope diagnostics in the aggregate envelope so the PR
	// comment can point at the language/step that actually failed instead of
	// just reporting passed=false.
	f.Errs = append(f.Errs, prefixErrors(fmt.Sprintf("%s %s", tool, lang), env.Errors)...)
	f.Warnings = append(f.Warnings, prefixErrors(fmt.Sprintf("%s %s", tool, lang), env.Warnings)...)
	return true
}

// addLint folds one language's lint leg: its verdict, its findings and its
// SARIF document.
func (f *checkFold) addLint(lang string, env *envelope, ran bool, err error) {
	if !f.foldLeg("lint", lang, ConcernLint, env, ran, err) {
		if err != nil {
			f.LintPassed = false
		}
		return
	}
	if !env.Passed {
		f.LintPassed = false
	}
	f.TotalFindings += env.FindingsCount
	for sev, cnt := range env.FindingsBySeverity {
		f.Combined[sev] += cnt
	}
	if env.SARIFReport != nil {
		f.SARIFReports = append(f.SARIFReports, env.SARIFReport)
	}
}

// addTest folds one language's native test leg: its verdict, its coverage
// figures, its test counts and the diagnostic payload it kept.
func (f *checkFold) addTest(lang string, env *envelope, ran bool, err error) {
	if !f.foldLeg("test", lang, ConcernTests, env, ran, err) {
		if err != nil {
			f.TestPassed = false
		}
		return
	}
	if !env.Passed {
		f.TestPassed = false
	}
	if env.CoveragePercent != nil {
		f.CoverageByLang[lang] = *env.CoveragePercent
	}
	if env.CoverageLines != nil {
		f.CoverageLinesByLang[lang] = *env.CoverageLines
	}
	if env.Tests != nil {
		f.TestsByLang[lang] = *env.Tests
	}
	if len(env.GenericReport) > 0 && env.GenericFormat != "" {
		f.Diagnostics[env.GenericFormat] = env.GenericReport
	}
}

// foldCoverage adds one coverage row per language.
//
// A coverage gate that could not measure must never read as satisfied. This
// used to `continue` on a missing figure, so --min-coverage passed for any
// language whose coverage report failed to appear — which, for .NET, was
// every run: the collector name was word-split by the shell, so no cobertura
// report was ever produced and the gate was structurally unfailable. The
// decision itself lives in coverageSource; this is the loop that reaches it.
//
// It runs whether or not a gate is configured, because the row is a report's
// coverage section and not only a gate's verdict. coverageSource emits no
// error and no warning when minCoverage is zero, so an ungated run reaches
// exactly the errs, warnings and AllRan it always did. lintOnly is exempt
// because it deliberately never runs the test leg, so there is no measurement
// to have missed.
func (f *checkFold) foldCoverage(langs []string, lintOnly bool, minCoverage float64, coverageMinLines int) {
	if lintOnly {
		return
	}
	for _, lang := range langs {
		pct, measured := f.CoverageByLang[lang]
		v := coverageSource(lang, pct, measured, f.CoverageLinesByLang[lang], minCoverage, coverageMinLines)
		f.Sources = append(f.Sources, v.Source)
		f.LegOutcomes = append(f.LegOutcomes, v.Source.Outcome)
		if v.Err != "" {
			f.Errs = append(f.Errs, v.Err)
		}
		if v.Warning != "" {
			f.Warnings = append(f.Warnings, v.Warning)
		}
		if !v.Ran {
			f.AllRan = false
		}
	}
}

// buildCheckEnvelope is the fold as the evidence envelope Check writes.
func buildCheckEnvelope(f *checkFold, langs []string, repo repoContext, threshold Severity, start time.Time) *envelope {
	passed := gatedPassed(f.AllRan && !anyLegErrored(f.LegOutcomes), len(f.Errs) == 0 && f.LintPassed && f.TestPassed, threshold)
	// The un-gated counterpart to passed, folded from the legs rather than
	// derived from passed — under `fail-on: NONE` passed carries no information
	// about what was found, which is the whole reason this exists.
	//
	// A run with no legs folds to unset, and that is the point. newCheckFold
	// documents the case: a language set that resolves to zero entries produces
	// passed=true over a repository where nothing was linted and no test ran,
	// "an envelope indistinguishable from one where every leg ran and found
	// nothing". They are distinguishable here — outcome is absent, not CLEAN.
	//
	// LegOutcomes and Sources are appended to in lockstep — every row's outcome
	// goes into both, and a leg that produces no row produces no outcome — so
	// this equals sourcesOutcome(Sources) by construction. That matters because
	// cross-cutting/evidence now propagates the rows INSTEAD OF this envelope,
	// and folds its combined outcome from them: if the two could disagree, the
	// combined verdict would improve the moment quality started declaring rows.
	outcome := worstOutcome(f.LegOutcomes)

	var covByLang map[string]float64
	if len(f.CoverageByLang) > 0 {
		covByLang = f.CoverageByLang
	}
	var testCountsByLang map[string]TestCounts
	if len(f.TestsByLang) > 0 {
		testCountsByLang = f.TestsByLang
	}
	var covLinesByLang map[string]int
	if len(f.CoverageLinesByLang) > 0 {
		covLinesByLang = f.CoverageLinesByLang
	}
	warnings := f.Warnings
	// Absent on a run with nothing to explain: the field is evidence of a
	// problem, not extra payload to add to an already large lint report.
	diagReport, diagFormat, diagErr := qualityDiagnosticsReport(f.Diagnostics)
	if diagErr != nil {
		warnings = append(warnings, diagErr.Error())
	}

	languages := make([]string, 0, len(langs))
	languages = append(languages, langs...)

	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: "quality"},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Languages:     languages,
		Passed:        passed,
		Outcome:       outcome,
		// One row per tool, replacing the row cross-cutting/evidence used to
		// synthesise for this envelope. That row carried every linter and every
		// test runner under `tool: "quality"` and one findings count. A large
		// formatting report could dominate that number and obscure the other
		// tools' results; per-tool rows preserve those distinctions.
		Sources:                 f.Sources,
		FailOnSeverity:          threshold,
		FindingsCount:           f.TotalFindings,
		FindingsBySeverity:      f.Combined,
		SARIFReport:             mergeSARIFReports(f.SARIFReports),
		Warnings:                warnings,
		Errors:                  f.Errs,
		CoverageByLanguage:      covByLang,
		CoverageLinesByLanguage: covLinesByLang,
		TestsByLanguage:         testCountsByLang,
		GenericReport:           diagReport,
		GenericFormat:           diagFormat,
	}
}
