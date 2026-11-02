package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// legOutcome is one leg's result: whether the container completed under our
// control (Ran), whether the command itself succeeded (Passed), its exit code
// when there is one, its output, its unprefixed diagnostics and the coverage
// reading it produced.
//
// Ran and Passed are separate for the same reason lintLanguage returns ran
// beside its envelope: a container error is a non-run, which no threshold may
// forgive, while a non-zero exit is the command reporting a real result.
type legOutcome struct {
	Ran      bool
	Passed   bool
	ExitCode *int
	Output   string
	Errors   []string
	Warnings []string
	// Counts is present only when the declared language's runner summary was
	// recognised and internally coherent. Nil means unknown, never zero.
	Counts   *TestCounts
	Coverage *nodeCoverage
	// CoverageMissing means the leg declared a coverage report and none was
	// there to read. The caller decides whether that needs saying: with a
	// single leg the ratchet's own "skipped:no-coverage-output" verdict already
	// names the path, but with several legs another leg's report satisfies the
	// ratchet and this leg's absence would otherwise vanish.
	CoverageMissing bool
	// CoverageSet is the harvest this leg's coverage pattern produced, or nil
	// when no patterned harvest ran — the leg declared no report, named exactly
	// one, or handed over a pattern cicd refused to expand.
	//
	// It escapes as structure rather than only as prose inside a warning because
	// the merged-document count is one of the two numbers dotnetLegScopeWarning
	// needs, and rebuilding it from a warning string would be parsing our own
	// evidence. Nil is not an empty set: a harvest that merged nothing is a
	// different statement from a harvest that was never asked for.
	CoverageSet *coverageSet
	// Services is one row per service this leg declared, in declaration order.
	// Present whether or not they all became usable — a service that did not
	// is exactly the row a reader is looking for.
	Services []serviceReport
	// Duration is the leg's wall clock, from its first service probe to its
	// coverage harvest. Under --parallelism it includes waiting on an engine
	// shared with the other legs, so it measures this leg's latency, not its
	// cost. Zero means not measured.
	Duration time.Duration
}

// byoTestFold is what the leg loop in Test folds its results into. It carries
// the plan the legs were run under (the legs, their images and how each image
// was resolved, whether the run is in application mode, and the .NET scope
// sweep) so that addLeg can file each result the way the entry function always
// did — one row per leg, the coverage reading keyed by language, the per-leg
// report for the generic document — without a Dagger session in the room.
//
// Exported fields are what buildTestEnvelope reads; the unexported ones are
// the plan.
type byoTestFold struct {
	legs        []testLeg
	images      []string
	resolutions []ToolchainResolution
	appMode     bool
	// dotnetScope is the denominator a BYO .NET leg is measured against, swept
	// once for the run: it is a property of the source tree, and two legs
	// naming dotnet would otherwise pay for the same container twice and could
	// report two different answers about one tree. A sweep that failed is not
	// an empty tree — dotnetScopeErr says which, because "found no .csproj"
	// about a tree nobody looked at is the class of statement this module
	// exists to refuse.
	dotnetScope    *dotnetDiscovery
	dotnetScopeErr error

	AllRan    bool
	AllPassed bool
	// LegOutcomes is what each leg found, as opposed to what its gate decided.
	// A caller-declared leg runs a command whose failure is a real result, not
	// a findings count; when the standard runner summary is recognisable, its
	// accounting sharpens that result through byoTestLegOutcome.
	LegOutcomes      []Outcome
	LegReports       []legReport
	ReadingsByLang   map[string][]nodeCoverage
	TestCountsByLang map[string][]*TestCounts
	AllReadings      []nodeCoverage
	RawOutputs       []string
	AppRows          []SourceStatus
	// RepoRows is one repository-mode row per leg; the coverage row joins
	// after the ratchet has spoken. See byoreport.go.
	RepoRows []SourceStatus
	Errs     []string
	Warnings []string
}

// newByoTestFold starts a fold for the given plan, seeded with the warnings
// resolution already produced. Test needs no zero-language verdict of its own:
// with no language detected it still runs the caller's command in a resolved
// default container, so work happens and a leg reports on it.
func newByoTestFold(legs []testLeg, images []string, resolutions []ToolchainResolution, appMode bool, warnings []string) *byoTestFold {
	return &byoTestFold{
		legs:             legs,
		images:           images,
		resolutions:      resolutions,
		appMode:          appMode,
		AllRan:           true,
		AllPassed:        true,
		LegReports:       make([]legReport, 0, len(legs)),
		ReadingsByLang:   map[string][]nodeCoverage{},
		TestCountsByLang: map[string][]*TestCounts{},
		RawOutputs:       make([]string, 0, len(legs)),
		Warnings:         warnings,
	}
}

// setDotnetScope records the one .NET discovery sweep of the run, or why it
// could not be made.
func (f *byoTestFold) setDotnetScope(d *dotnetDiscovery, err error) {
	f.dotnetScope, f.dotnetScopeErr = d, err
}

// addLeg files the result of running leg i.
func (f *byoTestFold) addLeg(i int, out legOutcome) {
	leg := f.legs[i]
	legCount := len(f.legs)

	if f.appMode {
		f.AppRows = append(f.AppRows, appTestStatuses(leg.Label, out.Ran, out.Passed, leg.CoveragePath != "", out.Coverage != nil)...)
	} else {
		f.RepoRows = append(f.RepoRows, byoTestSource(leg.Label, out.Ran, out.Passed, out.Counts, out.Errors, out.Warnings))
	}
	if f.appMode && leg.CoveragePath != "" && out.Coverage == nil {
		out.Errors = append(out.Errors, "declared application coverage output was missing or unusable")
		out.Passed = false
	}

	// With one leg every line keeps the exact wording it had before legs
	// existed; with several, each line says which leg it came from.
	if prefix := legPrefix(leg.Label, legCount); prefix != "" {
		f.Errs = append(f.Errs, prefixErrors(prefix, out.Errors)...)
		f.Warnings = append(f.Warnings, prefixErrors(prefix, out.Warnings)...)
		f.RawOutputs = append(f.RawOutputs, fmt.Sprintf("===== test-leg %s (%s) =====\n%s", leg.Label, f.images[i], out.Output))
	} else {
		f.Errs = append(f.Errs, prefixErrors("byo-test", out.Errors)...)
		f.Warnings = append(f.Warnings, out.Warnings...)
		f.RawOutputs = append(f.RawOutputs, out.Output)
	}

	if !out.Ran {
		f.AllRan = false
	}
	if !out.Passed {
		f.AllPassed = false
	}
	f.LegOutcomes = append(f.LegOutcomes, byoTestLegOutcome(out.Ran, out.Passed, out.Errors, out.Counts))

	countKey := leg.Language
	if countKey == "" {
		countKey = "unknown"
	}
	f.TestCountsByLang[countKey] = append(f.TestCountsByLang[countKey], out.Counts)

	// Only worth saying when there is more than one leg: with one, the
	// ratchet verdict "skipped:no-coverage-output" already names the path.
	// With several, a sibling leg's report satisfies the ratchet and this
	// leg's silence would read as measured.
	if legCount > 1 {
		switch {
		case leg.CoveragePath == "":
			f.Warnings = append(f.Warnings, fmt.Sprintf(
				"test-leg %s: no coverage-path configured, so this leg's coverage is not measured and the ratchet cannot see it", leg.Label))
		case out.CoverageMissing:
			f.Warnings = append(f.Warnings, fmt.Sprintf(
				"test-leg %s: no coverage report found at %s, so this leg contributed no coverage figure", leg.Label, leg.CoveragePath))
		}
	}

	var legPct *float64
	var legLines *int
	if out.Coverage != nil {
		key := leg.Language
		if key == "" {
			// Nothing detected plus an explicit image: the run is real and
			// the language genuinely is not known, so say that rather than
			// name one.
			key = "unknown"
		}
		f.ReadingsByLang[key] = append(f.ReadingsByLang[key], *out.Coverage)
		f.AllReadings = append(f.AllReadings, *out.Coverage)

		pct := out.Coverage.Percent
		legPct = &pct
		if out.Coverage.Lines > 0 {
			lines := out.Coverage.Lines
			legLines = &lines
		}
	}

	// What this leg's evidence covers, and what it does not. Witnessing is
	// per language, so a command touching part of a .NET tree used to
	// produce an envelope indistinguishable from one that touched all of
	// it; the numbers close that, and the sentence refuses the ratio
	// between them because only the consumer's command knows what its own
	// scope should have been.
	var merged *int
	if out.CoverageSet != nil {
		m := out.CoverageSet.Parsed
		merged = &m
	}
	var projects, testProjects *int
	if leg.Language == "dotnet" {
		qualifier := legScopeQualifier(leg.Label, legCount)
		switch {
		case f.dotnetScopeErr != nil:
			f.Warnings = append(f.Warnings, dotnetLegScopeUnknownWarning(qualifier, f.dotnetScopeErr))
		case f.dotnetScope != nil:
			p, tp := len(f.dotnetScope.Projects), len(f.dotnetScope.TestProjects)
			projects, testProjects = &p, &tp
			if w := dotnetLegScopeWarning(qualifier, *f.dotnetScope, merged); w != "" {
				f.Warnings = append(f.Warnings, w)
			}
		}
	}

	f.LegReports = append(f.LegReports, legReport{
		Label:                   leg.Label,
		Language:                leg.Language,
		Image:                   f.images[i],
		Ran:                     out.Ran,
		ExitCode:                out.ExitCode,
		Tests:                   out.Counts,
		CoveragePath:            leg.CoveragePath,
		CoverageMeasured:        out.Coverage != nil,
		CoveragePercent:         legPct,
		CoverageLines:           legLines,
		CoverageDocumentsMerged: merged,
		ProjectsDiscovered:      projects,
		TestProjectsDiscovered:  testProjects,
		ToolchainFrom:           f.resolutions[i].From,
		ToolchainNote:           f.resolutions[i].Note,
		Services:                out.Services,
		DurationMS:              out.Duration.Milliseconds(),
	})

	if w := servicesSummary(legScopeQualifier(leg.Label, legCount), out.Services); w != "" {
		f.Warnings = append(f.Warnings, w)
	}
}

// baselineDoc is the ratchet baseline as the entry function read it: whether
// one was supplied, its contents, or why it could not be read. The parse
// happens in buildTestEnvelope, so the fail-open rule it implements is under
// test.
type baselineDoc struct {
	Present bool
	Raw     string
	ReadErr error
}

// buildTestEnvelope states the verdict and assembles the envelope from a fold.
//
// detected is the language set the tree showed; `languages` in the envelope
// carries the witnessed set, not the detected one, so the envelope describes
// what it actually attests. The ratchet's own errors fold in as FAILED: they
// are a measured result that came out wrong, the same class as a failing leg,
// and leaving them out would let a run with a regressed ratchet report the
// outcome of its legs alone.
func buildTestEnvelope(
	f *byoTestFold,
	detected []string,
	baseline baselineDoc,
	tolerance float64,
	warnMode bool,
	repo repoContext,
	threshold Severity,
	start time.Time,
) (*envelope, error) {
	allErrs := f.Errs
	allWarnings := f.Warnings
	allRan := f.AllRan
	legOutcomes := f.LegOutcomes
	appRows := f.AppRows

	// The fact the old envelope could not express: which detected languages no
	// leg tested.
	witnessed := witnessedLanguages(f.legs)
	unwitnessed := unwitnessedLanguages(detected, witnessed)
	if len(unwitnessed) > 0 {
		allWarnings = append(allWarnings, notWitnessedWarning(unwitnessed, witnessed))
		if f.appMode {
			allErrs = append(allErrs, "application languages lack test legs: "+strings.Join(unwitnessed, ", "))
			allRan = false
			legOutcomes = append(legOutcomes, OutcomeError)
			appRows = append(appRows, SourceStatus{ModuleName: moduleName, Stage: moduleStage, Tool: "unwitnessed-languages", Concern: ConcernTests, Passed: false, Outcome: OutcomeError, ErrorsCount: 1})
		}
	}
	if f.appMode {
		allWarnings = append(allWarnings, "Application tests and coverage follow caller-owned commands; source scope is declared, and coverage totals do not prove complete application coverage.")
	}

	measured, measuredLines := mergeLegCoverage(f.ReadingsByLang)
	measuredTests := mergeLegTestCounts(f.TestCountsByLang)
	haveCoverage := len(measured) > 0
	covPct, covLines := foldCoverage(f.AllReadings)

	// Baseline parse — fail-open: a missing/unreadable/unusable baseline is a
	// warning and a skipped ratchet, never an error (ADR-003).
	haveBaseline := false
	var baselineMap map[string]float64
	if baseline.Present {
		if baseline.ReadErr != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("baseline file unreadable: %v", baseline.ReadErr))
		} else if parsed, parseErr := parseBaselineCoverage(baseline.Raw); parseErr != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("baseline unusable: %v", parseErr))
		} else {
			baselineMap = parsed
			haveBaseline = true
		}
	}

	outcome := applyRatchet(ratchetInput{
		Measured:     measured,
		Baseline:     baselineMap,
		HaveCoverage: haveCoverage,
		HaveBaseline: haveBaseline,
		CoveragePath: declaredCoveragePaths(f.legs),
		Tolerance:    tolerance,
		WarnMode:     warnMode,
	})
	allErrs = append(allErrs, outcome.Errors...)
	allWarnings = append(allWarnings, outcome.Warnings...)

	passed := gatedPassed(allRan && !anyLegErrored(legOutcomes), len(allErrs) == 0 && f.AllPassed, threshold)
	// envOutcome, not outcome: the ratchet verdict above already owns that name
	// in this scope, and the two are different things — one is the coverage
	// trend, this is what the legs did.
	envOutcome := worstOutcome(legOutcomes)
	if len(outcome.Errors) > 0 {
		envOutcome = worstOutcome(append(legOutcomes, OutcomeFailed))
	}

	var covByLang map[string]float64
	if len(measured) > 0 {
		covByLang = measured
	}
	var covLinesByLang map[string]int
	if len(measuredLines) > 0 {
		covLinesByLang = measuredLines
	}
	var baselineByLang map[string]float64
	if haveBaseline {
		baselineByLang = baselineMap
	}
	var testsByLang map[string]TestCounts
	if len(measuredTests) > 0 {
		testsByLang = measuredTests
	}

	legsJSON, err := json.Marshal(newLegsReport(detected, witnessed, unwitnessed, f.LegReports))
	if err != nil {
		return nil, fmt.Errorf("marshal test-leg report: %w", err)
	}

	env := &envelope{
		SchemaVersion:              evidenceSchemaVersion,
		ModuleName:                 moduleName,
		Stage:                      moduleStage,
		Tool:                       toolInfo{Name: "byo-test"},
		Repo:                       repo,
		TimestampUTC:               start.UTC(),
		DurationMS:                 time.Since(start).Milliseconds(),
		Languages:                  witnessed,
		Passed:                     passed,
		Outcome:                    envOutcome,
		FailOnSeverity:             threshold,
		RawOutputRef:               strings.Join(f.RawOutputs, "\n"),
		CoveragePercent:            covPct,
		CoverageLines:              covLines,
		CoverageByLanguage:         covByLang,
		CoverageLinesByLanguage:    covLinesByLang,
		CoverageBaselineByLanguage: baselineByLang,
		TestsByLanguage:            testsByLang,
		CoverageRatchet:            outcome.Verdict,
		GenericReport:              legsJSON,
		GenericFormat:              legsReportFormat,
		Warnings:                   allWarnings,
		Errors:                     allErrs,
	}
	if f.appMode {
		env.Sources = appRows
	} else {
		env.Sources = append(f.RepoRows, byoCoverageSource(outcome, covLines))
	}
	return env, nil
}
