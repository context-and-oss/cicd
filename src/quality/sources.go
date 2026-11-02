package main

import "fmt"

// Per-tool verdicts for the quality module.
//
// src/security/sources.go is the sibling, not a copy: security fuses a fixed
// set of scanners per entry point, while quality fuses one lint and one test
// leg per detected language, so the row builders and the concern they file
// under differ by design.
//
// quality fuses six linters and five test runners behind one envelope, and it
// used to ship that envelope with no sources[] at all — so cross-cutting/
// evidence synthesised a single row for it. A large formatting report could
// dominate that row's findingsCount, hiding the distinction between fixable
// line-ending disagreements, other lint findings and test results.
//
// One row per tool that actually ran separates clean lint, formatting findings,
// test errors and coverage with its denominator. That is the shape security
// has had since ScanSource, and the shape a per-concern report needs.

// legSource is the row for one language's lint or test leg.
//
// Everything is taken from the sub-envelope rather than recomputed: the leg
// already decided its own verdict and stated its own outcome, and a second
// derivation here could only disagree with it.
//
// The concern is the exception, and it is a parameter rather than something
// read off env.Tool.Name for the reason Concern's own doc gives: a table
// mapping tool names to concerns goes stale silently, and quality gains
// runners. The caller is inside the lint branch or the test branch and already
// knows which; passing it costs a word and cannot drift.
func legSource(lang string, concern Concern, env *envelope) SourceStatus {
	return SourceStatus{
		ModuleName: moduleName,
		Stage:      moduleStage,
		Tool:       env.Tool.Name,
		// The language, not the entrypoint. Scope exists so one tool appearing
		// twice can be told apart, and for quality the second axis is the
		// language: two .NET test projects and a node one all reach the same
		// sources[], and "coverage, coverage" is exactly the "gitleaks,
		// gitleaks" ambiguity this field was added for.
		Scope:         lang,
		Concern:       concern,
		Passed:        env.Passed,
		Outcome:       env.Outcome,
		Examined:      env.Examined,
		FindingsCount: env.FindingsCount,
		ErrorsCount:   len(env.Errors),
		WarningsCount: len(env.Warnings),
	}
}

// brokenLegSource is the row for a leg that returned an error instead of an
// envelope.
//
// There is nothing to read a verdict from, and that is the point: a leg that
// could not produce a result must appear in sources[] saying so. Leaving it out
// would shorten the list rather than fail it, and a consumer counting rows
// would see a smaller, cleaner-looking run.
func brokenLegSource(tool, lang string, concern Concern) SourceStatus {
	return SourceStatus{
		ModuleName: moduleName,
		Stage:      moduleStage,
		Tool:       tool,
		Scope:      lang,
		// Stated even though the leg produced nothing. A broken leg still
		// belongs to a concern, and a report that cannot file it has to drop
		// it from the concern's section — which is exactly the shorter,
		// cleaner-looking run this function exists to prevent.
		Concern:     concern,
		Passed:      false,
		Outcome:     OutcomeError,
		ErrorsCount: 1,
	}
}

// coverageVerdict is one language's coverage result: the row a report reads,
// plus the diagnostics the envelope has always carried.
//
// The three come back together because they are one decision. They used to be
// made inline in Check, behind a Dagger build tag, which is why the gate could
// be structurally unfailable for every .NET run without a test noticing.
type coverageVerdict struct {
	Source  SourceStatus
	Err     string
	Warning string
	// Ran is false only when the gate was asked to enforce a figure that was
	// never measured. It is the allRan input, not a statement about the tests.
	Ran bool
}

// coverageSource decides one language's coverage row and the diagnostics that
// go with it.
//
// minCoverage of zero means no gate was configured. That is not a waived gate
// and not a missing one — there is no policy to violate, so a measured figure
// is CLEAN in the same way a scanner with no findings is CLEAN. A configured
// gate that was deliberately not applied is a different thing and is SKIPPED:
// a threshold exists, this run declined to enforce it, and a report must not
// render that as a bar that was cleared.
func coverageSource(lang string, pct float64, measured bool, lines int, minCoverage float64, minLines int) coverageVerdict {
	row := SourceStatus{
		ModuleName: moduleName,
		Stage:      moduleStage,
		Tool:       "coverage",
		Scope:      lang,
		Concern:    ConcernCoverage,
		Passed:     true,
		Outcome:    OutcomeClean,
	}

	if !measured {
		// No figure at all. Without a gate that is simply coverage this run
		// does not have; with one it is a gate that could not run, which NONE
		// does not suppress — see gatedPassed.
		if minCoverage <= 0 {
			row.Outcome = OutcomeSkipped
			return coverageVerdict{Source: row, Ran: true}
		}
		row.Passed = false
		row.Outcome = OutcomeError
		row.ErrorsCount = 1
		return coverageVerdict{
			Source: row,
			Err: fmt.Sprintf(
				"%s coverage gate requires %.1f%% but no coverage was measured; refusing to pass a gate that could not run",
				lang, minCoverage),
		}
	}

	// The denominator the percentage needs. In a hypothetical example, 40% of
	// 1,000 coverable lines and 40% of 100 are the same percentage but not the
	// same measurement; a report printing only the percentage loses that scope.
	row.Examined = &Examined{Unit: "coverable lines", Count: lines}

	switch {
	case minCoverage <= 0:
		return coverageVerdict{Source: row, Ran: true}

	case minLines > 0 && lines < minLines:
		row.Outcome = OutcomeSkipped
		row.WarningsCount = 1
		return coverageVerdict{
			Source:  row,
			Warning: fmt.Sprintf("coverage gate skipped for %s: %d coverable lines (min %d)", lang, lines, minLines),
			Ran:     true,
		}

	case pct < minCoverage:
		// A measured figure under the bar is a real result that failed, not a
		// tool that found something and not a tool that broke.
		row.Passed = false
		row.Outcome = OutcomeFailed
		row.ErrorsCount = 1
		return coverageVerdict{
			Source: row,
			Err:    fmt.Sprintf("%s coverage %.1f%% below required %.1f%%", lang, pct, minCoverage),
			Ran:    true,
		}

	default:
		return coverageVerdict{Source: row, Ran: true}
	}
}
