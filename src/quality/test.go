//go:build !unit_test

package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// testLanguage dispatches to the test runner for lang. The second result is
// ran — see lintLanguage for why it travels beside the envelope rather than in
// it.
func testLanguage(
	ctx context.Context,
	lang language,
	src *dagger.Directory,
	threshold Severity,
	repo repoContext,
	npmFeedUrl string,
	npmFeedRouting string,
	npmToken *dagger.Secret,
	nugetFeedUrl string,
	nugetToken *dagger.Secret,
	nodeLimit int,
) (*envelope, bool, error) {
	switch lang {
	case langGo:
		return runGoTest(ctx, src, threshold, repo)
	case langNode:
		return runVitest(ctx, src, threshold, repo, npmFeedUrl, npmFeedRouting, npmToken, nodeLimit)
	case langPython:
		return runPytest(ctx, src, threshold, repo)
	case langDotnet:
		return runDotnetTest(ctx, src, threshold, repo, nugetFeedUrl, nugetToken)
	default:
		// Unsupported language: no tool was asked to run, so none failed to.
		return nil, true, nil
	}
}

// runGoTest runs `go test` over the source.
// v0.20.x: go test exits non-zero on failures, which is the correct signal —
// we capture the error and set passed=false rather than aborting the pipeline.
func runGoTest(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext) (*envelope, bool, error) {
	start := time.Now()

	// Workspace-aware package selector. Empty go.work (or no file) ⇒ "./...";
	// a populated go.work expands to each member's "./<use>/...". See
	// goworkspace.go for the reasoning.
	workContents, workErr := readGoWorkIfPresent(ctx, src)
	pkgs := goTestArgs(workContents)

	// Use sh wrapper to always exit 0 so Dagger doesn't abort.
	// Capture exit code manually via a sentinel file.
	cmd := fmt.Sprintf(
		`go test -v -coverprofile=/tmp/coverage.out %s > /tmp/gotest.out 2>&1; echo $? > /tmp/gotest.exit`,
		pkgs,
	)

	// GOTOOLCHAIN=auto lets the in-image Go fetch a newer toolchain when the
	// consumer's go.mod / go.work pins a version above the base image's. The
	// alpine images default to GOTOOLCHAIN=local, which hard-fails on a higher
	// directive (e.g. "go.work requires go >= 1.26.2; running 1.24") instead
	// of downloading. See https://go.dev/doc/toolchain.
	ctr := dag.Container().
		From(golangImage).
		WithMountedDirectory("/src", src).
		WithWorkdir("/src").
		WithEnvVariable("CGO_ENABLED", "0").
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithExec([]string{"sh", "-c", cmd})

	exitCodeStr, err := ctr.File("/tmp/gotest.exit").Contents(ctx)
	out, outErr := ctr.File("/tmp/gotest.out").Contents(ctx)

	// A container error is a non-run: the exit sentinel never came out, so there
	// is no test result at all. A non-zero exit is a real result. `fail-on NONE`
	// suppresses only the latter — see gatedPassed in gating.go. An output that
	// could not be read back is a non-run too: the counts below are parsed out
	// of it, and an empty string parses to no tests. So is a sentinel holding no
	// exit status, and a go.work cicd could not read, because the selector it
	// chose was then a guess. See foldTestLeg and readbackError.
	// A package that did not build, and a go command that never reached a
	// package, exit 1 like a failing test does; goTestNonRun tells them apart.
	leg := goTestNonRun(foldTestLeg("go test", "go test: ", err, "/tmp/gotest.out", outErr, "/tmp/gotest.exit", exitCodeStr), "go test", out, true)
	ran := workErr == nil && leg.ran
	rawPassed := ran && leg.passed
	var errs []string
	switch {
	case workErr != nil:
		errs = append(errs, "go test: "+workErr.Error())
	case leg.err != "":
		errs = append(errs, leg.err)
	}

	var goCovPct *float64
	var goCovLines *int
	if rawPassed {
		covOut, covErr := ctr.
			WithExec([]string{"go", "tool", "cover", "-func=/tmp/coverage.out"}).
			Stdout(ctx)
		if covErr == nil {
			if pct := parseTotalCoverage(covOut); pct >= 0 {
				goCovPct = &pct
			}
		}
		if profile, profileErr := ctr.File("/tmp/coverage.out").Contents(ctx); profileErr == nil {
			if stmts := parseCoverageOutStatements(profile); stmts > 0 {
				goCovLines = &stmts
			}
		}
	}

	// Counted from the captured output regardless of pass/fail. Coverage is
	// gated on rawPassed because a failed run's coverage report is unreliable,
	// but a failed run's test count is the most useful thing about it: "3 of
	// 431 failed" is a different report from "tests failed".
	var goCounts *TestCounts
	if ran {
		if c, countOK := parseGoTestCounts(out); countOK {
			goCounts = &c
		}
	}

	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: "go-test", Version: "1.26"},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Languages:     []string{"go"},
		Passed:        testLegPassed(ran, rawPassed, goCounts, threshold),
		// goCounts lets a failing suite be told apart from a `go test` that
		// exited non-zero with nothing failing (a build error in a package,
		// a panic outside a test). See testOutcome.
		Outcome:         testOutcome(ran, rawPassed, goCounts),
		FailOnSeverity:  threshold,
		RawOutputRef:    out,
		Errors:          errs,
		CoveragePercent: goCovPct,
		CoverageLines:   goCovLines,
		Tests:           goCounts,
	}, ran, nil
}

// readGoWorkIfPresent returns go.work contents when present at src root, or
// an empty string if absent. Absence is the common case and not an error. A
// root that could not be listed, or a go.work that is there and could not be
// read, is an error: it used to be swallowed into "", which selected `./...`
// for a workspace whose members `./...` does not reach, and the leg then
// reported Go's "directory prefix . does not contain modules listed in
// go.work" as the consumer's test failure.
func readGoWorkIfPresent(ctx context.Context, src *dagger.Directory) (string, error) {
	entries, err := src.Entries(ctx)
	if err != nil {
		return "", fmt.Errorf("could not list the source root for go.work: %w", err)
	}
	for _, e := range entries {
		if e == "go.work" {
			contents, ferr := src.File("go.work").Contents(ctx)
			if ferr != nil {
				return "", fmt.Errorf("could not read go.work: %w", ferr)
			}
			return contents, nil
		}
	}
	return "", nil
}

// parseTotalCoverage extracts the total coverage percentage from `go tool cover -func` output.
func parseTotalCoverage(output string) float64 {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "total:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				pctStr := strings.TrimSuffix(fields[len(fields)-1], "%")
				if f, err := strconv.ParseFloat(pctStr, 64); err == nil {
					return f
				}
			}
		}
	}
	return -1
}

// parseVitestCoverage parses the coverage-summary.json produced by @vitest/coverage-v8.
// Returns (pct, totalLines); pct is -1 on parse failure.
func parseVitestCoverage(raw string) (float64, int) {
	var summary struct {
		Total struct {
			Lines struct {
				Pct   float64 `json:"pct"`
				Total int     `json:"total"`
			} `json:"lines"`
		} `json:"total"`
	}
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		return -1, 0
	}
	return summary.Total.Lines.Pct, summary.Total.Lines.Total
}

// parsePytestCoverage parses the JSON report produced by pytest-cov.
// Returns (pct, numStatements); pct is -1 on parse failure.
func parsePytestCoverage(raw string) (float64, int) {
	var report struct {
		Totals struct {
			PercentCovered float64 `json:"percent_covered"`
			NumStatements  int     `json:"num_statements"`
		} `json:"totals"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return -1, 0
	}
	return report.Totals.PercentCovered, report.Totals.NumStatements
}

// Cobertura parsing lives in coverage.go (parseCobertura) — untagged, so it is
// covered by the unit suite. test.go used to carry a second, tagged copy that
// nothing could test; the .NET leg now shares the tested one.

// parseCoverageOutStatements counts total coverable statements in a Go coverage profile.
// Each non-header line has the format: file:startLine.startCol,endLine.endCol numStmts count
func parseCoverageOutStatements(profile string) int {
	total := 0
	for _, line := range strings.Split(profile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				total += n
			}
		}
	}
	return total
}

// runVitest runs the Node test suite once per Node project in the tree.
// vitest exits non-zero on test failures; the exit status is captured rather
// than aborting the pipeline.
//
// The projects come from the same resolution the lint leg uses. This used to be
// pinned to the mount root like runEslint was, with a worse failure: `npx vitest
// run` at a root with no node_modules makes npx fetch an unpinned vitest off the
// network, run it against a tree with no tests, and report "vitest failed (exit
// 1)" — a red gate whose message points nowhere near the actual problem.
//
// The second result is ran — see lintLanguage. Unlike the lint legs it cannot be
// derived from len(errs): a test leg records a genuine test failure in errs too,
// and `fail-on NONE` must still suppress that. Only a project whose container
// never produced an exit sentinel is a non-run.
func runVitest(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext, feedUrl, feedRouting string, feedToken *dagger.Secret, nodeLimit int) (*envelope, bool, error) {
	start := time.Now()

	var errs, warnings []string
	ran := true

	dirs, derr := resolveNodeProjects(ctx, src)
	if derr != nil {
		errs = append(errs, "vitest: could not locate the Node project: "+derr.Error())
		dirs = []string{"."}
		// Where the project lives is unknown, so testing the root is a fallback,
		// not evidence the project's suite ran.
		ran = false
	}
	if len(dirs) == 0 {
		warnings = append(warnings, "vitest: no package.json found; testing the source root")
		dirs = []string{"."}
	}
	if msg := nodeProjectLimitError(dirs, nodeLimit); msg != "" {
		// Same reasoning as the lint leg: running a subset and reporting "tests
		// passed" is the false pass. Reuse the lint message, retargeted.
		return &envelope{
			SchemaVersion:  evidenceSchemaVersion,
			ModuleName:     moduleName,
			Stage:          moduleStage,
			Tool:           toolInfo{Name: "vitest", Version: "2"},
			Repo:           repo,
			TimestampUTC:   start.UTC(),
			DurationMS:     time.Since(start).Milliseconds(),
			Languages:      []string{"node"},
			Passed:         gatedPassed(false, false, threshold),
			Outcome:        testOutcome(false, false, nil),
			FailOnSeverity: threshold,
			Warnings:       warnings,
			Errors:         []string{strings.Replace(msg, "eslint:", "vitest:", 1)},
		}, false, nil
	}
	if len(dirs) == 1 && dirs[0] != "." {
		warnings = append(warnings, "vitest: tested "+dirs[0]+" (no package.json at the source root)")
	} else if len(dirs) > 1 {
		warnings = append(warnings, "vitest: tested "+strconv.Itoa(len(dirs))+" Node projects: "+strings.Join(dirs, ", "))
	}

	rawPassed := true
	var outputs []string
	var cov []nodeCoverage
	var counted TestCounts
	allCountable := true

	for _, dir := range dirs {
		out, projErrs, projCov, projRan, projWarnings := runVitestIn(ctx, src, dir, feedUrl, feedRouting, feedToken, repo.RepoURL)
		if !projRan {
			ran = false
		}
		if c, ok := parseVitestTestCounts(out); projRan && ok {
			counted = addTestCounts(counted, c)
		} else {
			allCountable = false
		}
		for _, w := range projWarnings {
			warnings = append(warnings, nodeProjectLabel(dir, "vitest: "+w))
		}
		if len(projErrs) > 0 {
			rawPassed = false
		}
		for _, e := range projErrs {
			errs = append(errs, nodeProjectLabel(dir, e))
		}
		if dir == "." {
			outputs = append(outputs, out)
		} else {
			outputs = append(outputs, "=== "+dir+" ===\n"+out)
		}
		if projCov != nil {
			cov = append(cov, *projCov)
		}
	}

	nodeCovPct, nodeCovLines := mergeNodeCoverage(cov)
	var counts *TestCounts
	if allCountable {
		counts = &counted
	}

	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: "vitest", Version: "2"},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Languages:     []string{"node"},
		// severityOK is rawPassed alone. The old `&& len(errs) == 0` is subsumed:
		// every errs entry either came from a project whose exit was non-zero
		// (already rawPassed=false) or from a non-run, which ran=false fails at
		// every threshold.
		Passed:          testLegPassed(ran, rawPassed, counts, threshold),
		Outcome:         testOutcome(ran, rawPassed, counts),
		FailOnSeverity:  threshold,
		RawOutputRef:    strings.Join(outputs, "\n"),
		Warnings:        warnings,
		Errors:          errs,
		CoveragePercent: nodeCovPct,
		CoverageLines:   nodeCovLines,
		Tests:           counts,
	}, ran, nil
}

// runVitestIn tests a single Node project. dir reaches the container through
// WithWorkdir — an argument, not a shell word — so a consumer directory name is
// never spliced into the script below.
//
// The last result is ran. It is returned beside errs rather than folded into it
// because the two entries errs can hold are not the same kind of thing: a
// container error means no test result exists, a non-zero exit means the tests
// ran and failed. Only the second is a finding `fail-on NONE` may suppress.
//
// The project's package manager is detected first (nodeinstall.go). A project
// whose manager cicd cannot determine runs nothing and is a non-run: testing
// it with a guessed one would test a dependency tree nobody locked.
func runVitestIn(ctx context.Context, src *dagger.Directory, dir string, feedUrl, feedRouting string, feedToken *dagger.Secret, cacheScope string) (string, []string, *nodeCoverage, bool, []string) {
	pm, warnings, err := detectNodeProject(ctx, src, dir)
	if err != nil {
		return "", []string{"vitest: did not run: " + err.Error()}, nil, false, nil
	}
	warnings = append(warnings, nodeFeedWarnings(ctx, src, dir, pm, feedUrl, feedRouting, feedToken)...)

	ctr := commandCaches(dag.Container().From(nodeImage), cacheScope).WithMountedDirectory(srcMount, src).
		WithWorkdir(path.Join(srcMount, dir))
	ctr = withNodeFeed(ctr, feedUrl, feedRouting, feedToken)

	// Install project deps, then ensure a coverage provider is available. The
	// script and the sentinel it writes live in vitestcoverage.go, where they
	// are unit-testable — see vitestScript for why the outcome is recorded
	// rather than inferred.
	ctr = ctr.WithExec([]string{"sh", "-c", vitestScript(pm)})

	exitCodeStr, err := ctr.File("/tmp/vitest.exit").Contents(ctx)
	out, outErr := ctr.File("/tmp/vitest.out").Contents(ctx)

	// See runGoTest: err is a non-run — the exit sentinel never came out, so
	// there is no test result at all — and so is an output that could not be
	// read back, or a sentinel holding no exit status. A non-zero exit is a
	// real result only when vitest printed its Tests summary: exit 1 is also
	// what a vitest that never started returns (vitestNonRun).
	leg := foldTestLeg("vitest", "vitest: ", err, "/tmp/vitest.out", outErr, "/tmp/vitest.exit", exitCodeStr)
	_, counted := parseVitestTestCounts(out)
	installExit, _ := ctr.File(nodeInstallExitPath).Contents(ctx)
	vitestVersion, versionErr := ctr.File(vitestVersionPath).Contents(ctx)
	leg = vitestNonRun(leg, counted, pm.record(installExit), vitestVersion, versionErr == nil)
	// A file vitest could not load exits 1 like a failing test, and the Tests
	// line counts only the files that loaded; vitestSuiteNonRun tells them apart.
	leg = vitestSuiteNonRun(leg, "vitest", out, true)
	ran := leg.ran
	var errs []string
	if leg.err != "" {
		errs = append(errs, leg.err)
	}

	var cov *nodeCoverage
	if covRaw, covErr := ctr.File("/tmp/coverage/coverage-summary.json").Contents(ctx); covErr == nil {
		if pct, lines := parseVitestCoverage(covRaw); pct >= 0 {
			cov = &nodeCoverage{Percent: pct, Lines: lines}
		}
	}

	// Why there is no coverage number, when there is none. The sentinel is read
	// whatever happened to the run: a suite that failed still says whether its
	// coverage was measured, and a reader comparing two runs needs the reason
	// in both.
	state, stateErr := ctr.File(covStatePath).Contents(ctx)
	if w := coverageProviderWarning(state, stateErr, cov != nil, leg.passed); w != "" {
		warnings = append(warnings, w)
	}

	return out, errs, cov, ran, warnings
}

// runPytest runs pytest.
// v0.20.x: pytest exits non-zero on failures; use sh wrapper with exit sentinel.
func runPytest(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext) (*envelope, bool, error) {
	start := time.Now()

	ctr := dag.Container().
		From(pythonImage).
		WithMountedDirectory("/src", src).
		WithWorkdir("/src").
		WithExec([]string{"sh", "-c", pytestScript()})

	exitCodeStr, err := ctr.File("/tmp/pytest.exit").Contents(ctx)
	out, outErr := ctr.File("/tmp/pytest.out").Contents(ctx)

	// See runGoTest: err is a non-run, and so is an output that could not be
	// read back or a sentinel holding no exit status; a non-zero exit is a
	// result.
	pipExit, _ := ctr.File(pipInstallExitPath).Contents(ctx)
	leg := pytestNonRun(foldTestLeg("pytest", "pytest: ", err, "/tmp/pytest.out", outErr, "/tmp/pytest.exit", exitCodeStr), pipExit)
	ran := leg.ran
	rawPassed := ran && leg.passed

	var errs []string
	if leg.err != "" {
		errs = append(errs, leg.err)
	}

	var pyCovPct *float64
	var pyCovLines *int
	if covRaw, covErr := ctr.File("/tmp/coverage.json").Contents(ctx); covErr == nil {
		if pct, lines := parsePytestCoverage(covRaw); pct >= 0 {
			pyCovPct = &pct
			if lines > 0 {
				pyCovLines = &lines
			}
		}
	}
	var counts *TestCounts
	if ran {
		if c, ok := parsePytestTestCounts(out); ok {
			counts = &c
		}
	}

	return &envelope{
		SchemaVersion:   evidenceSchemaVersion,
		ModuleName:      moduleName,
		Stage:           moduleStage,
		Tool:            toolInfo{Name: "pytest", Version: "latest"},
		Repo:            repo,
		TimestampUTC:    start.UTC(),
		DurationMS:      time.Since(start).Milliseconds(),
		Languages:       []string{"python"},
		Passed:          testLegPassed(ran, rawPassed, counts, threshold),
		Outcome:         testOutcome(ran, rawPassed, counts),
		FailOnSeverity:  threshold,
		RawOutputRef:    out,
		Errors:          errs,
		CoveragePercent: pyCovPct,
		CoverageLines:   pyCovLines,
		Tests:           counts,
	}, ran, nil
}

// runDotnetTest runs `dotnet test` against the projects a test runner can
// actually execute.
//
// The bare invocation this replaces was a silent false pass. `dotnet test` with
// no argument asks MSBuild to resolve a project from the working directory;
// MSBuild picks the single project sitting there and does not recurse. When that
// project is not a test project, dotnet test finds nothing to execute, writes no
// .trx, and **exits 0** — measured under SDK 8.0.422 and 10.0.100 on this
// repository's own dotnet-app fixture, whose xUnit project lives in tests/ and
// had therefore never run in CI. Zero tests and all tests passing produced the
// same evidence, so both are now told apart explicitly: the run is only
// trustworthy if a .trx exists and accounts for at least one test.
func runDotnetTest(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext, feedUrl string, feedToken *dagger.Secret) (*envelope, bool, error) {
	start := time.Now()

	var errs, warnings []string

	// Every early return here is a non-run: nothing was executed, so ran=false
	// and no threshold — NONE included — may report this as passed.
	discovery, derr := discoverDotnetTargets(ctx, src)
	if derr != nil {
		errs = append(errs, "dotnet test: could not enumerate .NET projects: "+derr.Error())
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}

	kind, targets := dotnetTestTargets(discovery)
	if len(targets) == 0 {
		errs = append(errs, dotnetNoTargetError("dotnet test", discovery))
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	if msg := dotnetTargetLimitError("dotnet test", targets); msg != "" {
		errs = append(errs, msg)
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	// One owner for both branches, so the solution path cannot go quiet about
	// scope while the project path reports a ratio — the absence of a ratio would
	// otherwise be indistinguishable from a classification that was checked.
	if w := dotnetTestScopeWarning(kind, discovery, targets); w != "" {
		warnings = append(warnings, w)
	}

	// Which SDK band to run is resolved from the repository, not from a single
	// compile-time pin; both early returns here are non-runs.
	req, rerr := discoverDotnetBandRequest(ctx, src)
	if rerr != nil {
		errs = append(errs, "dotnet test: could not read which .NET SDK band this "+
			"repository needs: "+rerr.Error())
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	band, bandNote := dotnetResolveBand(req)
	warnings = append(warnings, "dotnet test: "+bandNote)

	// Which runner, asked rather than assumed — and named in the evidence beside
	// the band, because a consumer reading a green .NET leg otherwise cannot tell
	// which of two mutually exclusive command lines produced it. A runner cicd
	// could not resolve is a non-run: nothing is invoked, because there is no
	// default invocation to fall back on that would not be a guess.
	runner, runnerNote, runnerErr, rnErr := discoverDotnetTestRunner(ctx, src)
	if rnErr != nil {
		errs = append(errs, "dotnet test: could not read which test runner this "+
			"repository asks for: "+rnErr.Error())
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	if runnerErr != "" {
		errs = append(errs, "dotnet test: "+runnerErr)
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	warnings = append(warnings, "dotnet test: "+runnerNote)

	base, ok := dotnetContainer(ctx, src, band, feedUrl, feedToken, repo.RepoURL)
	if !ok {
		errs = append(errs, dotnetUnpinnedBandError("dotnet test", band))
		return dotnetTestEnvelope(start, repo, threshold, "unknown", "", false, errs, warnings, nil, nil, nil), false, nil
	}
	sdkVersion := readDotnetSDKVersion(ctx, base)

	var rawOut strings.Builder
	var summaries []trxSummary
	var coverage []dotnetCoverage
	label := len(targets) > 1
	ran := true
	// A sweep's accounting is only the repository's accounting if every project
	// in it was countable. One unreadable .trx among several makes the sum a
	// total for some of the solution, and there is nothing in a summed figure to
	// say which part — the same refusal totalTestCounts applies across languages.
	allCountable := true
	// kept collects each target's bounded output record; empty on a run whose
	// every exit is explained, so the envelope carries no genericReport then.
	var kept []dotnetTestOutput

	for _, target := range targets {
		res := runDotnetTestOn(ctx, base, target, band, runner)
		if !res.ran {
			ran = false
		}
		if res.output != nil {
			kept = append(kept, *res.output)
		}
		for _, e := range res.errs {
			errs = append(errs, dotnetTargetLabel(target, e))
		}
		for _, w := range res.warnings {
			warnings = append(warnings, dotnetTargetLabel(target, w))
		}
		if label {
			rawOut.WriteString("=== " + target + " ===\n")
		}
		rawOut.WriteString(res.out)
		if !strings.HasSuffix(res.out, "\n") {
			rawOut.WriteString("\n")
		}
		summaries = append(summaries, res.summary)
		if res.parsed <= 0 {
			allCountable = false
		}
		coverage = append(coverage, res.coverage...)
	}

	if w := dotnetSkippedWarning(sumTrx(summaries)); w != "" {
		warnings = append(warnings, w)
	}

	var counts *TestCounts
	if allCountable {
		if c, ok := trxTestCounts(sumTrx(summaries), len(summaries)); ok {
			counts = &c
		}
	}

	covPct, covLines := mergeDotnetCoverage(coverage)
	env := dotnetTestEnvelope(start, repo, threshold, sdkVersion, rawOut.String(),
		ran, errs, warnings, covPct, covLines, counts)
	if len(kept) > 0 {
		raw, err := json.Marshal(kept)
		if err != nil {
			// Unreachable for a struct of strings and ints, and still not a
			// silent drop: the record exists to be read, so its absence is said.
			env.Errors = append(env.Errors, "dotnet test: the kept output record could not be "+
				"written into genericReport: "+err.Error())
		} else {
			env.GenericReport = json.RawMessage(raw)
			env.GenericFormat = dotnetTestOutputFormat
		}
	}
	return env, ran, nil
}

type dotnetTestResult struct {
	out string
	// ran records that the runner executed and produced readable results. It is
	// false for every non-run — unreadable exit status, unparseable .trx, a
	// dotnetTestRunError — and stays true when the tests merely failed. Only the
	// latter is a severity verdict `fail-on NONE` may suppress; see gating.go.
	ran      bool
	errs     []string
	warnings []string
	summary  trxSummary
	// parsed is how many .trx documents were understood. The counters alone
	// cannot say whether there was an accounting: they sum to zero both when
	// nothing ran and when nothing could be read.
	parsed   int
	coverage []dotnetCoverage
	// output is the bounded record of the runner's stdout+stderr, kept only
	// when the exit status is not explained by a failing test (dotnetKeepOutput).
	// nil otherwise, so a green target adds nothing to the envelope.
	output *dotnetTestOutput
}

// runDotnetTestOn runs one solution or project with the runner the repository
// asked for. The target and every flag are argv elements, never shell words, and
// the results directory is per-target so a multi-project sweep cannot read another
// target's .trx as its own.
func runDotnetTestOn(ctx context.Context, base *dagger.Container, target, band string, runner dotnetRunner) dotnetTestResult {
	const results = "/tmp/test-results"

	args := dotnetTestArgs(runner, results)
	if len(args) == 0 {
		// Unreachable from runDotnetTest, which refuses an unresolved runner
		// before building a container — and still a non-run rather than a default
		// invocation, because "no runner" must never resolve to "run something".
		return dotnetTestResult{errs: []string{"dotnet test: no invocation is defined for " +
			"runner " + strconv.Quote(string(runner)) + ", so nothing was run"}}
	}

	// Every argument reaches dotnet through sh's "$@", so nothing here is parsed
	// as a shell word. That is what keeps the VSTest collector name whole:
	// --collect:"XPlat Code Coverage" spliced into a script body word-splits into
	// three arguments, the collector name becomes "XPlat", no coverage is
	// collected and `dotnet test` still exits 0. See dotnetTestArgs.
	//
	// The cobertura harvest globs '*.cobertura.xml' rather than coverlet's literal
	// coverage.cobertura.xml, because MTP names each test application's report
	// after a guid. It is deliberately not depth-limited: -maxdepth 1 would be
	// right for the pooled results directory and silently wrong for the
	// per-project layout, which is a shape-dependent correctness bug of exactly
	// the kind this change removes. The duplicates the glob picks up (MTP writes
	// each report a second time into the .trx attachment directory) are dropped by
	// parseCoberturaSet's byte-identical dedup — measured 4 files, 2 distinct
	// reports, on a two-project solution.
	//
	// The two counts are what makes a missed harvest visible: cobcount is what
	// reached the results directory, coboutside what landed in the projects' own
	// build trees instead. Without the second one, "cicd looked in the wrong
	// place" and "no coverage was produced" are the same evidence.
	script := `rm -rf ` + results + ` && mkdir -p ` + results + `
dotnet test "$TARGET" "$@" > /tmp/dotnet-test.out 2>&1
echo $? > /tmp/dotnet-test.exit
find ` + results + ` -name '*.trx' | wc -l > /tmp/dotnet-test.trxcount
: > /tmp/dotnet-test.trx
find ` + results + ` -name '*.trx' -print0 | xargs -0 -r cat >> /tmp/dotnet-test.trx
find ` + results + ` -name '` + dotnetCoberturaGlob + `' | wc -l > /tmp/dotnet-test.cobcount
: > /tmp/dotnet-test.cobertura
find ` + results + ` -name '` + dotnetCoberturaGlob + `' | while IFS= read -r f; do
  echo "` + coberturaSeparator + `"
  cat "$f"
done >> /tmp/dotnet-test.cobertura
find ` + dotnetSrcMount + ` -path '*/bin/*' -name '` + dotnetCoberturaGlob + `' \
  | wc -l > /tmp/dotnet-test.coboutside`

	ctr := base.
		WithEnvVariable("TARGET", target).
		// argv, not a command line: sh's $0 is the literal "sh" and everything
		// after it becomes "$@" verbatim, spaces included.
		WithExec(append([]string{"sh", "-c", script, "sh"}, args...))

	exitCode, err := ctr.File("/tmp/dotnet-test.exit").Contents(ctx)
	if err != nil {
		return dotnetTestResult{errs: []string{"dotnet test: could not read exit status: " + err.Error()}}
	}
	out, outErr := ctr.File("/tmp/dotnet-test.out").Contents(ctx)
	if outErr != nil {
		return dotnetTestResult{errs: []string{readbackError("dotnet test", "/tmp/dotnet-test.out", outErr)}}
	}
	res := dotnetTestResult{out: out, ran: true}

	// The script always writes all three accounting files (see dotnetTestScript),
	// so one that cannot be read back, or holds no count, is cicd's own failure
	// to collect the result and is reported as such — never as a run that wrote
	// no .trx, which is the claim a zero here would make.
	trxCountRaw, trxCountErr := ctr.File("/tmp/dotnet-test.trxcount").Contents(ctx)
	filesFound, countMsg := readbackCount("dotnet test", "/tmp/dotnet-test.trxcount", trxCountRaw, trxCountErr)
	if countMsg != "" {
		res.errs = append(res.errs, countMsg)
		res.ran = false
	}
	trxRaw, trxErr := ctr.File("/tmp/dotnet-test.trx").Contents(ctx)
	if trxErr != nil {
		res.errs = append(res.errs, readbackError("dotnet test", "/tmp/dotnet-test.trx", trxErr))
		res.ran = false
	}

	// parsed, not filesFound, is what proves results were readable: an
	// unparseable payload sums to zero tests, which is indistinguishable from a
	// passing run of none.
	sum, parsed := parseTrxAll(trxRaw)
	res.summary = sum
	res.parsed = parsed
	if filesFound > 0 && parsed == 0 {
		res.errs = append(res.errs, "dotnet test: wrote a .trx that could not be parsed")
		res.ran = false
	}

	runErr := dotnetTestRunError(runner, exitCode, parsed, res.summary, out, band)
	// The output is evidence whenever the exit status is a fact nothing else in
	// the envelope can verify: a classified non-run, or a non-zero exit with no
	// failing test behind it. It is captured before either message is built so
	// the message can say what was kept. Classification is unchanged by this —
	// dotnetKeepOutput reads runErr and the accounting, it decides neither.
	if dotnetKeepOutput(exitCode, runErr, res.summary, parsed > 0) {
		reason := dotnetKeepReasonUnexplained
		if runErr != "" {
			reason = "the run was classified as a non-run"
		}
		kept := dotnetCaptureOutput(target, runner, exitCode, reason, out)
		res.output = &kept
	}
	if runErr != "" {
		res.errs = append(res.errs, runErr+dotnetOutputKeptNote(res.output))
		res.ran = false
	}
	if code := strings.TrimSpace(exitCode); code != "0" {
		// parsed > 0 is what makes res.summary an accounting rather than a zero
		// value: an unparsed .trx sums to Failed 0, which must not be read as
		// "no test failed". See dotnetTestExitFailure.
		res.errs = append(res.errs, dotnetTestExitFailure(code, runErr, out, res.summary, parsed > 0, res.output))
	}

	cob, cobErr := ctr.File("/tmp/dotnet-test.cobertura").Contents(ctx)
	if cobErr != nil {
		res.errs = append(res.errs, readbackError("dotnet test", "/tmp/dotnet-test.cobertura", cobErr))
		res.ran = false
	}
	res.coverage = parseCoberturaSet(cob)

	// docs counts what the harvest found, len(res.coverage) what survived parsing
	// and the byte-identical dedup. Both numbers are needed: equal-and-zero is "no
	// report exists", docs>0 with nothing usable is "reports exist and measure
	// nothing", and coboutside separates either of those from "cicd looked in the
	// wrong place".
	cobCountRaw, cobCountErr := ctr.File("/tmp/dotnet-test.cobcount").Contents(ctx)
	docs, docsMsg := readbackCount("dotnet test", "/tmp/dotnet-test.cobcount", cobCountRaw, cobCountErr)
	cobOutsideRaw, cobOutsideErr := ctr.File("/tmp/dotnet-test.coboutside").Contents(ctx)
	outside, outsideMsg := readbackCount("dotnet test", "/tmp/dotnet-test.coboutside", cobOutsideRaw, cobOutsideErr)
	for _, msg := range []string{docsMsg, outsideMsg} {
		if msg != "" {
			res.errs = append(res.errs, msg)
			res.ran = false
		}
	}

	covErr, covWarn := dotnetCoverageOutcome(runner, out, docs, outside, len(res.coverage))
	if covWarn != "" {
		res.warnings = append(res.warnings, covWarn)
	}
	// A coverage non-run is only reported when the test run itself was healthy.
	// On a run that already failed, "no coverage was produced" is a consequence of
	// the failure and not a second independent fact, and stacking it would put a
	// cicd-defect message on a consumer's broken build.
	if covErr != "" && res.ran && len(res.errs) == 0 {
		// A coverage non-run on a healthy exit is the same kind of fact as an
		// unexplained exit: the reason no report was written is in the output
		// ("Unable to find a datacollector …") and nowhere else. Same record,
		// its own reason.
		if res.output == nil {
			kept := dotnetCaptureOutput(target, runner, exitCode,
				"coverage was requested and no report was produced", out)
			res.output = &kept
		}
		res.errs = append(res.errs, covErr+dotnetOutputKeptNote(res.output))
		res.ran = false
	}
	return res
}

func dotnetTestEnvelope(
	start time.Time,
	repo repoContext,
	threshold Severity,
	sdkVersion string,
	rawOut string,
	ran bool,
	errs, warnings []string,
	covPct *float64,
	covLines *int,
	counts *TestCounts,
) *envelope {
	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: "dotnet-test", Version: sdkVersion},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Languages:     []string{"dotnet"},
		Passed:        testLegPassed(ran, len(errs) == 0, counts, threshold),
		// The case this field was added for, and the case that showed how
		// easy it is to get wrong. Under `fail-on: NONE` Passed is true here
		// even when the leg did not succeed — the documented gate contract —
		// and a test leg reports zero findings, so nothing else in the
		// envelope said so either; the only record was English prose in
		// errors[].
		//
		// testOutcome, not runOutcome: counts is the runner's own accounting,
		// and it is what separates a failing suite from a runner that exited
		// non-zero with every test green. See testOutcome.
		Outcome:         testOutcome(ran, len(errs) == 0, counts),
		FailOnSeverity:  threshold,
		RawOutputRef:    rawOut,
		Warnings:        warnings,
		Errors:          errs,
		CoveragePercent: covPct,
		CoverageLines:   covLines,
		Tests:           counts,
	}
}
