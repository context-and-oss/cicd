//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"testing/fstest"
	"time"

	"dagger/quality/internal/dagger"
)

// Test runs consumer-owned test commands in resolved toolchain containers and
// returns witnessed test + coverage evidence (BYO test, ADR-002). The consumer
// owns the test definitions; cicd owns execution and attestation.
//
// One leg per language: pass testLegs (a JSON array of legs, each with its own
// command, language, coverage report and optional image) for a polyglot
// repository, or testCmd for the single-command case. The two are mutually
// exclusive.
//
// When a leg names a coverage report, it is harvested from that leg's container
// after the run and its format sniffed (v8 json-summary, go coverprofile,
// pytest-cov JSON, cobertura XML). Legs sharing a language are combined by
// coverable-line weighting. When a baseline is supplied the coverage ratchet
// (ADR-003) compares measured against baseline coverage per language; missing
// inputs skip the ratchet fail-open, never red.
//
// A language detected in the tree that no leg witnesses is named in warnings[]
// and in the genericReport, and `languages` lists what was witnessed rather
// than what was detected — a partially witnessed repository must never render
// identically to a fully witnessed one. See testlegs.go for why that is a
// warning and not a failure.
func (m *Quality) Test(
	ctx context.Context,
	// Source directory to test.
	src *dagger.Directory,
	// Single test command, run via `sh -c` in one toolchain container (always
	// explicit, never auto-detected). Mutually exclusive with testLegs; exactly
	// one of the two is required.
	// +optional
	testCmd string,
	// Witnessed test legs as a JSON array — one object per leg, each with keys
	// label, language (go|node|python|dotnet), cmd, and optionally coveragePath
	// and toolchainImage. Supersedes testCmd / coveragePath / toolchainImage,
	// which it carries per leg. Mutually exclusive with testCmd.
	// +optional
	testLegs string,
	// Path of the coverage report the test command writes — absolute, or relative to the source root.
	// A filename pattern is accepted too (any of * ? [ makes it one), for a command that cannot be
	// made to write a fixed name: Microsoft.Testing.Platform guid-names every test application's
	// report. The search descends from the pattern's directory, duplicate documents are
	// dropped, and the evidence states how many documents were merged.
	// Applies to testCmd only; a leg names its own.
	// +optional
	coveragePath string,
	// Baseline coverage document for the ratchet: a prior combined-evidence.json /
	// evidence envelope, or a bare {"coverageByLanguage": {...}} map (sniffed).
	// +optional
	baseline *dagger.File,
	// Allowed per-language coverage drop (percentage points) before the ratchet trips.
	// +default=1.0
	tolerance float64,
	// Ratchet mode: "gate" fails the envelope on a tripped ratchet, "warn" only warns.
	// +default="gate"
	coverageGate string,
	// Toolchain container image override — the only digest-pinnable level (ADR-004).
	// Applies to testCmd only; a leg names its own.
	// +optional
	toolchainImage string,
	// Languages to include: go, node, python, dotnet (repeatable, optional).
	// +optional
	include []string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Internal npm registry URL. When set with npmToken, the BYO test command
	// can restore from a private npm feed. Mirrors quality.Check.
	// +optional
	npmFeedUrl string,
	// "registry" (default) or "npmrc"; see quality.Check.
	// +optional
	npmFeedRouting string,
	// Auth token for the internal npm registry (Dagger secret, never plaintext).
	// +optional
	npmToken *dagger.Secret,
	// Internal NuGet feed URL. When set with nugetToken, the BYO test command
	// can restore private NuGet packages. Mirrors quality.Check.
	// +optional
	nugetFeedUrl string,
	// Auth token for the internal NuGet feed (Dagger secret, never plaintext).
	// +optional
	nugetToken *dagger.Secret,
	// Optional app source view for detection and scope accounting. Commands
	// still run in src. Named coverage output is mandatory and freshly produced.
	// +optional
	appSource *dagger.Directory,
	// Shared prepared container; only the selected test leg uses it.
	// +optional
	prepared *dagger.Container,
	// Label of the test leg sharing preparation; test-cmd for the single command.
	// +optional
	preparedTestLabel string,
	// Image used to produce prepared. Must agree with any explicit leg image.
	// +optional
	preparedImage string,
	// +optional
	preparedLanguage string,
	// Maximum test legs in flight at once, 1 to 4. 1 runs them one after
	// another, as before this input existed. The evidence is folded in
	// declaration order whatever order the legs finish in, so only the
	// per-leg durations differ between a sequential and a concurrent run.
	// +default=1
	parallelism int,
) (*dagger.File, error) {
	start := time.Now()

	// Leg configuration is validated before any container is built, the way
	// validateFeedCredentials is: a malformed leg document must not run half of
	// what was asked and then report on it. Every refusal lives in
	// byotestplan.go, untagged and under test.
	declared, err := validateTestInputs(testCmd, testLegs, coveragePath, coverageGate, tolerance, parallelism,
		npmFeedUrl, npmFeedRouting, npmToken != nil, nugetFeedUrl, nugetToken != nil)
	if err != nil {
		return nil, err
	}

	// Test has no fail-on knob: test failures always gate, and the ratchet's
	// escape hatch is coverage-gate=warn (ADR-003). The repo default severity
	// keeps gatedPassed semantics consistent with Check.
	threshold := SeverityHigh
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	detectionSource := src
	if appSource != nil {
		detectionSource = appSource
	}
	langs, detectWarnings, err := detectLanguages(ctx, detectionSource, include)
	if err != nil {
		return nil, fmt.Errorf("language detection: %w", err)
	}
	detected := make([]string, 0, len(langs))
	for _, lang := range langs {
		detected = append(detected, string(lang))
	}

	// No declared legs means the single test-cmd shape: one leg, whose language
	// is the first detected one. That is the behaviour this function always had,
	// carried over rather than reinterpreted — including the "unknown" coverage
	// key when nothing was detected at all.
	legs := declared
	if len(legs) == 0 {
		legs = []testLeg{legacyTestLeg(testCmd, coveragePath, toolchainImage, detected)}
	}

	legs, preparedTestLabel, err = applyPreparedLeg(legs, len(declared), prepared != nil, preparedTestLabel, preparedImage, preparedLanguage)
	if err != nil {
		return nil, err
	}

	// Resolve every leg's image up front, so a leg that cannot resolve a
	// toolchain fails before any container is pulled.
	images := make([]string, len(legs))
	resolutions := make([]ToolchainResolution, len(legs))
	for i, leg := range legs {
		// resolveTestToolchain reads the first entry of the slice it is given as
		// the primary language. A leg names its language outright, so it is
		// handed exactly that one — this is where the reported bug lived: the
		// image used to come from langs[0] for the whole run, i.e. from the
		// fixed order (go, node, python, dotnet) in autoDetectLanguages.
		res, resolveErr := resolveTestToolchain(ctx, src, []language{language(leg.Language)}, leg.ToolchainImage)
		if resolveErr != nil {
			return nil, resolveErr
		}
		resolutions[i] = res
		images[i] = res.Image
	}

	// Every decision between the container calls lives in byotestfold.go; this
	// function only runs the legs and hands their results in. The --include
	// disclosure applies here for the same reason it does in Check: the
	// language set decides which legs exist, so a language left out of it is a
	// language whose tests were not run.
	fold := newByoTestFold(legs, images, resolutions, appSource != nil,
		append(detectWarnings, testPlanWarnings(legs, resolutions, images, len(declared), toolchainImage, preparedTestLabel, detected)...))

	// The .NET denominator is swept once for the run, not once per leg; see
	// byoTestFold for why.
	if legsDeclare(legs, "dotnet") {
		if d, err := discoverDotnetTargets(ctx, detectionSource); err != nil {
			fold.setDotnetScope(nil, err)
		} else {
			fold.setDotnetScope(&d, nil)
		}
	}

	// Every refusal is decided before the first leg starts, so a bad path in
	// the third leg cannot leave the first two running for nothing.
	legSrcs := make([]*dagger.Directory, len(legs))
	for i, leg := range legs {
		legSrcs[i] = src
		if appSource != nil && leg.CoveragePath != "" {
			if !evidenceOutputPath(leg.CoveragePath) {
				return nil, fmt.Errorf("app coveragePath must be a literal relative file path")
			}
			legSrcs[i] = src.WithoutFile(leg.CoveragePath)
		}
	}

	// Legs run under the bound; legschedule.go hands the outcomes back in
	// declared order, so completion order never reaches the evidence.
	labels := make([]string, len(legs))
	for i, leg := range legs {
		labels[i] = leg.Label
	}
	outcomes, err := runLegsBounded(ctx, labels, parallelism, func(i int) legOutcome {
		var base *dagger.Container
		if legs[i].Label == preparedTestLabel {
			base = prepared
		}
		return runTestLeg(ctx, legSrcs[i], legs[i], images[i], npmFeedUrl, npmFeedRouting, npmToken, nugetFeedUrl, nugetToken, base, repoUrl)
	})
	if err != nil {
		return nil, err
	}
	for i := range legs {
		fold.addLeg(i, outcomes[i])
	}

	// The baseline is read here and parsed in the fold, so the fail-open rule
	// (ADR-003) is under test and only the read needs a session.
	var baselineIn baselineDoc
	if baseline != nil {
		baselineIn.Present = true
		baselineIn.Raw, baselineIn.ReadErr = baseline.Contents(ctx)
	}

	env, err := buildTestEnvelope(fold, detected, baselineIn, tolerance, coverageGate == "warn", repo, threshold, start)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}

// runTestLeg runs one leg's command in one container and harvests its coverage
// report. Diagnostics come back unprefixed; the caller labels them.
func runTestLeg(
	ctx context.Context,
	src *dagger.Directory,
	leg testLeg,
	image string,
	npmFeedUrl string,
	npmFeedRouting string,
	npmToken *dagger.Secret,
	nugetFeedUrl string,
	nugetToken *dagger.Secret,
	prepared *dagger.Container,
	cacheScope string,
) legOutcome {
	var errs, warnings []string

	// Dependency services first, and the command does not run unless every one
	// of them became usable.
	//
	// The order is the whole mechanism. Dagger gates a container on the
	// services bound to it, so binding a dead service straight to the leg
	// would fail the leg's *own* exec — and "invalid nil ref" on the test
	// command is indistinguishable from a suite that crashed. Probing each
	// service in its own container first does not detect anything the leg
	// would not have hit; it decides which exec the engine's verdict lands on,
	// and therefore whether the evidence can name the alias.
	services, serviceReports, serviceErrs, serviceWarnings := prepareServices(ctx, leg.Label, leg.Services)
	warnings = append(warnings, serviceWarnings...)
	if len(serviceErrs) > 0 {
		// A non-run, not a failure: Ran false fails gatedPassed at every
		// threshold, NONE included. A consumer at NONE is telling cicd not to
		// gate on findings; they are not telling it to run the suite against a
		// database that was never there and call the result a test outcome.
		return legOutcome{
			Ran:      false,
			Passed:   false,
			Errors:   serviceErrs,
			Warnings: warnings,
			Services: serviceReports,
		}
	}

	// GOTOOLCHAIN=auto lets an in-image Go fetch a newer toolchain when the
	// consumer's go.mod pins a version above the base image's (see runGoTest).
	// Only the Go toolchain reads it — inert for other languages.
	ctr := prepared
	if ctr == nil {
		ctr = commandBase(src, image, cacheScope)
	}
	ctr = ctr.WithWorkdir("/src").WithEnvVariable("GOTOOLCHAIN", "auto").WithEnvVariable(testLegEnv, leg.Label)
	// A prepared workspace can contain a report from a prior command. Remove
	// every declared match before execution; only this test may produce it.
	if prepared != nil && leg.CoveragePath != "" {
		cleaned, cleanErr := clearPreparedCoverage(ctx, ctr, leg.CoveragePath)
		if cleanErr != nil {
			return legOutcome{Errors: []string{cleanErr.Error()}}
		}
		ctr = cleaned
	}

	// Bind every service and tell the command where each one is. The alias is
	// the hostname, but "the alias is the hostname" is only obvious to someone
	// who read services.go, so each service also arrives as two environment
	// variables named after it — something deterministic a consumer's own
	// configuration can read without a convention to remember.
	for i, spec := range leg.Services {
		ctr = ctr.WithServiceBinding(spec.Alias, services[i])
		for _, kv := range serviceEnvVars(spec) {
			ctr = ctr.WithEnvVariable(kv[0], kv[1])
		}
	}

	// Private feed credentials — same injection mechanism as the auto-detect
	// path (test.go: runVitest / runDotnetTest). Passed as Dagger secrets so
	// the token never lands in plaintext or the evidence envelope. The repo's
	// own NuGet.config/.npmrc (if present) still applies; this adds auth.
	ctr = withNodeFeed(ctr, npmFeedUrl, npmFeedRouting, npmToken)
	if nugetFeedUrl != "" && nugetToken != nil {
		// Attach credentials to the consumer's existing source name (discovered
		// from the repo NuGet.config) so packageSourceMapping keeps routing
		// private packages correctly; fall back to "internal" when no match.
		// The config body is shared with the auto-detect .NET legs
		// (dotnetexec.go) — two renderings of a credential is a drift where one
		// copy silently restores anonymously.
		ctr = ctr.
			WithNewFile("/root/.nuget/NuGet/NuGet.Config",
				nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, nugetFeedUrl), nugetFeedUrl)).
			WithSecretVariable("NUGET_AUTH_TOKEN", nugetToken)
	}

	// Ensure git is on PATH before running the consumer command. cicd's default
	// toolchains are alpine-based (e.g. node:<major>-alpine), which ship without
	// git, yet consumer suites routinely shell out to it — temp-repo fixtures,
	// `git rev-list`, describe-based version stamping. Without git those tests
	// crash or pass vacuously, and the gate then reports a bare "exit 1" with no
	// hint that a missing binary, not a real regression, was the cause.
	//
	// Best-effort across the package managers our defaults use: apk (alpine) and
	// apt-get (the debian-based python/dotnet images). The step always exits 0 —
	// an unknown base image or a failed install leaves the container untouched
	// and is surfaced as a warning after the run, never a hard failure, so repos
	// whose tests never touch git are unaffected. An explicit --toolchain-image
	// that already carries git skips the install (the `command -v git` guard).
	gitEnsure := `if ! command -v git >/dev/null 2>&1; then ` +
		`if command -v apk >/dev/null 2>&1; then apk add --no-cache git; ` +
		`elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends git; ` +
		`fi >/dev/null 2>&1 || true; fi; ` +
		`if command -v git >/dev/null 2>&1; then echo yes; else echo no; fi > /tmp/byo-git-present`
	ctr = ctr.WithExec([]string{"sh", "-c", gitEnsure})

	ctr = ctr.WithExec(byoTestArgv(leg.Cmd, "/tmp/byo-test.out", "/tmp/byo-test.exit"))

	exitCodeStr, execErr := ctr.File("/tmp/byo-test.exit").Contents(ctx)
	out, outErr := ctr.File("/tmp/byo-test.out").Contents(ctx)

	// Whether git was there is a disclosure, not a verdict, so a sentinel cicd
	// could not read back is a warning that says the answer is unknown — never
	// a silent "yes", which is what the discarded error used to amount to.
	if gitPresent, gitErr := ctr.File("/tmp/byo-git-present").Contents(ctx); gitErr != nil {
		warnings = append(warnings, readbackError("test leg", "/tmp/byo-git-present", gitErr)+"; whether git is available in "+image+" is unknown")
	} else if strings.TrimSpace(gitPresent) != "yes" {
		warnings = append(warnings, fmt.Sprintf("git unavailable in toolchain image %s and could not be installed; test commands that shell out to git may fail or pass vacuously — pass --toolchain-image with git preinstalled (e.g. a -bookworm/-slim variant)", image))
	}

	// execErr means the consumer's command never completed under our control —
	// a non-run, which no threshold may report as passed. So is an output that
	// could not be read back (the counts are parsed out of it) and a sentinel
	// holding no exit status. A non-zero exit is the command telling us it
	// failed, which is a result NONE may suppress. See foldTestLeg.
	run := foldTestLeg("test command", fmt.Sprintf("run test command in %s: ", image), execErr, "/tmp/byo-test.out", outErr, "/tmp/byo-test.exit", exitCodeStr)
	// A Go leg whose command reports a package `[build failed]` ran on part of
	// the module. Only that explicit verdict counts here: the caller's command
	// may print another format, so a missing package line proves nothing.
	if leg.Language == "go" {
		run = goTestNonRun(run, "test command", out, false)
	}
	// And a Node leg whose vitest reported a file it could not load ran on
	// part of the suite. vitest's own Failed Suites block is the only signal,
	// so a command running another runner is untouched.
	if leg.Language == "node" {
		run = vitestSuiteNonRun(run, "test command", out, false)
	}
	ran := run.ran
	rawPassed := ran && run.passed
	var counts *TestCounts
	if ran {
		if parsed, ok := parseBYOTestCounts(leg.Language, out); ok {
			counts = &parsed
		}
	}
	// Only a leg that ran has an exit code. A fabricated 0 on a container error
	// would say the opposite of what happened.
	exitCode := run.code
	if run.err != "" {
		errs = append(errs, run.err)
	}

	// On failure, echo the captured command output to the module's stderr so the
	// failing test is visible in the CI job log without downloading the evidence
	// artifact. Green runs stay quiet. The same output is also written into the
	// audit dir by cross-cutting/evidence (see Wrap) for durable, greppable
	// access after logs age out.
	if !rawPassed {
		fmt.Fprintf(os.Stderr, "\n===== quality.Test: command output from %s (exit %s) =====\n%s\n===== end command output =====\n", image, strings.TrimSpace(exitCodeStr), out)
	}

	// Coverage harvest from this leg's own container. The caller keys the
	// reading under this leg's own language.
	var reading *nodeCoverage
	var covSet *coverageSet
	missing := false
	if leg.CoveragePath != "" && execErr == nil && coveragePathIsGlob(leg.CoveragePath) {
		// A pattern, not a path: MTP names each test application's report
		// <guid>.cobertura.xml, so a leg on that runner cannot name what it just
		// wrote. Everything decided here lives in coverageglob.go, which is
		// untagged and tested; this branch only reads files.
		var globErrs, globWarnings []string
		reading, covSet, globErrs, globWarnings = harvestCoverageGlob(ctx, ctr, leg)
		errs = append(errs, globErrs...)
		warnings = append(warnings, globWarnings...)
		// A pattern that matched nothing is the same state as a literal path that
		// was not there, and must reach the ratchet as such rather than as a
		// measurement of zero.
		missing = reading == nil && len(globErrs) == 0
	} else if leg.CoveragePath != "" && execErr == nil {
		reportPath := leg.CoveragePath
		if !strings.HasPrefix(reportPath, "/") {
			reportPath = path.Join("/src", reportPath)
		}
		if covRaw, covErr := ctr.File(reportPath).Contents(ctx); covErr != nil {
			missing = true
		} else if rep, ok := sniffCoverageReport(covRaw); ok {
			reading = &nodeCoverage{Percent: rep.Pct, Lines: rep.Lines}
		} else {
			// Two causes, and the message names both: an unrecognized format, or
			// a recognized one carrying no measurement. A cobertura document with
			// no coverable lines is the second — it parses, and reporting its
			// line-rate="1" as 100% is the inflation parseCobertura now refuses.
			warnings = append(warnings, fmt.Sprintf("coverage report at %s is in no recognized format (v8 json-summary, go coverprofile, pytest-cov JSON, cobertura XML), or reports no coverable lines", leg.CoveragePath))
		}
	}

	return legOutcome{
		Ran:             ran,
		Passed:          rawPassed,
		ExitCode:        exitCode,
		Output:          out,
		Errors:          errs,
		Warnings:        warnings,
		Counts:          counts,
		Coverage:        reading,
		CoverageMissing: missing,
		CoverageSet:     covSet,
		Services:        serviceReports,
	}
}

// prepareServices builds each declared service, proves each one usable in its
// own container, and returns them aligned with the specs, with the errors[]
// and warnings[] lines services.go decided for them.
//
// Deliberately thin. What a declaration may say, what a probe's raw bytes
// mean, and what is said about a service that did not come up are all decided
// in services.go, where `go test -tags unit_test` can reach them; this
// function builds containers and reads files.
func prepareServices(ctx context.Context, legLabel string, specs []serviceSpec) ([]*dagger.Service, []serviceReport, []string, []string) {
	if len(specs) == 0 {
		return nil, nil, nil, nil
	}
	services := make([]*dagger.Service, 0, len(specs))
	reports := make([]serviceReport, 0, len(specs))
	var errs, warnings []string

	for _, spec := range specs {
		svcCtr := dag.Container().From(spec.Image)
		// Sorted, because a Go map iterates in a random order and two runs over
		// one declaration must not produce two different containers.
		for _, key := range sortedEnvKeys(spec.Env) {
			svcCtr = svcCtr.WithEnvVariable(key, spec.Env[key])
		}
		// The engine starts one instance per service definition and hands it
		// to every container that binds it. Two legs declaring the same
		// postgres would otherwise share one database, and under
		// --parallelism their suites would write to it at the same time.
		// The label makes the definition this leg's and this alias's own; the
		// probes below bind the same svc, so they still check the instance
		// the leg gets.
		svcCtr = svcCtr.WithLabel(serviceInstanceLabel, serviceInstanceKey(legLabel, spec.Alias))
		svc := svcCtr.WithExposedPort(spec.Port).AsService()
		services = append(services, svc)

		var probe serviceProbe

		// The attribution probe. Pinned alpine, bound to this one service and
		// nothing else, running a command that cannot itself fail: whatever the
		// engine decides about the binding, it decides here, about one alias.
		bound := dag.Container().From(alpineImage).
			WithServiceBinding(spec.Alias, svc).
			WithExec([]string{"sh", "-c", "echo bound > /tmp/svc.bound"})
		if _, err := bound.File("/tmp/svc.bound").Contents(ctx); err != nil {
			probe.BindErr = err
		} else if spec.ReadyCmd != "" {
			// The consumer's own readiness check, in the service's own image so
			// that pg_isready and redis-cli exist. See serviceReadyScript.
			ready := dag.Container().From(spec.Image).
				WithServiceBinding(spec.Alias, svc).
				WithExec([]string{"sh", "-c", serviceReadyScript, "sh", spec.ReadyCmd, strconv.Itoa(spec.ReadyTimeout)})
			status, readErr := ready.File("/tmp/svc.status").Contents(ctx)
			if readErr != nil {
				probe.ReadyReadErr = readErr
			} else {
				probe.ReadyRan = true
				probe.ReadyStatus = status
				probe.ReadyAttempts, probe.ReadyCountersErr = ready.File("/tmp/svc.attempts").Contents(ctx)
				if probe.ReadyCountersErr == nil {
					probe.ReadyWaited, probe.ReadyCountersErr = ready.File("/tmp/svc.waited").Contents(ctx)
				}
			}
		}

		rep, errMsg, warnMsg := foldServiceProbe(spec, probe)
		reports = append(reports, rep)
		if errMsg != "" {
			errs = append(errs, errMsg)
		}
		if warnMsg != "" {
			warnings = append(warnings, warnMsg)
		}
	}
	return services, reports, errs, warnings
}

// harvestCoverageGlob reads every document a leg's coverage pattern matched and
// folds them into one reading.
//
// Deliberately thin. Which patterns are refused, how documents are deduped, and
// what is said about the ones nothing could parse are all decided in
// coverageglob.go, where they are tested; this function expands the pattern in
// the leg's own container and reads bytes. The container is the leg's, not a
// helper image, because the report exists only in the filesystem the command
// wrote it to.
//
// A pattern cicd cannot expand is an error, never an empty match set. The two
// are indistinguishable downstream — both yield no coverage figure — and only
// one of them means the consumer wrote a pattern this code will never honour.
func harvestCoverageGlob(ctx context.Context, ctr *dagger.Container, leg testLeg) (*nodeCoverage, *coverageSet, []string, []string) {
	pattern := leg.CoveragePath
	if !strings.HasPrefix(pattern, "/") {
		pattern = path.Join("/src", pattern)
	}
	dir, name, err := splitCoverageGlob(pattern)
	if err != nil {
		// A pattern cicd refused to expand: no harvest ran, so there is no set
		// to report. Returning an empty one would say "merged 0 documents"
		// about a search that never happened.
		return nil, nil, []string{err.Error()}, nil
	}

	// The pattern reaches find as an argv element. Spliced into an sh -c body it
	// would be shell injection whose vector is a coverage report's filename.
	found, findErr := ctr.WithExec(coverageFindArgs(dir, name)).Stdout(ctx)
	if findErr != nil {
		// find exits non-zero when the starting point does not exist, which is a
		// real answer (the command wrote nothing there) rather than a broken
		// search — so it is a warning about an empty harvest, not an error that
		// fails the leg.
		empty := coverageSet{}
		return nil, &empty, nil, coverageSetWarnings(leg.CoveragePath, empty)
	}

	docs := map[string]string{}
	for _, hit := range splitFindOutput(found) {
		raw, readErr := ctr.File(hit).Contents(ctx)
		if readErr != nil {
			// Matched by the search and then unreadable: not an empty harvest and
			// not a bad format, so it gets its own error rather than being folded
			// into either count.
			return nil, nil, []string{fmt.Sprintf(
				"coverage report %s was matched by %s and could not be read: %s",
				hit, leg.CoveragePath, readErr.Error())}, nil
		}
		docs[hit] = raw
	}

	set := buildCoverageSet(docs)
	warnings := coverageSetWarnings(leg.CoveragePath, set)
	pct, lines := foldCoverage(set.Readings)
	if pct == nil {
		// Documents were found and none of them could be read. That is a failed
		// measurement, and returning only warnings here is what let it come back
		// passed=true — see coverageSetErrors.
		return nil, &set, coverageSetErrors(leg.CoveragePath, set), warnings
	}
	reading := &nodeCoverage{Percent: *pct}
	if lines != nil {
		reading.Lines = *lines
	}
	return reading, &set, nil, warnings
}

// nugetSourceNameForFeed inspects the repo's NuGet.config (if present at the
// source root) and returns the <packageSources> key whose value matches
// feedURL — so injected credentials attach to the consumer's own source name
// (e.g. "company.nuget") and packageSourceMapping keeps working. Falls back
// to "internal" when there is no repo config or no matching source.
//
// Matching goes through sameFeedURL, so a config whose value differs from the
// pipeline's --nuget-feed-url only in host case or a trailing slash still
// resolves to the consumer's own key instead of silently falling back to
// "internal" and shadowing their source. Two sources sharing one URL resolve to
// the first in file order then document order — arbitrary but deterministic,
// and the alternative (guessing) is worse.
//
// Only the source root is inspected. A per-project NuGet.config in a
// subdirectory can name the same feed differently, and NuGet's own scope
// resolution would then pick that name; cicd writes a user-level config, so the
// root-level name is the one that composes with it. Nested-scope resolution is
// left undone deliberately rather than half-done.
func nugetSourceNameForFeed(ctx context.Context, src *dagger.Directory, feedURL string) string {
	for _, name := range nugetConfigNames {
		contents, err := src.File(name).Contents(ctx)
		if err != nil {
			continue
		}
		if key, ok := nugetSourceNameFromConfig(contents, feedURL); ok {
			return key
		}
	}
	return nugetDefaultSourceName
}

// resolveTestToolchain applies the ADR-004 precedence using the module-local
// ResolveToolchain copy: an explicit image short-circuits; otherwise the
// primary detected language plus root-level version files (.nvmrc,
// global.json) pick the image.
//
// It returns the resolution and not just the image, because the caller has to
// be able to tell a version file cicd used from one it read and discarded. That
// distinction does not survive the image string: the pinned .NET default is the
// same tag a global.json can legitimately ask for.
func resolveTestToolchain(ctx context.Context, src *dagger.Directory, langs []language, explicitImage string) (ToolchainResolution, error) {
	if explicitImage != "" {
		return ToolchainResolution{Image: explicitImage, From: ToolchainFromExplicit}, nil
	}

	primary := ""
	if len(langs) > 0 {
		primary = string(langs[0])
	}

	// .NET resolves from the tree, not from a root version file, so it does not
	// go through ResolveToolchainDetail at all. See resolveDotnetTestToolchain.
	if Language(strings.ToLower(primary)) == Dotnet {
		return resolveDotnetTestToolchain(ctx, src)
	}

	fsys, err := versionFileFS(ctx, src)
	if err != nil {
		return ToolchainResolution{}, fmt.Errorf("read version files: %w", err)
	}

	res := ResolveToolchainDetail(primary, "", fsys)
	if res.Image == "" {
		// The list names every marker detection actually looks for
		// (markers.go). A message that omits one sends the consumer who has
		// exactly that file looking for something else.
		return ToolchainResolution{}, fmt.Errorf("could not resolve a toolchain image: no language marker files (%s) detected — pass --toolchain-image explicitly",
			strings.Join(markerFileNames, ", "))
	}
	return res, nil
}

// resolveDotnetTestToolchain gathers the two facts dotnetTestToolchain decides
// from, and does nothing else with them.
//
// Split this way because byotest.go is //go:build !unit_test: a decision living
// here is invisible to `make test-module-units`, and the last default-less
// switch that survived in a tagged file survived untested. The Dagger work is
// the probe and the file read; the rule is in dotnettoolchain.go.
//
// A probe failure is an error, never a fallback, for the reason
// discoverDotnetBandRequest states: it is the same tiny image that answers the
// target sweep, so a failure means the engine or the mount is broken and every
// verdict downstream would describe a tree cicd could not read. The caller
// returns it without an envelope, so nothing can be misread as a result.
func resolveDotnetTestToolchain(ctx context.Context, src *dagger.Directory) (ToolchainResolution, error) {
	req, err := discoverDotnetBandRequest(ctx, src)
	if err != nil {
		return ToolchainResolution{}, fmt.Errorf(
			"read which .NET SDK band this repository needs: %w", err)
	}
	fsys, err := versionFileFS(ctx, src)
	if err != nil {
		return ToolchainResolution{}, fmt.Errorf("read version files: %w", err)
	}
	return dotnetTestToolchain(req, globalJSONSdkVersion(fsys)), nil
}

// versionFileFS materialises the root-level toolchain version files (.nvmrc,
// global.json) from src into an in-memory fs.FS for ResolveToolchain. Absent
// files are simply omitted — resolution falls through to the pinned defaults.
func versionFileFS(ctx context.Context, src *dagger.Directory) (fstest.MapFS, error) {
	entries, err := src.Entries(ctx)
	if err != nil {
		return nil, err
	}

	fsys := fstest.MapFS{}
	for _, name := range entries {
		if name != ".nvmrc" && name != "global.json" {
			continue
		}
		contents, err := src.File(name).Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		fsys[name] = &fstest.MapFile{Data: []byte(contents)}
	}
	return fsys, nil
}
