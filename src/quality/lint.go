//go:build !unit_test

package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

type language string

const (
	langGo     language = "go"
	langNode   language = "node"
	langPython language = "python"
	langDotnet language = "dotnet"
)

// detectLanguages resolves which languages to run, and reports what resolving
// them left out.
//
// The second result is warnings, which is the whole point of the include branch
// probing the tree it is about to skip: --include is the one way a consumer can
// reduce what cicd looks at, and an envelope from `--include go` on a repository
// containing package.json used to be byte-identical to one from a repository that
// only contains Go. Name resolution and the disclosure text live in include.go,
// untagged so they can be tested; this function is the Dagger half.
//
// An unrecognised name is an error rather than a dropped entry, so a non-empty
// include always resolves to at least one language. That is what closes the
// caller-mistake path into a passing gate over no work at all: `--include golang`
// used to resolve to nothing, the leg loop in Check never iterated, and
// gatedPassed(true, true, threshold) reported passed=true having linted nothing.
func detectLanguages(ctx context.Context, src *dagger.Directory, include []string) ([]language, []string, error) {
	if len(include) > 0 {
		names, err := resolveIncludeNames(include)
		if err != nil {
			return nil, nil, err
		}

		// Probe anyway, for the diff. One alpine exec, which the auto-detect
		// branch pays on every run.
		detected, markers, err := autoDetectLanguages(ctx, src)
		if err != nil {
			// A failed probe must not be reported as "nothing was excluded":
			// that is the silence this function is being fixed for. The
			// requested languages still run — they were named explicitly and
			// need no detection — and the warning says the disclosure is missing.
			return toLanguages(names), []string{fmt.Sprintf(
				"quality: EXCLUSION NOT CHECKED — --include %s ran as asked, but "+
					"probing for languages it leaves out failed (%v), so a language "+
					"present here and not scanned would not be named below",
				strings.Join(names, ","), err)}, nil
		}
		return toLanguages(names), excludedLanguageWarnings(names, detected, markers), nil
	}

	detected, _, err := autoDetectLanguages(ctx, src)
	if err != nil {
		return nil, nil, err
	}
	return toLanguages(detected), nil, nil
}

// toLanguages converts canonical language names into the module's language type.
// include.go deals in plain strings because the unit_test tag excludes this file,
// where the type is declared.
func toLanguages(names []string) []language {
	langs := make([]language, 0, len(names))
	for _, n := range names {
		langs = append(langs, language(n))
	}
	return langs
}

// srcMount is where every lint leg mounts the source tree. Marker paths are
// reported relative to it, so detection and project resolution must agree on it.
const srcMount = "/src"

// findMarkerFiles lists the language marker files in src. Both language
// detection and Node project resolution read this one search: they used to be
// destined to drift, because autoDetectLanguages found package.json at depth 4
// and then discarded the location, leaving the Node leg to guess the root.
func findMarkerFiles(ctx context.Context, src *dagger.Directory) (string, error) {
	return dag.Container().
		From(alpineImage).
		WithMountedDirectory(srcMount, src).
		WithExec([]string{"sh", "-c",
			`find ` + srcMount + ` ` + markerFindArgs() + ` 2>/dev/null || true`,
		}).
		Stdout(ctx)
}

// autoDetectLanguages probes src for language indicator files, returning the
// canonical language names it found and, for each, the marker path that proves
// it — the location used to be discarded, and a warning that says "node
// detected" is a claim a reader has to take on trust while "node detected
// (package.json)" is one they can check.
func autoDetectLanguages(ctx context.Context, src *dagger.Directory) ([]string, map[string]string, error) {
	entries, err := findMarkerFiles(ctx, src)
	if err != nil {
		return nil, nil, err
	}

	// Classification lives in markers.go, fed from the same list that generates
	// the find above, so a marker cannot be searched for and then not
	// understood (or the reverse).
	markers := map[string]string{}
	for _, line := range strings.Split(entries, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		l := markerLanguage(line)
		if l == "" {
			continue
		}
		// First marker wins, and find(1) walks depth-first from the root, so the
		// shallowest one is quoted. Reported relative to srcMount because an
		// absolute /src path is an implementation detail of the probe container.
		if _, already := markers[l]; !already {
			markers[l] = strings.TrimPrefix(strings.TrimPrefix(line, srcMount), "/")
		}
	}

	var langs []string
	for _, l := range canonicalLanguages {
		if _, ok := markers[l]; ok {
			langs = append(langs, l)
		}
	}
	return langs, markers, nil
}

// lintLanguage dispatches to the linter for lang.
//
// The second result is ran: false means the linter did not execute, as opposed
// to executing and finding problems. Check needs the two apart because
// `fail-on NONE` suppresses findings and must not suppress a non-run, and the
// evidence envelope has no field to carry it (schema.go is a verbatim copy
// shared across modules, so widening it is a wire change, not a local one).
func lintLanguage(
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
	prepared *dagger.Container,
	nodeLimit int,
) (*envelope, bool, error) {
	switch lang {
	case langGo:
		return runGolangciLint(ctx, src, threshold, repo)
	case langNode:
		return runEslint(ctx, src, threshold, repo, npmFeedUrl, npmFeedRouting, npmToken, prepared, nodeLimit)
	case langPython:
		return runPylint(ctx, src, threshold, repo)
	case langDotnet:
		return runDotnetFormat(ctx, src, threshold, repo, nugetFeedUrl, nugetToken, prepared)
	default:
		// Unsupported language: nothing was asked of a tool, so nothing failed
		// to run. Check skips a nil envelope.
		return nil, true, nil
	}
}

// runGolangciLint runs golangci-lint once per Go module in the tree.
//
// This leg had never run. It asked v1.57.2 for `--out-format sarif`, a format
// that binary does not have (its formats are json|line-number|…|teamcity), so
// every invocation died on flag validation with exit 3 — and the trailing
// `|| echo '{"version":"2.1.0","runs":[]}'` then wrote a clean report and left
// the *shell* exiting 0. Go therefore saw no error, an empty findings map and
// `ran=true`: the Go gate reported "clean" on every repository it was ever
// pointed at. Measured, both halves, before this change.
//
// Two things follow, and both are load-bearing:
//
//   - The exit status is captured and classified (golangciRunError) rather than
//     discarded. It is the *only* trustworthy signal: pointed outside its
//     workspace, v2.12.2 prints "0 issues.", writes a valid empty SARIF document
//     and exits 7. Report validity cannot distinguish that from a clean tree.
//   - The binary is v2.x, which is what can emit SARIF at all, and matches the
//     version ci.yml already runs and the `version: "2"` config schema this
//     repository already uses.
func runGolangciLint(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext) (*envelope, bool, error) {
	start := time.Now()

	var errs, warnings []string

	dirs, scope, derr := resolveGoModules(ctx, src)
	if derr != nil {
		// Where the modules live is unknown. Record it — it fails the gate on its
		// own — and still lint the root, which is what this leg did
		// unconditionally before. Degrading to a silent skip would be the false
		// pass this module exists to prevent.
		errs = append(errs, "golangci-lint: could not locate the Go modules: "+derr.Error())
		dirs, scope = []string{"."}, "source root"
	}
	if len(dirs) == 0 {
		// No go.mod anywhere: either --include forced go onto a tree that has
		// none, or every candidate sat in a directory the go tool ignores. Lint
		// the root so golangciRunError reports the real non-run with its remedy.
		warnings = append(warnings, "golangci-lint: no go.mod found; linting the source root")
		dirs, scope = []string{"."}, "source root"
	}
	if msg := goModuleLimitError(dirs); msg != "" {
		// ran=false: cicd declined to lint rather than lint a subset and call it
		// clean. Nothing executed, so this fails at every threshold including
		// NONE — see gatedPassed.
		return golangciEnvelope(start, repo, threshold, nil, nil, []string{msg}, warnings, nil), false, nil
	}
	// Scope is always stated, never implied. A gate that lints 1 of 16 modules
	// must say which, or "passed" cannot be read.
	warnings = append(warnings, "golangci-lint: linted "+strconv.Itoa(len(dirs))+
		" Go module(s) from "+scope+": "+strings.Join(dirs, ", "))

	var sarifReports []json.RawMessage
	var versions []string
	bySeverity := map[Severity]int{}

	for _, dir := range dirs {
		sarif, counts, version, modErrs := runGolangciIn(ctx, src, dir)
		versions = append(versions, version)
		for _, e := range modErrs {
			errs = append(errs, goModuleLabel(dir, e))
		}
		if sarif != nil {
			// Two runs named golangci-lint under one upload category are one
			// identity to Code Scanning, and the collision fails the whole
			// upload — see stampSARIFAutomationID.
			if len(dirs) > 1 {
				sarif = stampSARIFAutomationID(sarif, "golangci-lint", dir)
			}
			sarifReports = append(sarifReports, sarif)
		}
		for sev, n := range counts {
			bySeverity[sev] += n
		}
	}

	// ran is len(errs) == 0 for the same reason as the ESLint leg: lint findings
	// go to bySeverity, so errs holds only run failures (each labelled with its
	// module by goModuleLabel) plus a failed module search, which is itself a
	// non-run. Contrast the test legs, where a non-zero exit is a real result and
	// ran needs an explicit flag — see runVitest.
	return golangciEnvelope(start, repo, threshold, mergeSARIFReports(sarifReports), bySeverity, errs, warnings, versions), len(errs) == 0, nil
}

// resolveGoModules resolves the directories golangci-lint runs in, and names
// where that answer came from so the envelope can state the scope.
//
// A root go.work wins outright: it is Go's own declaration of which modules form
// this tree, and `go build ./...` under a workspace sees exactly those modules.
// A gate that honoured discovery instead would lint code the build never
// compiles, and in a repository whose non-workspace modules need code generation
// first that means a pile of typecheck failures describing nothing.
func resolveGoModules(ctx context.Context, src *dagger.Directory) ([]string, string, error) {
	entries, err := src.Entries(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, e := range entries {
		if e != "go.work" && e != "go.work/" {
			continue
		}
		content, cerr := src.File("go.work").Contents(ctx)
		if cerr != nil {
			// The file is listed but unreadable. Falling through to discovery
			// would silently widen the scope the consumer declared, so this is an
			// error the caller turns into a failed gate.
			return nil, "", cerr
		}
		if dirs := goWorkspaceDirs(srcMount, content); len(dirs) > 0 {
			return dirs, "go.work", nil
		}
		// A go.work with no usable `use` operand is a broken declaration, not an
		// empty one. Discovery below is the honest fallback, and the scope
		// warning will say the answer came from discovery.
		break
	}

	out, ferr := findMarkerFiles(ctx, src)
	if ferr != nil {
		return nil, "", ferr
	}
	return goModuleDirs(srcMount, strings.Split(out, "\n")), "go.mod discovery", nil
}

// runGolangciIn lints a single Go module. dir is relative to the mount root and
// reaches the container through WithWorkdir — an argument, not a shell word — so
// a consumer directory name is never spliced into the script below.
func runGolangciIn(ctx context.Context, src *dagger.Directory, dir string) (json.RawMessage, map[Severity]int, string, []string) {
	// The report path is fixed; the exit status, stdout and stderr are captured
	// to files and classified in Go. `: > report` pre-creates the file so a run
	// that dies before writing one still reads as empty — empty is a non-run,
	// and an unreadable file would be indistinguishable from a transport error.
	//
	// The --version probe may fail without invalidating the lint, so it is the
	// one command here allowed to fail quietly; golangciVersionLabel reports
	// "unknown" and the envelope says so rather than naming the pin.
	cmd := `: > /tmp/report.sarif
golangci-lint --version > /tmp/golangci.version 2>&1 || true
golangci-lint run --output.sarif.path=/tmp/report.sarif --issues-exit-code 0 ./... > /tmp/golangci.stdout 2>/tmp/golangci.stderr
echo $? > /tmp/golangci.exit
exit 0`

	ctr := dag.Container().
		From(golangciImage).
		WithoutEntrypoint().
		WithMountedDirectory(srcMount, src).
		WithWorkdir(path.Join(srcMount, dir)).
		// Keep the caches inside the container. Without this golangci-lint picks
		// a location from the image's HOME, which is not a promise the image
		// makes.
		WithEnvVariable("GOLANGCI_LINT_CACHE", "/tmp/golangci-cache").
		WithExec([]string{"sh", "-c", cmd})

	version, verr := ctr.File("/tmp/golangci.version").Contents(ctx)
	if verr != nil {
		version = ""
	}

	exitCode, err := ctr.File("/tmp/golangci.exit").Contents(ctx)
	if err != nil {
		return nil, nil, version, []string{"golangci-lint: could not read exit status: " + err.Error()}
	}
	report, rerr := ctr.File("/tmp/report.sarif").Contents(ctx)
	if rerr != nil {
		return nil, nil, version, []string{"golangci-lint: could not read the report: " + rerr.Error()}
	}
	stderr, serr := ctr.File("/tmp/golangci.stderr").Contents(ctx)
	if serr != nil {
		return nil, nil, version, []string{readbackError("golangci-lint", "/tmp/golangci.stderr", serr)}
	}
	stdout, oerr := ctr.File("/tmp/golangci.stdout").Contents(ctx)
	if oerr != nil {
		return nil, nil, version, []string{readbackError("golangci-lint", "/tmp/golangci.stdout", oerr)}
	}

	if msg := golangciRunError(exitCode, stderr+"\n"+stdout, report); msg != "" {
		return nil, nil, version, []string{msg}
	}

	// Severities are read from the stamped document deliberately: parsing the same
	// bytes that ship as evidence means a stamp that ever mangled a run would show
	// up as changed findings here, not as a quietly rewritten report.
	sarifRaw := stampSARIFDriverVersion(json.RawMessage(report), golangciVersionLabel(version))
	return sarifRaw, parseLintSarifSeverities(sarifRaw), version, nil
}

// golangciEnvelope assembles the Go lint envelope. Extracted so the
// declined-to-run path and the ran path cannot drift in how they fill it — the
// bug that survived into an earlier change was exactly two envelope literals disagreeing.
func golangciEnvelope(
	start time.Time,
	repo repoContext,
	threshold Severity,
	sarifRaw json.RawMessage,
	bySeverity map[Severity]int,
	errs, warnings []string,
	versions []string,
) *envelope {
	if sarifRaw == nil {
		sarifRaw = json.RawMessage(`{"version":"2.1.0","runs":[]}`)
	}

	total := 0
	for _, c := range bySeverity {
		total += c
	}

	return &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: "golangci-lint", Version: mergeGolangciVersions(versions)},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Languages:          []string{"go"},
		Passed:             gatedPassed(len(errs) == 0, !shouldFail(bySeverity, threshold), threshold),
		Outcome:            scanOutcome(len(errs) == 0, total),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: bySeverity,
		SARIFReport:        sarifRaw,
		Warnings:           warnings,
		Errors:             errs,
	}
}

// runEslint runs ESLint with JSON output, once per Node project in the tree.
//
// The projects come from nodeProjectDirs (package roots with no package-bearing
// ancestor). Before that this always ran at the mount root, so a monorepo whose
// package.json lives in a subdirectory had `node` detected — the marker search is
// depth-4 — and then linted at a root with neither package.json nor
// node_modules. Since eslintRunError that fails honestly with exit 127 instead
// of passing on an empty report, but the leg still could not lint the repo.
func runEslint(
	ctx context.Context,
	src *dagger.Directory,
	threshold Severity,
	repo repoContext,
	feedUrl string,
	feedRouting string,
	feedToken *dagger.Secret,
	prepared *dagger.Container,
	nodeLimit int,
) (*envelope, bool, error) {
	start := time.Now()

	var errs, warnings []string

	dirs, derr := resolveNodeProjects(ctx, src)
	if derr != nil {
		// The search itself failed, so where the project lives is unknown. Record
		// it — it fails the gate on its own — and still lint the root, which is
		// what this leg did unconditionally before. Degrading to a silent skip
		// would be the false pass this module exists to prevent.
		errs = append(errs, "eslint: could not locate the Node project: "+derr.Error())
		dirs = []string{"."}
	}
	if len(dirs) == 0 {
		// No package.json anywhere: either --include forced node onto a tree that
		// has none, or every candidate sat inside a dependency tree. Lint the root
		// so eslintRunError reports the real non-run with its remedy.
		warnings = append(warnings, "eslint: no package.json found; linting the source root")
		dirs = []string{"."}
	}
	if msg := nodeProjectLimitError(dirs, nodeLimit); msg != "" {
		// ran=false: cicd declined to lint rather than lint a subset and call it
		// clean. Nothing executed, so this fails at every threshold including
		// NONE — see gatedPassed.
		return eslintEnvelope(start, repo, threshold, nil, nil, []string{msg}, warnings, nil), false, nil
	}
	if len(dirs) == 1 && dirs[0] != "." {
		warnings = append(warnings, "eslint: linted "+dirs[0]+" (no package.json at the source root)")
	} else if len(dirs) > 1 {
		warnings = append(warnings, "eslint: linted "+strconv.Itoa(len(dirs))+" Node projects: "+strings.Join(dirs, ", "))
	}

	var sarifReports []json.RawMessage
	var versions []string
	var fileCounts []int
	bySeverity := map[Severity]int{}

	for _, dir := range dirs {
		sarif, counts, verr, projErrs, projWarnings, files := runEslintIn(ctx, src, dir, feedUrl, feedRouting, feedToken, repo.RepoURL, prepared)
		versions = append(versions, verr)
		fileCounts = append(fileCounts, files)
		for _, e := range projErrs {
			errs = append(errs, nodeProjectLabel(dir, e))
		}
		for _, w := range projWarnings {
			warnings = append(warnings, nodeProjectLabel(dir, "eslint: "+w))
		}
		if sarif != nil {
			// One eslint run per project must stay one identity per project at
			// upload time — see stampSARIFAutomationID.
			if len(dirs) > 1 {
				sarif = stampSARIFAutomationID(sarif, "eslint", dir)
			}
			sarifReports = append(sarifReports, sarif)
		}
		for sev, n := range counts {
			bySeverity[sev] += n
		}
	}

	// errs carries only per-project run errors (each labelled with its project by
	// nodeProjectLabel), so empty means eslint executed for every project found.
	// A failed project search also lands here, and is a non-run: the root was
	// linted as a fallback, which is not proof the project was.
	env := eslintEnvelope(start, repo, threshold, mergeSARIFReports(sarifReports), bySeverity, errs, warnings, versions)
	env.Examined = eslintExamined(fileCounts, len(errs) == 0)
	env.Outcome = lintOutcome(len(errs) == 0, env.FindingsCount, env.Examined)
	return env, len(errs) == 0, nil
}

// resolveNodeProjects resolves the Node project directories inside src. Both the
// lint and test legs read it, so they cannot disagree about where the project is.
func resolveNodeProjects(ctx context.Context, src *dagger.Directory) ([]string, error) {
	out, err := findMarkerFiles(ctx, src)
	if err != nil {
		return nil, err
	}
	return nodeProjectDirs(srcMount, strings.Split(out, "\n")), nil
}

// runEslintIn lints a single Node project. dir is relative to the mount root and
// reaches the container through WithWorkdir — an argument, not a shell word — so
// a consumer directory name is never spliced into the script below.
//
// The project's package manager is detected first (nodeinstall.go). Without a
// prepared container, a project whose manager cicd cannot determine is a
// non-run. With one, the install already happened in Prepare, so detection
// only chooses how eslint is resolved, and its refusal is not this leg's to
// make: an undeterminable manager falls back to `npx --no`.
func runEslintIn(
	ctx context.Context,
	src *dagger.Directory,
	dir string,
	feedUrl string,
	feedRouting string,
	feedToken *dagger.Secret,
	cacheScope string,
	prepared *dagger.Container,
) (json.RawMessage, map[Severity]int, string, []string, []string, int) {
	pm, warnings, derr := detectNodeProject(ctx, src, dir)
	switch {
	case derr != nil && prepared == nil:
		return nil, nil, "", []string{"eslint: did not run: " + derr.Error()}, nil, -1
	case derr != nil:
		pm, warnings = npmDefault, nil
	case prepared != nil:
		// The install warnings describe an install this leg did not run.
		warnings = nil
	default:
		warnings = append(warnings, nodeFeedWarnings(ctx, src, dir, pm, feedUrl, feedRouting, feedToken)...)
	}

	ctr := prepared
	if ctr == nil {
		ctr = commandCaches(dag.Container().From(nodeImage), cacheScope).WithMountedDirectory(srcMount, src)
	}
	ctr = ctr.WithWorkdir(path.Join(srcMount, dir))
	ctr = withNodeFeed(ctr, feedUrl, feedRouting, feedToken)

	// The install's exit is recorded, not swallowed (eslintScript).
	// eslint exits 0 with no problems, 1 when it reports problems, and >=2 when
	// it could not run at all (bad config, missing binary). The exit status is
	// recorded to a file rather than swallowed: previously the whole command
	// ended in `2>/dev/null || true`, so a repo where eslint never ran — e.g. a
	// monorepo whose package.json is not at the root — produced an empty report
	// that parsed as "no findings" and passed the gate silently.
	//
	// Two deliberate choices in this command, both of which were bugs before:
	//
	//  1. No config flags. This used to run
	//     `--no-eslintrc --env browser,node,es2021 --rule '{"no-undef":"error"}'`,
	//     i.e. cicd's own one-rule lint with the consumer's real ESLint config
	//     ignored — their plugins, their rule severities, their overrides, all
	//     discarded. Worse, ESLint 9 removed --no-eslintrc and --env outright:
	//     measured against eslint 9.39.5, that command exits 2 with an empty
	//     report, so on flat config the Node lint leg could not run at all. Bare
	//     `eslint --format json .` works on both eras (verified on 8.57.1 and
	//     9.39.5) and lints what the repository says to lint.
	//
	//  2. The repository's own binary, never a fetched one. Plain npx would
	//     silently fetch some unpinned latest ESLint from the network when the
	//     repo does not depend on one, so the gate's verdict would come from a
	//     version nobody chose. `npx --no` resolves only what the install put
	//     there; when nothing resolves the script records 127, which
	//     eslintRunError reports with the remedy (eslintScript).
	ran := ctr.WithExec([]string{"sh", "-c", eslintScript(pm, prepared == nil)})
	out, err := ran.File(eslintReportPath).Contents(ctx)

	// Whatever version actually produced the report — not a constant. The
	// consumer's lockfile decides it, so a hard-coded version in the evidence
	// would misattribute every finding.
	// The script always creates the file (`|| true` after `--version`), so a
	// read that fails is cicd's, and the version in the evidence would otherwise
	// be the empty string's label.
	eslintVer, verErr := ran.File(eslintVersionPath).Contents(ctx)

	var errs []string
	if verErr != nil {
		errs = append(errs, readbackError("eslint", eslintVersionPath, verErr))
	}
	var sarifRaw json.RawMessage
	var bySeverity map[Severity]int
	if err != nil {
		errs = append(errs, "eslint: "+err.Error())
	} else {
		code, cerr := ran.File(eslintExitPath).Contents(ctx)
		if cerr != nil {
			errs = append(errs, "eslint: could not read exit status: "+cerr.Error())
		} else if stderr, serr := ran.File(eslintStderrPath).Contents(ctx); serr != nil {
			errs = append(errs, readbackError("eslint", eslintStderrPath, serr))
		} else {
			// Absent on the prepared path, where no install ran here: "" is
			// unknown, and eslintRemedy says so.
			install := installRecord{}
			if prepared == nil {
				installExit, _ := ran.File(nodeInstallExitPath).Contents(ctx)
				install = pm.record(installExit)
			}
			var msg string
			sarifRaw, bySeverity, msg = foldEslintRun(code, stderr, out, eslintVer, install)
			if msg != "" {
				errs = append(errs, msg)
			}
		}
	}
	if len(errs) > 0 {
		return nil, nil, eslintVer, errs, warnings, -1
	}
	return sarifRaw, bySeverity, eslintVer, nil, warnings, eslintFilesLinted(out)
}

// eslintEnvelope assembles the Node leg's evidence from the merged per-project
// results.
func eslintEnvelope(
	start time.Time,
	repo repoContext,
	threshold Severity,
	sarifRaw json.RawMessage,
	bySeverity map[Severity]int,
	errs, warnings []string,
	versions []string,
) *envelope {
	if sarifRaw == nil {
		sarifRaw = json.RawMessage(`{"version":"2.1.0","runs":[]}`)
	}

	total := 0
	for _, c := range bySeverity {
		total += c
	}

	return &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: "eslint", Version: mergeEslintVersions(versions)},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Languages:          []string{"node"},
		Passed:             gatedPassed(len(errs) == 0, !shouldFail(bySeverity, threshold), threshold),
		Outcome:            scanOutcome(len(errs) == 0, total),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: bySeverity,
		SARIFReport:        sarifRaw,
		Warnings:           warnings,
		Errors:             errs,
	}
}

// pylintTargetsPath is where the leg writes the file list pylintScript reads.
const pylintTargetsPath = "/tmp/cicd-pylint-targets"

// runPylint runs pylint over the files pylintTargets selects (pylinttargets.go).
// --exit-zero ensures pylint always exits 0 so Dagger doesn't abort on findings.
func runPylint(ctx context.Context, src *dagger.Directory, threshold Severity, repo repoContext) (*envelope, bool, error) {
	start := time.Now()

	var (
		sarifRaw   json.RawMessage
		bySeverity map[Severity]int
		examined   *Examined
		errs       []string
		warnings   []string
	)

	pyFiles, gerr := src.Glob(ctx, pylintTargetGlob)
	venvCfgs, verr := src.Glob(ctx, pylintVenvGlob)
	switch {
	case gerr != nil || verr != nil:
		// Which files exist is unknown, so nothing was linted and nothing can
		// say how much was: a non-run, never an empty tree.
		sarifRaw = emptySARIF
		errs = []string{"pylint: could not list the Python files to lint: " + errors.Join(gerr, verr).Error()}
	default:
		targets, pruned := pylintTargets(pyFiles, venvCfgs)
		warnings = pylintTargetWarnings(targets, pruned)
		if len(targets) == 0 {
			sarifRaw = emptySARIF
			examined = &Examined{Unit: "files", Count: 0}
			break
		}
		out, err := dag.Container().
			From(pythonImage).
			WithMountedDirectory("/src", src).
			WithWorkdir("/src").
			WithExec([]string{"pip", "install", "pylint==" + pylintVersion, "--quiet"}).
			WithNewFile(pylintTargetsPath, strings.Join(targets, "\x00")).
			WithExec([]string{"python3", "-c", pylintScript(pylintTargetsPath)}).
			Stdout(ctx)
		sarifRaw, bySeverity, examined, errs = foldPylintRun(out, err, len(targets))
	}

	total := 0
	for _, c := range bySeverity {
		total += c
	}

	return &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: "pylint", Version: pylintVersion},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Languages:          []string{"python"},
		Passed:             gatedPassed(len(errs) == 0, !shouldFail(bySeverity, threshold), threshold),
		Outcome:            lintOutcome(len(errs) == 0, total, examined),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: bySeverity,
		Examined:           examined,
		SARIFReport:        sarifRaw,
		Warnings:           warnings,
		Errors:             errs,
	}, len(errs) == 0, nil
}

// runDotnetFormat runs `dotnet format --verify-no-changes` over every project
// the source tree declares.
//
// Two things here are load-bearing, and neither used to be:
//
//   - The exit status is classified rather than swallowed. The command used to
//     end in `|| true && [ -f report ] || echo '[]' > report`, so a formatter
//     that never started — a global.json naming an absent SDK (exit 145), an
//     unreachable private feed (exit 1) — produced a fabricated empty report
//     that parsed as clean and passed the gate with nothing in errors[].
//   - It is pointed at explicit targets. `dotnet format` with no argument loads
//     only the project sitting in the working directory and does not recurse,
//     so on any layout with nested projects most of the tree went unchecked.
func runDotnetFormat(
	ctx context.Context,
	src *dagger.Directory,
	threshold Severity,
	repo repoContext,
	feedUrl string,
	feedToken *dagger.Secret,
	prepared *dagger.Container,
) (*envelope, bool, error) {
	start := time.Now()

	var errs, warnings []string

	discovery, derr := discoverDotnetTargets(ctx, src)
	if derr != nil {
		errs = append(errs, "dotnet format: could not enumerate .NET projects: "+derr.Error())
		return dotnetFormatEnvelope(start, repo, threshold, "unknown", nil, nil, errs, warnings), false, nil
	}

	kind, targets := dotnetFormatTargets(discovery)
	if len(targets) == 0 {
		errs = append(errs, dotnetNoTargetError("dotnet format", discovery))
		return dotnetFormatEnvelope(start, repo, threshold, "unknown", nil, nil, errs, warnings), false, nil
	}
	if msg := dotnetTargetLimitError("dotnet format", targets); msg != "" {
		errs = append(errs, msg)
		return dotnetFormatEnvelope(start, repo, threshold, "unknown", nil, nil, errs, warnings), false, nil
	}
	if kind == "solution" {
		warnings = append(warnings, "dotnet format: checked solution "+targets[0])
	} else if len(targets) > 1 {
		warnings = append(warnings, "dotnet format: checked "+strconv.Itoa(len(targets))+
			" projects individually (no single solution file): "+strings.Join(targets, ", "))
	}

	// Which SDK band to run is resolved before the container exists, from the
	// repository rather than from a single compile-time pin. Every early return
	// from here is a non-run.
	req, rerr := discoverDotnetBandRequest(ctx, src)
	if rerr != nil {
		errs = append(errs, "dotnet format: could not read which .NET SDK band this "+
			"repository needs: "+rerr.Error())
		return dotnetFormatEnvelope(start, repo, threshold, "unknown", nil, nil, errs, warnings), false, nil
	}
	band, bandNote := dotnetResolveBand(req)
	warnings = append(warnings, "dotnet format: "+bandNote)

	base, ok := dotnetContainer(ctx, src, band, feedUrl, feedToken, repo.RepoURL)
	if prepared != nil {
		base, ok = prepared, true
	}
	if !ok {
		errs = append(errs, dotnetUnpinnedBandError("dotnet format", band))
		return dotnetFormatEnvelope(start, repo, threshold, "unknown", nil, nil, errs, warnings), false, nil
	}
	sdkVersion := readDotnetSDKVersion(ctx, base)

	var sarifReports []json.RawMessage
	bySeverity := map[Severity]int{}

	for _, target := range targets {
		sarif, counts, targetWarnings, targetErrs := runDotnetFormatOn(ctx, base, target, sdkVersion, band, prepared != nil)
		for _, w := range targetWarnings {
			warnings = append(warnings, dotnetTargetLabel(target, w))
		}
		for _, e := range targetErrs {
			errs = append(errs, dotnetTargetLabel(target, e))
		}
		if sarif != nil {
			// One dotnet-format run per project must stay one identity per
			// project at upload time — see stampSARIFAutomationID.
			if len(targets) > 1 {
				sarif = stampSARIFAutomationID(sarif, "dotnet-format", target)
			}
			sarifReports = append(sarifReports, sarif)
		}
		for sev, n := range counts {
			bySeverity[sev] += n
		}
	}

	return dotnetFormatEnvelope(start, repo, threshold, sdkVersion,
		mergeSARIFReports(sarifReports), bySeverity, errs, warnings), len(errs) == 0, nil
}

// runDotnetFormatOn checks one solution or project. The target is passed as an
// argv element, never interpolated into the shell body. It returns the SARIF,
// the severity counts, the warnings about the report (a finding whose location
// had to be coarsened to its bare file name) and the errors that make this a
// non-run.
func runDotnetFormatOn(
	ctx context.Context,
	base *dagger.Container,
	target string,
	sdkVersion string,
	band string,
	prepared bool,
) (json.RawMessage, map[Severity]int, []string, []string) {
	// The report path is fixed; stdout/stderr and the exit status are captured
	// so a non-run is distinguishable from a clean tree. Nothing fabricates the
	// report: when the command dies before writing one, the file stays empty and
	// dotnetFormatRunError says so.
	script := `: > /tmp/format-report.json
dotnet format "$TARGET" --verify-no-changes --report /tmp/format-report.json "$@" > /tmp/format.out 2>/tmp/format.err
echo $? > /tmp/format.exit`

	ctr := base.
		WithEnvVariable("TARGET", target).
		WithExec(append([]string{"sh", "-c", script, "sh"}, formatRestoreArgs(prepared)...))

	exitCode, err := ctr.File("/tmp/format.exit").Contents(ctx)
	if err != nil {
		return nil, nil, nil, []string{"dotnet format: could not read exit status: " + err.Error()}
	}
	// The script creates all three before the tool runs, so a read that fails
	// here is cicd's own, and dotnetFormatRunError must not be handed an empty
	// report it would classify as the tool's.
	report, rerr := ctr.File("/tmp/format-report.json").Contents(ctx)
	if rerr != nil {
		return nil, nil, nil, []string{readbackError("dotnet format", "/tmp/format-report.json", rerr)}
	}
	stderr, serr := ctr.File("/tmp/format.err").Contents(ctx)
	if serr != nil {
		return nil, nil, nil, []string{readbackError("dotnet format", "/tmp/format.err", serr)}
	}
	stdout, oerr := ctr.File("/tmp/format.out").Contents(ctx)
	if oerr != nil {
		return nil, nil, nil, []string{readbackError("dotnet format", "/tmp/format.out", oerr)}
	}

	if msg := dotnetFormatRunError(exitCode, stderr+"\n"+stdout, report, band); msg != "" {
		// `dotnet format` does not relay NETSDK1045 — measured on a net10.0
		// project under the 8.0 image, it reported only "Restore operation
		// failed" while `dotnet test` on the same tree printed the SDK's full
		// explanation. So when the tool named no cause we can act on, read the
		// project file: a target framework above the band that ran is the one
		// answer a consumer cannot reach from "Restore operation failed".
		if !strings.Contains(msg, dotnetSDKLabelFor(band)) {
			if csproj, err := base.File(path.Join(dotnetSrcMount, target)).Contents(ctx); err == nil {
				if tfm := dotnetTFMAboveBand(csproj, band); tfm != "" {
					msg += " — " + dotnetTargetBandRemedy(tfm, band)
				}
			}
		}
		return nil, nil, nil, []string{msg}
	}

	sarif, counts, reportWarnings := parseDotnetFormatReport([]byte(report), sdkVersion, dotnetSrcMount)
	if sarif == nil {
		return nil, nil, nil, []string{"dotnet format: wrote a report that is not a dotnet format report"}
	}
	return sarif, counts, reportWarnings, nil
}

func dotnetFormatEnvelope(
	start time.Time,
	repo repoContext,
	threshold Severity,
	sdkVersion string,
	sarifRaw json.RawMessage,
	bySeverity map[Severity]int,
	errs, warnings []string,
) *envelope {
	total := 0
	for _, c := range bySeverity {
		total += c
	}
	return &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: "dotnet-format", Version: sdkVersion},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Languages:          []string{"dotnet"},
		Passed:             gatedPassed(len(errs) == 0, !shouldFail(bySeverity, threshold), threshold),
		Outcome:            scanOutcome(len(errs) == 0, total),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: bySeverity,
		SARIFReport:        sarifRaw,
		Warnings:           warnings,
		Errors:             errs,
	}
}

// ---- SARIF/report parsers ----

type lintSarifDoc struct {
	Runs []struct {
		Results []struct {
			Level string `json:"level"`
		} `json:"results"`
	} `json:"runs"`
}

func parseLintSarifSeverities(raw json.RawMessage) map[Severity]int {
	var doc lintSarifDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	counts := map[Severity]int{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			switch r.Level {
			case "error":
				counts[SeverityHigh]++
			case "warning":
				counts[SeverityMedium]++
			default:
				counts[SeverityLow]++
			}
		}
	}
	return counts
}

// dotnet format's report parser lives in dotnetreport.go — untagged, so its
// severity mapping and its "this is not a format report" nil return are covered
// by the unit suite.
