package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// testLegRun is what a test leg learned from the files its script left behind:
// whether the runner produced a result at all (ran), whether that result was a
// pass, and the exit code when there was one.
type testLegRun struct {
	ran    bool
	passed bool
	code   *int
	err    string
}

// foldTestLeg classifies a test leg's readback. Every test leg runs its runner
// as `<cmd> > out 2>&1; echo $? > exit`, so the result exists only as those two
// files, and the order of the cases is the order in which they can fail:
//
//   - execErr: the exit sentinel could not be read, which Dagger reports when
//     the container itself failed. execPrefix words it per leg.
//   - outErr: the output cicd parses the counts from could not be read back.
//   - an exit sentinel that is empty or not a number. This used to be compared
//     against "0" and, failing that, reported as `<tool> failed (exit )`: a
//     failed suite made out of nothing, which --fail-on NONE then passed. A
//     sentinel that holds no exit status is a result cicd never received.
//
// Only a numeric exit is a result. Zero is a pass; anything else is the runner
// saying the suite failed, which is the one verdict NONE may suppress.
func foldTestLeg(tool, execPrefix string, execErr error, outPath string, outErr error, exitPath, exitRaw string) testLegRun {
	switch {
	case execErr != nil:
		return testLegRun{err: execPrefix + execErr.Error()}
	case outErr != nil:
		return testLegRun{err: readbackError(tool, outPath, outErr)}
	}
	code, msg := readbackExit(tool, exitPath, exitRaw)
	if msg != "" {
		return testLegRun{err: msg}
	}
	r := testLegRun{ran: true, passed: code == 0, code: &code}
	if code != 0 {
		r.err = fmt.Sprintf("%s failed (exit %d)", tool, code)
	}
	return r
}

// readbackExit parses the exit status a leg's script echoed into a sentinel
// file. A shell's `$?` is 0-255, so anything else, the empty string included,
// is a sentinel that was truncated, overwritten or never written, and is
// worded as such rather than as an exit.
func readbackExit(tool, path, raw string) (int, string) {
	trimmed := strings.TrimSpace(raw)
	n, err := strconv.Atoi(trimmed)
	if err != nil || n < 0 || n > 255 {
		return 0, fmt.Sprintf("%s: %s holds %q, which is not an exit status, so the runner's result never reached cicd", tool, path, trimmed)
	}
	return n, ""
}

// asNonRun turns a leg whose runner exited with a status, but whose status
// says no suite result exists, into a non-run. The exit code is dropped with
// the result: a non-run carries no code, which is how every reader tells the
// two apart.
func (r testLegRun) asNonRun(reason string) testLegRun {
	return testLegRun{err: reason}
}

// Where pytestScript records what `pip install pytest` exited with.
const pipInstallExitPath = "/tmp/pip-install.exit"

// pytestScript is the auto-detected Python leg's command. pytest's exit is
// written to its sentinel only when pytest ran: the script used to chain the
// install with `&&` and echo $? after it, so a pip that could not install
// pytest wrote pip's own exit into pytest's sentinel and read as `pytest
// failed (exit 1)` — a failing suite, which `--fail-on NONE` passes.
func pytestScript() string {
	return `pip install pytest --quiet 2>/dev/null; echo $? > ` + pipInstallExitPath + `; ` +
		`if [ "$(cat ` + pipInstallExitPath + `)" = 0 ]; then ` +
		`if pip install pytest-cov --quiet 2>/dev/null; then ` +
		`pytest -v --tb=short --cov --cov-report=json:/tmp/coverage.json > /tmp/pytest.out 2>&1; ` +
		`else pytest -v --tb=short > /tmp/pytest.out 2>&1; fi; ` +
		`echo $? > /tmp/pytest.exit; fi`
}

// pytestNonRun reclassifies pytest's documented exits that carry no suite
// result (pytest.ExitCode). Only 1, TESTS_FAILED, is a suite that ran and
// failed; the rest used to be reported as `pytest failed (exit N)` and so as a
// failing suite `--fail-on NONE` may suppress. Measured on python-poetry/cleo:
// its conftest.py imports the package, which the auto-detected leg never
// installs, so pytest exited 4 having run no test, and the quality module read
// passed:true at NONE.
//
// Exit 2 is a non-run too, not a partial result: pytest stops the session on a
// collection error before any test runs, and an interrupt mid-run leaves a
// suite that ran on part of its input, which must not read as all of it.
//
// pipExit is what `pip install pytest` exited with, or "" when unknown. A
// failed install is a non-run whatever the pytest sentinel says: pytestScript
// never runs pytest after one, so the sentinel is absent and foldTestLeg's
// reason would name a missing file instead of the install that caused it.
func pytestNonRun(r testLegRun, pipExit string) testLegRun {
	if code := strings.TrimSpace(pipExit); code != "" && code != "0" {
		return r.asNonRun(fmt.Sprintf("pytest: did not run: pip install pytest exited %s, so pytest was never installed", code))
	}
	if !r.ran || r.code == nil {
		return r
	}
	var why string
	switch *r.code {
	case 2:
		why = "interrupted, or a test module that could not be collected"
	case 3:
		why = "pytest's own internal error"
	case 4:
		why = "a command-line usage error, or a conftest.py that could not be imported"
	case 5:
		why = "no tests were collected"
	default:
		return r
	}
	return r.asNonRun(fmt.Sprintf("pytest: did not run (exit %d: %s), so no test result exists. "+
		"The auto-detected Python leg installs pytest and pytest-cov only, never the project or its dependencies; "+
		"a suite that imports the project needs the witnessed test leg (--test-cmd), which runs the repository's own install first",
		*r.code, why))
}

// vitestNonRun reclassifies a non-zero vitest exit that printed no `Tests`
// summary. Vitest exits 1 both for failing tests and for a run that never
// started — a Startup Error, a config it could not load, vitest itself absent —
// and the summary line is the only difference: a run that executed tests
// prints it, failing or not. Measured on changesets/changesets, a pnpm
// workspace, before the legs installed with the project's own manager: npm
// could not install it, so `npx` fetched a vitest nobody pinned, which could
// not load vitest.config.ts and exited 1 having run nothing.
//
// install is the dependency install the leg ran (npm, pnpm or yarn, per
// nodeinstall.go) and what it exited with; a failed install is named because
// it is nearly always the cause.
//
// version is the vitest version the script resolved before running anything,
// and versionRead whether that sentinel could be read at all. Read and empty
// means no vitest is installed, so the script ran nothing: that is a non-run
// whatever the exit says, and it is checked first. An unreadable sentinel
// claims nothing, since the script may have died before writing it.
func vitestNonRun(r testLegRun, counted bool, install installRecord, version string, versionRead bool) testLegRun {
	ie, installFailed := install.failed()
	if r.ran && versionRead && strings.TrimSpace(version) == "" {
		// The remedy depends on why. A failed install is nearly always the
		// cause and "declare vitest" would be wrong advice for a project that
		// does (measured: npm 10.8.2 crashes in arborist resolving a fresh
		// vitest ^4 tree).
		if installFailed {
			return r.asNonRun(fmt.Sprintf("vitest: did not run: %s exited %s, so vitest is not installed "+
				"in this Node project, and cicd does not fetch one. Fix the install (%s), or run the suite through the "+
				"witnessed test leg (--test-cmd) with its own install", install.name(), ie, installFailureCauses(install)))
		}
		msg := "vitest: did not run: vitest is not installed in this Node project, and cicd does not " +
			"fetch one. Declare vitest in the project's devDependencies"
		// The workspace caveat is npm's alone: pnpm and yarn install the
		// whole workspace from a member, so a root-declared vitest resolves
		// there, and naming `npm install` to a pnpm project is wrong advice.
		if install.corepack {
			msg += ", or run the suite through the witnessed test leg (--test-cmd)"
		} else {
			msg += "; when it is declared at an npm workspace root, `npm install` in the member does not " +
				"install it, so run the suite through the witnessed test leg (--test-cmd)"
		}
		return r.asNonRun(msg)
	}
	if !r.ran || r.passed || counted || r.code == nil {
		return r
	}
	msg := fmt.Sprintf("vitest: did not run (exit %d with no test summary), so no test result exists: "+
		"vitest stopped before reporting a test — a startup error or a config it could not load", *r.code)
	if installFailed {
		msg += fmt.Sprintf(". %s exited %s, so the project's dependencies were never installed: fix the install (%s), "+
			"or run the suite through the witnessed test leg (--test-cmd) with its own install",
			install.name(), ie, installFailureCauses(install))
	}
	return r.asNonRun(msg)
}

// goBuildFailureLine is the verdict `go test` prints for a package it could not
// test at all: `FAIL\t<pkg> [build failed]` for a compile or vet error in the
// package or its tests, `FAIL\t<pkg> [setup failed]` for an import it could not
// resolve. Measured on go1.26.3 across a syntax error, an unused variable in a
// _test.go, a vet printf error and a missing import: each one prints this line
// after the `# <pkg>` block naming the cause, so the line alone identifies
// every package that never ran.
var goBuildFailureLine = regexp.MustCompile(`(?m)^FAIL\s+(\S+)\s+\[(build|setup) failed\]\s*$`)

const (
	// goNonRunPackageCap bounds how many unbuilt packages an error names; the
	// rest are counted, and the full list is in the leg's raw output.
	goNonRunPackageCap = 10
	// goNonRunTailLines and goNonRunTailBytes bound the output quoted when go
	// test exited non-zero having printed no package verdict at all.
	goNonRunTailLines = 20
	goNonRunTailBytes = 400
)

// goBuildFailures returns, sorted and deduplicated, each package go test
// reported as `[build failed]` or `[setup failed]`, worded with which.
func goBuildFailures(out string) []string {
	seen := map[string]bool{}
	var pkgs []string
	for _, m := range goBuildFailureLine.FindAllStringSubmatch(ansiEscape.ReplaceAllString(out, ""), -1) {
		entry := m[1] + " (" + m[2] + " failed)"
		if !seen[entry] {
			seen[entry] = true
			pkgs = append(pkgs, entry)
		}
	}
	sort.Strings(pkgs)
	return pkgs
}

// goTestNonRun reclassifies a non-zero `go test` exit that is not a failing
// suite. go test exits 1 for a failing test, for a package that did not
// compile, and for a toolchain it could not download, and foldTestLeg read all
// three as `go test failed (exit 1)`: a failing suite, which --fail-on NONE
// passes. Two shapes are non-runs:
//
//   - Any package reported `[build failed]` or `[setup failed]`. Its tests never
//     ran, so the leg ran on part of the module, and that must not read as all
//     of it — even beside a real failing test elsewhere, which is exactly the
//     run where the failing test hid the build error. The counts the packages
//     that did build produced are quoted in the reason and withheld from the
//     leg: a count published beside the word total would claim the whole suite.
//   - native only: no package verdict and no `=== RUN` line at all, which is a
//     go command that stopped before testing anything (a toolchain it could not
//     fetch, a go.mod it could not parse). cicd chose `go test -v`, so a verdict
//     line is guaranteed when anything ran. A caller's command (the BYO Go leg)
//     may print another format — gotestsum's, a Makefile's — so there the
//     missing line proves nothing and only the explicit build verdict counts.
//
// tool prefixes the reason, as foldTestLeg's does.
func goTestNonRun(r testLegRun, tool, out string, native bool) testLegRun {
	if !r.ran || r.passed || r.code == nil {
		return r
	}
	if pkgs := goBuildFailures(out); len(pkgs) > 0 {
		named := pkgs
		more := ""
		if len(named) > goNonRunPackageCap {
			named = named[:goNonRunPackageCap]
			more = fmt.Sprintf(" and %d more (first %d by name)", len(pkgs)-goNonRunPackageCap, goNonRunPackageCap)
		}
		list, _ := scrubCredentials(strings.Join(named, ", "))
		msg := fmt.Sprintf("%s: did not run on the whole module (exit %d): %d package(s) could not be built or set up, so their tests never ran: %s%s",
			tool, *r.code, len(pkgs), list, more)
		if c, ok := parseGoTestCounts(out); ok {
			msg += fmt.Sprintf(". The packages that did build ran %d test(s), %d failed; that is a partial result, so it is not reported as the suite's counts", c.Total, c.Failed)
		}
		return r.asNonRun(msg)
	}
	clean := ansiEscape.ReplaceAllString(out, "")
	if native && !goPkgLine.MatchString(clean) && !goRunLine.MatchString(clean) {
		return r.asNonRun(fmt.Sprintf("%s: did not run (exit %d): it printed no package verdict, so no test result exists. Last output: %s",
			tool, *r.code, boundedTail(clean, goNonRunTailLines, goNonRunTailBytes)))
	}
	return r
}

// boundedTail is the last maxLines lines of s, each cut to maxBytes and
// scrubbed of credentials, joined with " | " so it fits in one errors[] entry.
// An empty s says so rather than quoting nothing.
func boundedTail(s string, maxLines, maxBytes int) string {
	var kept []string
	for _, line := range splitOutputLines(s) {
		if strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return "(no output)"
	}
	if len(kept) > maxLines {
		kept = kept[len(kept)-maxLines:]
	}
	for i, line := range kept {
		line, _ = truncateLineBytes(strings.TrimSpace(line), maxBytes)
		kept[i], _ = scrubCredentials(line)
	}
	return strings.Join(kept, " | ")
}

// vitest prints a `Failed Suites N` block, apart from `Failed Tests`, for every
// test file that reported an error at file level: a file it could not import or
// transform, or a hook that failed, so its tests did not all run. Each entry is
// a `FAIL  <file> [ <file> ]` line.
var (
	vitestFailedSuitesHeader = regexp.MustCompile(`^\s*⎯+\s*Failed Suites\s+([0-9]+)\s*⎯+\s*$`)
	// A section header is rule, space, words; the `⎯⎯[3/21]⎯` rule between
	// two entries of one section is not.
	vitestSectionHeader  = regexp.MustCompile(`^\s*⎯+\s+[A-Za-z]`)
	vitestFailLine       = regexp.MustCompile(`^\s*FAIL\s+(.+?)\s*$`)
	vitestFailFile       = regexp.MustCompile(`\[\s*(.+?)\s*\]$`)
	vitestTestFilesTotal = regexp.MustCompile(`(?m)^\s*Test Files\s+.+?\(([0-9]+)\)\s*$`)
)

// vitestNonRunFileCap bounds how many files a suite-level error names; the
// rest are counted, and the full list is in the leg's raw output.
const vitestNonRunFileCap = 10

// vitestFailedSuites returns how many test files vitest reported in its
// `Failed Suites` block, and, sorted and deduplicated, the ones it named. The
// count is vitest's own header, so a block whose entries cicd could not read is
// still counted. ok is false when there is no such block.
func vitestFailedSuites(out string) (int, []string, bool) {
	count, ok := 0, false
	seen := map[string]bool{}
	var files []string
	in := false
	for _, line := range strings.Split(ansiEscape.ReplaceAllString(out, ""), "\n") {
		if m := vitestFailedSuitesHeader.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				return 0, nil, false
			}
			count, ok, in = count+n, true, true
			continue
		}
		if vitestSectionHeader.MatchString(line) || strings.Contains(line, "Test Files") {
			in = false
			continue
		}
		if !in {
			continue
		}
		m := vitestFailLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		file := m[1]
		if f := vitestFailFile.FindStringSubmatch(file); f != nil {
			file = f[1]
		} else if i := strings.Index(file, " > "); i >= 0 {
			file = file[:i]
		}
		if !seen[file] {
			seen[file] = true
			files = append(files, file)
		}
	}
	sort.Strings(files)
	return count, files, ok
}

// vitestSuiteNonRun reclassifies a vitest run that reported a suite-level
// error. vitest exits 1 for it as it does for a failing test, and its `Tests`
// line counts only the tests in the files that loaded, so foldTestLeg read the
// run as `vitest failed (exit 1)` — measured on changesets: 21 of 39 files could
// not resolve a workspace package, 129 tests passed, and the envelope read as a
// suite that ran and failed. The leg ran on part of its input, which must not
// read as all of it, beside a real failing test too; the counts the loaded files
// produced are quoted in the reason and withheld from the leg, as goTestNonRun
// does for packages that did not build.
//
// native is the auto-detected leg, whose install cicd runs with lifecycle
// scripts off: a workspace package built by its own postinstall or prepare is
// then not built, which is the likeliest cause and the one remedy cicd can
// name. It is worded as a condition, never a diagnosis — the files' errors are
// in the raw output, and quoting one line of them would be a claim. A caller's
// command (the BYO leg) ran its own install, so there the remedy is not cicd's
// to give.
func vitestSuiteNonRun(r testLegRun, tool, out string, native bool) testLegRun {
	if !r.ran || r.passed || r.code == nil {
		return r
	}
	n, files, ok := vitestFailedSuites(out)
	if !ok || n == 0 {
		return r
	}
	of := ""
	if m := vitestTestFilesTotal.FindStringSubmatch(ansiEscape.ReplaceAllString(out, "")); m != nil {
		of = " of " + m[1]
	}
	named := files
	more := ""
	if len(named) > vitestNonRunFileCap {
		named = named[:vitestNonRunFileCap]
		more = fmt.Sprintf(" and %d more (first %d by name)", len(files)-vitestNonRunFileCap, vitestNonRunFileCap)
	}
	list := "vitest named none of them"
	if len(named) > 0 {
		list, _ = scrubCredentials(strings.Join(named, ", "))
	}
	msg := fmt.Sprintf("%s: did not run on the whole suite (exit %d): %d%s test file(s) reported a suite-level error "+
		"(vitest's Failed Suites: a file it could not load, or a hook that failed), so their tests did not all run: %s%s",
		tool, *r.code, n, of, list, more)
	if c, ok := parseVitestTestCounts(out); ok {
		msg += fmt.Sprintf(". The rest ran %d test(s), %d failed; that is a partial result, so it is not reported as the suite's counts", c.Total, c.Failed)
	}
	if native {
		msg += ". cicd installs with lifecycle scripts off, so a workspace package that builds itself in postinstall or " +
			"prepare is not built here; when that is why a file could not load, run the suite through the witnessed " +
			"test leg (--test-cmd) with its own build"
	}
	return r.asNonRun(msg)
}
