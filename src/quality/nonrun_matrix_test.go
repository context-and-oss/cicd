package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The founding rule as a matrix: every fault a leg's readback can carry,
// against every threshold, must come out ran=false with an error naming it and
// passed=false, `--fail-on NONE` included. The positive controls prove the
// matrix is not passing because the fold refuses everything.

var allThresholds = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone}

func TestNonRunMatrixTestLeg(t *testing.T) {
	boom := errors.New("container exited 137")
	faults := []struct {
		name    string
		execErr error
		outErr  error
		exit    string
		wantErr string
	}{
		{"exec error", boom, nil, "", "pytest: container exited 137"},
		{"output unreadable", nil, boom, "0", "could not read /tmp/pytest.out back"},
		{"empty sentinel", nil, nil, "", `/tmp/pytest.exit holds ""`},
		{"whitespace sentinel", nil, nil, " \n", `/tmp/pytest.exit holds ""`},
		{"garbage sentinel", nil, nil, "Killed", `holds "Killed", which is not an exit status`},
		{"truncated sentinel", nil, nil, "1\x00", "which is not an exit status"},
		{"negative sentinel", nil, nil, "-1", "which is not an exit status"},
		{"out-of-range sentinel", nil, nil, "256", "which is not an exit status"},
	}
	for _, f := range faults {
		leg := foldTestLeg("pytest", "pytest: ", f.execErr, "/tmp/pytest.out", f.outErr, "/tmp/pytest.exit", f.exit)
		if leg.ran || leg.passed || leg.code != nil {
			t.Errorf("%s: got ran=%v passed=%v code=%v, want a non-run with no exit code", f.name, leg.ran, leg.passed, leg.code)
		}
		if !strings.Contains(leg.err, f.wantErr) {
			t.Errorf("%s: error %q does not contain %q", f.name, leg.err, f.wantErr)
		}
		if got := testOutcome(leg.ran, leg.passed, nil); got != OutcomeError {
			t.Errorf("%s: outcome %s, want %s", f.name, got, OutcomeError)
		}
		for _, th := range allThresholds {
			if gatedPassed(leg.ran, leg.passed, th) {
				t.Errorf("%s: passed at --fail-on %s", f.name, th)
			}
		}
	}
}

func TestNonRunMatrixTestLegControls(t *testing.T) {
	pass := foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "0\n")
	if !pass.ran || !pass.passed || pass.err != "" || pass.code == nil || *pass.code != 0 {
		t.Fatalf("exit 0: got %+v, want a clean pass", pass)
	}
	fail := foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n")
	if !fail.ran || fail.passed || fail.code == nil || *fail.code != 1 {
		t.Fatalf("exit 1: got %+v, want a run that failed", fail)
	}
	if fail.err != "go test failed (exit 1)" {
		t.Errorf("exit 1: error %q, want the wording the smokes grep", fail.err)
	}
	// A failed suite is a result, so NONE is the one threshold that passes it.
	for _, th := range allThresholds {
		if got, want := gatedPassed(fail.ran, fail.passed, th), th == SeverityNone; got != want {
			t.Errorf("exit 1 at --fail-on %s: passed=%v, want %v", th, got, want)
		}
	}
}

// Fixtures measured with go1.26.3 `go test -v ./...` over a three-package
// module where ex/b has a failing test and ex/c is broken one way or another.
const (
	goOutPassFail = "=== RUN   TestA\n--- PASS: TestA (0.00s)\nPASS\nok  \tex/a\t0.186s\n" +
		"=== RUN   TestB\n    b_test.go:3: boom\n--- FAIL: TestB (0.00s)\nFAIL\nFAIL\tex/b\t0.185s\n"
	goOutBuildFailed = "# ex/c [ex/c.test]\nc/c.go:3:1: syntax error: unexpected EOF, expected }\n" +
		goOutPassFail + "FAIL\tex/c [build failed]\nFAIL\n"
	goOutSetupFailed = "# ex/c\nc/c_test.go:3:8: package ex/nope is not in std\nFAIL\tex/c [setup failed]\n" +
		goOutPassFail + "FAIL\n"
	goOutToolchain = "go: downloading go1.99.0 (linux/amd64)\ngo: download go1.99.0 for linux/amd64: toolchain not available\n"
)

func TestNonRunMatrixGoTestPartOfTheModule(t *testing.T) {
	cases := []struct {
		name, out, want string
	}{
		{"build failed beside a failing test", goOutBuildFailed, "1 package(s) could not be built or set up, so their tests never ran: ex/c (build failed)"},
		{"setup failed beside a failing test", goOutSetupFailed, "ex/c (setup failed)"},
		{"build failed alone", "# ex/c\nc/c.go:3:1: syntax error\nFAIL\tex/c [build failed]\nFAIL\n", "ex/c (build failed)"},
	}
	for _, tc := range cases {
		for _, native := range []bool{true, false} {
			leg := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n"), "go test", tc.out, native)
			assertLegNeverPasses(t, tc.name, leg, tc.want)
			if !strings.HasPrefix(leg.err, "go test: did not run on the whole module (exit 1)") {
				t.Errorf("%s: error %q does not state the rule", tc.name, leg.err)
			}
		}
	}
	// The packages that built are quoted, never published as the suite's counts.
	leg := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n"), "go test", goOutBuildFailed, true)
	if !strings.Contains(leg.err, "ran 2 test(s), 1 failed; that is a partial result") {
		t.Errorf("partial counts not quoted: %q", leg.err)
	}
}

func TestGoBuildFailuresAreSortedDedupedAndCapped(t *testing.T) {
	var b strings.Builder
	for i := 11; i >= 0; i-- {
		fmt.Fprintf(&b, "FAIL\tex/p%02d [build failed]\n", i)
	}
	b.WriteString("FAIL\tex/p00 [build failed]\n")
	got := goBuildFailures(b.String())
	if len(got) != 12 || got[0] != "ex/p00 (build failed)" || got[11] != "ex/p11 (build failed)" {
		t.Fatalf("got %v, want 12 sorted unique packages", got)
	}
	leg := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n"), "go test", b.String(), true)
	if !strings.Contains(leg.err, "12 package(s)") || !strings.Contains(leg.err, "and 2 more (first 10 by name)") || strings.Contains(leg.err, "ex/p10") {
		t.Errorf("cap not applied as stated: %q", leg.err)
	}
}

func TestNonRunMatrixGoTestNeverReachedAPackage(t *testing.T) {
	leg := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n"), "go test", goOutToolchain, true)
	assertLegNeverPasses(t, "toolchain download failed", leg,
		"go test: did not run (exit 1): it printed no package verdict, so no test result exists. Last output: go: downloading go1.99.0")
	if !strings.Contains(leg.err, "toolchain not available") {
		t.Errorf("tail lost the cause: %q", leg.err)
	}
	empty := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "2\n"), "go test", "", true)
	assertLegNeverPasses(t, "no output", empty, "Last output: (no output)")
}

func TestGoTestNonRunControls(t *testing.T) {
	// A real failing suite stays a failure, the one verdict NONE may suppress.
	for _, native := range []bool{true, false} {
		fail := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "1\n"), "go test", goOutPassFail+"FAIL\n", native)
		if !fail.ran || fail.code == nil || fail.err != "go test failed (exit 1)" {
			t.Errorf("native=%v: a failing suite became %+v", native, fail)
		}
	}
	// A caller's command may print another format: no verdict line proves nothing.
	byo := goTestNonRun(foldTestLeg("test command", "x: ", nil, "/o", nil, "/e", "1\n"), "test command", "✖  ex/b (12ms)\nDONE 2 tests, 1 failure\n", false)
	if !byo.ran || byo.err != "test command failed (exit 1)" {
		t.Errorf("BYO gotestsum failure became %+v", byo)
	}
	pass := goTestNonRun(foldTestLeg("go test", "go test: ", nil, "/o", nil, "/e", "0\n"), "go test", "", true)
	if !pass.ran || !pass.passed {
		t.Errorf("exit 0 became %+v", pass)
	}
	nonRun := foldTestLeg("go test", "go test: ", errors.New("boom"), "/o", nil, "/e", "")
	if got := goTestNonRun(nonRun, "go test", goOutBuildFailed, true); got.err != nonRun.err {
		t.Errorf("a container error was reworded: %q", got.err)
	}
}

func TestBoundedTailCutsScrubsAndKeepsTheEnd(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "line %d\n\n", i)
	}
	b.WriteString("token ghp_" + strings.Repeat("a", 36) + " " + strings.Repeat("x", 600) + "\n")
	got := boundedTail(b.String(), 3, 100)
	if strings.Contains(got, "line 27") || !strings.HasPrefix(got, "line 28 | line 29 | ") {
		t.Errorf("tail did not keep the last non-empty lines: %q", got)
	}
	if strings.Contains(got, "ghp_aaaa") || !strings.Contains(got, "more bytes]") {
		t.Errorf("tail not scrubbed or not cut: %q", got)
	}
}

// assertLegNeverPasses holds a reclassified leg to the same bar as a readback
// fault: no result, no exit code, a reason, and a fail at every threshold.
func assertLegNeverPasses(t *testing.T, name string, leg testLegRun, wantErr string) {
	t.Helper()
	if leg.ran || leg.passed || leg.code != nil {
		t.Errorf("%s: got ran=%v passed=%v code=%v, want a non-run with no exit code", name, leg.ran, leg.passed, leg.code)
	}
	if !strings.Contains(leg.err, wantErr) {
		t.Errorf("%s: error %q does not contain %q", name, leg.err, wantErr)
	}
	for _, th := range allThresholds {
		if gatedPassed(leg.ran, leg.passed, th) {
			t.Errorf("%s: passed at --fail-on %s", name, th)
		}
	}
}

// pytest's exits other than 0 and 1 carry no suite result. Measured on
// python-poetry/cleo: exit 4, a conftest.py importing a package the leg never
// installs, read passed:true at NONE.
func TestNonRunMatrixPytestNoResultExits(t *testing.T) {
	for exit, want := range map[string]string{
		"2": "did not run (exit 2: interrupted",
		"3": "did not run (exit 3: pytest's own internal error",
		"4": "did not run (exit 4: a command-line usage error, or a conftest.py",
		"5": "did not run (exit 5: no tests were collected",
	} {
		leg := pytestNonRun(foldTestLeg("pytest", "pytest: ", nil, "/tmp/pytest.out", nil, "/tmp/pytest.exit", exit+"\n"), "0\n")
		assertLegNeverPasses(t, "pytest exit "+exit, leg, want)
		if !strings.Contains(leg.err, "--test-cmd") {
			t.Errorf("pytest exit %s: error %q does not name the remedy", exit, leg.err)
		}
	}
	// A pip that could not install pytest leaves no pytest sentinel, and the
	// reason must name the install rather than the missing file.
	missing := errors.New("no such file or directory")
	leg := pytestNonRun(foldTestLeg("pytest", "pytest: ", missing, "/tmp/pytest.out", missing, "/tmp/pytest.exit", ""), "1\n")
	assertLegNeverPasses(t, "pip install failed", leg, "pip install pytest exited 1")
}

func TestNonRunMatrixPytestControls(t *testing.T) {
	pass := pytestNonRun(foldTestLeg("pytest", "pytest: ", nil, "/o", nil, "/e", "0\n"), "0\n")
	if !pass.ran || !pass.passed || pass.err != "" {
		t.Fatalf("exit 0: got %+v, want a clean pass", pass)
	}
	fail := pytestNonRun(foldTestLeg("pytest", "pytest: ", nil, "/o", nil, "/e", "1\n"), "0\n")
	if !fail.ran || fail.passed || fail.code == nil || *fail.code != 1 || fail.err != "pytest failed (exit 1)" {
		t.Fatalf("exit 1: got %+v, want a run that failed", fail)
	}
	// A pip exit nobody could read is not evidence of a failed install.
	unknown := pytestNonRun(foldTestLeg("pytest", "pytest: ", nil, "/o", nil, "/e", "1\n"), "")
	if !unknown.ran || unknown.code == nil {
		t.Fatalf("unreadable pip exit: got %+v, want the suite's own result kept", unknown)
	}
}

func TestPytestScriptRunsPytestOnlyAfterItsInstall(t *testing.T) {
	s := pytestScript()
	gate := strings.Index(s, `if [ "$(cat `+pipInstallExitPath+`)" = 0 ]; then`)
	sentinel := strings.Index(s, "echo $? > /tmp/pytest.exit")
	if gate == -1 || sentinel == -1 || sentinel < gate {
		t.Fatalf("pytest's sentinel must be written only inside the install gate: %s", s)
	}
	if strings.Contains(s, "pip install pytest --quiet 2>/dev/null &&") {
		t.Error("an install chained with && writes pip's exit into pytest's sentinel")
	}
	if !strings.HasSuffix(s, "echo $? > /tmp/pytest.exit; fi") {
		t.Errorf("nothing may run between the suite and its exit capture: %s", s)
	}
}

// Vitest exits 1 for failing tests and for a run that never started; only the
// Tests summary tells them apart. Measured on changesets/changesets: a Startup
// Error after npm could not install a pnpm workspace read as a failing suite.
func TestNonRunMatrixVitestNeverStarted(t *testing.T) {
	startup := foldTestLeg("vitest", "vitest: ", nil, "/tmp/vitest.out", nil, "/tmp/vitest.exit", "1\n")
	out := "Startup Error\nError: Cannot find package 'vitest' imported from /src/vitest.config.ts\n"
	_, counted := parseVitestTestCounts(out)
	leg := vitestNonRun(startup, counted, npmDefault.record("1\n"), "3.2.4\n", true)
	assertLegNeverPasses(t, "vitest startup error", leg, "vitest: did not run (exit 1 with no test summary)")
	if !strings.Contains(leg.err, "npm install exited 1") || !strings.Contains(leg.err, "--test-cmd") {
		t.Errorf("startup error after a failed install: %q, want the install and the remedy named", leg.err)
	}
	leg = vitestNonRun(startup, counted, npmDefault.record("0\n"), "3.2.4\n", true)
	assertLegNeverPasses(t, "vitest startup error, install ok", leg, "did not run (exit 1 with no test summary)")
	if strings.Contains(leg.err, "npm install exited") {
		t.Errorf("a clean install must not be blamed: %q", leg.err)
	}
}

// A project with no vitest used to be tested by whichever vitest `npx` fetched.
// Measured in node:20-alpine: an npm workspace whose vitest is declared at the
// root installs none from the member, and `npx vitest` then fetched 4.1.12.
// The script now runs nothing there; the exit it leaves is never trusted.
func TestNonRunMatrixVitestNotInstalled(t *testing.T) {
	for _, exit := range []string{"1\n", "0\n"} {
		leg := vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", exit), false, npmDefault.record("0\n"), "", true)
		assertLegNeverPasses(t, "no vitest, exit "+strings.TrimSpace(exit), leg,
			"vitest: did not run: vitest is not installed in this Node project, and cicd does not fetch one. Declare vitest")
		if !strings.Contains(leg.err, "--test-cmd") {
			t.Errorf("no vitest: %q, want the witnessed-leg remedy", leg.err)
		}
	}
	// Measured on testdata/app-workspace (pnpm 11.19.0): the npm workspace
	// caveat was given to a pnpm project, whose member installs do reach the root.
	pnpm := nodePM{name: "pnpm", version: "11.19.0", lockfile: "pnpm-lock.yaml"}
	leg := vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), false, pnpm.record("0\n"), "", true)
	assertLegNeverPasses(t, "no vitest under pnpm", leg,
		"vitest: did not run: vitest is not installed in this Node project, and cicd does not fetch one. Declare vitest")
	if strings.Contains(leg.err, "npm install") || !strings.Contains(leg.err, "--test-cmd") {
		t.Errorf("no vitest under pnpm: %q, want the witnessed-leg remedy and no npm advice", leg.err)
	}

	leg = vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), false, npmDefault.record("1\n"), "\n", true)
	assertLegNeverPasses(t, "no vitest after a failed install", leg,
		"vitest: did not run: npm install exited 1, so vitest is not installed in this Node project, and cicd does not fetch one. Fix the install")
	if strings.Contains(leg.err, "Declare vitest") {
		t.Errorf("a failed install must not be answered with \"declare vitest\": %q", leg.err)
	}

	// An unreadable sentinel claims nothing: the existing rules decide.
	unread := vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "0\n"), false, npmDefault.record("0\n"), "", false)
	if !unread.ran || !unread.passed {
		t.Errorf("an unreadable version sentinel must not make a non-run of a pass: %+v", unread)
	}
	// A leg that is already a non-run keeps its own reason.
	gone := foldTestLeg("vitest", "vitest: ", errors.New("exec failed"), "/o", nil, "/e", "")
	if got := vitestNonRun(gone, false, npmDefault.record(""), "", true); got.err != gone.err {
		t.Errorf("a container failure was reworded: %q, want %q", got.err, gone.err)
	}
}

func TestNonRunMatrixVitestControls(t *testing.T) {
	out := " Test Files  1 failed (1)\n      Tests  1 failed | 3 passed (4)\n"
	counts, counted := parseVitestTestCounts(out)
	if !counted || counts.Failed != 1 {
		t.Fatalf("control fixture does not parse as a failing suite: %+v %v", counts, counted)
	}
	fail := vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), counted, npmDefault.record("1\n"), "3.2.4\n", true)
	if !fail.ran || fail.passed || fail.code == nil || fail.err != "vitest failed (exit 1)" {
		t.Fatalf("exit 1 with a summary: got %+v, want a run that failed", fail)
	}
	pass := vitestNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "0\n"), false, npmDefault.record(""), "3.2.4\n", true)
	if !pass.ran || !pass.passed {
		t.Fatalf("exit 0: got %+v, want a pass whatever the summary", pass)
	}
}

// vitestOutSuitesFailed is the shape vitest 5 printed on changesets with its
// lifecycle scripts off (measured, node:24-alpine, pnpm 11): files that could
// not resolve a workspace package, each a `Failed Suites` entry, separated by
// numbered rules, and a Tests line counting only the files that loaded. The
// ANSI styling is vitest's own, which it emits even into a file.
const vitestOutSuitesFailed = "\x1b[31m⎯⎯⎯⎯⎯⎯\x1b[39m\x1b[1m\x1b[41m Failed Suites 21 \x1b[49m\x1b[22m\x1b[31m⎯⎯⎯⎯⎯⎯\x1b[39m\n" +
	"\n" +
	"\x1b[41m\x1b[1m FAIL \x1b[22m\x1b[49m packages/b/src/index.test.ts\x1b[2m [ packages/b/src/index.test.ts ]\x1b[22m\n" +
	"\x1b[31m\x1b[1mError\x1b[22m: Failed to resolve entry for package \"@ex/config\".\x1b[39m\n" +
	"\x1b[31m\x1b[2m⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[1/21]⎯\x1b[22m\x1b[39m\n" +
	"\n" +
	"\x1b[41m\x1b[1m FAIL \x1b[22m\x1b[49m packages/a/src/index.test.ts\x1b[2m [ packages/a/src/index.test.ts ]\x1b[22m\n" +
	"\x1b[31m\x1b[1mError\x1b[22m: Failed to resolve entry for package \"@ex/git\".\x1b[39m\n" +
	"\x1b[31m\x1b[2m⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯[2/21]⎯\x1b[22m\x1b[39m\n" +
	"\n" +
	"\x1b[41m\x1b[1m FAIL \x1b[22m\x1b[49m packages/a/src/index.test.ts\x1b[2m [ packages/a/src/index.test.ts ]\x1b[22m\n" +
	"\n" +
	"\x1b[2m Test Files \x1b[22m \x1b[1m\x1b[31m21 failed\x1b[39m\x1b[22m\x1b[2m | \x1b[22m\x1b[1m\x1b[32m18 passed\x1b[39m\x1b[22m\x1b[90m (39)\x1b[39m\n" +
	"\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m129 passed\x1b[39m\x1b[22m\x1b[90m (129)\x1b[39m\n"

// vitestOutTestFailed is an ordinary failing test: a `Failed Tests` block,
// whose FAIL line names a test, not a file that could not load.
const vitestOutTestFailed = "⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯\n" +
	"\n" +
	" FAIL  src/sum.test.ts > sum > adds\n" +
	"AssertionError: expected 3 to be 4\n" +
	"⎯⎯⎯⎯⎯⎯⎯⎯[1/1]⎯\n" +
	"\n" +
	" Test Files  1 failed | 2 passed (3)\n" +
	"      Tests  1 failed | 7 passed (8)\n"

func TestNonRunMatrixVitestSuitesThatNeverLoaded(t *testing.T) {
	n, files, ok := vitestFailedSuites(vitestOutSuitesFailed)
	if !ok || n != 21 || strings.Join(files, ",") != "packages/a/src/index.test.ts,packages/b/src/index.test.ts" {
		t.Fatalf("vitestFailedSuites = %d %v %v; want vitest's own count, every entry past its rule, sorted and deduped", n, files, ok)
	}
	leg := vitestSuiteNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), "vitest", vitestOutSuitesFailed, true)
	assertLegNeverPasses(t, "files that never loaded", leg,
		"vitest: did not run on the whole suite (exit 1): 21 of 39 test file(s) reported a suite-level error")
	for _, want := range []string{
		"packages/a/src/index.test.ts, packages/b/src/index.test.ts",
		"The rest ran 129 test(s), 0 failed; that is a partial result",
		"lifecycle scripts off", "--test-cmd",
	} {
		if !strings.Contains(leg.err, want) {
			t.Errorf("reason lacks %q: %q", want, leg.err)
		}
	}
	// One line of the files' errors would be a claim: none is quoted.
	if strings.Contains(leg.err, "Failed to resolve") {
		t.Errorf("reason quotes a log line: %q", leg.err)
	}

	// Beside a real failing test it is still a partial run, and only the
	// suite-level file is named.
	// vitest prints Failed Suites, then Failed Tests, then one summary.
	mixed := vitestOutSuitesFailed[:strings.Index(vitestOutSuitesFailed, "\x1b[2m Test Files")] + vitestOutTestFailed
	leg = vitestSuiteNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), "vitest", mixed, true)
	assertLegNeverPasses(t, "suite error beside a failing test", leg, "did not run on the whole suite")
	if strings.Contains(leg.err, "src/sum.test.ts") || !strings.Contains(leg.err, "The rest ran 8 test(s), 1 failed") {
		t.Errorf("mixed run misreported: %q", leg.err)
	}

	// The caller ran its own install: cicd's lifecycle remedy is not its to give.
	byo := vitestSuiteNonRun(foldTestLeg("test command", "x: ", nil, "/o", nil, "/e", "1\n"), "test command", vitestOutSuitesFailed, false)
	assertLegNeverPasses(t, "BYO files that never loaded", byo, "test command: did not run on the whole suite (exit 1)")
	if strings.Contains(byo.err, "lifecycle") {
		t.Errorf("BYO reason names cicd's install: %q", byo.err)
	}
}

func TestVitestFailedSuitesAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("⎯⎯⎯ Failed Suites 12 ⎯⎯⎯\n")
	for i := 11; i >= 0; i-- {
		fmt.Fprintf(&b, " FAIL  t%02d.test.ts [ t%02d.test.ts ]\n⎯⎯[%d/12]⎯\n", i, i, 12-i)
	}
	b.WriteString(" Test Files  12 failed (12)\n")
	leg := vitestSuiteNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), "vitest", b.String(), true)
	if !strings.Contains(leg.err, "12 of 12 test file(s)") || !strings.Contains(leg.err, "and 2 more (first 10 by name)") || strings.Contains(leg.err, "t10.test.ts") {
		t.Errorf("cap not applied as stated: %q", leg.err)
	}
	// No Tests line at all: nothing loaded, and no count is claimed.
	if strings.Contains(leg.err, "The rest ran") {
		t.Errorf("a count was claimed with no Tests line: %q", leg.err)
	}
}

func TestVitestSuiteNonRunControls(t *testing.T) {
	// A real failing test stays a failure, the one verdict NONE may suppress.
	fail := vitestSuiteNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "1\n"), "vitest", vitestOutTestFailed, true)
	if !fail.ran || fail.code == nil || fail.err != "vitest failed (exit 1)" {
		t.Errorf("a failing test became %+v", fail)
	}
	pass := vitestSuiteNonRun(foldTestLeg("vitest", "vitest: ", nil, "/o", nil, "/e", "0\n"), "vitest", vitestOutSuitesFailed, true)
	if !pass.ran || !pass.passed {
		t.Errorf("exit 0 became %+v", pass)
	}
	nonRun := foldTestLeg("vitest", "vitest: ", errors.New("boom"), "/o", nil, "/e", "")
	if got := vitestSuiteNonRun(nonRun, "vitest", vitestOutSuitesFailed, true); got.err != nonRun.err {
		t.Errorf("a container error was reworded: %q", got.err)
	}
}

func TestVitestScriptRecordsTheInstallExit(t *testing.T) {
	s := vitestScript(npmDefault)
	if strings.Contains(s, "|| true") {
		t.Error("the install's exit must be recorded, not swallowed")
	}
	rec := strings.Index(s, "echo $? > "+nodeInstallExitPath)
	if rec == -1 || rec > strings.Index(s, "npx --no -- vitest run") {
		t.Errorf("the install exit must be recorded before vitest runs: %s", s)
	}
}

func TestNonRunMatrixEslint(t *testing.T) {
	faults := []struct {
		name, exit, report, wantErr string
	}{
		{"empty sentinel", "", "[]", "unreadable exit status"},
		{"crash exit", "2", "", "did not run (exit 2)"},
		{"exit 0, empty report", "0", "", "wrote an empty report"},
		{"exit 1, truncated report", "1", `[{"filePath":"/src/a.js","messages":[`, "not ESLint JSON"},
		{"exit 0, html report", "0", "<html></html>", "not ESLint JSON"},
		{"exit 0, json object", "0", `{"results":[]}`, "not ESLint JSON"},
		{"exit 0, json null", "0", "null", "not ESLint JSON"},
	}
	// eslintScript's missing-eslint arm, under each install state: every one
	// is a non-run, and each names its own cause.
	for _, m := range []struct{ name, install, want string }{
		{"no eslint, install failed", "1", "npm install exited 1"},
		{"no eslint, install ok", "0", "add eslint to devDependencies"},
		{"no eslint, install unknown", "", "cannot see whether the dependency install succeeded"},
	} {
		sarif, counts, msg := foldEslintRun("127", eslintMissingStderr, "", "", npmDefault.record(m.install))
		if sarif != nil || counts != nil || !strings.Contains(msg, m.want) {
			t.Errorf("%s: got sarif=%v counts=%v err=%q, want no result and %q", m.name, sarif != nil, counts, msg, m.want)
		}
		for _, th := range allThresholds {
			if gatedPassed(msg == "", !shouldFail(counts, th), th) {
				t.Errorf("%s: passed at --fail-on %s", m.name, th)
			}
		}
	}
	for _, f := range faults {
		sarif, counts, msg := foldEslintRun(f.exit, "", f.report, "v9.39.5", npmDefault.record("0"))
		if sarif != nil || counts != nil || !strings.Contains(msg, f.wantErr) {
			t.Errorf("%s: got sarif=%v counts=%v err=%q, want no result and %q", f.name, sarif != nil, counts, msg, f.wantErr)
		}
		ran := msg == ""
		for _, th := range allThresholds {
			if gatedPassed(ran, !shouldFail(counts, th), th) {
				t.Errorf("%s: passed at --fail-on %s", f.name, th)
			}
		}
	}
	sarif, counts, msg := foldEslintRun("0", "", "[]", "v9.39.5", npmDefault.record("0"))
	if sarif == nil || msg != "" || len(counts) != 0 {
		t.Fatalf("clean report: got sarif=%v counts=%v err=%q, want a clean run", sarif != nil, counts, msg)
	}
}

func TestNonRunMatrixPylint(t *testing.T) {
	faults := []struct {
		name, out string
		err       error
		wantErr   string
	}{
		{"exec error with partial stdout", `{"messages":[{"type":"warning"}]}`, errors.New("exit code: 1"), "pylint: exit code: 1"},
		{"exec error, no stdout", "", errors.New("pip: no matching distribution"), "pylint: pip"},
		{"empty stdout", "", nil, "wrote no report"},
		{"truncated report", `{"messages":[{"type":"error","path":"a.py"`, nil, "not pylint JSON"},
		{"json null", "null", nil, "not pylint JSON"},
		{"json1 array", "[]", nil, "not pylint JSON"},
		{"object without messages", `{"statistics":{}}`, nil, "not pylint JSON"},
		// pylint . on a flat tree: one fatal and nothing linted. It used to be
		// one HIGH finding, so the leg failed as if it had found a bug and
		// passed at NONE as if it had run.
		{"fatal parse-error", `{"messages":[{"type":"fatal","symbol":"parse-error","path":"__init__.py","messageId":"F0010"}]}`, nil, "could not read 1 of 3 file(s)"},
		{"text report", "************* Module a\n", nil, "not pylint JSON"},
	}
	for _, f := range faults {
		sarif, counts, examined, errs := foldPylintRun(f.out, f.err, 3)
		if len(errs) != 1 || !strings.Contains(errs[0], f.wantErr) {
			t.Errorf("%s: errors %q, want one containing %q", f.name, errs, f.wantErr)
		}
		if sarif == nil || len(counts) != 0 {
			t.Errorf("%s: want a SARIF document and no counts, got counts=%v", f.name, counts)
		}
		if examined != nil {
			t.Errorf("%s: a leg that did not run reported examined %+v", f.name, *examined)
		}
		for _, th := range allThresholds {
			if gatedPassed(len(errs) == 0, !shouldFail(counts, th), th) {
				t.Errorf("%s: passed at --fail-on %s", f.name, th)
			}
		}
	}
	_, counts, examined, errs := foldPylintRun(`{"messages":[],"statistics":{"modulesLinted":2}}`+"\n", nil, 3)
	if errs != nil || len(counts) != 0 || examined == nil || examined.Count != 3 || examined.Unit != "files" {
		t.Fatalf("clean report: got counts=%v examined=%+v errors=%q, want a clean run over 3 files", counts, examined, errs)
	}
	_, counts, _, errs = foldPylintRun(`{"messages":[{"type":"error","symbol":"syntax-error","path":"sub/a.py","message":"m","line":1,"messageId":"E0001"}]}`, nil, 3)
	if errs != nil || counts[SeverityHigh] != 1 {
		t.Fatalf("one error: got counts=%v errors=%q", counts, errs)
	}
}
