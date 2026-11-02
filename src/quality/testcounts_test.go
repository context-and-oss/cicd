package main

import "testing"

// Real `go test -v` output, copied from a run of this repo's own evidence
// module rather than invented, because the whole parser is a claim about that
// format and a hand-made fixture would only test my memory of it.
const goTestVerboseReal = `=== RUN   TestTruffleHogArgs
=== RUN   TestTruffleHogArgs/verifySecrets_on_adds_--only-verified
=== RUN   TestTruffleHogArgs/verifySecrets_off_(default)_omits_--only-verified
--- PASS: TestTruffleHogArgs (0.00s)
    --- PASS: TestTruffleHogArgs/verifySecrets_on_adds_--only-verified (0.00s)
    --- PASS: TestTruffleHogArgs/verifySecrets_off_(default)_omits_--only-verified (0.00s)
=== RUN   TestBrokenThing
--- FAIL: TestBrokenThing (0.01s)
    main_test.go:42: boom
=== RUN   TestNotToday
--- SKIP: TestNotToday (0.00s)
    main_test.go:50: needs docker
FAIL
exit status 1
FAIL	dagger/security	0.263s
ok  	dagger/evidence	0.161s
`

func TestParseGoTestCountsCountsEveryDepth(t *testing.T) {
	got, ok := parseGoTestCounts(goTestVerboseReal)
	if !ok {
		t.Fatal("ok = false, want true — this is real go test -v output")
	}
	// 5 RUN lines: TrufflehogArgs + its 2 subtests, BrokenThing, NotToday.
	if got.Total != 5 {
		t.Fatalf("Total = %d, want 5 — subtests count at every depth, matching scripts/test-module-units.sh", got.Total)
	}
	if got.Passed != 3 {
		t.Fatalf("Passed = %d, want 3 (one top-level + two indented subtests)", got.Passed)
	}
	if got.Failed != 1 {
		t.Fatalf("Failed = %d, want 1", got.Failed)
	}
	if got.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", got.Skipped)
	}
	// 0.263 + 0.161 = 0.424s of test time across two packages.
	if got.DurationMS != 424 {
		t.Fatalf("DurationMS = %d, want 424 — the sum of the per-package elapsed times", got.DurationMS)
	}
}

func TestParseGoTestCountsRejectsOutputItDoesNotRecognise(t *testing.T) {
	// The failure that matters: an unrecognised payload counts to zero, and
	// zero is exactly what a clean run of an empty suite looks like. Without
	// the ok flag a consumer cannot tell "no tests failed" from "cicd could not
	// read the results", and the first reads as a pass.
	for name, in := range map[string]string{
		"empty":             "",
		"whitespace":        "   \n\t\n",
		"a build failure":   "# dagger/evidence\n./main.go:12:2: undefined: foo\n",
		"an unrelated tool": "Semgrep found 0 findings in 12 files\n",
	} {
		if got, ok := parseGoTestCounts(in); ok {
			t.Fatalf("%s: ok = true with %+v, want false — an unreadable payload must not report zero failures", name, got)
		}
	}
}

func TestParseGoTestCountsAcceptsALegitimateZero(t *testing.T) {
	// A package with no test files is a real, countable answer of zero. It must
	// be distinguishable from the unreadable payloads above, or the withholding
	// rule collapses into "never report anything".
	got, ok := parseGoTestCounts("?   \tdagger/composites/precommit\t[no test files]\n")
	if !ok {
		t.Fatal("ok = false, want true — 'no test files' is a measurement, not a failure to measure")
	}
	if got.Total != 0 {
		t.Fatalf("Total = %d, want 0", got.Total)
	}
}

func TestParseGoTestCountsSurfacesTestsWithNoVerdict(t *testing.T) {
	// A panic kills the run mid-test: the RUN line is printed and no verdict
	// ever is. Reporting Total as Passed+Failed+Skipped would silently discard
	// the test whose outcome nobody knows, so the two must be allowed to
	// disagree and the gap must survive to the envelope.
	const panicked = `=== RUN   TestOne
--- PASS: TestOne (0.00s)
=== RUN   TestTwo
panic: runtime error: index out of range [3] with length 0
FAIL	dagger/evidence	0.104s
`
	got, ok := parseGoTestCounts(panicked)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got.Total != 2 {
		t.Fatalf("Total = %d, want 2 — both tests started", got.Total)
	}
	if got.Passed+got.Failed+got.Skipped != 1 {
		t.Fatalf("breakdown sums to %d, want 1 — only one test reached a verdict, and the gap is the finding", got.Passed+got.Failed+got.Skipped)
	}
}

func TestParseGoTestCountsStillCountsACachedPackage(t *testing.T) {
	// A cache hit is a verdict: the tests ran, their results are known, and the
	// only thing missing is a duration. Refusing the whole payload would lose a
	// count that is perfectly good.
	got, ok := parseGoTestCounts("=== RUN   TestFoo\n--- PASS: TestFoo (0.00s)\nok  \tdagger/evidence\t(cached)\n")
	if !ok {
		t.Fatal("ok = false, want true — a cached package verdict is still a verdict")
	}
	if got.Total != 1 || got.Passed != 1 {
		t.Fatalf("counts = %+v, want Total 1 / Passed 1 — caching does not lose results", got)
	}
}

func TestParseGoTestCountsWithholdsTheDurationOfAPartlyCachedRun(t *testing.T) {
	// When only some packages miss the cache, summing their elapsed times
	// presents a partial duration as the whole suite's figure. A partial
	// measurement is not a small measurement, so it is withheld.
	out := "ok  \tdagger/one\t(cached)\n" +
		"ok  \tdagger/two\t1.234s\n"
	got, ok := parseGoTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got.DurationMS != 0 {
		t.Fatalf("DurationMS = %d, want 0 — one package ran, the rest were cached, so 1234ms is not this suite's duration", got.DurationMS)
	}
}

func TestParseGoTestCountsTimesAFullyUncachedRun(t *testing.T) {
	// The converse, so withholding cannot be satisfied by never reporting a
	// duration at all.
	out := "ok  \tdagger/one\t0.500s\n" +
		"ok  \tdagger/two\t1.250s\n"
	got, ok := parseGoTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got.DurationMS != 1750 {
		t.Fatalf("DurationMS = %d, want 1750 — every package ran, so the sum is honest", got.DurationMS)
	}
}

func TestTrxTestCountsDerivesPassedAndSkipped(t *testing.T) {
	// 431 known, 428 executed, 2 of those failed. TRX states total/executed/
	// failed; passed and skipped are the gaps.
	got, ok := trxTestCounts(trxSummary{Total: 431, Executed: 428, Failed: 2}, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := TestCounts{Total: 431, Passed: 426, Failed: 2, Skipped: 3}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestTrxTestCountsWithholdsWhenNoDocumentWasReadable(t *testing.T) {
	// The counters are zero either because nothing ran or because nothing could
	// be read, and those must not collapse into the same answer — a run of zero
	// tests reads as a pass. parseTrxAll returns the document count precisely so
	// this call can tell them apart.
	if got, ok := trxTestCounts(trxSummary{}, 0); ok {
		t.Fatalf("ok = true with %+v, want false — zero readable documents is not a run of zero tests", got)
	}
}

func TestTrxTestCountsWithholdsAnIncoherentDocument(t *testing.T) {
	for name, sum := range map[string]trxSummary{
		"more failures than executions": {Total: 10, Executed: 2, Failed: 5},
		"more executions than tests":    {Total: 3, Executed: 9, Failed: 0},
	} {
		if got, ok := trxTestCounts(sum, 1); ok {
			t.Fatalf("%s: ok = true with %+v, want false — clamping a corrupt report to zero would make it look plausible", name, got)
		}
	}
}

func TestParseVitestTestCountsReadsStyledSyntheticSummary(t *testing.T) {
	// Invented counts in Vitest's redirected-output shape retain ANSI styling
	// and a three-digit test total, as quality.Test must accept.
	const out = "\x1b[2m Test Files \x1b[22m \x1b[1m\x1b[32m73 passed\x1b[39m\x1b[22m\x1b[90m (73)\x1b[39m\n" +
		"\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m684 passed\x1b[39m\x1b[22m\x1b[90m (684)\x1b[39m\n"
	got, ok := parseVitestTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true for Vitest's styled summary")
	}
	want := TestCounts{Total: 684, Passed: 684}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseVitestTestCountsDerivesEveryNonSuccessAsSkipped(t *testing.T) {
	const out = ` Test Files  1 failed | 2 passed (3)
      Tests  2 failed | 8 passed | 3 skipped | 1 todo (14)
`
	got, ok := parseVitestTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := TestCounts{Total: 14, Passed: 8, Failed: 2, Skipped: 4}
	if got != want {
		t.Fatalf("counts = %+v, want %+v — todo is a known test that did not execute", got, want)
	}
}

func TestParseVitestTestCountsSumsSeveralInvocations(t *testing.T) {
	got, ok := parseVitestTestCounts("      Tests  684 passed (684)\n=== worker-ui ===\n      Tests  2 failed | 55 passed (57)\n")
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := TestCounts{Total: 741, Passed: 739, Failed: 2}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseVitestTestCountsRejectsUnrecognisedOrIncoherentOutput(t *testing.T) {
	for name, out := range map[string]string{
		"npm message":  "added 684 packages, and audited 685 packages\n",
		"file summary": "Test Files  73 passed (73)\n",
		"incoherent":   "Tests  5 failed | 6 passed (10)\n",
	} {
		if got, ok := parseVitestTestCounts(out); ok {
			t.Fatalf("%s: ok = true with %+v, want false", name, got)
		}
	}
}

func TestParseDotnetConsoleTestCountsReadsMTPSyntheticSummary(t *testing.T) {
	// Invented counts and durations exercise a four-digit total and interleaved
	// DLL rows: the counters need not immediately follow the heading.
	const out = `Test run summary: Passed!
  /src/tests/Alpha.Tests.dll (net10.0|x64) passed (4s 210ms)
  /src/tests/Beta.Tests.dll (net10.0|x64) passed (6s 570ms)

  total: 2486
  failed: 0
  succeeded: 2486
  skipped: 0
  duration: 2m 17s 420ms
`
	got, ok := parseDotnetConsoleTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true for Microsoft.Testing.Platform's summary")
	}
	want := TestCounts{Total: 2486, Passed: 2486}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseDotnetConsoleTestCountsReadsVSTestSummary(t *testing.T) {
	const out = "Failed! - Failed: 2, Passed: 426, Skipped: 3, Total: 431, Duration: 8 s\n"
	got, ok := parseDotnetConsoleTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := TestCounts{Total: 431, Passed: 426, Failed: 2, Skipped: 3}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseDotnetConsoleTestCountsRejectsPartialSummary(t *testing.T) {
	const out = `Test run summary: Passed!
  total: 10
  succeeded: 10
`
	if got, ok := parseDotnetConsoleTestCounts(out); ok {
		t.Fatalf("ok = true with %+v, want false — a partial summary is not accounting", got)
	}
}

func TestParsePytestTestCountsMapsTerminalVerdicts(t *testing.T) {
	const out = `================ short test summary info ================
FAILED test_api.py::test_bad - AssertionError
===== 2 failed, 8 passed, 3 skipped, 1 xfailed, 1 xpassed, 1 error, 4 deselected, 2 warnings in 1.23s =====
`
	got, ok := parsePytestTestCounts(out)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := TestCounts{Total: 20, Passed: 9, Failed: 3, Skipped: 8}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParsePytestTestCountsAcceptsLegitimateZero(t *testing.T) {
	got, ok := parsePytestTestCounts("================ no tests ran in 0.01s ================\n")
	if !ok || got != (TestCounts{}) {
		t.Fatalf("counts = %+v, ok = %v; want zero counts and true", got, ok)
	}
}

func TestParsePytestTestCountsRejectsUnrelatedOutput(t *testing.T) {
	if got, ok := parsePytestTestCounts("2 packages passed audit in 1.2s\n"); ok {
		t.Fatalf("ok = true with %+v, want false", got)
	}
}

func TestMergeLegTestCountsRequiresEveryLegInALanguage(t *testing.T) {
	webUI := &TestCounts{Total: 684, Passed: 684}
	workerUI := &TestCounts{Total: 57, Passed: 55, Skipped: 2}
	dotnet := &TestCounts{Total: 2486, Passed: 2486}
	got := mergeLegTestCounts(map[string][]*TestCounts{
		"node":   {webUI, workerUI},
		"dotnet": {dotnet},
		"python": {nil},
	})
	if want := (TestCounts{Total: 741, Passed: 739, Skipped: 2}); got["node"] != want {
		t.Fatalf("node counts = %+v, want %+v", got["node"], want)
	}
	if got["dotnet"] != *dotnet {
		t.Fatalf("dotnet counts = %+v, want %+v", got["dotnet"], *dotnet)
	}
	if _, ok := got["python"]; ok {
		t.Fatalf("python counts = %+v, want absent because its leg was unreadable", got["python"])
	}
}

func TestMergeLegTestCountsWithholdsPartialSameLanguageTotal(t *testing.T) {
	known := &TestCounts{Total: 684, Passed: 684}
	got := mergeLegTestCounts(map[string][]*TestCounts{"node": {known, nil}})
	if _, ok := got["node"]; ok {
		t.Fatalf("node counts = %+v, want absent — 684 plus an unknown number is not 684 total", got["node"])
	}
}
