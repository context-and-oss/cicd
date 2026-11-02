//go:build unit_test

package main

import (
	"errors"
	"strings"
	"testing"
)

// The script and the sentinel reader are tested together because the property
// that matters spans them: every run that reports no coverage number must also
// report why. Before this change the else branch dropped --coverage and said
// nothing, so a consumer whose provider install crashed got a green suite, no
// coverage figure, and no indication that anything had degraded — identical
// bytes to a repository that measures no coverage on purpose.

func TestVitestScriptRunsCoverageOnThePreferredBranch(t *testing.T) {
	s := vitestScript(npmDefault)
	if !strings.Contains(s, "npm ls @vitest/coverage-v8") {
		t.Error("the script must prefer the repository's own pinned provider")
	}
	if !strings.Contains(s, "--coverage --coverage.reporter=json-summary") {
		t.Error("the provider-available branch must ask vitest for coverage")
	}
}

func TestVitestScriptWritesTheSentinelOnBothBranches(t *testing.T) {
	s := vitestScript(npmDefault)
	// The load-bearing test. Writing the sentinel only when the provider is
	// missing would leave "installed" and "the script died first"
	// indistinguishable, and a reader treating an absent file as success is the
	// failure this change exists to close.
	if got := strings.Count(s, covStatePath); got != 3 {
		t.Errorf("sentinel path written %d time(s), want 3 (one per branch): %s", got, s)
	}
	if !strings.Contains(s, "echo "+covVitestMissing+" > "+covStatePath) {
		t.Error("the no-vitest branch must record vitest-missing")
	}
	if !strings.Contains(s, "echo "+covProviderOK+" > "+covStatePath) {
		t.Error("the provider-available branch must record provider-ok")
	}
	if !strings.Contains(s, "echo "+covProviderMissing+" > "+covStatePath) {
		t.Error("the fallback branch must record provider-missing")
	}
}

func TestVitestScriptRecordsTheStateBeforeRunningVitest(t *testing.T) {
	// A sentinel written after the suite would be missing for exactly the runs
	// most worth explaining: a container killed mid-suite, or a vitest that
	// never returns.
	s := vitestScript(npmDefault)
	firstSentinel := strings.Index(s, covStatePath)
	firstVitest := strings.Index(s, "npx --no -- vitest run")
	if firstSentinel == -1 || firstVitest == -1 {
		t.Fatalf("script is missing the sentinel or the vitest invocation: %s", s)
	}
	if firstSentinel > firstVitest {
		t.Error("the sentinel must be written before vitest runs, not after")
	}
}

func TestVitestScriptStillFallsBackToAPlainRun(t *testing.T) {
	// Coverage availability must never decide test pass/fail. This is the
	// behaviour the original fallback got right and the change must not lose.
	s := vitestScript(npmDefault)
	if !strings.Contains(s, "else echo "+covProviderMissing) {
		t.Error("a missing provider must take the else branch, not fail the run")
	}
	if !strings.Contains(s, "npx --no -- vitest run > /tmp/vitest.out") {
		t.Error("the fallback must still run the suite without --coverage")
	}
}

func TestVitestScriptCapturesTheSuiteExitNotTheSentinelWrite(t *testing.T) {
	// `echo $?` after `fi` reports whichever vitest ran. An echo of the
	// sentinel placed after the suite would overwrite $? and report the write's
	// exit instead — the tests would then always look like they passed.
	s := vitestScript(npmDefault)
	exitIdx := strings.Index(s, "echo $? > /tmp/vitest.exit")
	if exitIdx == -1 {
		t.Fatalf("script does not capture an exit code: %s", s)
	}
	lastVitest := strings.LastIndex(s, "npx --no -- vitest run")
	if lastVitest == -1 {
		t.Fatalf("script does not run vitest: %s", s)
	}
	if lastVitest > exitIdx {
		t.Error("the exit capture must come after the last vitest invocation")
	}
	if strings.LastIndex(s, covStatePath) > exitIdx {
		t.Error("nothing may be written to the sentinel after $? is captured")
	}
}

func TestAMeasuredRunWarnsAboutNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		err   error
	}{
		{"provider ok", covProviderOK, nil},
		// The number is the stronger evidence. A warning beside a real figure
		// would only teach readers to skip the warnings.
		{"sentinel unreadable", "", errors.New("no such file")},
		{"sentinel garbage", "who knows", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := coverageProviderWarning(tc.state, tc.err, true, true); got != "" {
				t.Errorf("measured run warned: %q", got)
			}
		})
	}
}

func TestAMissingProviderIsNamedWithItsRemedy(t *testing.T) {
	got := coverageProviderWarning(covProviderMissing, nil, false, true)
	if got == "" {
		t.Fatal("a missing provider must be reported, not swallowed")
	}
	for _, want := range []string{"@vitest/coverage-v8", "without --coverage", "Declare the provider"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning omits %q: %s", want, got)
		}
	}
	// Naming the tests as unaffected matters: the warning must not read as a
	// test failure, or it will be triaged as one.
	if !strings.Contains(got, "Test results are unaffected") {
		t.Errorf("warning does not say the suite result stands: %s", got)
	}
}

func TestAProviderThatWorkedAndStillProducedNothingIsADistinctReport(t *testing.T) {
	missing := coverageProviderWarning(covProviderMissing, nil, false, true)
	empty := coverageProviderWarning(covProviderOK, nil, false, true)
	if empty == "" {
		t.Fatal("--coverage passed and no report parsed must still be reported")
	}
	// Two different causes, two different remedies. Collapsing them would send
	// somebody to pin a provider they already have.
	if empty == missing {
		t.Error("an unusable report reads identically to an uninstallable provider")
	}
	if !strings.Contains(empty, "no parseable") {
		t.Errorf("warning does not say the report was unusable: %s", empty)
	}
}

func TestAnUnreadableSentinelDoesNotReadAsAWorkingOne(t *testing.T) {
	got := coverageProviderWarning("", errors.New("no such file"), false, true)
	if got == "" {
		t.Fatal("an unreadable sentinel with no coverage must still be reported")
	}
	if got == coverageProviderWarning(covProviderOK, nil, false, true) {
		t.Error("could-not-determine reads identically to provider-was-fine")
	}
	if !strings.Contains(got, "could not be determined") {
		t.Errorf("warning claims to know more than it does: %s", got)
	}
}

func TestAnUnexpectedSentinelValueIsNotSilent(t *testing.T) {
	got := coverageProviderWarning("provider-maybe", nil, false, true)
	if got == "" {
		t.Fatal("an unrecognised sentinel value must not read as success")
	}
	if !strings.Contains(got, "unexpected value") {
		t.Errorf("warning does not name the cause: %s", got)
	}
}

func TestEveryUnmeasuredRunSaysNotCoverageOfZero(t *testing.T) {
	// The board's floor, asserted directly: cicd must not report a
	// coverage-less run and a coverage-of-zero run identically. Every
	// unmeasured path therefore opens with the same three words, so the
	// distinction survives whichever cause produced it.
	for _, state := range []string{covProviderMissing, covProviderOK, "", "nonsense"} {
		for _, err := range []error{nil, errors.New("boom")} {
			got := coverageProviderWarning(state, err, false, true)
			if got == "" {
				t.Errorf("state=%q err=%v produced no warning", state, err)
				continue
			}
			if !strings.HasPrefix(got, "coverage not measured") {
				t.Errorf("state=%q err=%v does not open with the distinction: %s", state, err, got)
			}
		}
	}
}

func TestTheTwoSentinelWordsAreDistinct(t *testing.T) {
	// The equality half is enforced by the compiler, not by this assertion:
	// giving the two constants the same value makes coverageProviderWarning's
	// switch a duplicate case and the package stops building. Kept anyway so
	// the requirement is stated where a reader looks for it.
	if covProviderOK == covProviderMissing {
		t.Fatal("the two sentinel values must differ or the reader cannot branch")
	}
	// The blank half is not compiler-checked, and it is the one that matters:
	// an empty sentinel is what an unreadable or truncated file looks like, so
	// a blank constant would move that case out of "unknown" and into a
	// confident claim.
	if strings.TrimSpace(covProviderOK) == "" || strings.TrimSpace(covProviderMissing) == "" {
		t.Fatal("a sentinel value must not be blank")
	}
}

func TestVitestScriptNeverFetchesVitest(t *testing.T) {
	// `npx vitest` with vitest absent downloads the newest one and tests the
	// tree with it. Every invocation must refuse the fetch.
	s := vitestScript(npmDefault)
	if got, refused := strings.Count(s, "npx "), strings.Count(s, "npx --no -- vitest run"); got != refused || got != 2 {
		t.Errorf("%d npx invocation(s), %d refusing the fetch, want 2 and 2: %s", got, refused, s)
	}
}

func TestVitestScriptReadsTheVersionBeforeTheProviderInstall(t *testing.T) {
	// The provider peer-requires vitest, so an install placed first could
	// bring a vitest in and make a project without one look like it has one.
	s := vitestScript(npmDefault)
	read := strings.Index(s, "> "+vitestVersionPath)
	provider := strings.Index(s, "npm install --no-save")
	if read == -1 || provider == -1 || read > provider {
		t.Fatalf("the vitest version must be recorded before the provider install: %s", s)
	}
	if !strings.Contains(s, `"@vitest/coverage-v8@$(cat `+vitestVersionPath+`)"`) {
		t.Errorf("the provider must be pinned to the project's vitest: %s", s)
	}
	if strings.Contains(s, "--no-save @vitest/coverage-v8 ") {
		t.Errorf("an unversioned provider install survived: %s", s)
	}
}

func TestVitestScriptRunsNothingWithoutVitest(t *testing.T) {
	// The no-vitest branch must end non-zero, so a reader that could not read
	// the version sentinel still cannot see a pass.
	s := vitestScript(npmDefault)
	missing := strings.Index(s, "echo "+covVitestMissing)
	elif := strings.Index(s, "elif ")
	if missing == -1 || elif == -1 || missing > elif {
		t.Fatalf("the no-vitest branch must come first: %s", s)
	}
	if branch := s[missing:elif]; strings.Contains(branch, "vitest run") || !strings.HasSuffix(strings.TrimSpace(branch), "false;") {
		t.Errorf("the no-vitest branch must run nothing and end non-zero: %q", branch)
	}
}

func TestAMissingVitestHasACoverageReason(t *testing.T) {
	w := coverageProviderWarning(covVitestMissing, nil, false, true)
	if !strings.Contains(w, "vitest is not installed") {
		t.Errorf("got %q, want the missing vitest named", w)
	}
}

// vitest writes no coverage report for a run that did not pass, so with the
// provider in place the failed suite is the reason, and the warning must not
// send the reader after the provider (measured on changesets).
func TestCoverageWarningNamesAFailedSuite(t *testing.T) {
	got := coverageProviderWarning(covProviderOK, nil, false, false)
	if !strings.Contains(got, "suite did not pass") || !strings.Contains(got, "reportOnFailure") {
		t.Errorf("failed suite not named: %q", got)
	}
	if strings.Contains(got, "no parseable coverage-summary.json") {
		t.Errorf("failed suite blamed on the report: %q", got)
	}
	if passed := coverageProviderWarning(covProviderOK, nil, false, true); !strings.Contains(passed, "no parseable coverage-summary.json") {
		t.Errorf("a passing suite lost its reason: %q", passed)
	}
	// The other states do not depend on the suite: their cause is upstream.
	if a, b := coverageProviderWarning(covProviderMissing, nil, false, false), coverageProviderWarning(covProviderMissing, nil, false, true); a != b {
		t.Errorf("provider-missing changed with the suite: %q vs %q", a, b)
	}
	if got := coverageProviderWarning(covProviderOK, nil, true, false); got != "" {
		t.Errorf("a measured run warned: %q", got)
	}
}
