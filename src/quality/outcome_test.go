package main

import "testing"

// Synthetic accounting separates a green suite from a non-zero runner exit.
// Under NONE, the gate stays open over a result, but Outcome must describe
// the contradiction without substring-matching errors[]. See
// specs/none-suppresses-findings-not-nonruns.md.
//
// All 72 invented tests passed. Calling the suite FAILED because the runner
// exited 1 would contradict its accounting; ERROR preserves that distinction.
func TestTheGateStaysPutAndTheOutcomeTellsTheTruth(t *testing.T) {
	ran, subjectPassed := true, false
	counts := &TestCounts{Total: 72, Passed: 72, Failed: 0}

	if !gatedPassed(ran, subjectPassed, SeverityNone) {
		t.Fatal("the gate contract changed: NONE must still report passed=true")
	}
	if got := testOutcome(ran, subjectPassed, counts); got != OutcomeError {
		t.Fatalf("outcome = %q, want %q — 72 of 72 tests passed, so no test failed", got, OutcomeError)
	}
}

// testOutcome's whole reason to exist: the runner's accounting beats its exit
// status, but only where there is accounting to read.
func TestTheRunnersOwnCountsOverruleItsExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ran           bool
		subjectPassed bool
		counts        *TestCounts
		want          Outcome
	}{
		{"green suite", true, true, &TestCounts{Total: 72, Passed: 72}, OutcomeClean},
		{"green suite, no accounting", true, true, nil, OutcomeClean},
		{"a test genuinely failed", true, false, &TestCounts{Total: 72, Passed: 71, Failed: 1}, OutcomeFailed},
		{"synthetic contradiction: exit 1, nothing failed", true, false, &TestCounts{Total: 72, Passed: 72}, OutcomeError},
		{"no accounting: trust the exit status", true, false, nil, OutcomeFailed},
		{"nothing ran", false, false, nil, OutcomeError},
		{"nothing ran, counts from a partial sweep", false, false, &TestCounts{Total: 3, Failed: 2}, OutcomeError},
	} {
		if got := testOutcome(tc.ran, tc.subjectPassed, tc.counts); got != tc.want {
			t.Errorf("%s: testOutcome = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// An empty-but-present accounting is a real claim: the runner looked and
// counted nothing failing. It must not be read as "no accounting", which would
// flip the verdict from ERROR to FAILED.
func TestAZeroedAccountingIsStillAnAccounting(t *testing.T) {
	if got := testOutcome(true, false, &TestCounts{}); got != OutcomeError {
		t.Fatalf("testOutcome with a zeroed TestCounts = %q, want ERROR — a present count of zero failures contradicts the exit status", got)
	}
	if got := testOutcome(true, false, nil); got != OutcomeFailed {
		t.Fatalf("testOutcome with no TestCounts = %q, want FAILED — with nothing to overrule, the exit status stands", got)
	}
}

// SKIPPED's placement in the rank is the design, so it is pinned rather than
// left to the map literal. Above CLEAN: a run where any check was skipped must
// not report a clean headline. Below FINDINGS: incomplete coverage never buries
// a real finding.
func TestSkippedDegradesACleanRunButNeverHidesAFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []Outcome
		want Outcome
	}{
		{"a skipped check degrades a clean run", []Outcome{OutcomeClean, OutcomeSkipped}, OutcomeSkipped},
		{"order does not matter", []Outcome{OutcomeSkipped, OutcomeClean}, OutcomeSkipped},
		{"findings still win the headline", []Outcome{OutcomeSkipped, OutcomeFindings}, OutcomeFindings},
		{"so does a failure", []Outcome{OutcomeSkipped, OutcomeFailed}, OutcomeFailed},
		{"so does an error", []Outcome{OutcomeSkipped, OutcomeError}, OutcomeError},
		{"everything skipped", []Outcome{OutcomeSkipped, OutcomeSkipped}, OutcomeSkipped},
		{"three skipped checks beside a clean check", []Outcome{OutcomeSkipped, OutcomeSkipped, OutcomeSkipped, OutcomeClean}, OutcomeSkipped},
	} {
		if got := worstOutcome(tc.in); got != tc.want {
			t.Errorf("%s: worstOutcome(%v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// scanOutcome and runOutcome differ in exactly one place, and it is the place
// that matters. A linter's verdict IS its findings count, so scanOutcome has no
// FAILED to report; a test runner's is not, so runOutcome must.
func TestScanOutcomeAndRunOutcomeDisagreeOnlyAboutFailure(t *testing.T) {
	if got := scanOutcome(true, 0); got != OutcomeClean {
		t.Errorf("scanOutcome(ran, 0) = %q, want CLEAN", got)
	}
	if got := scanOutcome(true, 1); got != OutcomeFindings {
		t.Errorf("scanOutcome(ran, 1) = %q, want FINDINGS", got)
	}
	if got := scanOutcome(false, 0); got != OutcomeError {
		t.Errorf("scanOutcome(!ran, 0) = %q, want ERROR — a tool that could not run has not seen a clean tree", got)
	}
	if got := scanOutcome(false, 7); got != OutcomeError {
		t.Errorf("scanOutcome(!ran, 7) = %q, want ERROR — a partial count from a broken run is not FINDINGS", got)
	}

	if got := runOutcome(true, true); got != OutcomeClean {
		t.Errorf("runOutcome(ran, passed) = %q, want CLEAN", got)
	}
	if got := runOutcome(true, false); got != OutcomeFailed {
		t.Errorf("runOutcome(ran, !passed) = %q, want FAILED", got)
	}
	if got := runOutcome(false, true); got != OutcomeError {
		t.Errorf("runOutcome(!ran, passed) = %q, want ERROR — subjectPassed is meaningless when nothing ran", got)
	}
	if got := runOutcome(false, false); got != OutcomeError {
		t.Errorf("runOutcome(!ran, !passed) = %q, want ERROR", got)
	}
}

func TestWorstOutcomeReportsTheMostAlarmingLeg(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []Outcome
		want Outcome
	}{
		{"one clean leg", []Outcome{OutcomeClean}, OutcomeClean},
		{"skipped beats clean", []Outcome{OutcomeClean, OutcomeSkipped}, OutcomeSkipped},
		{"findings beat clean", []Outcome{OutcomeClean, OutcomeFindings}, OutcomeFindings},
		{"findings beat skipped", []Outcome{OutcomeSkipped, OutcomeFindings}, OutcomeFindings},
		{"failed beats findings", []Outcome{OutcomeFindings, OutcomeFailed}, OutcomeFailed},
		{"error beats failed", []Outcome{OutcomeFailed, OutcomeError}, OutcomeError},
		{"order does not matter", []Outcome{OutcomeError, OutcomeClean}, OutcomeError},
		{"all clean stays clean", []Outcome{OutcomeClean, OutcomeClean, OutcomeClean}, OutcomeClean},
	} {
		if got := worstOutcome(tc.in); got != tc.want {
			t.Errorf("%s: worstOutcome(%v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// An envelope that folds a leg with no outcome must report no outcome, not
// CLEAN. Folding unset in as if it were clean would manufacture the exact claim
// this field exists to stop being manufactured.
func TestOneSilentLegCollapsesTheWholeFold(t *testing.T) {
	for _, in := range [][]Outcome{
		{"", OutcomeClean},
		{OutcomeClean, ""},
		{OutcomeClean, "", OutcomeError},
		{OutcomeError, ""},
		{"UNRECOGNISED"},
	} {
		if got := worstOutcome(in); got != "" {
			t.Errorf("worstOutcome(%v) = %q, want unset", in, got)
		}
	}
}

// The bug this test exists for: worstOutcome originally folded pairwise, and a
// "" accumulator cannot distinguish "nothing folded yet" from "a leg declined to
// answer". Folding [CLEAN, "", CLEAN] therefore collapsed to "" and then revived
// to CLEAN on the next valid input, silently losing the decline. Reading the
// whole set at once is what fixes it, so the case is pinned here — a refactor
// back to an accumulator turns this red.
func TestASilentLegIsNotRevivedByALaterCleanOne(t *testing.T) {
	if got := worstOutcome([]Outcome{OutcomeClean, "", OutcomeClean}); got != "" {
		t.Fatalf("worstOutcome = %q, want unset: a decline in the middle must survive the legs after it", got)
	}
}

// A run with no legs has not observed a clean tree. It has observed nothing.
// quality.Check documents the same case for passed: a language set that
// resolves to zero entries produces passed=true over a repository where nothing
// was linted and no test ran. Outcome is what distinguishes the two.
func TestFoldingNothingIsNotClean(t *testing.T) {
	if got := worstOutcome(nil); got != "" {
		t.Fatalf("worstOutcome(nil) = %q, want unset", got)
	}
	if got := worstOutcome([]Outcome{}); got != "" {
		t.Fatalf("worstOutcome(empty) = %q, want unset", got)
	}
}

// TestAnErrorAfterTheExitCodeIsStillAnError pins the inverted form of the bug
// this whole file exists for.
//
// A BYO leg's exit status is settled when its command returns; the coverage
// harvest runs afterwards and has its own failures. Those land in the leg's
// errors with ran and passed already true, and the caller folds them into
// allErrs, which fails the envelope. runOutcome alone cannot see them, so the
// leg reported CLEAN inside an envelope its own errors had just failed — the
// gate blocking while the outcome says nothing happened.
func TestAnErrorAfterTheExitCodeIsStillAnError(t *testing.T) {
	cases := []struct {
		name   string
		ran    bool
		passed bool
		errs   []string
		want   Outcome
	}{
		{
			name: "clean leg, nothing to say",
			ran:  true, passed: true,
			want: OutcomeClean,
		},
		{
			name: "the regression: green command, unreadable coverage report",
			ran:  true, passed: true,
			errs: []string{"coverage glob /src/**/*.cobertura.xml: parse: unexpected EOF"},
			want: OutcomeError,
		},
		{
			name: "an empty error slice is not an error",
			ran:  true, passed: true,
			errs: []string{},
			want: OutcomeClean,
		},
		{
			name: "never ran: ERROR, as it always was",
			ran:  false, passed: false,
			errs: []string{"run test command in mcr.microsoft.com/dotnet/sdk:10.0: exec failed"},
			want: OutcomeError,
		},
		{
			name: "ran and failed: the command is the result",
			ran:  true, passed: false,
			errs: []string{"test command failed (exit 1)"},
			want: OutcomeFailed,
		},
		{
			name: "ran and failed with a harvest error stacked on: still FAILED",
			ran:  true, passed: false,
			errs: []string{"test command failed (exit 1)", "coverage glob: parse error"},
			want: OutcomeFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := byoLegOutcome(tc.ran, tc.passed, tc.errs); got != tc.want {
				t.Fatalf("byoLegOutcome(ran=%v, passed=%v, errs=%v) = %q, want %q",
					tc.ran, tc.passed, tc.errs, got, tc.want)
			}
		})
	}
}

func TestByoTestLegOutcomeUsesRunnerAccounting(t *testing.T) {
	green := &TestCounts{Total: 12, Passed: 12}
	red := &TestCounts{Total: 12, Passed: 11, Failed: 1}
	for _, tc := range []struct {
		name   string
		passed bool
		counts *TestCounts
		want   Outcome
	}{
		{"green", true, green, OutcomeClean},
		{"failed test", false, red, OutcomeFailed},
		{"runner contradicted green counts", false, green, OutcomeError},
		{"unparsed command keeps exit verdict", false, nil, OutcomeFailed},
	} {
		if got := byoTestLegOutcome(true, tc.passed, nil, tc.counts); got != tc.want {
			t.Fatalf("%s: outcome = %q, want %q", tc.name, got, tc.want)
		}
	}
}
