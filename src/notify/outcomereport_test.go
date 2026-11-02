package main

import (
	"strings"
	"testing"
)

func f64(v float64) *float64 { return &v }
func intp(v int) *int        { return &v }

// TestTheHeadlineSaysWhatHappenedWhenTheGateSaysNothing is the bug this file
// was written for: a run whose dotnet suite exited 1 published "✅ Passed" with
// "dotnet test failed (exit 1)" three lines below it, because fail-on: NONE
// makes Passed true by design and nothing else reached the headline.
func TestTheHeadlineSaysWhatHappenedWhenTheGateSaysNothing(t *testing.T) {
	got := headline(&envelope{Passed: true, Outcome: OutcomeError})
	if !strings.Contains(got, "Passed") {
		t.Errorf("the gate verdict must survive: %q", got)
	}
	if !strings.Contains(got, "errored") {
		t.Errorf("an errored run must not headline as a plain pass: %q", got)
	}
}

func TestACleanPassIsNotSaidTwice(t *testing.T) {
	got := headline(&envelope{Passed: true, Outcome: OutcomeClean})
	if got != "✅ Passed" {
		t.Errorf("clean pass should read exactly as before, got %q", got)
	}
}

// TestAnUnconvertedProducerGetsNoOutcomeInTheHeadline: "not stated" in a
// headline reads as an alarm about the run rather than a gap in reporting.
func TestAnUnconvertedProducerGetsNoOutcomeInTheHeadline(t *testing.T) {
	if got := headline(&envelope{Passed: true}); got != "✅ Passed" {
		t.Errorf("empty outcome must not reach the headline, got %q", got)
	}
	if got := headline(&envelope{Passed: false}); got != "❌ Failed" {
		t.Errorf("empty outcome must not reach the headline, got %q", got)
	}
}

// TestAFailingGateStillNamesItsOutcome — "Failed · errored" and "Failed ·
// failed" send a reader to different places.
func TestAFailingGateStillNamesItsOutcome(t *testing.T) {
	errored := headline(&envelope{Passed: false, Outcome: OutcomeError})
	failed := headline(&envelope{Passed: false, Outcome: OutcomeFailed})
	if errored == failed {
		t.Fatalf("a crashed tool and a failed subject must not render alike: %q", errored)
	}
	for _, got := range []string{errored, failed} {
		if !strings.Contains(got, "Failed") {
			t.Errorf("gate verdict lost: %q", got)
		}
	}
}

func TestAnAbsentOutcomeIsWordsNotADash(t *testing.T) {
	got := outcomeLabel("")
	if got != notStated {
		t.Errorf("absent outcome must say so, got %q", got)
	}
	if strings.Contains(got, "—") || got == "" {
		t.Errorf("absent outcome must not render as a dash or a blank, got %q", got)
	}
}

// TestAnUnknownOutcomeIsPrintedNotFlattened keeps a future vocabulary addition
// visible instead of silently reporting it as unstated.
func TestAnUnknownOutcomeIsPrintedNotFlattened(t *testing.T) {
	if got := outcomeLabel(Outcome("QUARANTINED")); got != "QUARANTINED" {
		t.Errorf("unknown outcome should print verbatim, got %q", got)
	}
}

// TestOneScannerOverTwoScopesIsDistinguishable — the "gitleaks, gitleaks" case
// SourceStatus.Scope exists for.
func TestOneScannerOverTwoScopesIsDistinguishable(t *testing.T) {
	src := sourceLabel(SourceStatus{ModuleName: "security", Tool: "gitleaks", Scope: "security-source"})
	arc := sourceLabel(SourceStatus{ModuleName: "security", Tool: "gitleaks", Scope: "security-archive"})
	if src == arc {
		t.Fatalf("two scopes rendered identically: %q", src)
	}
	if !strings.Contains(src, "security-source") {
		t.Errorf("scope dropped: %q", src)
	}
}

func TestASourceLabelDoesNotRepeatItself(t *testing.T) {
	if got := sourceLabel(SourceStatus{ModuleName: "quality", Tool: "quality"}); got != "quality" {
		t.Errorf("module and tool are the same word; got %q", got)
	}
	if got := sourceLabel(SourceStatus{ModuleName: "security", Tool: "semgrep"}); got != "security / semgrep" {
		t.Errorf("got %q", got)
	}
	if got := sourceLabel(SourceStatus{ModuleName: "risk"}); got != "risk" {
		t.Errorf("a row with no tool should fall back to the module, got %q", got)
	}
}

// TestExaminedShowsItsDenominatorWhenTheToolKnowsIt uses synthetic counts:
// a few hundred licence declarations beside thousands of components.
func TestExaminedShowsItsDenominatorWhenTheToolKnowsIt(t *testing.T) {
	got := examinedCell(&Examined{Unit: "licence declarations", Count: 480, Total: 6400})
	if !strings.Contains(got, "480") || !strings.Contains(got, "6,400") {
		t.Errorf("both figures must appear, got %q", got)
	}
	if !strings.Contains(got, "licence declarations") {
		t.Errorf("unit dropped, got %q", got)
	}
}

// TestAnAbsentExaminedIsNotZero — "0 findings over an unknown denominator" and
// "0 findings over 3,000 components" are different claims.
func TestAnAbsentExaminedIsNotZero(t *testing.T) {
	got := examinedCell(nil)
	if got != notStated {
		t.Errorf("absent examined must say so, got %q", got)
	}
	if strings.Contains(got, "0") {
		t.Errorf("absent must never render as a count, got %q", got)
	}
}

// TestExaminedZeroIsARealClaim — the tool looked, and there was nothing in scope.
func TestExaminedZeroIsARealClaim(t *testing.T) {
	got := examinedCell(&Examined{Unit: "components", Count: 0})
	if got == notStated {
		t.Fatalf("a present zero is a statement, not a silence: %q", got)
	}
	if !strings.Contains(got, "0 components") {
		t.Errorf("got %q", got)
	}
}

func TestAnExaminedWithNoUnitSaysTheUnitIsMissing(t *testing.T) {
	got := examinedCell(&Examined{Count: 7})
	if !strings.Contains(got, "7") || !strings.Contains(got, "unit not stated") {
		t.Errorf("a unitless count must flag itself, got %q", got)
	}
}

func TestALargeCountIsGrouped(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000",
		34567: "34,567", 123456: "123,456", 1234567: "1,234,567", -4321: "-4,321"}
	for in, want := range cases {
		if got := humanCount(in); got != want {
			t.Errorf("humanCount(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestTheSourceTableRendersEveryToolInEnvelopeOrder — the aggregator's order is
// the one it published; this renderer must not invent a ranking.
func TestTheSourceTableRendersEveryToolInEnvelopeOrder(t *testing.T) {
	var sb strings.Builder
	writeSourceTable(&sb, []SourceStatus{
		{ModuleName: "quality", Tool: "quality", Outcome: OutcomeError, FindingsCount: 123456, ErrorsCount: 1, WarningsCount: 7},
		{ModuleName: "security", Tool: "semgrep", Outcome: OutcomeFindings, FindingsCount: 14},
		{ModuleName: "security", Tool: "trivy-license", Outcome: OutcomeClean,
			Examined: &Examined{Unit: "licence declarations", Count: 480}, WarningsCount: 1},
	})
	out := sb.String()
	for _, want := range []string{"quality", "semgrep", "trivy-license", "123,456", "480 licence declarations", "⚠️ errored", "🔎 findings", "✅ clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "quality") > strings.Index(out, "semgrep") {
		t.Error("rows reordered; envelope order must be preserved")
	}
}

func TestNoSourcesRendersNoTable(t *testing.T) {
	var sb strings.Builder
	writeSourceTable(&sb, nil)
	if sb.Len() != 0 {
		t.Errorf("expected nothing, got %q", sb.String())
	}
}

// TestTestsAreNotInventedWhenNoRunnerCounted guards the setup-only false pass
// in report form: a suite that never collected must not render as a row of zeros.
func TestTestsAreNotInventedWhenNoRunnerCounted(t *testing.T) {
	var sb strings.Builder
	writeTestSummary(&sb, &envelope{})
	if sb.Len() != 0 {
		t.Errorf("expected no test section, got %q", sb.String())
	}
}

func TestPerLanguageTestsRenderInAStableOrder(t *testing.T) {
	env := &envelope{TestsByLanguage: map[string]TestCounts{
		"python": {Total: 40, Passed: 39, Failed: 1},
		"dotnet": {Total: 100, Passed: 100},
	}}
	var sb strings.Builder
	writeTestSummary(&sb, env)
	out := sb.String()
	if !strings.Contains(out, "| dotnet | 100 | 100 | 0 | 0 |") {
		t.Errorf("dotnet row wrong:\n%s", out)
	}
	if strings.Index(out, "dotnet") > strings.Index(out, "python") {
		t.Error("languages must sort so two runs of the same suite diff cleanly")
	}
}

func TestAnUnsplitTestCountStillRenders(t *testing.T) {
	var sb strings.Builder
	writeTestSummary(&sb, &envelope{Tests: &TestCounts{Total: 5, Passed: 4, Failed: 1}})
	if !strings.Contains(sb.String(), "| all | 5 | 4 | 1 | 0 |") {
		t.Errorf("got:\n%s", sb.String())
	}
}

// TestCoverageAbsenceIsStated — the combined envelope withholds the figure on
// purpose when its weights are incomplete, and that must be visible.
func TestCoverageAbsenceIsStated(t *testing.T) {
	if got := coverageLine(&envelope{}); !strings.Contains(got, "not measured") {
		t.Errorf("got %q", got)
	}
}

func TestCoverageRendersItsDenominator(t *testing.T) {
	// Synthetic long-decimal coverage and denominator exercise rounding and grouping.
	got := coverageLine(&envelope{CoveragePercent: f64(7.2631578947368425), CoverageLines: intp(24680)})
	if !strings.Contains(got, "7.3%") || !strings.Contains(got, "24,680 lines") {
		t.Errorf("got %q", got)
	}
}

// TestTheReportNoLongerReadsAsAnAllClear drives the whole renderer over the
// envelope shape that produced the bug.
func TestTheReportNoLongerReadsAsAnAllClear(t *testing.T) {
	env := &envelope{Passed: true, Outcome: OutcomeError, FindingsCount: 345678}
	env.Errors = []string{"test dotnet: Consumer.slnx: dotnet test failed (exit 1)"}
	env.TestsByLanguage = map[string]TestCounts{"dotnet": {Total: 100, Passed: 100}}
	env.CoveragePercent = f64(7.26)
	env.Sources = []SourceStatus{
		{ModuleName: "quality", Tool: "quality", Outcome: OutcomeError, FindingsCount: 123456, ErrorsCount: 1},
	}
	out := buildMarkdown("commit", "", env)

	head := strings.SplitN(out, "\n", 3)[1]
	if !strings.Contains(head, "errored") {
		t.Errorf("headline still reads as an all-clear: %q", head)
	}
	for _, want := range []string{"What each tool found:", "123,456", "**Tests:**", "Coverage: 7.3%"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTheTeamsCardDoesNotPaintAnErroredRunGreen(t *testing.T) {
	if got := cardColor(&envelope{Passed: true, Outcome: OutcomeError}); got != "Attention" {
		t.Errorf("errored run coloured %q", got)
	}
	if got := cardColor(&envelope{Passed: true, Outcome: OutcomeFindings}); got != "Warning" {
		t.Errorf("findings coloured %q", got)
	}
	if got := cardColor(&envelope{Passed: true, Outcome: OutcomeClean}); got != "Good" {
		t.Errorf("clean run coloured %q", got)
	}
	card := buildTeamsCard("commit", "", &envelope{Passed: true, Outcome: OutcomeError})
	title := card.Attachments[0].Content.Body[0].Text
	if !strings.Contains(title, "errored") {
		t.Errorf("card title reads as an all-clear: %q", title)
	}
}

// TestAnUnconvertedProducerStillFlagsItsErrors closes the reported bug for the
// producers that have no Outcome yet — the majority. The headline counts the
// errors[] the report prints in full below; it does not name an outcome,
// because that would be the inference schema.go forbids.
func TestAnUnconvertedProducerStillFlagsItsErrors(t *testing.T) {
	env := &envelope{Passed: true}
	env.Errors = []string{"test dotnet: Consumer.slnx: dotnet test failed (exit 1)"}
	got := headline(env)
	if !strings.Contains(got, "1 error reported") {
		t.Errorf("a passing gate over a reported error must say so, got %q", got)
	}
	for _, banned := range []string{"errored", "failed", "clean", notStated} {
		if strings.Contains(got, banned) {
			t.Errorf("headline named an outcome it was not told: %q", got)
		}
	}
	env.Errors = append(env.Errors, "second")
	if got := headline(env); !strings.Contains(got, "2 errors reported") {
		t.Errorf("plural wrong: %q", got)
	}
}

// TestAStatedOutcomeWinsOverTheErrorCount — once a producer says what happened,
// the count is redundant and the outcome is the better sentence.
func TestAStatedOutcomeWinsOverTheErrorCount(t *testing.T) {
	env := &envelope{Passed: true, Outcome: OutcomeError}
	env.Errors = []string{"boom"}
	got := headline(env)
	if strings.Contains(got, "reported") {
		t.Errorf("error count should give way to the stated outcome: %q", got)
	}
	if !strings.Contains(got, "errored") {
		t.Errorf("got %q", got)
	}
}
