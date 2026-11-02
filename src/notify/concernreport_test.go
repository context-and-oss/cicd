package main

import (
	"strings"
	"testing"
)

func renderConcerns(rep *ConcernReport) string {
	var sb strings.Builder
	writeConcernSummary(&sb, rep)
	return sb.String()
}

// TestTheReportAnswersTheQuestionAReaderAsks is the point of the whole
// section. "Is our SAST clean?" is answerable from this table without knowing
// that Semgrep is the SAST leg.
func TestTheReportAnswersTheQuestionAReaderAsks(t *testing.T) {
	got := renderConcerns(&ConcernReport{
		Answered: []ConcernRollup{
			{Concern: ConcernSAST, Passed: true, Outcome: OutcomeClean,
				Examined: &Examined{Count: 1204, Unit: "files"}, Tools: 1},
			{Concern: ConcernSCA, Passed: false, Outcome: OutcomeFindings,
				Examined: &Examined{Count: 3500, Unit: "packages"}, FindingsCount: 12, Tools: 2},
		},
	})
	for _, want := range []string{"| SAST |", "| SCA |", "1,204 files", "3,500 packages", "| 12 |"} {
		if !strings.Contains(got, want) {
			t.Errorf("report does not contain %q:\n%s", want, got)
		}
	}
}

// TestAConcernNobodyAnsweredIsNamed. This is the failure the section exists to
// prevent: seven rows in a table give a reader no way to see that ten
// questions exist, so an absent SAST row reads exactly like a clean one.
func TestAConcernNobodyAnsweredIsNamed(t *testing.T) {
	got := renderConcerns(&ConcernReport{
		Answered:    []ConcernRollup{{Concern: ConcernSAST, Passed: true, Outcome: OutcomeClean, Tools: 1}},
		NotAnswered: []Concern{ConcernDAST, ConcernIaC},
	})
	if !strings.Contains(got, "No tool in this run reported on: DAST, IaC.") {
		t.Errorf("unanswered concerns are not named:\n%s", got)
	}
}

// TestAnUnansweredConcernIsNotCalledAFailure. Nothing here knows which
// concerns a repository OUGHT to answer, and a repository with no
// infrastructure has no IaC leg and is not missing one.
func TestAnUnansweredConcernIsNotCalledAFailure(t *testing.T) {
	got := renderConcerns(&ConcernReport{NotAnswered: []Concern{ConcernDAST}})
	for _, banned := range []string{"missing", "fail", "❌", "⚠️", "gap"} {
		if strings.Contains(strings.ToLower(got), banned) {
			t.Errorf("an unanswered concern is rendered as a defect (%q):\n%s", banned, got)
		}
	}
}

// TestAToolThatSaidNothingAboutScopeSaysSo. Same rule as examinedCell: a blank
// denominator beside "0 findings" is read as the reassuring answer.
func TestAToolThatSaidNothingAboutScopeSaysSo(t *testing.T) {
	got := renderConcerns(&ConcernReport{
		Answered: []ConcernRollup{{Concern: ConcernSecrets, Passed: true, Outcome: OutcomeClean, Tools: 2}},
	})
	if !strings.Contains(got, notStated) {
		t.Errorf("an unstated denominator is rendered as blank:\n%s", got)
	}
}

// TestAnUnclassifiedRollupIsVisible. A producer that ran and declared no
// concern must show up, or the gap closes itself by hiding.
func TestAnUnclassifiedRollupIsVisible(t *testing.T) {
	got := renderConcerns(&ConcernReport{
		Answered: []ConcernRollup{{Passed: false, Outcome: OutcomeFindings, FindingsCount: 4, Tools: 1}},
	})
	if !strings.Contains(got, unclassifiedLabel) {
		t.Errorf("an unclassified rollup is not shown:\n%s", got)
	}
}

// TestAConcernThisVersionHasNeverHeardOfPrintsVerbatim. Flattening a
// forward-compatible addition to the vocabulary into silence is the same bug
// as an absent row reading clean.
func TestAConcernThisVersionHasNeverHeardOfPrintsVerbatim(t *testing.T) {
	got := renderConcerns(&ConcernReport{
		Answered:    []ConcernRollup{{Concern: Concern("fuzzing"), Passed: true, Outcome: OutcomeClean, Tools: 1}},
		NotAnswered: []Concern{Concern("threat-model")},
	})
	if !strings.Contains(got, "fuzzing") || !strings.Contains(got, "threat-model") {
		t.Errorf("an unknown concern was dropped:\n%s", got)
	}
}

// TestEvidenceWithNoFoldRendersNoSection. Nil means the aggregator never
// folded — old evidence, or none at all — so there is no claim to make. The
// per-tool table underneath still reports everything that ran.
func TestEvidenceWithNoFoldRendersNoSection(t *testing.T) {
	if got := renderConcerns(nil); got != "" {
		t.Errorf("unfolded evidence rendered a concern section:\n%s", got)
	}
}

// TestEveryConcernInTheSchemaHasWords. A constant added to the vocabulary
// without a label here still renders (verbatim), but it renders as a wire
// identifier in a document a customer reads.
func TestEveryConcernInTheSchemaHasWords(t *testing.T) {
	all := []Concern{
		ConcernSAST, ConcernSCA, ConcernSecrets, ConcernLicenses, ConcernSBOM,
		ConcernLint, ConcernTests, ConcernCoverage, ConcernIaC, ConcernDAST,
	}
	for _, c := range all {
		if _, ok := concernLabels[c]; !ok {
			t.Errorf("concern %q has no label; it would print as a wire identifier", c)
		}
	}
}

// TestTheConcernTableComesBeforeTheToolTable. Which question was answered
// outranks which binary answered it; a reader who never scrolls past the first
// table should still have the summary.
func TestTheConcernTableComesBeforeTheToolTable(t *testing.T) {
	env := &envelope{
		Concerns: &ConcernReport{
			Answered: []ConcernRollup{{Concern: ConcernSAST, Passed: true, Outcome: OutcomeClean, Tools: 1}},
		},
		Sources: []SourceStatus{{ModuleName: "security", Tool: "semgrep", Passed: true, Outcome: OutcomeClean}},
	}
	md := buildMarkdown("commit", "", env)
	byConcern := strings.Index(md, "**By concern:**")
	byTool := strings.Index(md, "**What each tool found:**")
	if byConcern < 0 || byTool < 0 {
		t.Fatalf("one of the two tables is missing:\n%s", md)
	}
	if byConcern > byTool {
		t.Errorf("the per-tool table precedes the by-concern summary:\n%s", md)
	}
}

// TestFindingsWithNoSeverityBreakdownSayNothingIsKnown. An empty severity
// table beside a non-zero count reads as findings that are severe in no way,
// which is the reassuring answer and is not one any tool gave.
func TestFindingsWithNoSeverityBreakdownSayNothingIsKnown(t *testing.T) {
	md := buildMarkdown("commit", "", &envelope{FindingsCount: 12})
	if strings.Contains(md, "| Severity | Count |") {
		t.Errorf("an empty severity table was rendered:\n%s", md)
	}
	if !strings.Contains(md, "**Findings by severity:** "+notStated) {
		t.Errorf("a missing severity breakdown is not stated:\n%s", md)
	}
}

// TestASeverityBreakdownStillRendersAsATable guards the fix from swallowing
// the case it was not about.
func TestASeverityBreakdownStillRendersAsATable(t *testing.T) {
	md := buildMarkdown("commit", "", &envelope{
		FindingsCount:      3,
		FindingsBySeverity: map[Severity]int{SeverityHigh: 3},
	})
	if !strings.Contains(md, "| HIGH | 3 |") {
		t.Errorf("severity rows are missing:\n%s", md)
	}
}
