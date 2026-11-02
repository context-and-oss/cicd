package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// This file renders the half of the report that says what the run FOUND, as
// distinct from whether the gate opened.
//
// The combined envelope has carried Sources, Outcome, Examined, TestsByLanguage
// and CoveragePercent for several releases and nothing rendered any of them.
// comment.md is not a side channel — commit.yml appends it to
// GITHUB_STEP_SUMMARY and notify posts the same bytes as the pull request
// comment — so everything those fields were added to say stopped at the last
// step, and the report a customer reads said "over 200,000 findings" with nothing
// anywhere naming which tool found them.
//
// One rule runs through all of it: a field the producer did not set is
// rendered as words that say so, never as a dash, a zero, or an omitted row.
// This column sits beside "✅ clean" and "0", and in that company silence is
// read as good news — the exact conflation Outcome and Examined were added to
// end, reintroduced at the point of display.

// outcomeLabels maps each outcome to the words the report uses for it. The
// emoji is a scanning aid and never the message: the word beside it carries the
// meaning for a client that strips emoji, for a terminal rendering the job
// summary, and for anyone reading the markdown as text.
var outcomeLabels = map[Outcome]string{
	OutcomeClean:    "✅ clean",
	OutcomeSkipped:  "⏭️ skipped",
	OutcomeFindings: "🔎 findings",
	OutcomeFailed:   "❌ failed",
	OutcomeError:    "⚠️ errored",
}

// notStated is what an unset field renders as. Deliberately words rather than
// an em-dash: cellOrDash's "—" is right for a location or a rule name, where
// absent means "not applicable", and wrong here, where absent means "nobody
// said" and the neighbouring cells say "✅ clean" and "0".
const notStated = "not stated"

// outcomeLabel renders one Outcome for a human.
func outcomeLabel(o Outcome) string {
	if lbl, ok := outcomeLabels[o]; ok {
		return lbl
	}
	if o == "" {
		return notStated
	}
	// An outcome this renderer has never heard of is still a claim its
	// producer made. Print it verbatim. Flattening it to "not stated" would
	// turn a forward-compatible addition to the vocabulary into silence, and
	// silence is the failure this file exists to stop.
	return string(o)
}

// headline renders the report's first line: the gate verdict, and the outcome
// beside it whenever the verdict alone would mislead.
//
// They answer different questions and the report has to carry both. Passed
// answers "should this block the pipeline?" — under fail-on: NONE it is true
// however bad the news is, by design (schema.go). Outcome answers "what
// actually happened?". Rendering only the first is how a run whose dotnet suite
// exited 1 published `## commit — ✅ Passed` with `dotnet test failed (exit 1)`
// three lines underneath it.
//
// A clean pass prints exactly as it always did, because appending "· ✅ clean"
// to "✅ Passed" says one thing twice. Everything else gets the outcome — a
// failing gate included, since "❌ Failed · ⚠️ errored" and "❌ Failed · ❌
// failed" send a reader to different places.
func headline(env *envelope) string {
	gate := "✅ Passed"
	if !env.Passed {
		gate = "❌ Failed"
	}
	switch env.Outcome {
	case "":
		// The producer has not been converted, so there is no outcome to
		// state. "not stated" belongs in a table cell a reader is already
		// scanning, not in a headline, where it reads as an alarm about the
		// run rather than a gap in the reporting.
		//
		// Counting the errors the envelope already carries is not deriving
		// an outcome. schema.go forbids inferring one from passed,
		// findingsCount and errors[] because that inference is a guess
		// wearing a verdict's clothes — it cannot tell "the tests failed"
		// from "the scanner crashed". This guesses nothing: it reports the
		// length of a list printed in full further down the same document.
		// Without it the bug this file exists to fix survives untouched on
		// every producer not yet converted, which today is most of them.
		if n := len(env.Errors); n > 0 {
			noun := "errors"
			if n == 1 {
				noun = "error"
			}
			return fmt.Sprintf("%s · ⚠️ %s %s reported", gate, humanCount(n), noun)
		}
		return gate
	case OutcomeClean:
		if env.Passed {
			return gate
		}
	}
	return gate + " · " + outcomeLabel(env.Outcome)
}

// sourceLabel names one row of the per-tool table.
//
// Scope is kept because without it one scanner over two scopes is
// indistinguishable: a report renders "gitleaks, gitleaks" when both the source
// scan and the archive scan emit a Gitleaks run and neither row says which.
// That is the whole reason SourceStatus.Scope exists, and dropping it here
// would discard it at the one place a human ever reads it.
func sourceLabel(s SourceStatus) string {
	name := strings.TrimSpace(s.Tool)
	module := strings.TrimSpace(s.ModuleName)
	switch {
	case name == "":
		name = module
	case module != "" && module != name:
		name = module + " / " + name
	}
	if scope := strings.TrimSpace(s.Scope); scope != "" {
		name += " (" + scope + ")"
	}
	return name
}

// examinedCell renders how much one tool actually looked at.
//
// A nil Examined is "not stated" rather than a dash or a blank, because this
// column's entire job is to be the denominator a zero finding count needs. "0
// findings" over an unknown denominator and "0 findings" over three thousand
// components are different claims, and a dash between them is read as the
// reassuring one. Examined{Count: 0} genuinely is "the tool looked and found
// nothing in scope", and prints as the zero it is.
//
// Total is rendered whenever the tool knew its own denominator, because the gap
// is usually the story: a consumer's licence scan reported a few hundred
// declarations scanned beside an SBOM listing thousands of components, and both
// figures were right.
func examinedCell(ex *Examined) string {
	if ex == nil {
		return notStated
	}
	unit := strings.TrimSpace(ex.Unit)
	if unit == "" {
		// Examined's own contract: without a unit the number cannot be
		// reported. Saying the unit is missing beats printing a bare
		// integer under a heading that implies one.
		unit = "(unit not stated)"
	}
	if ex.Total > 0 {
		return fmt.Sprintf("%s of %s %s", humanCount(ex.Count), humanCount(ex.Total), unit)
	}
	return fmt.Sprintf("%s %s", humanCount(ex.Count), unit)
}

// humanCount groups thousands so a large count is legible at a glance. 123456
// and 12345 are the same shape to a scanning eye; 123,456 and 12,345 are not,
// and this report exists to help someone decide whether to look further.
func humanCount(n int) string {
	s := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	return sign + b.String()
}

// writeSourceTable renders one row per tool that reported.
//
// Rows stay in the envelope's order, which SourceStatus documents as input
// order. Sorting by severity or by name here would be this renderer inventing a
// ranking the aggregator did not make.
func writeSourceTable(sb *strings.Builder, sources []SourceStatus) {
	if len(sources) == 0 {
		return
	}
	sb.WriteString("\n**What each tool found:**\n\n")
	sb.WriteString("| Tool | Outcome | Examined | Findings | Errors | Warnings |\n")
	sb.WriteString("|------|---------|----------|---------:|-------:|---------:|\n")
	for _, s := range sources {
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s |\n",
			cellOrDash(escapeCell(sourceLabel(s))),
			escapeCell(outcomeLabel(s.Outcome)),
			escapeCell(examinedCell(s.Examined)),
			humanCount(s.FindingsCount),
			humanCount(s.ErrorsCount),
			humanCount(s.WarningsCount),
		)
	}
}

// testRow is one language's accounting in the rendered table.
type testRow struct {
	name   string
	counts TestCounts
}

// writeTestSummary renders the executed-test accounting, per language when the
// envelope splits it that way.
//
// Nothing is rendered when no runner accounted for its own run. A table of
// zeros here would be the setup-only false pass in report form: a suite that
// never collected and a suite containing no tests produce identical rows, which
// is why TestCounts is a pointer and why scripts/test-module-units.sh guards
// the same conflation in cicd's own suite.
func writeTestSummary(sb *strings.Builder, env *envelope) {
	rows := make([]testRow, 0, len(env.TestsByLanguage)+1)
	for lang, counts := range env.TestsByLanguage {
		rows = append(rows, testRow{name: lang, counts: counts})
	}
	// Map iteration order is random; a report whose rows move between two
	// runs of the same suite cannot be diffed against the previous run.
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	if len(rows) == 0 && env.Tests != nil {
		// An envelope that counted its tests without splitting by language.
		rows = append(rows, testRow{name: "all", counts: *env.Tests})
	}
	if len(rows) == 0 {
		return
	}
	sb.WriteString("\n**Tests:**\n\n")
	sb.WriteString("| Language | Total | Passed | Failed | Skipped |\n")
	sb.WriteString("|----------|------:|-------:|-------:|--------:|\n")
	for _, r := range rows {
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s |\n",
			cellOrDash(escapeCell(r.name)),
			humanCount(r.counts.Total),
			humanCount(r.counts.Passed),
			humanCount(r.counts.Failed),
			humanCount(r.counts.Skipped),
		)
	}
	fmt.Fprintf(sb, "\n%s\n", coverageLine(env))
}

// coverageLine states coverage beside the test table, because that is the run
// it describes.
//
// Absent renders as words rather than as an omitted line. The combined envelope
// withholds the figure deliberately whenever its per-language weights are
// incomplete (schema.go) — an unweighted mean over languages is a number about
// no run that ever happened — and that withholding is something a reader needs
// to see. A report that simply stops mentioning coverage is indistinguishable
// from one whose coverage was fine.
func coverageLine(env *envelope) string {
	if env.CoveragePercent == nil {
		return "Coverage: not measured"
	}
	if env.CoverageLines != nil && *env.CoverageLines > 0 {
		return fmt.Sprintf("Coverage: %.1f%% of %s lines",
			*env.CoveragePercent, humanCount(*env.CoverageLines))
	}
	return fmt.Sprintf("Coverage: %.1f%%", *env.CoveragePercent)
}
