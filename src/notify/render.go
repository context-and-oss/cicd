package main

import (
	"fmt"
	"strings"
	"time"
)

// maxRenderedFindings caps how many findings appear in the PR comment / job
// summary. The cap protects GitHub's ~65k comment-size limit and keeps the job
// summary readable on large scans.
//
// combined-evidence.json is NOT where the full list always lives, and the
// overflow note must not say it is: the aggregator caps its own detail list too
// (evidence.capFindings), so on a run large enough to trip that cap the rows
// this note counts are themselves a subset. findings.sarif and parts/ hold
// every one.
const maxRenderedFindings = 25

// findingMessageMaxLen truncates an individual finding message so one noisy
// tool can't blow the comment budget.
const findingMessageMaxLen = 200

// PipelineMarker returns the hidden HTML comment used to identify an existing
// pipeline status comment on a PR so it can be updated instead of duplicated.
func PipelineMarker(pipelineName string) string {
	return fmt.Sprintf("<!-- cicd-pipeline:%s -->", pipelineName)
}

// formatDuration renders a run's wall time for a human reading a comment or a
// card, and refuses two renderings that mislead.
//
// A duration under a second used to be Round(time.Second)ed to "0s". Beside a
// real verdict that reads as "this run took no time", when what it usually
// means is that something measured the wrong clock, such as aggregation rather
// than scanning. As a hypothetical rendering example, 125 ms would round to
// "Duration 0s", hiding the sub-second measurement.
//
// A zero or negative duration is not a run that took under a millisecond, it
// is an absent measurement: build.NoArtifact sets DurationMS 0 deliberately
// because nothing ran. Saying "not measured" keeps an unmeasured run from
// reading as an instant one, which is the same rule the rest of this repo
// applies to a tool that could not run.
func formatDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d <= 0:
		return "not measured"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	default:
		return d.Round(time.Second).String()
	}
}

// buildMarkdown produces the markdown body for GitHub and ADO PR comments.
func buildMarkdown(pipelineName, runUrl string, env *envelope) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", PipelineMarker(pipelineName))
	fmt.Fprintf(&sb, "## %s — %s\n\n", pipelineName, headline(env))
	fmt.Fprintf(&sb, "| | |\n|---|---|\n")
	fmt.Fprintf(&sb, "| **Commit** | %s |\n", cellCode(env.Repo.CommitSHA))
	fmt.Fprintf(&sb, "| **Branch** | %s |\n", cellCode(env.Repo.Branch))
	fmt.Fprintf(&sb, "| **Findings** | %s |\n", humanCount(env.FindingsCount))
	fmt.Fprintf(&sb, "| **Duration** | %s |\n", formatDuration(env.DurationMS))
	// By concern first, by tool second. A reader wants to know which tool is
	// talking before they are handed a count — and before that, which QUESTION
	// is being answered, because "eleven scanners ran" is not something anyone
	// outside this repository can act on and "SCA failed" is. On a run with
	// thousands of findings these two tables are the only part of this report
	// that fits on a screen.
	writeConcernSummary(&sb, env.Concerns)
	writeSourceTable(&sb, env.Sources)
	writeTestSummary(&sb, env)
	writeSeverityTable(&sb, env)
	// Before the detail table, not after: the rollup is the compressed view
	// and the table is the head of the long one, so a reader who stops after
	// the first screen has been told where the findings are rather than what
	// the first 25 of them say.
	writeLocationRollup(&sb, env.Findings)
	writeFindingsDetail(&sb, env.Findings)
	writeQuotedList(&sb, "Warnings", env.Warnings)
	writeQuotedList(&sb, "Errors", env.Errors)
	if runUrl != "" {
		fmt.Fprintf(&sb, "\n[→ View run](%s)\n", runUrl)
	}
	return sb.String()
}

// writeSeverityTable breaks the finding count down by severity, and says so
// when it cannot.
//
// The header used to be written before the rows were known to exist, so a run
// reporting findings whose producers gave no severity breakdown published a
// table with a heading, a rule, and nothing under it. Beside "Findings: 12"
// that is worse than saying nothing: an empty severity table reads as twelve
// findings that are severe in no way, which is the reassuring answer and is
// not one any tool gave. Saying the breakdown was not reported keeps an
// unclassified finding from rendering as a harmless one — the same rule
// examinedCell applies to an absent denominator.
func writeSeverityTable(sb *strings.Builder, env *envelope) {
	if env.FindingsCount == 0 {
		return
	}
	rows := make([]string, 0, 4)
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if c := env.FindingsBySeverity[sev]; c > 0 {
			rows = append(rows, fmt.Sprintf("| %s | %s |\n", sev, humanCount(c)))
		}
	}
	if len(rows) == 0 {
		fmt.Fprintf(sb, "\n**Findings by severity:** %s\n", notStated)
		return
	}
	sb.WriteString("\n**Findings by severity:**\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, r := range rows {
		sb.WriteString(r)
	}
}

// writeFindingsDetail renders the per-finding detail table — the answer to
// "what tripped the gate", not just how many. Capped at maxRenderedFindings
// with an overflow note that counts only what it can actually see — the rows
// in this envelope — and points at the files that hold the rest.
//
// It takes the HEAD of the list and never reorders it. The aggregator writes
// combined.findings in one total order — most severe first, then within a
// severity the security module's rows before the style tools', then tool,
// rule, path, line — and states that rule in the truncation warning rendered
// further down this same comment. This renderer cannot reproduce that order
// on its own: the class of a row comes from the module that produced it, and a
// Finding does not carry its module. So the two caps, 1000 rows there and 25
// here, agree on which rows survive by construction — one order, decided once,
// truncated twice. A re-sort here would be a second rule the warning does not
// state; see docs/explanation/doctrine.md, "And a truncated table must keep
// the rows a reader came for, by a rule it states".
func writeFindingsDetail(sb *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		return
	}
	sb.WriteString("\n**Findings:**\n\n")
	sb.WriteString("| Severity | Source | Location | Message |\n")
	sb.WriteString("|----------|--------|----------|--------|\n")
	shown := findings
	if len(shown) > maxRenderedFindings {
		shown = shown[:maxRenderedFindings]
	}
	for _, f := range shown {
		fmt.Fprintf(sb, "| %s | %s | %s | %s |\n",
			cellOrDash(string(f.Severity)),
			cellOrDash(findingSource(f)),
			cellCode(findingLocation(f)),
			cellOrDash(truncate(f.Message, findingMessageMaxLen)),
		)
	}
	if extra := len(findings) - maxRenderedFindings; extra > 0 {
		fmt.Fprintf(sb, "\n_+%d more of the %d rows in this envelope; the rows shown are the first %d in the envelope's order (most severe first) — the complete set is in the evidence artifact (findings.sarif, parts/)._\n",
			extra, len(findings), maxRenderedFindings)
	}
}

// writeQuotedList renders a heading and one code-span bullet per entry. The
// warning and error loops used to format "- `%s`" directly, which gave them no
// line flattening at all: a multi-line warning became several list items, the
// second of which was raw markdown. An empty entry is skipped rather than
// rendered as an empty pair of backticks.
func writeQuotedList(sb *strings.Builder, heading string, items []string) {
	var rendered []string
	for _, it := range items {
		if f := strings.TrimSpace(flattenLines(it)); f != "" {
			rendered = append(rendered, codeSpan(f))
		}
	}
	if len(rendered) == 0 {
		return
	}
	fmt.Fprintf(sb, "\n**%s:**\n", heading)
	for _, r := range rendered {
		fmt.Fprintf(sb, "- %s\n", r)
	}
}

// findingSource combines tool and rule into a single human-readable source,
// e.g. "intent-gate / min-causal-language" or "trivy".
func findingSource(f Finding) string {
	switch {
	case f.Tool != "" && f.Rule != "":
		return f.Tool + " / " + f.Rule
	case f.Tool != "":
		return f.Tool
	default:
		return f.Rule
	}
}

// findingLocation renders the location cell as `path:line`, the form every
// editor and terminal turns into a jump. A line without a path is not rendered
// as a bare number — "42" tells a reader nothing they can act on — and a line
// of 0 means the producing tool reported none, so it is left off rather than
// printed as `path:0`.
func findingLocation(f Finding) string {
	if f.ArtifactPath == "" {
		return ""
	}
	if f.Line <= 0 {
		return f.ArtifactPath
	}
	return fmt.Sprintf("%s:%d", f.ArtifactPath, f.Line)
}

// escapeCell makes a string safe inside a markdown table cell: pipes would
// start a new column and newlines would break the row.
func escapeCell(s string) string {
	s = flattenLines(s)
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

// flattenLines collapses the line terminators that would end a table row or a
// list item into spaces. Split out of escapeCell because the warning and error
// lists need it without the pipe escaping a table cell needs.
func flattenLines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// codeSpan wraps arbitrary text in a markdown code span the text cannot escape,
// preserving it byte for byte.
//
// Every string this package renders inside backticks comes from outside it: a
// branch name (a backtick is legal in a refname: git check-ref-format --branch
// accepts one, exit 0), a commit subject, a path a scanner read off the tree, a
// warning assembled from paths a container's find returned. A single
// backtick in any of them used to close the span early, after which the rest of
// the string was parsed as markdown inside a comment posted under cicd's name
// beside a pass/fail verdict — so the person being gated authored part of the
// gate's own report.
//
// It does not strip. Removing a backtick from a path changes a finding's
// location, and this package renders locations as a path:line code span so a
// reviewer can jump to them; a silently edited path lands them somewhere else,
// which is the same lie as an unlocated finding that looks located, only
// harder to notice. Instead it uses CommonMark's own rule (§6.1): a code span may be
// delimited by any number of backticks and contain any shorter run. Fence with
// the longest internal run plus one and the content can never terminate it.
//
// The padding is not cosmetic. CommonMark strips one space from each end of a
// code span's content, but only when it begins *and* ends with a space and is
// not all spaces — both or neither. So a pad on one end only survives into the
// output, and a path rendered with a leading space is the quieter version of the
// mutation stripping was rejected for. Content beginning or ending with a
// backtick needs the pad to keep its own backtick away from the fence; content
// already flanked by spaces needs it so those spaces are not eaten.
//
// Callers must not pass an empty string: two backticks with nothing between them
// are not a code span, they are a literal pair. cellCode and the warning/error
// loops all guard on non-empty first.
func codeSpan(s string) string {
	s = flattenLines(s)
	fence := strings.Repeat("`", longestBacktickRun(s)+1)
	pad := ""
	switch {
	case strings.HasPrefix(s, "`"), strings.HasSuffix(s, "`"):
		pad = " "
	case strings.TrimSpace(s) != "" &&
		strings.HasPrefix(s, " ") && strings.HasSuffix(s, " "):
		pad = " "
	}
	return fence + pad + s + pad + fence
}

// longestBacktickRun returns the length of the longest consecutive run of
// backticks in s, which is what decides the fence length in codeSpan. Counted
// over bytes rather than runes because U+0060 is single-byte in UTF-8 and can
// never appear inside a multi-byte sequence.
func longestBacktickRun(s string) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != '`' {
			run = 0
			continue
		}
		run++
		if run > longest {
			longest = run
		}
	}
	return longest
}

func cellOrDash(s string) string {
	if e := escapeCell(s); e != "" {
		return e
	}
	return "—"
}

// cellCode renders a table cell as a code span. escapeCell trims before
// codeSpan pads, which is the order that matters: a trim applied after the pad
// would remove it silently, and only on the inputs the pad exists for.
func cellCode(s string) string {
	if e := escapeCell(s); e != "" {
		return codeSpan(e)
	}
	return "—"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "…"
}
