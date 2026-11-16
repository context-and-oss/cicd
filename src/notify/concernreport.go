package main

import (
	"fmt"
	"strings"
)

// This file renders the run by the question it answers, above the table that
// renders it by the tool that answered.
//
// The per-tool table below it is the detail and stays the detail: it is in
// input order, one row per scanner, and on a pipeline running eleven of them
// the reader has to know that Semgrep is the SAST leg and Trivy is two
// different legs before any of it means anything. That is pipeline trivia, and
// a customer reading this report does not have it. "Is our SAST clean?" is the
// question, and until now nothing in this document answered it.
//
// Nothing here folds anything. The aggregator did the fold and shipped it in
// Envelope.Concerns, for the reason ConcernReport documents: the bundle's
// concerns/ directory and this comment are read by the same person in the same
// sitting, and a second fold written here would eventually disagree with the
// first over some run nobody is looking at closely.

// concernLabels are the words a report uses for each concern.
//
// The wire values are lowercase identifiers because that is what a filename
// and a JSON enum should be; "sast" in a table a customer reads is neither the
// acronym nor a word. This is presentation and nothing else — it never decides
// which concern a row belongs to, which is a producer's job and stays one.
var concernLabels = map[Concern]string{
	ConcernSAST:     "SAST",
	ConcernSCA:      "SCA",
	ConcernSecrets:  "Secrets",
	ConcernLicenses: "Licences",
	ConcernSBOM:     "SBOM",
	ConcernIaC:      "IaC",
	ConcernDAST:     "DAST",
	ConcernLint:     "Lint",
	ConcernTests:    "Tests",
	ConcernCoverage: "Coverage",
}

// unclassifiedLabel names the rollup over rows whose producer declared no
// concern. It says the tools ran and could not be filed, which is the honest
// report of an unconverted producer and the thing that makes the gap visible
// enough to close.
const unclassifiedLabel = "unclassified"

// concernLabel renders one concern for a human.
//
// A concern this renderer has never heard of prints verbatim, for the same
// reason outcomeLabel prints an unknown outcome verbatim: a forward-compatible
// addition to the vocabulary must not be flattened into silence by a consumer
// that shipped before it.
func concernLabel(c Concern) string {
	if lbl, ok := concernLabels[c]; ok {
		return lbl
	}
	if c == "" {
		return unclassifiedLabel
	}
	return string(c)
}

// writeConcernSummary renders the by-concern table and the list of concerns
// this run did not answer.
//
// A nil report renders nothing at all. That is not the "absent reads as clean"
// conflation this package exists to fight: nil means the evidence predates the
// fold or was never aggregated, so there is no claim to render, and the
// per-tool table underneath still reports everything that ran. Printing an
// empty concern table there would be the invention.
func writeConcernSummary(sb *strings.Builder, rep *ConcernReport) {
	if rep == nil {
		return
	}
	if len(rep.Answered) > 0 {
		sb.WriteString("\n**By concern:**\n\n")
		sb.WriteString("| Concern | Outcome | Examined | Findings | Errors | Warnings | Tools |\n")
		sb.WriteString("|---------|---------|----------|---------:|-------:|---------:|------:|\n")
		for _, c := range rep.Answered {
			fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s | %s |\n",
				escapeCell(concernLabel(c.Concern)),
				escapeCell(rowOutcomeLabel(c.Outcome, c.Examined)),
				escapeCell(examinedCell(c.Examined)),
				humanCount(c.FindingsCount),
				humanCount(c.ErrorsCount),
				humanCount(c.WarningsCount),
				humanCount(c.Tools),
			)
		}
	}
	writeNotAnswered(sb, rep.NotAnswered)
}

// writeNotAnswered names the questions this run did not answer, and is the
// half of the section that stops the other half from misleading.
//
// A reader shown seven concerns can see which seven are there; they cannot see
// that ten exist, so an absent SAST row reads exactly like a clean one. This
// supplies the denominator the table cannot.
//
// The wording is careful and the care is the point. Nothing in this pipeline
// knows which concerns a given repository OUGHT to answer — one with no
// infrastructure has no IaC leg and is not missing one, and calling that a gap
// would be inventing a denominator, which is the same mistake the table above
// refuses to make with Examined. So it reports what ran, not what should have.
func writeNotAnswered(sb *strings.Builder, cs []Concern) {
	if len(cs) == 0 {
		return
	}
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, concernLabel(c))
	}
	fmt.Fprintf(sb, "\nNo tool in this run reported on: %s.\n", strings.Join(names, ", "))
}
