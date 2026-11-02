package main

import (
	"cmp"
	"sort"
)

// findingClass ranks the producing module of a finding for the purpose of
// ordering rows of EQUAL severity. Lower is listed first.
//
// Severity is the first key and always wins across tiers; the class only
// decides who goes first inside a tier. It exists because a formatter reports
// one row per line and a scanner reports one row per problem, so on any
// repository large enough for the detail cap to bite, the tier the cap lands in
// is dominated by style rows — and under a severity-only sort the rows a
// reviewer would act on were pushed out of the table by whitespace. Measured on
// a consumer's run: over 200,000 rows capped to 1000 kept a few HIGH rows
// and filled the rest with dotnet-format WHITESPACE rows at MEDIUM, while every
// MEDIUM Semgrep security finding fell off the end. "Most severe kept" was true and the
// table still lied by omission.
//
// The class comes from the module that produced the envelope, never from a
// tool-name table: tool names are chosen by upstream projects and change with
// them, while the set of finding-producing modules is this repository's own.
// TestFindingClassCoversEveryModule holds the switch below to that set.
//
// The rank is by flood risk, which is what the reader needs protecting from,
// not by importance: security (one row per vulnerability, secret or SAST hit),
// then risk (one row per policy violation), then intent (one row per artifact
// rule), then quality (linters and formatters, one row per line on a bad day).
// A module the switch does not know is placed ahead of quality and behind the
// three it does know: this aggregator has to accept an envelope from a module
// newer than itself, and of the two wrong guesses — a new scanner buried under
// style rows, or a new formatter flooding a tier — the first is the defect this
// order exists to prevent. The test above is what keeps that arm from being
// reached by a module in this repository.
type findingClass int

const (
	classSecurity findingClass = iota
	classRisk
	classIntent
	classUnclassified
	classQuality
)

// findingClassOf maps a producing module's name to its class. The default arm
// is deliberate and documented on findingClass; it is the one place an unknown
// module lands, and the test that walks the repository's module names is what
// makes reaching it a CI failure rather than a silent choice.
func findingClassOf(moduleName string) findingClass {
	switch moduleName {
	case "security":
		return classSecurity
	case "risk":
		return classRisk
	case "intent":
		return classIntent
	case "quality":
		return classQuality
	default:
		return classUnclassified
	}
}

// findingOrderRule is the rule, in the words the truncation warning uses. It is
// a constant so the warning cannot drift from the comparator without the test
// that asserts the warning quotes it noticing; when compareFindings changes,
// this sentence changes with it.
const findingOrderRule = "most severe kept; within a severity, security findings before " +
	"style findings (by producing module: security, risk, intent, then quality), " +
	"then by tool, rule, path, line and message"

// classedFinding is a Finding together with the class of the module that
// produced it. The class travels beside the row rather than inside it because
// it is an ordering concern of this aggregator, not a property of the finding —
// the schema does not carry it and the comment renderer does not need it: it
// takes the head of the list this order produced.
type classedFinding struct {
	Finding
	class findingClass
}

// compareFindings is the total order the detail list is written in. It is total
// — no two distinct rows compare equal — because the tiebreak descends through
// every field of Finding, and dedupeFindings has already removed exact repeats.
// So the list is the same for the same set of rows however the composite
// happened to collect them, and the row at position 1000 is the same row on
// every run. Module order in the parts list decides nothing here.
func compareFindings(a, b classedFinding) int {
	return cmp.Or(
		// Highest severity first: severityOrder is larger for more severe.
		cmp.Compare(severityOrder(b.Severity), severityOrder(a.Severity)),
		cmp.Compare(a.class, b.class),
		cmp.Compare(a.Tool, b.Tool),
		cmp.Compare(a.Rule, b.Rule),
		cmp.Compare(a.ArtifactPath, b.ArtifactPath),
		cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Message, b.Message),
	)
}

// orderFindings deduplicates and sorts the pooled detail rows, returning the
// bare Findings in the order the bundle writes them.
//
// Dedupe runs first, on the Finding alone. Two modules stating a byte-identical
// finding would otherwise be two rows differing only in class, and the reader
// would see the duplicate this repository's dedupe exists to remove. First
// occurrence wins, so the class a duplicate keeps is the class of the module
// that stated it first — a tie that only matters for ordering and only when two
// modules report the same row, which no module pair here does.
func orderFindings(in []classedFinding) []Finding {
	in = dedupeFindings(in)
	sort.SliceStable(in, func(i, j int) bool {
		return compareFindings(in[i], in[j]) < 0
	})
	if len(in) == 0 {
		return nil
	}
	out := make([]Finding, len(in))
	for i, f := range in {
		out[i] = f.Finding
	}
	return out
}

// dedupeFindings drops exact repeats of a Finding, keeping the first occurrence.
//
// Every field of Finding participates in the key — including Line, which is why
// Finding carries one. Collapsing on location alone would merge two distinct
// vulnerabilities in the same lockfile, or a lint error and a secret on one
// line, and under-reporting to tidy a table is the trade this repo does not
// make. The same argument runs the other way: while the key held no line, two
// findings the tool distinguished only by line were byte-identical here and one
// of them silently vanished. Adding a field to Finding therefore widens this
// key, and a field a producer leaves at its zero value cannot fix that on its
// own — see sarifFindings.
//
// The class is NOT part of the key. It describes the producer, not the finding,
// and keying on it would let a row stated by two modules through twice.
func dedupeFindings(in []classedFinding) []classedFinding {
	seen := make(map[Finding]bool, len(in))
	out := make([]classedFinding, 0, len(in))
	for _, f := range in {
		if seen[f.Finding] {
			continue
		}
		seen[f.Finding] = true
		out = append(out, f)
	}
	return out
}
