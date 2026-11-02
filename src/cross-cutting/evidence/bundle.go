package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Where the bundle is assembled and what it is made of.
//
// Untagged on purpose. wrap.go carries the Dagger build tag, and both
// bundle.go and concerns.go — which build the documents these name — are
// untagged so a test can reach them. Names a tagged file owns are names a test
// cannot see.
const (
	moduleName  = "cross-cutting/evidence"
	moduleStage = "cross-cutting"

	// auditDirName is the subdirectory of the module runtime's scratch workdir
	// that the bundle is assembled in, and the directory this module returns.
	auditDirName = "audit"

	// partsDirName holds one verbatim copy of each input envelope.
	partsDirName = "parts"

	// concernsDirName holds the same run re-indexed by the question a reader
	// is asking, as pointers into parts/. See concerns.go.
	concernsDirName = "concerns"
)

// maxCombinedFindings bounds the normalised detail list embedded in
// combined-evidence.json.
//
// The list is best-effort detail behind FindingsBySeverity and the counts stay
// authoritative — but until this cap existed it was unbounded, and one
// consumer's run put every row it had into it. A formatter reporting a
// line-ending fix per line, over a repository with mixed endings, produced a
// combined document large enough that Dagger refused to return the audit
// directory at all:
//
//	read function output file: file size 134250496 exceeds limit 134217728
//
// These diagnostic bytes are the public 128 MiB limit plus one fixed 32 KiB
// reader chunk, not a measurement of the payload.
//
// So the run rendered no verdict, published no artifact, and failed with an
// error about a file size. A detail list nobody can read, inside a bundle
// nobody can receive, is worth strictly less than a truncated one that says it
// was truncated.
//
// The bound has to hold for the file's consumers too, not only its producer:
// notify reads combined-evidence.json back through the same 128 MiB
// function-output ceiling to render the PR comment, so leaving the list
// unbounded here only moves the same failure one module downstream.
//
// 1000 is far above what any consumer renders — notify shows 25 — and far below
// the ceiling. Findings arrive in the total order compareFindings defines
// (findingorder.go): most severe first, and within a severity the security
// module's rows before the style tools'. What a truncation keeps is therefore
// the end a reader came for — the severe rows, and among equally severe rows
// the ones a reviewer acts on rather than the ones a formatter would fix. A
// severity-only order was measured to keep nearly a thousand whitespace rows and drop every
// MEDIUM SAST finding; see findingClass.
const maxCombinedFindings = 1000

// capFindings truncates a pre-sorted findings list to maxCombinedFindings and
// returns the warning that must travel with a truncation, empty when none
// happened.
//
// The warning is not decoration. A short list is indistinguishable from a
// quiet run unless the document says which it is, and "the detail list is
// complete" is exactly the kind of thing a reader assumes without checking.
// It states the rule the kept rows were chosen by — quoting findingOrderRule,
// the same constant the comparator is documented against — so a reader can
// tell from the document alone why a row is in the table and another is not,
// and it names where the dropped rows still live, because they are not lost:
// findings.sarif carries every SARIF result no accepted suppression covers, and
// parts/ carries every envelope verbatim.
//
// It takes the head of the list and does not reorder it: the order is decided
// once, in mergeFindings, and every consumer that shows fewer rows than exist
// (this cap, notify's table) truncates the same list. Two caps with two rules
// would keep two different sets of rows and agree on neither.
func capFindings(findings []Finding) ([]Finding, string) {
	if len(findings) <= maxCombinedFindings {
		return findings, ""
	}
	return findings[:maxCombinedFindings], fmt.Sprintf(
		"findings detail truncated: %d of %d rows listed, %d omitted; %s. "+
			"findingsCount and findingsBySeverity are unaffected and remain authoritative; "+
			"every omitted row is still in findings.sarif and in the producing module's envelope under parts/.",
		maxCombinedFindings, len(findings), len(findings)-maxCombinedFindings, findingOrderRule)
}

// auditPart is one row of parts/index.json: what a per-module envelope file in
// the bundle is, and what it said.
//
// The index exists so that a missing part is detectable rather than merely
// absent. A reader handed a parts/ directory can see which files are there; it
// cannot see which ones should have been, and a bundle assembled from four
// envelopes when five modules ran looks exactly like a bundle from a pipeline
// with four modules. The counts are duplicated from the envelope on purpose —
// they let a reader scan the run without opening every part, and they disagree
// loudly with a truncated or corrupted part file rather than quietly.
type auditPart struct {
	File          string `json:"file"`
	ModuleName    string `json:"moduleName"`
	Stage         string `json:"stage,omitempty"`
	Tool          string `json:"tool,omitempty"`
	Passed        bool   `json:"passed"`
	FindingsCount int    `json:"findingsCount"`
	ErrorsCount   int    `json:"errorsCount"`
	WarningsCount int    `json:"warningsCount"`
	Bytes         int    `json:"bytes"`
}

// partFileName derives the bundle filename for the i-th input envelope.
//
// The ordinal prefix is what makes the name unique and the directory listing
// match the order the composite collected evidence in; the module and tool
// names are what make it readable. Two runs of the same module — the security
// module scans source and archive — therefore differ by their ordinal and not
// by a suffix bolted on after a collision.
func partFileName(i int, e *envelope) string {
	base := sanitiseNameSegment(e.ModuleName)
	if base == "" {
		base = "envelope"
	}
	if tool := sanitiseNameSegment(e.Tool.Name); tool != "" && tool != base {
		base += "-" + tool
	}
	return fmt.Sprintf("%02d-%s.json", i+1, base)
}

// buildPartsIndex summarises the envelopes written to parts/, in input order.
// names must be partFileName's output for the same slice, index for index.
func buildPartsIndex(envs []*envelope, names []string, sizes []int) []auditPart {
	out := make([]auditPart, 0, len(envs))
	for i, e := range envs {
		out = append(out, auditPart{
			File:          names[i],
			ModuleName:    e.ModuleName,
			Stage:         e.Stage,
			Tool:          e.Tool.Name,
			Passed:        e.Passed,
			FindingsCount: e.FindingsCount,
			ErrorsCount:   len(e.Errors),
			WarningsCount: len(e.Warnings),
			Bytes:         sizes[i],
		})
	}
	return out
}

// sanitiseNameSegment reduces an arbitrary module or tool name to a filesystem-
// safe segment: [A-Za-z0-9-_] survives, everything else becomes a hyphen, and
// runs of hyphens collapse so "cross-cutting/evidence" reads as
// "cross-cutting-evidence" rather than trailing punctuation.
func sanitiseNameSegment(s string) string {
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
	for strings.Contains(mapped, "--") {
		mapped = strings.ReplaceAll(mapped, "--", "-")
	}
	return strings.Trim(mapped, "-")
}

// combinedSpan derives the combined envelope's start time and duration from the
// envelopes it aggregates, rather than from the aggregator's own clock.
//
// buildCombined used to stamp the combined envelope with `start` — the moment
// Wrap began — and `time.Since(start)` — how long Wrap itself took. Wrap runs
// after every module has finished, so both described the aggregation step and
// neither described the run. A consumer's shadow spent the better part of half
// an hour scanning but reported only the sub-second aggregation time; the
// rendered comment said "Duration 0s" beside a real verdict. A field that names
// one thing and measures another is
// the same defect class as a tool that could not run reading as clean.
//
// The span runs from the earliest module start to now — the point the bundle is
// assembled — which covers modules run in parallel and in sequence alike. A sum
// of per-module durations would overstate a parallel run.
//
// A zero TimestampUTC means the module never stamped one. Those are skipped: a
// single unstamped envelope would otherwise drag the earliest start back to the
// zero time and report a duration of two thousand years. If no envelope carries
// a usable stamp, or the earliest stamp is somehow after now, the aggregator's
// own start is used and the duration says how long aggregation took — wrong,
// but bounded, and preferable to a number no reader could take seriously.
func combinedSpan(envs []*envelope, fallbackStart, now time.Time) (time.Time, int64) {
	earliest := time.Time{}
	for _, e := range envs {
		if e == nil || e.TimestampUTC.IsZero() {
			continue
		}
		if earliest.IsZero() || e.TimestampUTC.Before(earliest) {
			earliest = e.TimestampUTC
		}
	}
	if earliest.IsZero() || earliest.After(now) {
		earliest = fallbackStart
	}
	ms := now.Sub(earliest).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	return earliest.UTC(), ms
}

// marshalBundleDoc encodes one file of the bundle, indented or not according to
// who opens it.
//
// Every document in the bundle used to be MarshalIndent'ed. For the two a
// person actually reads that is right; for the two a machine consumes it is
// whitespace for no reader. Measured across the bundles this repo has produced,
// compacting saves 19-20% of findings.sarif and 30-39% of sbom.cdx.json.
//
// That matters beyond disk, because the engine caps a single transfer at
// 128 MiB and the saving grows with the file. The largest bundle observed here
// carried a findings.sarif of roughly 150 MB, over the cap, so the whole bundle
// failed to return; the same document compact is roughly 86 MB, a saving of about 40%
// and under the cap. Indentation alone decided whether that run had evidence.
//
// This is headroom, not a fix: a scan with enough findings still reaches the
// cap, just later, and reaching it later makes it rarer without making it
// louder. The cap itself is a separate problem. A bundle that fails to transfer
// is the failure class this repo exists to catch — evidence that is absent
// read as evidence that is clean.
//
// Only whitespace changes. encoding/json escapes the same characters either
// way, so every jq expression and every SARIF upload sees the same document.
func marshalBundleDoc(name string, v any) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if readByEye(name) {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", name, err)
	}
	return data, nil
}

// readByEye reports whether a bundle file is one a person opens directly.
//
// combined-evidence.json is the verdict and parts/index.json is the manifest
// that says what the run should have produced; both get read by a human
// chasing a finding, and both are small enough that indenting costs nothing.
// Everything else is fed to a tool. Unknown names default to indented: a new
// document is more likely to be a summary than a dump, and guessing wrong that
// way only wastes bytes rather than making a file unreadable.
func readByEye(name string) bool {
	switch filepath.Base(name) {
	case "findings.sarif", "sbom.cdx.json":
		return false
	default:
		return true
	}
}
