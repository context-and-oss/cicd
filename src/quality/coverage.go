package main

// coverage.go holds the pure logic behind Quality.Test (BYO test, ADR-002):
// coverage-report format sniffing/parsing, baseline sniffing and the
// coverage ratchet rule (ADR-003). No Dagger imports — this file compiles
// under both build modes so plain `go test -tags unit_test` covers it
// (gating_test.go pattern).
//
// The v8/pytest/go parsers here intentionally duplicate the small structs in
// test.go (parseVitestCoverage, parsePytestCoverage, parseCoberturaRate):
// test.go is frozen behind the !unit_test tag, so its helpers are invisible
// to the unit-test build and cannot back the sniffer.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Coverage report formats recognized by sniffCoverageReport.
const (
	covFormatGoCover   = "go-coverprofile"
	covFormatV8Summary = "v8-json-summary"
	covFormatPytestCov = "pytest-cov-json"
	covFormatCobertura = "cobertura-xml"
)

// Ratchet verdicts recorded in the envelope's coverageRatchet field
// (schema.go). The skipped:* verdicts are fail-open by design (ADR-003).
const (
	ratchetPass           = "pass"
	ratchetFail           = "fail"
	ratchetSkipNoBaseline = "skipped:no-baseline"
	ratchetSkipNoCoverage = "skipped:no-coverage-output"
	ratchetSkipWarnMode   = "skipped:warn-mode"
)

// utf8BOM is the byte order mark Microsoft.Testing.Platform writes at the head
// of every cobertura document it produces.
//
// It has to be stripped explicitly, because strings.TrimSpace does not do it:
// U+FEFF was removed from the White_Space property in Unicode 4.0.1, so
// unicode.IsSpace(U+FEFF) is false. A BOM'd document therefore still begins
// U+FEFF rather than "<", no arm of sniffCoverageReport's switch fires, and a
// document that parses perfectly well is reported as being in no recognized
// coverage format.
//
// parseCobertura is innocent: xml.Unmarshal strips the BOM itself and returns
// the same figures either way (measured on a real MTP report — 25% over some 3,400
// coverable lines with the BOM present and absent). The defect was one frame
// out, in the sniffer that decides which parser to call, which is why cicd's own
// .NET leg never hit it — parseCoberturaSet calls parseCobertura directly and
// never goes through the sniffer, so the bug was reachable only from the BYO
// coverageGlob path and shipped invisible.
const utf8BOM = "\uFEFF"

// stripBOM removes a leading UTF-8 BOM, tolerating whitespace on either side of
// it so a caller can test a document's first real character.
//
// Applied before the format switch rather than inside its XML arm, because the
// JSON arm has exactly the same exposure the moment any tool writes a BOM'd
// json-summary — and the failure would look identical: a readable report
// reported as unreadable.
//
// Stripped once, not with TrimLeft: one BOM is what a writer emits, and a
// document carrying two is malformed in a way this code should not launder into
// a measurement.
func stripBOM(raw string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), utf8BOM))
}

// coverageReport is the normalized result of parsing a coverage file.
type coverageReport struct {
	// Format identifies which parser recognized the report (covFormat*).
	Format string
	// Pct is the line/statement coverage percentage (0–100).
	Pct float64
	// Lines is the number of coverable lines/statements; 0 when the
	// format omits it.
	Lines int
}

// sniffCoverageReport detects the format of a coverage report and parses it.
// Recognized formats: go coverprofile ("mode:" header), cobertura XML,
// v8 json-summary (top-level "total"), pytest-cov JSON (top-level "totals").
// Returns ok=false for empty, unrecognized or unparseable input.
func sniffCoverageReport(raw string) (coverageReport, bool) {
	trimmed := stripBOM(raw)
	switch {
	case trimmed == "":
		return coverageReport{}, false
	case strings.HasPrefix(trimmed, "mode:"):
		pct, lines, ok := parseGoCoverprofile(trimmed)
		return coverageReport{Format: covFormatGoCover, Pct: pct, Lines: lines}, ok
	case strings.HasPrefix(trimmed, "<"):
		pct, lines, ok := parseCobertura(trimmed)
		return coverageReport{Format: covFormatCobertura, Pct: pct, Lines: lines}, ok
	case strings.HasPrefix(trimmed, "{"):
		var probe map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
			return coverageReport{}, false
		}
		if _, isV8 := probe["total"]; isV8 {
			pct, lines, ok := parseV8Summary(trimmed)
			return coverageReport{Format: covFormatV8Summary, Pct: pct, Lines: lines}, ok
		}
		if _, isPytest := probe["totals"]; isPytest {
			pct, lines, ok := parsePytestCovJSON(trimmed)
			return coverageReport{Format: covFormatPytestCov, Pct: pct, Lines: lines}, ok
		}
		return coverageReport{}, false
	}
	return coverageReport{}, false
}

// parseCobertura parses a Cobertura XML coverage report: the root
// <coverage> element's line-rate attribute (0–1) yields the percentage and
// lines-valid the coverable line count. A missing or non-numeric line-rate makes
// the report unusable (ok=false), and so does an absent or zero lines-valid.
//
// That last rule replaces "a missing lines-valid degrades to 0", which was a
// documented decision and a measured wrong number. A test project that runs tests
// but instruments nothing writes a valid 178-byte report:
//
//	<coverage line-rate="1" branch-rate="1" complexity="1" version="1.9" …>
//	  <packages />
//	</coverage>
//
// Degrading gave (100.0, 0, ok=true). mergeDotnetCoverage skips zero-line reports
// from its weighted sum, so when *every* report is empty it falls through to the
// unweighted mean and returns 100% with a nil line count — and a coverage gate
// then reads **100% for a repository that measured nothing**. This is worse than
// a figure that is merely wrong: it is wrong in the direction that survives a
// ratchet. A deflated figure is noticed on the next run when it fails to clear
// the bar; an inflated one *sets* the bar, and locks the consumer to a number no
// code change can reach.
//
// The precedent is four functions below: parseGoCoverprofile returns ok=false at
// zero statements because "a profile with no statements carries no coverage
// information". A cobertura document with no coverable lines carries none either.
// Not MTP-specific — coverlet writes the same document for the same tree, so this
// exposure predates the runner work and every .NET consumer had it.
func parseCobertura(raw string) (pct float64, lines int, ok bool) {
	var doc struct {
		XMLName    xml.Name `xml:"coverage"`
		LineRate   string   `xml:"line-rate,attr"`
		LinesValid string   `xml:"lines-valid,attr"`
	}
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		return 0, 0, false
	}
	rate, err := strconv.ParseFloat(doc.LineRate, 64)
	if err != nil {
		return 0, 0, false
	}
	lines, err = strconv.Atoi(doc.LinesValid)
	if err != nil || lines <= 0 {
		return 0, 0, false
	}
	return rate * 100, lines, true
}

// parseGoCoverprofile computes coverage from a raw Go coverage profile
// (coverage.out). Each non-header line is "file:start,end numStmts hitCount";
// pct = covered statements / total statements. A profile with no statements
// carries no coverage information (ok=false).
func parseGoCoverprofile(raw string) (pct float64, lines int, ok bool) {
	var total, covered int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		stmts, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		hits, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		total += stmts
		if hits > 0 {
			covered += stmts
		}
	}
	if total == 0 {
		return 0, 0, false
	}
	return float64(covered) / float64(total) * 100, total, true
}

// parseV8Summary parses the coverage-summary.json produced by
// @vitest/coverage-v8 (and istanbul's json-summary reporter generally).
func parseV8Summary(raw string) (pct float64, lines int, ok bool) {
	var summary struct {
		Total *struct {
			Lines struct {
				Pct   float64 `json:"pct"`
				Total int     `json:"total"`
			} `json:"lines"`
		} `json:"total"`
	}
	if err := json.Unmarshal([]byte(raw), &summary); err != nil || summary.Total == nil {
		return 0, 0, false
	}
	return summary.Total.Lines.Pct, summary.Total.Lines.Total, true
}

// parsePytestCovJSON parses the JSON report produced by pytest-cov
// (--cov-report=json).
func parsePytestCovJSON(raw string) (pct float64, lines int, ok bool) {
	var report struct {
		Totals *struct {
			PercentCovered float64 `json:"percent_covered"`
			NumStatements  int     `json:"num_statements"`
		} `json:"totals"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil || report.Totals == nil {
		return 0, 0, false
	}
	return report.Totals.PercentCovered, report.Totals.NumStatements, true
}

// parseBaselineCoverage sniffs a baseline document and returns its
// per-language coverage percentages. Both accepted formats — a full evidence
// envelope / combined-evidence.json and a bare
// {"coverageByLanguage": {...}} map — carry the map at the top level, so a
// single decode handles both (specs/non-container-artifacts/design.md → Contracts,
// baseline file format).
// A document without a non-empty coverageByLanguage is not a usable baseline.
func parseBaselineCoverage(raw string) (map[string]float64, error) {
	var doc struct {
		CoverageByLanguage map[string]float64 `json:"coverageByLanguage"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if len(doc.CoverageByLanguage) == 0 {
		return nil, fmt.Errorf("baseline contains no coverageByLanguage map")
	}
	return doc.CoverageByLanguage, nil
}

// ratchetInput carries everything the ratchet rule needs. Measured and
// Baseline are per-language coverage percentages; HaveCoverage/HaveBaseline
// distinguish "absent input" (fail-open skip) from "empty map".
type ratchetInput struct {
	Measured     map[string]float64
	Baseline     map[string]float64
	HaveCoverage bool
	HaveBaseline bool
	// CoveragePath is the expected report path, named in the
	// no-coverage-output skip warning.
	CoveragePath string
	Tolerance    float64
	WarnMode     bool
}

// ratchetOutcome is the result of applying the ratchet rule: a verdict for
// the envelope's coverageRatchet field plus the errors/warnings to merge
// into the envelope.
type ratchetOutcome struct {
	Verdict  string
	Errors   []string
	Warnings []string
}

// applyRatchet implements the ADR-003 ratchet rule. Per language present in
// BOTH the measured and baseline maps:
//
//	measured < baseline − tolerance  →  gate mode: error + verdict "fail"
//	                                    warn mode: warning + "skipped:warn-mode"
//
// Boundary equality (measured == baseline − tolerance) passes. Missing
// baseline or missing coverage output skips the ratchet with a warning —
// fail-open, never an error. Measured above baseline emits an advisory
// ("ratchet advances on merge"). Languages present in only one of the two
// maps get no verdict at all; if the maps share no language the rule is
// vacuously satisfied ("pass").
func applyRatchet(in ratchetInput) ratchetOutcome {
	if !in.HaveCoverage {
		at := in.CoveragePath
		if at == "" {
			at = "(no coverage-path configured)"
		}
		return ratchetOutcome{
			Verdict:  ratchetSkipNoCoverage,
			Warnings: []string{fmt.Sprintf("coverage ratchet skipped: the test command produced no coverage report at %s", at)},
		}
	}
	if !in.HaveBaseline {
		return ratchetOutcome{
			Verdict:  ratchetSkipNoBaseline,
			Warnings: []string{"coverage ratchet skipped: no baseline supplied — this run's coverage seeds the next baseline"},
		}
	}

	// Deterministic per-language order for stable evidence output.
	langs := make([]string, 0, len(in.Measured))
	for lang := range in.Measured {
		if _, inBaseline := in.Baseline[lang]; inBaseline {
			langs = append(langs, lang)
		}
	}
	sort.Strings(langs)

	var violations, advisories []string
	for _, lang := range langs {
		measured, base := in.Measured[lang], in.Baseline[lang]
		floor := base - in.Tolerance
		switch {
		case measured < floor:
			violations = append(violations, fmt.Sprintf(
				"%s coverage %.1f%% fell below baseline %.1f%% - tolerance %.1f (floor %.1f%%)",
				lang, measured, base, in.Tolerance, floor))
		case measured > base:
			advisories = append(advisories, fmt.Sprintf(
				"%s coverage %.1f%% > baseline %.1f%% — ratchet advances on merge",
				lang, measured, base))
		}
	}

	if len(violations) > 0 {
		if in.WarnMode {
			return ratchetOutcome{
				Verdict:  ratchetSkipWarnMode,
				Warnings: append(prefixErrors("coverage ratchet (warn mode)", violations), advisories...),
			}
		}
		return ratchetOutcome{
			Verdict:  ratchetFail,
			Errors:   prefixErrors("coverage ratchet", violations),
			Warnings: advisories,
		}
	}
	return ratchetOutcome{Verdict: ratchetPass, Warnings: advisories}
}
