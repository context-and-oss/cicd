package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	moduleName  = "risk"
	moduleStage = "domain"
)

// Risk provides AI-driven repository risk analysis with OPA policy enforcement.
// Use Scan to generate findings (committed to the repo), Validate to gate CI,
// Check as a Dagger check directive, and Report to render a markdown summary.
type Risk struct{}

// ParsedViolation is a single conftest violation enriched with the
// policy-supplied severity (lowercase, as emitted by the rego rule).
// Empty Severity means the conftest entry carried no metadata.severity field.
type ParsedViolation struct {
	Msg      string
	Severity string
	PolicyID string
	Filename string
	Resource string
}

// parseConftestViolations parses conftest JSON output into deduplicated
// violations carrying msg + policy severity.
//
// Why dedup: rego policies in this repo follow a `violation contains finding`
// / `deny contains msg` pattern. Conftest reports both rule families in the
// `failures` channel, so each unique finding shows up twice — once with full
// metadata (from `violation`), once as a bare msg (from `deny`). Without
// dedup the envelope's findingsCount is doubled and half the entries lack
// severity.
//
// Dedup scope: per file. Conftest emits one result entry per input file with
// its own `filename`; the same msg in two files is a legitimately separate
// finding (e.g., the same unpinned action in workflow_a.yml and workflow_b.yml).
// Keying by filename+msg keeps cross-file findings distinct while still
// collapsing the violation+deny duplicate emitted for one file.
//
// A non-nil error means the output is not conftest JSON — an empty stdout, a
// truncated write, a tool that printed a Go panic. That used to be returned as a
// single synthetic HIGH violation reading "Failed to parse conftest JSON output",
// which is the false-pass shape this repository forbids twice over: the evidence
// claimed a policy violation that no policy produced, and at `--fail-on NONE` the
// severity was suppressed and the run reported clean. The caller must put the
// error in the envelope's errors[] and fail the gate at every threshold.
func parseConftestViolations(output string) ([]ParsedViolation, error) {
	type entry struct {
		Msg      string `json:"msg"`
		Metadata struct {
			Severity string `json:"severity"`
			PolicyID string `json:"id"`
			Resource string `json:"resource"`
		} `json:"metadata"`
	}
	var results []struct {
		Filename string  `json:"filename"`
		Failures []entry `json:"failures"`
		Warnings []entry `json:"warnings"`
	}
	if strings.TrimSpace(output) == "" {
		// Distinguished from a decode failure on purpose: conftest --output json
		// always writes a document, so nothing at all means the tool produced no
		// output rather than bad output, and the remedy differs.
		return nil, fmt.Errorf("conftest wrote no output")
	}
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("conftest output is not JSON: %w", err)
	}
	if len(results) == 0 {
		// `null` and `[]` decode without error into no results, and used to
		// read as no violations. Measured against conftest v0.58.0, every input
		// file gets a result, even one no policy namespace matched, so an empty
		// list means nothing was evaluated rather than nothing was wrong.
		return nil, fmt.Errorf("conftest output names no evaluated file")
	}

	byKey := make(map[string]int)
	var out []ParsedViolation
	add := func(filename string, e entry) {
		if e.Msg == "" {
			return
		}
		msg := "  - " + e.Msg
		key := filename + "\x00" + msg
		if idx, ok := byKey[key]; ok {
			// Already seen — upgrade metadata if the new entry has it and the existing doesn't.
			if out[idx].Severity == "" && e.Metadata.Severity != "" {
				out[idx].Severity = e.Metadata.Severity
			}
			if out[idx].PolicyID == "" && e.Metadata.PolicyID != "" {
				out[idx].PolicyID = e.Metadata.PolicyID
			}
			if out[idx].Resource == "" && e.Metadata.Resource != "" {
				out[idx].Resource = e.Metadata.Resource
			}
			return
		}
		byKey[key] = len(out)
		out = append(out, ParsedViolation{
			Msg:      msg,
			Severity: e.Metadata.Severity,
			PolicyID: e.Metadata.PolicyID,
			Filename: filename,
			Resource: e.Metadata.Resource,
		})
	}
	for _, r := range results {
		for _, f := range r.Failures {
			add(r.Filename, f)
		}
		for _, w := range r.Warnings {
			add(r.Filename, w)
		}
	}
	return out, nil
}

// normalizeSeverity maps a policy-supplied severity string (any case, possibly
// empty) to the module's canonical Severity. Missing or unknown values fall
// back to HIGH so findings remain visible at the default fail-on threshold.
func normalizeSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	}
	return SeverityHigh
}

// shouldFail returns true when any finding at or above threshold exists.
// SeverityNone always returns false (never fail). Threshold is inclusive.
func shouldFail(bySeverity map[Severity]int, threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for _, sev := range order {
		if bySeverity[sev] > 0 {
			return true
		}
		if sev == threshold {
			return false
		}
	}
	return false
}
