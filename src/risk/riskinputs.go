// The findings and decisions files, read and merged into the one input the
// findings/decisions policy pass evaluates.
//
// Untagged (no //go:build !unit_test): opa.go carries the Dagger build tag,
// and the parse rules below — which file is refused, with which message, and
// what the merged document looks like — were unreachable from any test for as
// long as they lived beside the container calls.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// riskInputs is the parsed pair, plus the merged document conftest reads.
type riskInputs struct {
	findings  FindingsFile
	decisions map[string]Decision
	// merged is {"findings": [...], "decisions": {...}}, the input shape
	// policy/findings/ is written against.
	merged []byte
}

// parseRiskInputs refuses either file it cannot parse, naming the file. Both
// are refused as hard errors rather than filed under errors[]: the pass fails
// before there is an envelope to put anything in, and a findings review that
// cannot be read is not a review that found nothing.
//
// Each file must also be the shape a scan writes, not merely valid JSON:
// `null`, `{}` and `{"findings": null}` decode without error into a review of
// no findings and used to pass as one. A findings.json cicd read and could not
// use must not look like a review that found nothing. `{"findings": []}` stays
// a legitimate empty review.
func parseRiskInputs(findingsJSON, decisionsJSON string) (riskInputs, error) {
	var in riskInputs
	if err := json.Unmarshal([]byte(findingsJSON), &in.findings); err != nil {
		return riskInputs{}, fmt.Errorf("parse findings.json: %w", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(findingsJSON), &probe); err != nil || probe == nil {
		return riskInputs{}, fmt.Errorf("parse findings.json: not a JSON object")
	}
	if raw, ok := probe["findings"]; !ok || strings.TrimSpace(string(raw)) == "null" {
		return riskInputs{}, fmt.Errorf("parse findings.json: no \"findings\" array, so this is not a risk scan's output and no finding was reviewed")
	}
	in.decisions = map[string]Decision{}
	if err := json.Unmarshal([]byte(decisionsJSON), &in.decisions); err != nil {
		return riskInputs{}, fmt.Errorf("parse decisions.json: %w", err)
	}
	if in.decisions == nil {
		return riskInputs{}, fmt.Errorf("parse decisions.json: null is not a decisions map")
	}
	merged, err := json.Marshal(map[string]any{"findings": in.findings.Findings, "decisions": in.decisions})
	if err != nil {
		return riskInputs{}, fmt.Errorf("merge findings+decisions: %w", err)
	}
	in.merged = merged
	return in, nil
}
