// Which embedded document an envelope yields, and under which filename.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session, and for as long as the
// selection lived beside the entry function no test could reach it. The
// function existed "so it can be unit-tested without a Dagger connection" and
// had no test, which is the same thing as none.
package main

import (
	"encoding/json"
	"fmt"
)

// reportEnvelope is a minimal parse target — only the report fields we need.
type reportEnvelope struct {
	SARIFReport     json.RawMessage `json:"sarifReport"`
	CycloneDXReport json.RawMessage `json:"cyclonedxReport"`
	GenericReport   json.RawMessage `json:"genericReport"`
}

// extractFromJSON parses evidence JSON and returns the embedded report bytes and filename.
//
// Priority: sarifReport → cyclonedxReport → genericReport. A field that is
// absent or JSON null is passed over for the next; an envelope with none
// populated is an error, never an empty file, because an empty report is what
// a consumer's `upload-sarif` step would accept as a clean scan.
func extractFromJSON(content string) ([]byte, string, error) {
	var env reportEnvelope
	if err := json.Unmarshal([]byte(content), &env); err != nil {
		return nil, "", fmt.Errorf("parse evidence JSON: %w", err)
	}
	switch {
	case len(env.SARIFReport) > 0 && string(env.SARIFReport) != "null":
		return []byte(env.SARIFReport), "report.sarif", nil
	case len(env.CycloneDXReport) > 0 && string(env.CycloneDXReport) != "null":
		return []byte(env.CycloneDXReport), "report.cdx.json", nil
	case len(env.GenericReport) > 0 && string(env.GenericReport) != "null":
		return []byte(env.GenericReport), "report.json", nil
	default:
		return nil, "", fmt.Errorf("evidence envelope contains no embedded report (sarifReport, cyclonedxReport, and genericReport are all empty or null)")
	}
}
