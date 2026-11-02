// SBOM input validation for ScanSbom.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so sbominput_test.go can drive it with `go test -tags unit_test ./...`.
//
// The check runs before any container is built, because Trivy answers a
// document it cannot read with its own error, and classifying that after the
// fact names Trivy's failure rather than the real cause — the caller handed
// cicd something that was never a CycloneDX document. Failing here puts the
// actual defect in errors[], where it fails the gate at every threshold
// including --fail-on NONE, because a rescan that never read its SBOM must
// never read as a rescan that found nothing.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// sbomInputError returns a non-run error message when contents is not a
// CycloneDX JSON document, and "" when it is. Only the document shape is
// checked — whether the components inside are scannable is Trivy's verdict to
// give. The UTF-8 BOM is stripped once before parsing (the read-the-document-
// a-leg-wrote lesson: encoding/json refuses a BOM'd document outright, and a
// document carrying two BOMs stays malformed rather than being laundered).
func sbomInputError(contents string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(contents, "\ufeff"))
	if trimmed == "" {
		return "sbom-input: the supplied SBOM file is empty, so there is nothing to rescan"
	}
	if !json.Valid([]byte(trimmed)) {
		return "sbom-input: the supplied SBOM is not valid JSON, so it cannot be a CycloneDX document"
	}

	var doc struct {
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil || doc.BomFormat == "" {
		return "sbom-input: the supplied JSON declares no bomFormat, so it is not a CycloneDX SBOM — cicd's own SBOMs carry one under the envelope key cyclonedxReport"
	}
	if doc.BomFormat != "CycloneDX" {
		return fmt.Sprintf("sbom-input: the supplied document declares bomFormat %q, not %q — only CycloneDX can be rescanned here", doc.BomFormat, "CycloneDX")
	}
	return ""
}
