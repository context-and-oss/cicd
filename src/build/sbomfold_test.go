package main

import (
	"errors"
	"strings"
	"testing"
)

// The founding rule for Sbom: a document that is not a CycloneDX BOM is a
// non-run, never an image with nothing in it, at every threshold.
func TestNonRunMatrixSbom(t *testing.T) {
	notABOM := []string{``, ` `, `null`, `[]`, `{}`, `"x"`, `not json`, `{"bomFormat":`,
		`{"bomFormat":"SPDX","specVersion":"1.5"}`, `{"bomFormat":"CycloneDX"}`}
	for _, raw := range notABOM {
		f := foldSbom(raw, nil)
		if f.ran || len(f.errs) != 1 || f.report != nil || f.examined != nil {
			t.Errorf("%q: ran=%v errs=%q report=%s examined=%v, want a non-run with no inventory", raw, f.ran, f.errs, f.report, f.examined)
		}
		if scanOutcome(f.ran, 0) != OutcomeError {
			t.Errorf("%q: outcome %s, want ERROR", raw, scanOutcome(f.ran, 0))
		}
	}

	f := foldSbom(`{"bomFormat":"CycloneDX"}`, errors.New("trivy sbom: exit 1"))
	if f.ran || len(f.errs) != 1 || f.errs[0] != "trivy sbom: exit 1" {
		t.Errorf("run error: ran=%v errs=%q", f.ran, f.errs)
	}

	f = foldSbom(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"},{"name":"b"}]}`+"\n", nil)
	if !f.ran || len(f.errs) != 0 || f.examined == nil || f.examined.Count != 2 || f.examined.Unit != "components" || len(f.warnings) != 0 {
		t.Fatalf("control: a BOM: %+v", f)
	}

	f = foldSbom(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`, nil)
	if !f.ran || f.examined == nil || f.examined.Count != 0 || len(f.warnings) != 1 || !strings.Contains(f.warnings[0], "no components") {
		t.Fatalf("an empty BOM ran, says it counted zero, and warns: %+v", f)
	}
}
