//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestInventoryResult_claimsSBOMWithTheDocumentsOwnCount(t *testing.T) {
	cdx := json.RawMessage(`{"bomFormat":"CycloneDX","components":[{"name":"a"},{"name":"b"},{"name":"lockfile"}]}`)
	row, err := inventoryResult(nil, trivyResult{CycloneDX: cdx})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row.Name != "trivy" || row.Concern != ConcernSBOM || row.Err != nil {
		t.Errorf("row = %+v, want trivy under sbom with no error", row)
	}
	if row.Examined == nil || row.Examined.Unit != inventoryUnit || row.Examined.Count != 3 {
		t.Errorf("examined = %+v, want 3 components", row.Examined)
	}
	rows := perToolSources(scopeSource, SeverityHigh, row)
	if !rows[0].Passed || rows[0].Outcome != OutcomeClean || rows[0].FindingsCount != 0 {
		t.Errorf("rendered row = %+v, want passed CLEAN with nothing to find", rows[0])
	}
}

func TestInventoryResult_emptyTreeIsCleanNotAnError(t *testing.T) {
	row, err := inventoryResult(nil, trivyResult{CycloneDX: json.RawMessage(`{"components":[]}`)})
	if err != nil || row.Err != nil || row.Examined == nil || row.Examined.Count != 0 {
		t.Errorf("row = %+v, err = %v; want CLEAN over 0 components", row, err)
	}
}

func TestInventoryResult_scanErrorIsCarriedOnceNotTwice(t *testing.T) {
	scanErr := errors.New("trivy: exit 1")
	row, err := inventoryResult(scanErr, trivyResult{})
	if err != nil {
		t.Errorf("a scan error is already in errors[]; inventoryResult must not add it again, got %v", err)
	}
	if row.Err != scanErr {
		t.Errorf("row.Err = %v, want the scan error so the row reads ERROR", row.Err)
	}
	if rows := perToolSources(scopeSource, SeverityNone, row); rows[0].Outcome != OutcomeError || rows[0].Passed {
		t.Errorf("rendered row = %+v, want ERROR that NONE does not forgive", rows[0])
	}
}

func TestInventoryResult_unusableInventoryIsAnErrorOnRowAndEnvelope(t *testing.T) {
	for name, cdx := range map[string]json.RawMessage{
		"absent":        nil,
		"not json":      json.RawMessage(`<xml/>`),
		"no components": json.RawMessage(`{"bomFormat":"CycloneDX"}`),
	} {
		row, err := inventoryResult(nil, trivyResult{CycloneDX: cdx})
		if err == nil || row.Err == nil || row.Err.Error() != err.Error() {
			t.Errorf("%s: row.Err = %v, err = %v; want the same error on both so Passed and the rows agree", name, row.Err, err)
		}
		if row.Examined != nil {
			t.Errorf("%s: examined = %+v, want none: zero is a claim this layer cannot make about a document it could not read", name, row.Examined)
		}
	}
}

func TestInventoryResult_dependencyFreeTreeIsSkipped(t *testing.T) {
	row, err := inventoryResult(nil, trivyResult{
		Skipped:           true,
		InventoryWarnings: []string{inventoryNotApplicableWarning},
	})
	if err != nil || row.Err != nil {
		t.Fatalf("row = %+v, err = %v; a proven dependency-free tree is not an error", row, err)
	}
	if row.Examined != nil {
		t.Errorf("examined = %+v, want absent: the inventory did not run", row.Examined)
	}
	rendered := perToolSources(scopeSource, SeverityHigh, row)[0]
	if !rendered.Passed || rendered.Outcome != OutcomeSkipped || rendered.WarningsCount != 1 {
		t.Errorf("rendered row = %+v, want a passing warned SKIPPED row", rendered)
	}
}
