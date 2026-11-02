package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// sbomFold is what Sbom states about the document Trivy wrote.
//
// Trivy runs with --exit-code 0 and the envelope used to pass whenever the
// file could be read, so an empty file, `null` or any JSON that is not a
// CycloneDX BOM went out as CLEAN with no inventory in it — an absent SBOM
// reading as an image with nothing in it, which is the one claim this
// envelope exists to keep apart. The document now has to say it is a
// CycloneDX BOM before it counts, and the components it lists are the
// denominator.
type sbomFold struct {
	report   json.RawMessage
	examined *Examined
	ran      bool
	errs     []string
	warnings []string
}

func foldSbom(raw string, runErr error) sbomFold {
	if runErr != nil {
		return sbomFold{errs: []string{runErr.Error()}}
	}
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 {
		return sbomFold{errs: []string{"trivy sbom: wrote an empty document, so no inventory was produced"}}
	}
	var doc struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if trimmed[0] != '{' || json.Unmarshal(trimmed, &doc) != nil {
		return sbomFold{errs: []string{"trivy sbom: output is not a JSON object, so no inventory was produced"}}
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion == "" {
		return sbomFold{errs: []string{fmt.Sprintf("trivy sbom: output names bomFormat %q and specVersion %q, so it is not a CycloneDX BOM and no inventory was produced", doc.BOMFormat, doc.SpecVersion)}}
	}
	f := sbomFold{
		report:   json.RawMessage(trimmed),
		examined: &Examined{Unit: "components", Count: len(doc.Components)},
		ran:      true,
	}
	if len(doc.Components) == 0 {
		// A scratch image with a stripped binary really can have nothing to
		// list, so this does not fail. It is said out loud because an image
		// Trivy could not analyse produces the same empty list.
		f.warnings = []string{"trivy sbom: the BOM lists no components; an image Trivy could not analyse reads the same as an empty one"}
	}
	return f
}
