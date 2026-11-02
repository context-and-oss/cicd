package main

import (
	"strings"
	"testing"
)

func TestSbomInputAcceptsCycloneDX(t *testing.T) {
	cases := map[string]string{
		"minimal":       `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
		"leading space": "\n  {\"bomFormat\":\"CycloneDX\"}",
		"utf-8 bom":     "\ufeff{\"bomFormat\":\"CycloneDX\"}",
	}
	for name, doc := range cases {
		if msg := sbomInputError(doc); msg != "" {
			t.Errorf("%s: valid CycloneDX rejected: %s", name, msg)
		}
	}
}

// Each rejection must name the actual defect, because the message lands in
// errors[] where it is the only explanation the consumer gets.
func TestSbomInputRejectionsAreNamed(t *testing.T) {
	cases := map[string]struct {
		doc  string
		want string
	}{
		"empty file":        {"", "empty"},
		"whitespace only":   {" \n\t ", "empty"},
		"bom only":          {"\ufeff", "empty"},
		"not json":          {"not a document", "not valid JSON"},
		"double bom":        {"\ufeff\ufeff{\"bomFormat\":\"CycloneDX\"}", "not valid JSON"},
		"json array":        {`[1,2,3]`, "declares no bomFormat"},
		"json scalar":       {`42`, "declares no bomFormat"},
		"no bomFormat":      {`{"components":[]}`, "declares no bomFormat"},
		"spdx document":     {`{"bomFormat":"SPDX"}`, `bomFormat "SPDX"`},
		"sarif masquerades": {`{"bomFormat":"SARIF","runs":[]}`, `bomFormat "SARIF"`},
	}
	for name, tc := range cases {
		msg := sbomInputError(tc.doc)
		if msg == "" {
			t.Errorf("%s: accepted a document that is not a CycloneDX SBOM", name)
			continue
		}
		if !strings.HasPrefix(msg, "sbom-input: ") {
			t.Errorf("%s: rejection lacks the sbom-input prefix: %s", name, msg)
		}
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: rejection does not name the defect (want %q): %s", name, tc.want, msg)
		}
	}
}
