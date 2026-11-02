package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Source and inventory licence checks have explicit, disjoint inputs. Trivy
// identifies source declarations by FilePath; package metadata has PkgName and
// no FilePath. Preserve the source declarations without applying a policy here.
func sourceLicenseReport(raw json.RawMessage) (json.RawMessage, error) {
	var doc trivyLicenseDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return nil, fmt.Errorf("source licence output is null")
	}
	for i := range doc.Results {
		var kept []licenseEntry
		for _, l := range doc.Results[i].Licenses {
			if l.FilePath != "" {
				kept = append(kept, l)
			}
		}
		doc.Results[i].Licenses = kept
	}
	return json.Marshal(doc)
}
