package main

import (
	"encoding/json"
	"regexp"
	"slices"
)

// This is a descriptive projection, never an input to severity or gate logic.
// Unknown/malformed optional metadata cannot remove an otherwise usable finding.
func applyFindingMetadata(f *Finding, raw json.RawMessage) {
	var m struct {
		Concern              Concern  `json:"concern"`
		Category             string   `json:"category"`
		Subcategories        []string `json:"subcategories"`
		Confidence           string   `json:"confidence"`
		WeaknessIDs          []string `json:"weaknessIds"`
		ClassificationSource string   `json:"classificationSource"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	switch m.Concern {
	case ConcernSAST, ConcernSCA, ConcernSecrets, ConcernLicenses, ConcernSBOM,
		ConcernLint, ConcernTests, ConcernCoverage, ConcernIaC, ConcernDAST:
		f.Concern = m.Concern
	}
	if m.ClassificationSource != "scanner-metadata" {
		return
	}
	switch m.Category {
	case "security", "correctness", "maintainability", "style", "unknown":
		f.Category = m.Category
	}
	switch m.Confidence {
	case "HIGH", "MEDIUM", "LOW":
		f.Confidence = m.Confidence
	}
	for _, s := range m.Subcategories {
		if s == "audit" || s == "vuln" {
			f.Subcategories = append(f.Subcategories, s)
		}
	}
	for _, id := range m.WeaknessIDs {
		if weaknessID.MatchString(id) {
			f.WeaknessIDs = append(f.WeaknessIDs, id)
		}
	}
	slices.Sort(f.Subcategories)
	f.Subcategories = slices.Compact(f.Subcategories)
	slices.Sort(f.WeaknessIDs)
	f.WeaknessIDs = slices.Compact(f.WeaknessIDs)
	if f.Category != "" || f.Confidence != "" || len(f.Subcategories) > 0 || len(f.WeaknessIDs) > 0 {
		f.ClassificationSource = m.ClassificationSource
	}
}

var weaknessID = regexp.MustCompile(`^CWE-[1-9][0-9]*$`)
