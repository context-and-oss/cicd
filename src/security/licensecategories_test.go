package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The licence taxonomy this module reasons about belongs to Trivy, not to cicd,
// and for five releases a comment in licensereport.go described it wrongly:
// it filed LGPL under `reciprocal`, when Trivy files LGPL-2.0/2.1/3.0 under
// `restricted` beside GPL, and AGPL under `forbidden`. Nothing contradicted the
// sentence, so it was quoted in review and in the issue that eventually found
// it, and a consumer reading it would have expected
// `--license-allow reciprocal` to accept weak copyleft. It accepts neither
// LGPL nor GPL.
//
// So the taxonomy is pinned against a fixture captured from the pinned Trivy's
// own source rather than from its documentation or from memory. The fixture is
// data, and these tests are the only place that reads it: when the Trivy pin in
// images.go moves, recapture it and let the diff say what changed. A category
// added upstream shows up here as a category cicd has no constant for, which is
// the case knownLicenseCategories exists to refuse loudly.

type trivyLicenseTaxonomy struct {
	TrivyVersion     string              `json:"trivyVersion"`
	Categories       []string            `json:"categories"`
	CategorySeverity map[string]string   `json:"categorySeverity"`
	Licenses         map[string][]string `json:"licenses"`
}

func loadTrivyTaxonomy(t *testing.T) trivyLicenseTaxonomy {
	t.Helper()
	path := filepath.Join("testdata", "trivy-0.70.0-license-categories.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc trivyLicenseTaxonomy
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	// A fixture that decoded to nothing would make every assertion below pass
	// by vacuity, which is the shape of failure this whole module is about.
	if len(doc.Categories) == 0 || len(doc.Licenses) == 0 {
		t.Fatalf("%s decoded to an empty taxonomy", path)
	}
	return doc
}

// TestTheFixtureTracksThePinnedTrivy keeps the fixture and the image pin
// together. A recapture from a different Trivy is still readable, and would
// otherwise pin the wrong release's answers.
func TestTheFixtureTracksThePinnedTrivy(t *testing.T) {
	doc := loadTrivyTaxonomy(t)
	if doc.TrivyVersion != trivyVersion {
		t.Fatalf("fixture captured from trivy %s, images.go pins %s — recapture "+
			"src/security/testdata/ and re-read the diff", doc.TrivyVersion, trivyVersion)
	}
}

// TestKnownCategoriesMatchTrivysOwnSet is the closed-set claim
// knownLicenseCategories makes. Both directions: a category Trivy has that cicd
// does not know would be validated away as a typo, and a category cicd invented
// would never match a report.
func TestKnownCategoriesMatchTrivysOwnSet(t *testing.T) {
	doc := loadTrivyTaxonomy(t)
	for _, category := range doc.Categories {
		if !slices.Contains(knownLicenseCategories, category) {
			t.Errorf("trivy category %q has no constant in knownLicenseCategories", category)
		}
	}
	for _, category := range knownLicenseCategories {
		if !slices.Contains(doc.Categories, category) {
			t.Errorf("knownLicenseCategories names %q, which trivy %s does not emit",
				category, doc.TrivyVersion)
		}
	}
}

// TestLicenseSeverityMatchesTrivysProjection checks cicd's category→severity
// map against Trivy's categoryToSeverity, with one deliberate divergence.
// licensereport.go derives severity itself rather than reading Trivy's field,
// so the two are allowed to differ — but only on purpose, and `unknown` is the
// only place it does: Trivy answers UNKNOWN, cicd answers HIGH, because a
// licence nobody could classify is exactly what a compliance check is for.
func TestLicenseSeverityMatchesTrivysProjection(t *testing.T) {
	doc := loadTrivyTaxonomy(t)
	for category, want := range doc.CategorySeverity {
		got := licenseSeverity(category)
		if category == licenseUnknown {
			if got != SeverityHigh {
				t.Errorf("unknown must map to HIGH (fail-closed), got %s", got)
			}
			continue
		}
		if string(got) != want {
			t.Errorf("category %q: trivy says %s, licenseSeverity says %s",
				category, want, got)
		}
	}
	// An unfamiliar category takes the same fail-closed route as unknown.
	if got := licenseSeverity("copyleft-ish"); got != SeverityHigh {
		t.Errorf("an unrecognised category must map to HIGH, got %s", got)
	}
}

// TestTheCopyleftCliffIsWhereTheCommentSaysItIs is the assertion the wrong
// comment would have failed. Each name below is quoted in prose somewhere in
// this repository, so each one is checked against the captured table.
func TestTheCopyleftCliffIsWhereTheCommentSaysItIs(t *testing.T) {
	doc := loadTrivyTaxonomy(t)
	want := map[string]string{
		"AGPL-1.0":  licenseForbidden,
		"AGPL-3.0":  licenseForbidden,
		"WTFPL":     licenseForbidden,
		"GPL-2.0":   licenseRestricted,
		"GPL-3.0":   licenseRestricted,
		"LGPL-2.1":  licenseRestricted,
		"LGPL-3.0":  licenseRestricted,
		"MPL-2.0":   licenseReciprocal,
		"EPL-2.0":   licenseReciprocal,
		"CDDL-1.0":  licenseReciprocal,
		"Ruby":      licenseReciprocal,
		"CC0-1.0":   licenseUnencumbered,
		"Unlicense": licenseUnencumbered,
	}
	for name, category := range want {
		if !slices.Contains(doc.Licenses[category], name) {
			t.Errorf("%s is not in trivy's %q list — the taxonomy moved, and every "+
				"sentence in this repository naming it needs rereading", name, category)
		}
	}
	// The sentence that was wrong, stated as a test: no GNU copyleft licence is
	// reciprocal. `--license-allow reciprocal` accepts MPL and EPL and nothing
	// from the GPL family.
	for _, name := range doc.Licenses[licenseReciprocal] {
		// HasPrefix rather than a slice: a three-character name would make
		// name[:4] panic, and the test that guards a taxonomy must not be the
		// thing that breaks when the taxonomy changes shape.
		if strings.HasPrefix(name, "GPL") || strings.HasPrefix(name, "LGPL") ||
			strings.HasPrefix(name, "AGPL") {
			t.Errorf("reciprocal contains %q — the comment in licensereport.go is "+
				"describing a different taxonomy again", name)
		}
	}
}

// TestTheDefaultAllowlistAdmitsNoSourceSharingObligation states what the
// default policy is, in the terms a consumer reads it in: every category it
// admits imposes at most attribution. The fixture is the evidence — the test
// asserts over the captured lists, not over a second copy of the claim.
func TestTheDefaultAllowlistAdmitsNoSourceSharingObligation(t *testing.T) {
	doc := loadTrivyTaxonomy(t)
	obliged := map[string]bool{
		licenseForbidden: true, licenseRestricted: true, licenseReciprocal: true,
	}
	for _, category := range defaultLicenseAllowlist {
		if obliged[category] {
			t.Errorf("defaultLicenseAllowlist admits %q, which holds source-sharing "+
				"obligations (for example %v)", category, doc.Licenses[category])
		}
		if !slices.Contains(knownLicenseCategories, category) {
			t.Errorf("defaultLicenseAllowlist names %q, which is not a known category", category)
		}
	}
	// And it is not empty, which would flag MIT and get the check switched off.
	if len(defaultLicenseAllowlist) == 0 {
		t.Fatal("an empty default allowlist flags every dependency, including MIT")
	}
}
