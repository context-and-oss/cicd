package main

import (
	"strings"
	"testing"
)

// dastFindings is the shape this rollup exists for: a web scan, where the
// location is an endpoint, ZAP reports no line at all, and one rule firing on
// many URLs produces many rows.
func dastFindings(n int, path string, sev Severity) []Finding {
	out := make([]Finding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Finding{
			Severity: sev, Tool: "zap", Rule: "10015",
			Message: "Re-examine Cache-control Directives", ArtifactPath: path,
		})
	}
	return out
}

func rollup(findings []Finding) string {
	var sb strings.Builder
	writeLocationRollup(&sb, findings)
	return sb.String()
}

// TestTheRollupNamesTheEndpointsTheTruncatedTableCannot.
//
// 40 findings over 3 endpoints renders as 25 rows and "+15 more". Every
// endpoint may well be in the 25 — or none of them may be. The rollup is the
// only part of the comment that answers "where" without the reader opening the
// evidence artifact.
func TestTheRollupNamesTheEndpointsTheTruncatedTableCannot(t *testing.T) {
	var findings []Finding
	findings = append(findings, dastFindings(20, "http://app/api/orders", SeverityMedium)...)
	findings = append(findings, dastFindings(15, "http://app/api/users", SeverityHigh)...)
	findings = append(findings, dastFindings(5, "http://app/swagger/index.html", SeverityLow)...)

	got := rollup(findings)
	for _, want := range []string{"api/orders", "api/users", "swagger/index.html"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing from the rollup:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "| 20 |") || !strings.Contains(got, "| 15 |") {
		t.Errorf("per-location counts missing:\n%s", got)
	}
}

// TestTheRollupOrdersByCountAndBreaksTiesBySeverityNotAlphabet.
//
// The envelope's order is most-severe-first, so first-appearance carries
// severity into the tie-break. An alphabetical tie-break would be equally
// deterministic and would sort a critical endpoint below an "a" one.
func TestTheRollupOrdersByCountAndBreaksTiesBySeverityNotAlphabet(t *testing.T) {
	var findings []Finding
	findings = append(findings, dastFindings(2, "http://app/z-critical", SeverityCritical)...)
	findings = append(findings, dastFindings(2, "http://app/a-low", SeverityLow)...)
	findings = append(findings, dastFindings(9, "http://app/m-medium", SeverityMedium)...)
	// Truncation is what makes the rollup render at all here.
	findings = append(findings, dastFindings(20, "http://app/busy", SeverityLow)...)

	got := rollup(findings)
	order := []string{"busy", "m-medium", "z-critical", "a-low"}
	at := -1
	for _, want := range order {
		i := strings.Index(got, want)
		if i < 0 {
			t.Fatalf("%q missing:\n%s", want, got)
		}
		if i < at {
			t.Errorf("%q rendered out of order; want %v:\n%s", want, order, got)
		}
		at = i
	}
}

// TestTheRollupReportsTheWorstSeverityAtEachLocation. A location with one HIGH
// is a different errand from one with forty LOWs, and a count alone cannot
// separate them.
func TestTheRollupReportsTheWorstSeverityAtEachLocation(t *testing.T) {
	findings := dastFindings(30, "http://app/api/orders", SeverityLow)
	findings[17].Severity = SeverityHigh
	got := rollup(findings)
	if !strings.Contains(got, "HIGH") {
		t.Errorf("the one HIGH at this location was rolled up as LOW:\n%s", got)
	}
}

// TestTheRollupIsSilentWhenGroupingChangesNothing. Six findings on six
// locations, all six rendered above: the rollup would be the same rows in the
// same order with a 1 in every count column.
func TestTheRollupIsSilentWhenGroupingChangesNothing(t *testing.T) {
	var findings []Finding
	for _, p := range []string{"a.go", "b.go", "c.go", "d.go", "e.go", "f.go"} {
		findings = append(findings, Finding{Severity: SeverityLow, Tool: "semgrep", ArtifactPath: p})
	}
	if got := rollup(findings); got != "" {
		t.Errorf("a rollup that compresses nothing rendered anyway:\n%s", got)
	}
}

// TestTheRollupSpeaksWheneverGroupingCompresses, even under the table cap:
// "12 findings, 2 files" is worth a line the untruncated table does not give.
func TestTheRollupSpeaksWheneverGroupingCompresses(t *testing.T) {
	var findings []Finding
	findings = append(findings, dastFindings(7, "http://app/api/orders", SeverityLow)...)
	findings = append(findings, dastFindings(5, "http://app/api/users", SeverityLow)...)
	if got := rollup(findings); got == "" {
		t.Error("12 findings over 2 endpoints produced no rollup")
	}
}

// TestAnUnlocatedFindingIsCountedAndNeverPlacedSomewhere.
//
// A producer that reported no location has said something. Attaching that
// finding to the nearest path would be the rollup inventing the one fact it
// exists to report; dropping it would under-count the total it summarises.
func TestAnUnlocatedFindingIsCountedAndNeverPlacedSomewhere(t *testing.T) {
	findings := dastFindings(26, "http://app/api/orders", SeverityLow)
	findings = append(findings, Finding{Severity: SeverityMedium, Tool: "zap", Message: "no instances"})
	got := rollup(findings)
	if !strings.Contains(got, "no location stated") {
		t.Errorf("an unlocated finding vanished from the rollup:\n%s", got)
	}

	groups, unlocated := groupByLocation(findings)
	total := unlocated
	for _, g := range groups {
		total += g.Count
	}
	if total != len(findings) {
		t.Errorf("rollup accounts for %d of %d findings", total, len(findings))
	}
	if len(groups) != 1 {
		t.Errorf("the unlocated finding became a location: %+v", groups)
	}
}

// TestTheRollupGroupsALineNumberedFileOnceForTheWholeFile. Three findings on
// three lines of one file are one file to open.
func TestTheRollupGroupsALineNumberedFileOnceForTheWholeFile(t *testing.T) {
	var findings []Finding
	for i := 1; i <= 30; i++ {
		findings = append(findings, Finding{
			Severity: SeverityLow, Tool: "gitleaks", ArtifactPath: ".env", Line: i,
		})
	}
	groups, _ := groupByLocation(findings)
	if len(groups) != 1 || groups[0].Count != 30 {
		t.Errorf("line numbers de-grouped one file into %d locations: %+v", len(groups), groups)
	}
}

// TestTheRollupIsCappedAndSaysByHowMuch.
func TestTheRollupIsCappedAndSaysByHowMuch(t *testing.T) {
	var findings []Finding
	for i := 0; i < maxRolledUpLocations+4; i++ {
		findings = append(findings, dastFindings(2, "http://app/api/"+string(rune('a'+i)), SeverityLow)...)
	}
	got := rollup(findings)
	if !strings.Contains(got, "+4 more location(s)") {
		t.Errorf("the overflow count is wrong or missing:\n%s", got)
	}
	if n := strings.Count(got, "| `http://app/api/"); n != maxRolledUpLocations {
		t.Errorf("rendered %d location rows, want %d", n, maxRolledUpLocations)
	}
}

// TestARollupLocationCannotCloseItsOwnCodeSpan. A ZAP instance URI is a URL the
// application under test controls, and this renderer writes it inside backticks
// in a comment posted under cicd's name. Same rule as every other cell; see
// specs/fence-the-span-a-branch-name-can-close.md.
func TestARollupLocationCannotCloseItsOwnCodeSpan(t *testing.T) {
	nasty := "http://app/api/`|`x?q=`"
	findings := dastFindings(26, nasty, SeverityLow)
	got := rollup(findings)
	if strings.Contains(got, "| `"+nasty) {
		t.Errorf("the location was rendered in a span it can close:\n%s", got)
	}
	if !strings.Contains(got, cellCode(nasty)) {
		t.Errorf("the location was not rendered through cellCode:\n%s", got)
	}
}
