package main

// Unit tests for ScanArchive's severity merge (Trivy source vulns + Gitleaks
// output secrets) and failOn gating, against synthetic findings. Run with:
//
//	go test -tags unit_test -run TestArchiveSeverityMerge ./...

import (
	"reflect"
	"testing"
)

// TestArchiveSeverityMerge covers the merge of the two ScanArchive
// sub-results — Trivy severity counts from source and Gitleaks secrets
// findings from the built output — including empty sub-results on either
// or both sides.
func TestArchiveSeverityMerge(t *testing.T) {
	cases := []struct {
		name    string
		trivy   map[Severity]int
		secrets []finding
		want    map[Severity]int
	}{
		{
			name:  "both populated",
			trivy: map[Severity]int{SeverityCritical: 1, SeverityMedium: 2, SeverityLow: 3},
			secrets: []finding{
				{RuleID: "aws-access-token", File: "dist/leaked.env", Line: 3},
			},
			want: map[Severity]int{SeverityCritical: 1, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3},
		},
		{
			name:  "secrets stack onto existing HIGH vulns",
			trivy: map[Severity]int{SeverityHigh: 2},
			secrets: []finding{
				{RuleID: "aws-access-token", File: "dist/leaked.env", Line: 3},
				{RuleID: "generic-api-key", File: "dist/config.js", Line: 12},
			},
			want: map[Severity]int{SeverityHigh: 4},
		},
		{
			name:  "empty trivy sub-result",
			trivy: nil,
			secrets: []finding{
				{RuleID: "aws-access-token", File: "dist/leaked.env", Line: 3},
			},
			want: map[Severity]int{SeverityHigh: 1},
		},
		{
			name:    "empty gitleaks sub-result",
			trivy:   map[Severity]int{SeverityMedium: 5},
			secrets: nil,
			want:    map[Severity]int{SeverityMedium: 5},
		},
		{
			name:    "empty gitleaks sub-result (non-nil empty slice)",
			trivy:   map[Severity]int{SeverityLow: 1},
			secrets: []finding{},
			want:    map[Severity]int{SeverityLow: 1},
		},
		{
			name:    "both sub-results empty",
			trivy:   nil,
			secrets: nil,
			want:    map[Severity]int{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSeverity(tc.trivy, bySeverityFromFindings(tc.secrets))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("merged severity = %v, want %v", got, tc.want)
			}
			total := 0
			for _, c := range got {
				total += c
			}
			wantTotal := 0
			for _, c := range tc.want {
				wantTotal += c
			}
			if total != wantTotal {
				t.Fatalf("findingsCount = %d, want %d", total, wantTotal)
			}
		})
	}
}

// TestArchiveSeverityMergeFailOnGating exercises the gating verdict ScanArchive
// computes (passed := !shouldFail(merged, threshold), then gatedPassed) at
// every failOn level against synthetic merged findings.
func TestArchiveSeverityMergeFailOnGating(t *testing.T) {
	// One planted secret (HIGH via bySeverityFromFindings) + one MEDIUM and
	// one LOW dependency vuln from Trivy.
	merged := mergeSeverity(
		map[Severity]int{SeverityMedium: 1, SeverityLow: 1},
		bySeverityFromFindings([]finding{
			{RuleID: "aws-access-token", File: "dist/leaked.env", Line: 3},
		}),
	)

	criticalOnly := map[Severity]int{SeverityCritical: 1}
	empty := map[Severity]int{}

	cases := []struct {
		name       string
		counts     map[Severity]int
		failOn     Severity
		wantPassed bool
	}{
		// Planted secret is HIGH: fails HIGH and below, passes CRITICAL-only gate.
		{"secret+vulns at CRITICAL", merged, SeverityCritical, true},
		{"secret+vulns at HIGH", merged, SeverityHigh, false},
		{"secret+vulns at MEDIUM", merged, SeverityMedium, false},
		{"secret+vulns at LOW", merged, SeverityLow, false},
		{"secret+vulns at NONE", merged, SeverityNone, true},

		// A CRITICAL finding trips every gating level.
		{"critical at CRITICAL", criticalOnly, SeverityCritical, false},
		{"critical at HIGH", criticalOnly, SeverityHigh, false},
		{"critical at MEDIUM", criticalOnly, SeverityMedium, false},
		{"critical at LOW", criticalOnly, SeverityLow, false},
		{"critical at NONE", criticalOnly, SeverityNone, true},

		// No findings passes everywhere.
		{"empty at CRITICAL", empty, SeverityCritical, true},
		{"empty at HIGH", empty, SeverityHigh, true},
		{"empty at MEDIUM", empty, SeverityMedium, true},
		{"empty at LOW", empty, SeverityLow, true},
		{"empty at NONE", empty, SeverityNone, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severityOK := !shouldFail(tc.counts, tc.failOn)
			if got := gatedPassed(true, severityOK, tc.failOn); got != tc.wantPassed {
				t.Fatalf("gatedPassed(true, %v, %s) over %v = %v, want %v",
					severityOK, tc.failOn, tc.counts, got, tc.wantPassed)
			}
		})
	}

	// A scanner that errored did not scan, so it fails at every threshold —
	// NONE included. This subtest used to assert the opposite ("fail-on NONE
	// must report passed even when a scanner errored"), which is how a Trivy
	// that could not reach its vulnerability database came out looking the same
	// as a clean archive. NONE suppresses findings, not non-runs.
	t.Run("scanner error fails even at NONE", func(t *testing.T) {
		errs := []string{"trivy: exit status 1"}
		ran := len(errs) == 0
		if gatedPassed(ran, !shouldFail(empty, SeverityNone), SeverityNone) {
			t.Fatal("a scanner that errored must not report passed, not even at fail-on NONE")
		}
	})
	t.Run("scanner error with failOn HIGH fails", func(t *testing.T) {
		errs := []string{"trivy: exit status 1"}
		ran := len(errs) == 0
		if gatedPassed(ran, !shouldFail(empty, SeverityHigh), SeverityHigh) {
			t.Fatal("a scanner error must fail the gate when failOn is not NONE")
		}
	})
}
