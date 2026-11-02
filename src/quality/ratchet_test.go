package main

// Truth-table tests for the ADR-003 coverage ratchet rule and the baseline
// sniffing it depends on. Run with:
//
//	go test -tags unit_test -run TestRatchet ./...

import (
	"reflect"
	"strings"
	"testing"
)

func TestRatchet_truthTable(t *testing.T) {
	cases := []struct {
		name        string
		in          ratchetInput
		wantVerdict string
		wantErrors  int
		wantWarn    int
	}{
		{
			name: "below tolerance fails in gate mode",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 85.0},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetFail,
			wantErrors:  1,
		},
		{
			name: "below tolerance warns in warn mode",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 85.0},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0, WarnMode: true,
			},
			wantVerdict: ratchetSkipWarnMode,
			wantWarn:    1,
		},
		{
			name: "boundary equality passes: measured == baseline − tolerance",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 98.0},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetPass,
		},
		{
			name: "just below the floor fails",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 97.9},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetFail,
			wantErrors:  1,
		},
		{
			name: "within tolerance passes without advisory",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 98.5},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetPass,
		},
		{
			name: "above baseline passes with advisory warning",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 99.5},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetPass,
			wantWarn:    1,
		},
		{
			name: "missing baseline skips fail-open",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 85.0},
				HaveCoverage: true, HaveBaseline: false,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetSkipNoBaseline,
			wantWarn:    1,
		},
		{
			name: "missing coverage output skips fail-open",
			in: ratchetInput{
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: false, HaveBaseline: true,
				CoveragePath: "/tmp/cov/coverage-summary.json",
				Tolerance:    1.0,
			},
			wantVerdict: ratchetSkipNoCoverage,
			wantWarn:    1,
		},
		{
			name: "both inputs missing skips on coverage first",
			in: ratchetInput{
				HaveCoverage: false, HaveBaseline: false,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetSkipNoCoverage,
			wantWarn:    1,
		},
		{
			name: "language only in measured map gets no verdict",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 10.0},
				Baseline:     map[string]float64{"python": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetPass, // vacuously satisfied — never invented
		},
		{
			name: "language only in baseline map gets no verdict",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 99.0},
				Baseline:     map[string]float64{"node": 99.0, "go": 99.9},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetPass,
		},
		{
			name: "one common language failing fails the whole verdict",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 50.0, "go": 99.0},
				Baseline:     map[string]float64{"node": 99.0, "go": 98.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 1.0,
			},
			wantVerdict: ratchetFail,
			wantErrors:  1,
			wantWarn:    1, // go advisory: above baseline
		},
		{
			name: "zero tolerance: any drop fails",
			in: ratchetInput{
				Measured:     map[string]float64{"node": 98.9},
				Baseline:     map[string]float64{"node": 99.0},
				HaveCoverage: true, HaveBaseline: true,
				Tolerance: 0.0,
			},
			wantVerdict: ratchetFail,
			wantErrors:  1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyRatchet(tc.in)
			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", got.Verdict, tc.wantVerdict)
			}
			if len(got.Errors) != tc.wantErrors {
				t.Errorf("errors = %d (%v), want %d", len(got.Errors), got.Errors, tc.wantErrors)
			}
			if len(got.Warnings) != tc.wantWarn {
				t.Errorf("warnings = %d (%v), want %d", len(got.Warnings), got.Warnings, tc.wantWarn)
			}
		})
	}
}

// Skips are warnings, never errors — fail-open by design (ADR-003).
func TestRatchet_skipsAreNeverErrors(t *testing.T) {
	for _, in := range []ratchetInput{
		{HaveCoverage: false, HaveBaseline: true, Baseline: map[string]float64{"node": 99}},
		{HaveCoverage: true, HaveBaseline: false, Measured: map[string]float64{"node": 1}},
	} {
		got := applyRatchet(in)
		if len(got.Errors) != 0 {
			t.Errorf("skip produced errors: %v", got.Errors)
		}
		if !strings.HasPrefix(got.Verdict, "skipped:") {
			t.Errorf("verdict = %q, want a skipped:* verdict", got.Verdict)
		}
	}
}

func TestRatchet_noCoverageWarningNamesExpectedPath(t *testing.T) {
	got := applyRatchet(ratchetInput{
		HaveCoverage: false, HaveBaseline: true,
		Baseline:     map[string]float64{"node": 99.0},
		CoveragePath: "/tmp/cov/coverage-summary.json",
	})
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "/tmp/cov/coverage-summary.json") {
		t.Errorf("warning must name the expected coverage path, got %v", got.Warnings)
	}
}

func TestRatchet_advisoryMentionsAdvanceOnMerge(t *testing.T) {
	got := applyRatchet(ratchetInput{
		Measured:     map[string]float64{"node": 99.5},
		Baseline:     map[string]float64{"node": 99.0},
		HaveCoverage: true, HaveBaseline: true,
		Tolerance: 1.0,
	})
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "ratchet advances on merge") {
		t.Errorf("advisory must mention the ratchet advancing on merge, got %v", got.Warnings)
	}
}

// Baseline sniffing — both accepted formats carry coverageByLanguage at the
// top level (specs/non-container-artifacts/design.md → Contracts,
// baseline file format).
func TestRatchet_baselineSniffing(t *testing.T) {
	want := map[string]float64{"node": 87.5, "go": 91.2}

	t.Run("full evidence envelope", func(t *testing.T) {
		raw := `{
			"schemaVersion": "1.0.0",
			"moduleName": "evidence",
			"stage": "cross-cutting",
			"tool": {"name": "evidence", "version": "1"},
			"repo": {"repoUrl": "https://example.com", "commitSha": "abc", "branch": "main"},
			"passed": true,
			"findingsCount": 0,
			"coverageByLanguage": {"node": 87.5, "go": 91.2},
			"languages": ["node", "go"]
		}`
		got, err := parseBaselineCoverage(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("bare coverageByLanguage map", func(t *testing.T) {
		got, err := parseBaselineCoverage(`{"coverageByLanguage":{"node":87.5,"go":91.2}}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("rejects documents without the map", func(t *testing.T) {
		for name, raw := range map[string]string{
			"empty object":   `{}`,
			"empty map":      `{"coverageByLanguage":{}}`,
			"invalid JSON":   `{"coverageByLanguage":`,
			"unrelated keys": `{"passed":true}`,
		} {
			if got, err := parseBaselineCoverage(raw); err == nil {
				t.Errorf("%s: expected error, got %v", name, got)
			}
		}
	})
}
