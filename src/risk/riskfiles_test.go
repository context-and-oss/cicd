package main

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyRiskFilePaths(t *testing.T) {
	cases := []struct {
		name        string
		paths       []string
		wantF       string
		wantD       string
		wantErr     error
		wantErrFrag string
	}{
		{
			name:    "empty list",
			paths:   nil,
			wantErr: errNoRiskFiles,
		},
		{
			name:    "findings only",
			paths:   []string{"findings.json"},
			wantErr: errNoRiskFiles,
		},
		{
			name:    "decisions only",
			paths:   []string{"decisions.json"},
			wantErr: errNoRiskFiles,
		},
		{
			name:  "both in root",
			paths: []string{"findings.json", "decisions.json"},
			wantF: "findings.json",
			wantD: "decisions.json",
		},
		{
			name:  "both in subdirectory",
			paths: []string{"risk/findings.json", "risk/decisions.json"},
			wantF: "risk/findings.json",
			wantD: "risk/decisions.json",
		},
		{
			name:        "different directories",
			paths:       []string{"a/findings.json", "b/decisions.json"},
			wantErrFrag: "different directories",
		},
		{
			name:        "multiple findings.json",
			paths:       []string{"a/findings.json", "b/findings.json", "a/decisions.json"},
			wantErrFrag: "multiple findings.json",
		},
		{
			name:        "multiple decisions.json",
			paths:       []string{"a/findings.json", "a/decisions.json", "b/decisions.json"},
			wantErrFrag: "multiple decisions.json",
		},
		{
			name:  "blank lines ignored",
			paths: []string{"", "findings.json", "  ", "decisions.json", ""},
			wantF: "findings.json",
			wantD: "decisions.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, d, err := classifyRiskFilePaths(tc.paths)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrFrag)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f != tc.wantF {
				t.Errorf("findingsPath = %q, want %q", f, tc.wantF)
			}
			if d != tc.wantD {
				t.Errorf("decisionsPath = %q, want %q", d, tc.wantD)
			}
		})
	}
}
