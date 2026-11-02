package main

import "testing"

func TestValidatePrecommitInputs(t *testing.T) {
	cases := []struct {
		name                          string
		parallelism, nodeProjectLimit int
		wantErr                       string
	}{
		{"defaults", 1, 4, ""},
		{"upper bound", 4, 1, ""},
		{"parallelism zero", 0, 4, "parallelism must be an integer from 1 to 4, got 0"},
		{"parallelism five", 5, 4, "parallelism must be an integer from 1 to 4, got 5"},
		{"node project limit zero", 1, 0, "node-project-limit must be positive"},
		{"both wrong names parallelism first", 0, 0, "parallelism must be an integer from 1 to 4, got 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePrecommitInputs(tc.parallelism, tc.nodeProjectLimit)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("expected %q, got nil", tc.wantErr)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}
