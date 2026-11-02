package main

import "testing"

func TestPreparationSelection(t *testing.T) {
	legs := `[{"label":"api","language":"dotnet","cmd":"dotnet test --no-build"},{"label":"web","language":"node","cmd":"npm test"}]`
	for _, tt := range []struct {
		cmd, lang, image, label, test, legs string
		ok                                  bool
	}{
		{"", "", "", "", "", "", true},
		{"restore && build", "dotnet", "sdk:10", "api", "", legs, true},
		{"npm ci", "node", "node:22", "", "npm test", "", true},
		{"restore", "dotnet", "sdk:10", "web", "", legs, false},
		{"restore", "dotnet", "sdk:10", "missing", "", legs, false},
		{"restore", "dotnet", "", "api", "", legs, false},
		{"", "node", "node:22", "", "npm test", "", false},
		{"restore", "dotnet", "sdk:10", "api", "", `[{"label":"api","language":"dotnet","toolchainImage":"other"}]`, false},
	} {
		if err := validatePreparation(tt.cmd, tt.lang, tt.image, tt.label, tt.test, tt.legs); (err == nil) != tt.ok {
			t.Errorf("%+v: %v", tt, err)
		}
	}
}
