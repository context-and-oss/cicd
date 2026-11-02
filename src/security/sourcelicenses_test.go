package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppSourceLicencesExcludeWorkspaceDependencyMetadata(t *testing.T) {
	raw := json.RawMessage(`{"Results":[{"Target":"pnpm-lock.yaml","Licenses":[{"Name":"GPL-3.0","PkgName":"other-app-dependency"}]},{"Target":"apps/a/LICENSE","Licenses":[{"Name":"MIT","FilePath":"apps/a/LICENSE"}]}]}`)
	filtered, err := sourceLicenseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(filtered), "other-app-dependency") || !strings.Contains(string(filtered), "MIT") {
		t.Fatalf("wrong boundary: %s", filtered)
	}
	if _, err := sourceLicenseReport(json.RawMessage(`broken`)); err == nil {
		t.Fatal("malformed output became clean")
	}
}
