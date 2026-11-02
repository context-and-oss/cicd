package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppTestAndCoverageEvidenceStayDistinct(t *testing.T) {
	rows := appTestStatuses("client", true, true, true, false)
	if !rows[0].Passed || rows[0].Concern != ConcernTests || rows[1].Passed || rows[1].Outcome != OutcomeError {
		t.Fatalf("missing coverage changed test execution or passed: %+v", rows)
	}
	rows = appTestStatuses("client", true, true, false, false)
	if !rows[1].Passed || rows[1].Outcome != OutcomeSkipped {
		t.Fatalf("unmeasured coverage became clean: %+v", rows)
	}
	rows = appTestStatuses("plugin", false, false, true, false)
	if rows[0].Outcome != OutcomeError || rows[1].Outcome != OutcomeError {
		t.Fatalf("nonrun became clean: %+v", rows)
	}
}

func TestAppLintCannotCreditAnotherApplication(t *testing.T) {
	for _, p := range []string{"/src/apps/a/main.js", "/src/shared/lib.js"} {
		raw := `[{"filePath":"` + p + `","messages":[{"ruleId":"example","severity":2,"message":"issue","line":1}]}]`
		sarif, counts, _, err := parseAppLint([]byte(raw), "eslint", []string{"apps/a", "shared"})
		if err != nil || counts[SeverityHigh] != 1 || strings.Contains(string(sarif), "/src/") {
			t.Fatalf("bad accepted evidence: %s %v", sarif, err)
		}
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `[{}]`, `[{"filePath":"/src/apps/a/x.js","messages":null}]`, `[{"filePath":"/src/apps/b/x.js","messages":[]}]`, `[{"filePath":"/src/apps/ab/x.js","messages":[]}]`, `[{"filePath":"/src/apps/a/../b/x.js","messages":[]}]`} {
		if _, _, _, err := parseAppLint([]byte(raw), "eslint", []string{"apps/a"}); err == nil {
			t.Errorf("accepted invalid/unscoped evidence %s", raw)
		}
	}
}

func TestAppPluginLintUsesNativeEvidence(t *testing.T) {
	raw := `[{"FilePath":"/src/plugins/a/Plugin.cs","FileChanges":[{"LineNumber":7,"DiagnosticId":"WHITESPACE","FormatDescription":"format"}]}]`
	if _, c, _, err := parseAppLint([]byte(raw), "dotnet-format", []string{"plugins/a"}); err != nil || c[SeverityMedium] != 1 {
		t.Fatalf("%v %v", c, err)
	}
	if _, _, _, err := parseAppLint([]byte(raw), "dotnet-format", []string{"apps/a"}); err == nil {
		t.Fatal("plugin evidence crossed app boundary")
	}
	if sarif, _, warnings, err := parseAppLint([]byte(strings.ReplaceAll(raw, "/src/", "")), "dotnet-format", []string{"plugins/a"}); err != nil || len(warnings) != 0 || !strings.Contains(string(sarif), "plugins/a/Plugin.cs") {
		t.Fatalf("relative location lost its scoped path: %s %v %v", sarif, warnings, err)
	}
	if _, _, _, err := parseAppLint([]byte(`[]`), "dotnet-format", []string{"plugins/a"}); err != nil {
		t.Fatal("dotnet format emits [] when no edits are needed:", err)
	}
}

func TestApplicationInventoryRequiresScannableIdentity(t *testing.T) {
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"app-a"}},"components":[{"name":"example","purl":"pkg:npm/example@1.0.0"}],"dependencies":[{"ref":"app-a","dependsOn":["example"]}]}`
	if n, err := validateAppInventory([]byte(bom), "node"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	for _, raw := range []string{`{}`, `null`, strings.Replace(bom, `"components":`, `"unused":`, 1), strings.Replace(bom, "pkg:npm/", "pkg:nuget/", 1), strings.Replace(bom, "pkg:npm/example@1.0.0", "", 1)} {
		if _, err := validateAppInventory([]byte(raw), "node"); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bom), &fields); err != nil {
		t.Fatal(err)
	}
	fields["components"] = json.RawMessage(`[]`)
	empty, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := validateAppInventory(empty, "node"); err != nil || n != 0 {
		t.Fatalf("explicit zero dependency inventory: %d %v", n, err)
	}
}
