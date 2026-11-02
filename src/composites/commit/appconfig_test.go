package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const appLint = `[{"label":"client","language":"node","cmd":"sh ci/lint.sh","reportPath":"out/lint.json","format":"eslint"}]`
const appTests = `[{"label":"client","language":"node","cmd":"sh ci/test.sh","coveragePath":"out/coverage.json"}]`

func TestApplicationContract(t *testing.T) {
	c, err := parseAppConfig("app-a", []string{"apps/a", "shared", "apps/a"}, appLint, appTests)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 2 || c.ID != "app-a" {
		t.Fatalf("bad scope: %+v", c)
	}
	for _, p := range []string{"", ".", "..", "../app", "apps/../b", "/src/a", "apps/*", ".git", ".git/config", "a\nb", "a\\b"} {
		if _, err := parseAppConfig("app-a", []string{p}, appLint, appTests); err == nil {
			t.Errorf("accepted unsafe or ambiguous path %q", p)
		}
	}
	for _, id := range []string{"", "../a", "a/b", "App", strings.Repeat("a", 65)} {
		if _, err := parseAppConfig(id, []string{"apps/a"}, appLint, appTests); err == nil {
			t.Errorf("accepted id %q", id)
		}
	}
	if _, err := parseAppConfig("a", nil, appLint, appTests); err == nil {
		t.Fatal("accepted empty scope")
	}
}

func TestApplicationLegsCannotSilentlyLoseWork(t *testing.T) {
	for _, raw := range []string{"[]", "null", appLint + " {}", strings.Replace(appLint, "reportPath", "reportpath", 1), strings.Replace(appLint, "eslint", "cyclonedx", 1), strings.Replace(appLint, "out/lint.json", "../lint.json", 1), "[" + appLint[1:len(appLint)-1] + "," + appLint[1:len(appLint)-1] + "]"} {
		if _, err := parseAppLegs(raw, "lint"); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	plugin := `{"label":"plugin","language":"dotnet","cmd":"dotnet format --report out/format.json","reportPath":"out/format.json","format":"dotnet-format"}`
	mixed := strings.TrimSuffix(appLint, "]") + "," + plugin + "]"
	if _, err := parseAppConfig("a", []string{"apps/a", "plugins/a"}, mixed, appTests); err == nil {
		t.Fatal("plugin was allowed to lose its tests")
	}
	if _, err := parseAppLegs(appLint, "sbom"); err == nil {
		t.Fatal("application SBOM legs are deferred, not an accepted input")
	}
}

// legServiceCorpus is read by this test and by quality's
// TestLegServiceDocumentsParseAsDeclared. app mode marshals []appLeg straight
// into quality.Test's --test-legs, so the two parsers read one document and a
// key only one of them models is a service the consumer declared and nothing
// binds. Asserting each parser against its own fixture cannot catch that: only
// a single corpus both sides answer can.
const legServiceCorpus = "../../quality/testdata/leg-service-documents.json"

type legServiceCase struct {
	Name   string `json:"name"`
	Accept bool   `json:"accept"`
	Legs   string `json:"legs"`
}

func loadLegServiceCorpus(t *testing.T, path string) []legServiceCase {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc struct {
		Documents []legServiceCase `json:"documents"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(doc.Documents) == 0 {
		t.Fatal("corpus is empty — a test that reads no case passes on anything")
	}
	return doc.Documents
}

func TestAppLegsAndTestLegsShareOneKeySet(t *testing.T) {
	cases := loadLegServiceCorpus(t, legServiceCorpus)
	accepted := 0
	for _, c := range cases {
		_, err := parseAppLegs(c.Legs, "test")
		switch {
		case c.Accept && err != nil:
			t.Errorf("%s: quality accepts this document and parseAppLegs rejected it: %v", c.Name, err)
		case !c.Accept && err == nil:
			t.Errorf("%s: quality rejects this document and parseAppLegs accepted it", c.Name)
		}
		if c.Accept {
			accepted++
		}
	}
	// A corpus that is all rejections would pass against a parser that refuses
	// everything, and one that is all acceptances against a parser that refuses
	// nothing.
	if accepted == 0 || accepted == len(cases) {
		t.Fatalf("corpus must hold both accepted and rejected documents, got %d of %d accepted", accepted, len(cases))
	}
}

func TestLintLegsCannotDeclareServices(t *testing.T) {
	raw := `[{"label":"client","language":"node","cmd":"sh ci/lint.sh","reportPath":"out/lint.json","format":"eslint","services":[{"alias":"db","image":"postgres:16","port":5432}]}]`
	_, err := parseAppLegs(raw, "lint")
	if err == nil {
		t.Fatal("a lint leg reads the source and reaches nothing; declaring a service there must be refused")
	}
	if !strings.Contains(err.Error(), "services are for test legs") {
		t.Fatalf("refusal must say why, got %v", err)
	}
}
