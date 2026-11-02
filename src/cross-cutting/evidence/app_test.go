package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeferredDependenciesAreSkippedNotClean(t *testing.T) {
	e, err := deferredAppDependencies(nil, repoContext{AppID: "app-a"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !e.Passed || e.Outcome != OutcomeSkipped || e.Examined != nil || len(e.CycloneDXReport) != 0 {
		t.Fatalf("deferral became a clean measurement: %+v", e)
	}
	combined := buildCombined(moduleName, moduleStage, repoContext{AppID: "app-a"}, []*envelope{e}, time.Now())
	if !combined.Passed || !strings.Contains(strings.Join(combined.Warnings, " "), "NOT ASSESSED") {
		t.Fatalf("combined evidence lost the intentional skip: %+v", combined)
	}
	failed := &envelope{ModuleName: "quality", Passed: false, Outcome: OutcomeError, Errors: []string{"test failed"}}
	if buildCombined(moduleName, moduleStage, repoContext{}, []*envelope{e, failed}, time.Now()).Passed {
		t.Fatal("dependency deferral masked an enabled check failure")
	}
	files, _ := buildConcerns([]*envelope{e}, []string{"deferred.json"})
	for _, name := range []string{"sbom.json", "sca.json", "licenses.json"} {
		c := files[name]
		if c.Outcome != OutcomeSkipped || c.Examined != nil || len(c.Tools) != 1 || c.Tools[0].Scope != "application-dependencies" {
			t.Fatalf("lost explicit dependency deferral in %s: %+v", name, c)
		}
	}
	if _, err := deferredAppDependencies(nil, repoContext{}, time.Now()); err == nil {
		t.Fatal("allowed SBOM omission for ordinary repository mode")
	}
	if _, err := deferredAppDependencies([]*envelope{{CycloneDXReport: json.RawMessage(`{"components":[]}`)}}, repoContext{AppID: "app-a"}, time.Now()); err == nil {
		t.Fatal("silently discarded supplied inventory")
	}
}

func TestAppEvidenceIdentityPreservesNativePayload(t *testing.T) {
	raw := `{"repo":{"repoUrl":"https://example.test/repo","commitSha":"abc","branch":"main"},"moduleName":"quality","futureField":{"kept":true},"cyclonedxReport":{"dependencies":[{"ref":"a","dependsOn":["shared"]}]}}`
	repo := repoContext{RepoURL: "https://example.test/repo", CommitSHA: "abc", Branch: "main", AppID: "a", SourcePaths: []string{"apps/a", "shared"}}
	out, err := stampApp(raw, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"appId":"a"`) || !strings.Contains(out, `"futureField":{"kept":true}`) || !strings.Contains(out, `"dependsOn":["shared"]`) {
		t.Fatalf("lost evidence: %s", out)
	}
	repo.AppID = "b"
	if _, err := stampApp(out, repo); err == nil {
		t.Fatal("combined two applications")
	}
	repo.AppID = "a"
	repo.CommitSHA = "other"
	if _, err := stampApp(out, repo); err == nil {
		t.Fatal("combined different commits")
	}
}

func TestApplicationsHaveDistinctSBOMAndSARIFIdentities(t *testing.T) {
	a := repoContext{RepoURL: "https://example.test/repo", CommitSHA: "abc", AppID: "a"}
	b := a
	b.AppID = "b"
	if cdxSerialNumber(a) == cdxSerialNumber(b) {
		t.Fatal("SBOM identities collide")
	}
	if buildCDXMetadata(a, time.Now()).Component.Name != "a" {
		t.Fatal("SBOM subject still names the entire repository")
	}
	makeDoc := func() sarifDocument {
		return sarifDocument{Runs: []json.RawMessage{json.RawMessage(`{"tool":{"driver":{"name":"eslint"}},"automationDetails":{"id":"lint"},"results":[]}`)}}
	}
	da, err := appSARIF(makeDoc(), "a")
	if err != nil {
		t.Fatal(err)
	}
	db, err := appSARIF(makeDoc(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if string(da.Runs[0]) == string(db.Runs[0]) {
		t.Fatal("SARIF identities collide")
	}
}
