//go:build unit_test

package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// goModuleDoc is the shape the pinned Trivy emits for a Go tree with
// --license-full, as measured: one root package, the dependencies (licensed
// only when the module cache was populated), and the tree's own LICENSE as a
// loose-file declaration.
func goModuleDoc(deps int, licensed bool) json.RawMessage {
	pkgs := []string{`{"Name":"example.com/app","Relationship":"root"}`}
	for i := 0; i < deps; i++ {
		lic := ""
		if licensed {
			lic = `,"Licenses":["BSD-3-Clause"]`
		}
		rel := "indirect"
		if i%3 == 0 {
			rel = "direct"
		}
		pkgs = append(pkgs, `{"Name":"example.com/dep`+strconv.Itoa(i)+`","Relationship":"`+rel+`"`+lic+`}`)
	}
	return json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Packages":[` + strings.Join(pkgs, ",") + `]},
	  {"Target":"Loose File License(s)","Class":"license-file","Licenses":[
	    {"Severity":"LOW","Category":"notice","PkgName":"","FilePath":"LICENSE","Name":"Apache-2.0","Confidence":1}]}]}`)
}

// TestAGoModuleWithNoModuleCacheReadsNoDependencyLicence is the measured case:
// the root LICENSE is one declaration, the 36 dependencies carry none, and the
// row must not read CLEAN on the strength of the root alone.
func TestAGoModuleWithNoModuleCacheReadsNoDependencyLicence(t *testing.T) {
	cov, err := readLicenceCoverage(goModuleDoc(36, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 36 || cov.WithLicence != 0 {
		t.Fatalf("coverage = %d of %d, want 0 of 36 (the root is first-party, not a dependency)", cov.WithLicence, cov.Packages)
	}
	if len(cov.Ecosystems) != 1 || cov.Ecosystems[0].Type != "gomod" || cov.Ecosystems[0].Targets[0] != "go.mod" {
		t.Fatalf("ecosystems = %+v, want one gomod entry for go.mod", cov.Ecosystems)
	}
	if !licenceDependenciesUnread(true, cov) {
		t.Error("36 unread dependencies beside one root declaration must make the row SKIPPED")
	}
	msg := licenceCoverageWarning(licenceScanTree, cov, 1)
	for _, want := range []string{"NOT READ", "36 dependency package(s)", "gomod 0 of 36 in go.mod", "1 licence declaration(s)", "SKIPPED rather than CLEAN", "Go module cache"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}

	res, err := evaluateLicenses(goModuleDoc(36, false), defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 1 {
		t.Fatalf("scanned = %d, want the one root declaration", res.Scanned)
	}
	if res.Coverage.Packages != 36 || res.Coverage.WithLicence != 0 {
		t.Errorf("evaluateLicenses coverage = %+v, want 0 of 36", res.Coverage)
	}
	if licenceZeroRead(true, res.Scanned, res.Excluded) {
		t.Error("one declaration was read, so this is not the zero-read case; the coverage rule is what catches it")
	}
}

// TestAPopulatedModuleCacheIsFullyRead: every dependency licensed is no
// warning and no SKIPPED.
func TestAPopulatedModuleCacheIsFullyRead(t *testing.T) {
	cov, err := readLicenceCoverage(goModuleDoc(36, true), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 36 || cov.WithLicence != 36 {
		t.Fatalf("coverage = %d of %d, want 36 of 36", cov.WithLicence, cov.Packages)
	}
	if licenceDependenciesUnread(true, cov) {
		t.Error("a fully read graph is not unread")
	}
	if msg := licenceCoverageWarning(licenceScanTree, cov, 37); msg != "" {
		t.Errorf("a fully read graph warns: %s", msg)
	}
}

// TestAPartlyReadGraphWarnsAndStillGrades: some ecosystems read, some not. The
// row stays graded — what was read is real — and the warning names only the
// ecosystem that fell short.
func TestAPartlyReadGraphWarnsAndStillGrades(t *testing.T) {
	doc := json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"src/api/packages.lock.json","Class":"lang-pkgs","Type":"nuget","Packages":[
	    {"Name":"A","Relationship":"direct","Licenses":["MIT"]},
	    {"Name":"B","Relationship":"indirect","Licenses":["Apache-2.0"]}]},
	  {"Target":"web/package-lock.json","Class":"lang-pkgs","Type":"npm","Packages":[
	    {"Name":"web","Relationship":"root"},
	    {"Name":"left-pad","Relationship":"direct"},
	    {"Name":"ws","Relationship":""}]}]}`)
	cov, err := readLicenceCoverage(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 4 || cov.WithLicence != 2 {
		t.Fatalf("coverage = %d of %d, want 2 of 4 (an empty relationship is a dependency)", cov.WithLicence, cov.Packages)
	}
	if got := []string{cov.Ecosystems[0].Type, cov.Ecosystems[1].Type}; got[0] != "npm" || got[1] != "nuget" {
		t.Errorf("ecosystems not sorted by type: %v", got)
	}
	if licenceDependenciesUnread(true, cov) {
		t.Error("a partly read graph is graded, not SKIPPED")
	}
	msg := licenceCoverageWarning(licenceScanTree, cov, 2)
	if !strings.Contains(msg, "PARTLY READ — 2 of 4") || !strings.Contains(msg, "npm 0 of 2 in web/package-lock.json") {
		t.Errorf("warning does not name the shortfall:\n%s", msg)
	}
	if strings.Contains(msg, "nuget") {
		t.Errorf("warning names an ecosystem that was fully read:\n%s", msg)
	}
}

// TestFirstPartyPackagesAreNeitherReadNorMissed: a workspace of root and
// member packages lists no dependency, so there is nothing to cover.
func TestFirstPartyPackagesAreNeitherReadNorMissed(t *testing.T) {
	doc := json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"go.work","Class":"lang-pkgs","Type":"gomod","Packages":[
	    {"Name":"example.com/a","Relationship":"Root"},
	    {"Name":"example.com/b","Relationship":"workspace"}]}]}`)
	cov, err := readLicenceCoverage(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 0 || len(cov.Ecosystems) != 0 {
		t.Fatalf("coverage = %+v, want nothing: first-party packages are not dependencies", cov)
	}
	if licenceDependenciesUnread(true, cov) || licenceCoverageWarning(licenceScanTree, cov, 0) != "" {
		t.Error("no dependency listed must neither skip nor warn")
	}
}

// TestAnExcludedManifestIsLeftOutWithoutCountingAsAHit: covers must not
// record a hit, or a pattern that removed no declaration would stop being
// reported inert.
func TestAnExcludedManifestIsLeftOutWithoutCountingAsAHit(t *testing.T) {
	ex, err := newLicenseExcluder([]string{"vendor/**"})
	if err != nil {
		t.Fatal(err)
	}
	doc := json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"vendor/tool/go.mod","Class":"lang-pkgs","Type":"gomod","Packages":[
	    {"Name":"x","Relationship":"direct"}]},
	  {"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Packages":[
	    {"Name":"y","Relationship":"direct","Licenses":["MIT"]}]}]}`)
	cov, err := readLicenceCoverage(doc, ex)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 1 || cov.WithLicence != 1 {
		t.Fatalf("coverage = %d of %d, want 1 of 1 with vendor/ excluded", cov.WithLicence, cov.Packages)
	}
	if w := ex.inertWarnings(); len(w) != 1 {
		t.Errorf("the coverage pass recorded a hit; the pattern removed no declaration and must still read inert: %v", w)
	}
}

// TestAScanThatErroredIsNeverUnread: a failed run is an error, not SKIPPED.
func TestAScanThatErroredIsNeverUnread(t *testing.T) {
	if licenceDependenciesUnread(false, licenceCoverage{Packages: 36}) {
		t.Error("ran=false must stay an error, never SKIPPED")
	}
}

// TestASourceOnlyReportCarriesNoPackages: the source-only rewrite drops the
// package list, so a source-only scan never claims or misses a dependency.
func TestASourceOnlyReportCarriesNoPackages(t *testing.T) {
	src, err := sourceLicenseReport(goModuleDoc(36, false))
	if err != nil {
		t.Fatal(err)
	}
	cov, err := readLicenceCoverage(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Packages != 0 {
		t.Fatalf("source-only coverage = %+v, want no packages", cov)
	}
}

// TestTheSBOMRescanSaysWhereItsLicencesComeFrom: an SBOM rescan reads no
// package metadata, so the remedy must not point at a module cache.
func TestTheSBOMRescanSaysWhereItsLicencesComeFrom(t *testing.T) {
	msg := licenceCoverageWarning(licenceScanSBOM, licenceCoverage{Packages: 3,
		Ecosystems: []licenceEcosystemCoverage{{Type: "npm", Targets: []string{"sbom.cdx.json"}, Packages: 3}}}, 0)
	if !strings.Contains(msg, "supplied SBOM declares") || strings.Contains(msg, "module cache") {
		t.Errorf("SBOM warning gives the tree remedy:\n%s", msg)
	}
}

// TestAnUnreadablePackageListIsAnError: never an empty coverage.
func TestAnUnreadablePackageListIsAnError(t *testing.T) {
	if _, err := readLicenceCoverage(json.RawMessage(`{"Results":[{"Packages":"nope"}]}`), nil); err == nil {
		t.Error("a package list that does not parse must be an error")
	}
}

// TestCoverageTravelsInTheReport: the payload carries the package counts, so
// the audit bundle can show the denominator Examined cannot.
func TestCoverageTravelsInTheReport(t *testing.T) {
	res, err := evaluateLicenses(goModuleDoc(36, false), defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		DependencyCoverage *licenceCoverage `json:"dependencyCoverage"`
	}
	if err := json.Unmarshal(res.Report, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.DependencyCoverage == nil || payload.DependencyCoverage.Packages != 36 {
		t.Fatalf("payload dependencyCoverage = %+v, want 36 packages", payload.DependencyCoverage)
	}
}
