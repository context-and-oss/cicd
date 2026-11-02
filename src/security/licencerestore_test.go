//go:build unit_test

package main

import (
	"strings"
	"testing"
)

// restoredFixture is a .NET restore that completed for three projects.
func restoredFixture() dotnetRestoreOutcome {
	return dotnetRestoreOutcome{
		Band:       "8.0",
		BandNote:   "the newest band, no global.json",
		FindExit:   "0",
		Projects:   []string{"src/Api/Api.csproj", "src/Worker/Worker.csproj", "testdata/Fixture/Fixture.csproj"},
		NuspecExit: "0",
	}
}

// nugetReport is a Trivy licence report listing one package for each lockfile.
func nugetReport(lockfiles ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"SchemaVersion":2,"Results":[`)
	for i, l := range lockfiles {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"Target":"` + l + `","Class":"lang-pkgs","Type":"nuget","Packages":[` +
			`{"Name":"Example.Lib","Relationship":"direct","Licenses":["MIT"]}]}`)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func restoreWarningFor(t *testing.T, raw []byte, patterns ...string) string {
	t.Helper()
	ex, err := newLicenseExcluder(patterns)
	if err != nil {
		t.Fatal(err)
	}
	cov, err := readLicenceCoverage(raw, ex)
	if err != nil {
		t.Fatal(err)
	}
	return dotnetLicenceRestoreWarning(restoredFixture(), &cov, ex)
}

// TestRestoredIsNotRead is the case the old message hid: every project restored,
// trivy.yaml skipped the directory holding them, and the warning still said the
// restore was so Trivy could read their licences.
func TestRestoredIsNotRead(t *testing.T) {
	msg := restoreWarningFor(t, []byte(`{"SchemaVersion":2,"Results":[]}`))
	for _, want := range []string{"(3 project(s);", "Trivy listed the NuGet packages of none of them",
		"no NuGet package for 3 (src/Api/Api.csproj, src/Worker/Worker.csproj, testdata/Fixture/Fixture.csproj)",
		"trivy.yaml", "not judged"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	// Nothing listed, so nothing resolved now can have drifted from it.
	if strings.Contains(msg, "floating version range") {
		t.Errorf("drift caveat on a graph nothing read:\n%s", msg)
	}
}

func TestRestoredAndListed(t *testing.T) {
	msg := restoreWarningFor(t, nugetReport("src/Api/packages.lock.json",
		"src/Worker/packages.lock.json", "testdata/Fixture/packages.lock.json"))
	if !strings.Contains(msg, "Trivy listed the NuGet packages of all of them.") {
		t.Errorf("want all listed:\n%s", msg)
	}
	if strings.Contains(msg, "not judged") || strings.Contains(msg, "--license-exclude") {
		t.Errorf("a fully listed graph names no gap:\n%s", msg)
	}
	if !strings.Contains(msg, "floating version range") || !strings.Contains(msg, "dependency coverage") {
		t.Errorf("drift caveat and coverage pointer missing:\n%s", msg)
	}
}

// TestRestoredSplitNamesEachBucket: one listed, one removed by the consumer's own
// pattern, one Trivy never listed. Each says which, because the remedies differ.
func TestRestoredSplitNamesEachBucket(t *testing.T) {
	msg := restoreWarningFor(t, nugetReport("src/Api/packages.lock.json"), "testdata/**")
	for _, want := range []string{"Trivy listed the NuGet packages of 1 of them",
		"--license-exclude removed 1 (testdata/Fixture/Fixture.csproj)",
		"no NuGet package for 1 (src/Worker/Worker.csproj)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

// TestRestoreSplitLeavesThePatternInert: covering a restored project removed no
// declaration, so the pattern must still be reported as matching nothing.
func TestRestoreSplitLeavesThePatternInert(t *testing.T) {
	ex, err := newLicenseExcluder([]string{"testdata/**"})
	if err != nil {
		t.Fatal(err)
	}
	dotnetLicenceRestoreWarning(restoredFixture(), &licenceCoverage{}, ex)
	if len(ex.inertWarnings()) != 1 {
		t.Fatalf("the restore split recorded a hit: %v", ex.inertWarnings())
	}
}

// TestRestoreMatchesLockfileByDirectory: a root-level project and a per-project
// lockfile name in a shared folder both match on directory.
func TestRestoreMatchesLockfileByDirectory(t *testing.T) {
	cov := licenceCoverage{Ecosystems: []licenceEcosystemCoverage{
		{Type: "nuget", Targets: []string{"packages.lock.json", "./lib/packages.Lib.lock.json"}, Packages: 2, WithLicence: 2},
		// Another ecosystem's lockfile in a project's folder is not that project's NuGet graph.
		{Type: "npm", Targets: []string{"web/package-lock.json"}, Packages: 1, WithLicence: 1},
	}}
	read, excluded, unlisted := dotnetRestoreReadSplit(
		[]string{"App.csproj", "lib/Lib.csproj", "web/Web.csproj"}, cov, nil)
	if read != 2 || len(excluded) != 0 || len(unlisted) != 1 || unlisted[0] != "web/Web.csproj" {
		t.Fatalf("read=%d excluded=%v unlisted=%v", read, excluded, unlisted)
	}
}

// TestRestoreWarningClaimsNothingWhenTheScanFailed: with no report there is no
// "listed" to say, and "none" would be a measurement nobody took.
func TestRestoreWarningClaimsNothingWhenTheScanFailed(t *testing.T) {
	msg := dotnetLicenceRestoreWarning(restoredFixture(), nil, nil)
	if !strings.Contains(msg, "is unknown") || strings.Contains(msg, "none of them") {
		t.Fatalf("want an unknown read:\n%s", msg)
	}
}
