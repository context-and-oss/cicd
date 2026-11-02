//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// allDevRescan is the shape trivy 0.70.0 wrote for a Poetry project whose
// packages all sit in dependency groups, rescanned with --include-dev-deps:
// one result, every package Dev, vulnerabilities listed against them.
const allDevRescan = `{"SchemaVersion":2,"Results":[{"Target":"poetry.lock","Class":"lang-pkgs","Type":"poetry",
 "Packages":[{"Name":"pytest","Version":"8.0.0","Dev":true},{"Name":"jinja2","Version":"3.1.2","Dev":true}],
 "Vulnerabilities":[
  {"VulnerabilityID":"CVE-2024-22195","PkgName":"jinja2","InstalledVersion":"3.1.2","Severity":"MEDIUM"},
  {"VulnerabilityID":"CVE-2024-34064","PkgName":"jinja2","InstalledVersion":"3.1.2","Severity":"HIGH"}]}]}`

func TestDevOnlyRescanProvesTheInputParsed(t *testing.T) {
	scan, err := classifyDevOnlyRescan([]byte(allDevRescan))
	if err != nil {
		t.Fatalf("an all-development rescan was refused: %v", err)
	}
	if scan.Packages != 2 || len(scan.Inputs) != 1 || scan.Inputs[0] != "poetry.lock" {
		t.Errorf("scan = %+v, want 2 packages from poetry.lock", scan)
	}
	if len(scan.ResolvedTypes) != 1 || scan.ResolvedTypes[0] != "poetry" {
		t.Errorf("resolved types = %v, want [poetry] for the reconciliation", scan.ResolvedTypes)
	}
	if scan.BySeverity[SeverityHigh] != 1 || scan.BySeverity[SeverityMedium] != 1 {
		t.Errorf("by severity = %v", scan.BySeverity)
	}
}

// TestDevOnlyRescanRefusesWhatItCannotProve is the false-pass half: a lockfile
// Trivy cannot parse writes the same `Results: null` as a development-only one,
// and only a rescan that reads packages, all Dev, may tell them apart.
func TestDevOnlyRescanRefusesWhatItCannotProve(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"rescan empty too":   {`{"SchemaVersion":2}`, "also produced no results"},
		"rescan null":        {`null`, "could not be read"},
		"rescan not json":    {`{"Results":`, "could not be read"},
		"heading, no pkgs":   {`{"Results":[{"Target":"poetry.lock","Type":"poetry","Packages":[]}]}`, "resolved no package"},
		"package not object": {`{"Results":[{"Target":"poetry.lock","Packages":[42]}]}`, "not an object"},
		"one runtime package": {`{"Results":[{"Target":"poetry.lock","Type":"poetry","Packages":[
			{"Name":"pytest","Version":"8.0.0","Dev":true},{"Name":"requests","Version":"2.31.0"}]}]}`,
			"1 package(s) Trivy did not flag as development (e.g. requests@2.31.0)"},
	} {
		_, err := classifyDevOnlyRescan([]byte(tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
			continue
		}
		wrapped := noTargetsWithInputsError([]string{"/src/poetry.lock", "/src/pyproject.toml"}, errTrivyNoTargets, err)
		if !errors.Is(wrapped, errTrivyNoTargets) {
			t.Errorf("%s: the kept error lost errTrivyNoTargets: %v", name, wrapped)
		}
		// The original sentence is quoted by the composite smoke and the
		// capsule; it must survive the wrapping verbatim.
		for _, frag := range []string{errTrivyNoTargets.Error(), "poetry.lock", tc.want, "Fix:"} {
			if !strings.Contains(wrapped.Error(), frag) {
				t.Errorf("%s: kept error %q is missing %q", name, wrapped, frag)
			}
		}
		if strings.Contains(wrapped.Error(), "/src/") {
			t.Errorf("%s: kept error names mount paths, not repository paths: %q", name, wrapped)
		}
		assertNeverPasses(t, name, false)
	}
}

func TestDevOnlyResultGatesNothingAndSaysWhich(t *testing.T) {
	scan, err := classifyDevOnlyRescan([]byte(allDevRescan))
	if err != nil {
		t.Fatal(err)
	}
	cdx := json.RawMessage(`{"bomFormat":"CycloneDX","components":[]}`)
	res := devOnlyResult(scan, cdx, []string{"narrowing note"})

	if len(res.BySeverity) != 0 || len(res.Findings) != 0 {
		t.Errorf("development vulnerabilities reached the gate: %v / %v", res.BySeverity, res.Findings)
	}
	if res.Skipped {
		t.Error("a scan that read the input is not a skip")
	}
	if res.Examined == nil || res.Examined.Count != 0 || res.Examined.Total != 0 {
		t.Errorf("examined = %+v, want 0 resolved packages and no total", res.Examined)
	}
	if string(res.CycloneDX) != string(cdx) {
		t.Errorf("the SBOM is not the gated scan's: %s", res.CycloneDX)
	}
	if len(res.Warnings) != 2 || res.Warnings[0] != "narrowing note" {
		t.Fatalf("warnings = %q, want the scan's own note then the dev-only one", res.Warnings)
	}
	w := res.Warnings[1]
	for _, frag := range []string{
		"RUNTIME SET EMPTY", "all 2 package(s) in poetry.lock", "not gated",
		"2 known vulnerability finding(s) (1 HIGH, 1 MEDIUM)",
		// Named, most severe first: a count can never say which.
		"HIGH CVE-2024-34064 in jinja2@3.1.2; MEDIUM CVE-2024-22195 in jinja2@3.1.2",
		"classification is Trivy's",
	} {
		if !strings.Contains(w, frag) {
			t.Errorf("warning %q is missing %q", w, frag)
		}
	}
	if len(res.InventoryWarnings) != 1 || !strings.Contains(res.InventoryWarnings[0], "Source SBOM: RUNTIME SET EMPTY") {
		t.Errorf("inventory warnings = %q", res.InventoryWarnings)
	}

	// The SBOM row reads the empty inventory as a measurement, not an error.
	row, rowErr := inventoryResult(nil, res)
	if rowErr != nil || row.Examined == nil || row.Examined.Count != 0 || row.Skipped {
		t.Errorf("inventory row = %+v, err %v; want CLEAN over 0 components", row, rowErr)
	}
}

func TestDevOnlyWarningCapsTheNamedVulnerabilities(t *testing.T) {
	scan := devOnlyScan{Inputs: []string{"package-lock.json"}, Packages: 1, BySeverity: map[Severity]int{SeverityLow: 12}}
	for i := 0; i < 12; i++ {
		scan.Vulns = append(scan.Vulns, trivyVuln{VulnerabilityID: "CVE-2024-" + string(rune('A'+i)), PkgName: "p", InstalledVersion: "1", Severity: "LOW"})
	}
	w := devOnlyWarning(scan)
	if !strings.Contains(w, "; and 2 more.") || strings.Count(w, " in p@1") != maxNamedDevVulns {
		t.Errorf("warning does not name %d and count the rest: %q", maxNamedDevVulns, w)
	}
	scan.Vulns, scan.BySeverity = nil, nil
	if w := devOnlyWarning(scan); !strings.Contains(w, "carry no known vulnerability") {
		t.Errorf("clean development set reads %q", w)
	}
}

// TestDevOnlyKeepsTheReconciliation: a development-only lockfile clears its
// own ecosystem and nothing else. A .csproj with no NuGet graph beside it is
// still a non-run.
func TestDevOnlyKeepsTheReconciliation(t *testing.T) {
	scan, err := classifyDevOnlyRescan([]byte(allDevRescan))
	if err != nil {
		t.Fatal(err)
	}
	files := []string{"/src/pyproject.toml", "/src/poetry.lock", "/src/App/App.csproj"}
	got := unresolvedEcosystems(trivyConfigDir, files, devOnlyResult(scan, nil, nil).ResolvedTypes)
	if len(got) != 1 || got[0].Name != "dotnet" {
		t.Errorf("unresolved = %+v, want only dotnet", got)
	}
}

// TestTrivyFSPinsDevelopmentDependenciesOut: a consumer trivy.yaml must not
// widen the gated set, and `image`/`sbom` must not receive a flag they reject.
func TestTrivyFSPinsDevelopmentDependenciesOut(t *testing.T) {
	fs := trivyFSArgs("/src")
	if fs[1] != "fs" || fs[len(fs)-1] != "/src" || !hasArg(fs, "--include-dev-deps=false") {
		t.Errorf("trivyFSArgs = %v", fs)
	}
	for _, sub := range []string{"image", "sbom"} {
		for _, a := range trivyScanArgs(sub, "/x") {
			if strings.HasPrefix(a, "--include-dev-deps") {
				t.Errorf("trivy %s does not accept %s on 0.70.0", sub, a)
			}
		}
	}

	dev := trivyDevRescanArgs("/src")
	if !hasArg(dev, "--include-dev-deps") || hasArg(dev, "--include-dev-deps=false") {
		t.Errorf("rescan does not include development dependencies: %v", dev)
	}
	if !hasFlagValue(dev, "--output", trivyDevNativePath) || hasArg(dev, trivyNativePath) {
		t.Errorf("rescan writes over the gated report: %v", dev)
	}
	// Everything else is the gated scan's, so the two read the same tree the
	// same way.
	if len(dev) != len(fs) || !hasFlagValue(dev, "--severity", trivySeverityPin) || dev[len(dev)-1] != "/src" {
		t.Errorf("rescan drifted from the gated command line:\n fs  %v\n dev %v", fs, dev)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
