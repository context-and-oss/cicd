package main

import "testing"

// TestLicenseScanArgsPinsIgnoredLicensesEmpty is the regression guard for the
// hole this flag list exists to close. Measured on the pinned Trivy 0.70.0
// against testdata/node-app: a trivy.yaml carrying `license.ignored: [MIT]`
// took the license report from one finding to zero, and passing
// `--ignored-licenses ""` on the command line took it back to one. Drop the pin
// and a consumer can zero the license scan from a file cicd honours.
func TestLicenseScanArgsPinsIgnoredLicensesEmpty(t *testing.T) {
	for _, full := range []bool{false, true} {
		args := trivyLicenseScanArgs(full, "/src")
		v, ok := flagValuePresent(args, "--ignored-licenses")
		if !ok || v != "" {
			t.Errorf("trivyLicenseScanArgs(%v) = %v, missing --ignored-licenses \"\" — a consumer trivy.yaml could zero the report", full, args)
		}
	}
}

// TestLicenseScanArgsScansLicenses guards the other half: without
// --scanners license Trivy runs its default scanners and the report carries no
// Licenses[] at all, which reads downstream as a clean policy rather than as a
// scan that never looked.
func TestLicenseScanArgsScansLicenses(t *testing.T) {
	args := trivyLicenseScanArgs(false, "/src")
	if !hasFlagValue(args, "--scanners", "license") {
		t.Errorf("trivyLicenseScanArgs = %v, missing --scanners license", args)
	}
	if args[0] != "trivy" || args[1] != "fs" {
		t.Errorf("trivyLicenseScanArgs starts with %v, want trivy fs", args[:2])
	}
}

// TestLicenseScanArgsConfidencePinned keeps the confidence filter on cicd's side
// of the config boundary. It has no observable effect on metadata-declared
// licences (Confidence 1), so only the file-content mode would show a consumer
// raising it to hide findings — which is exactly why it is pinned rather than
// left out for being unmeasurable.
func TestLicenseScanArgsConfidencePinned(t *testing.T) {
	args := trivyLicenseScanArgs(true, "/src")
	if !hasFlagValue(args, "--license-confidence-level", trivyLicenseConfidencePin) {
		t.Errorf("trivyLicenseScanArgs = %v, missing pinned --license-confidence-level", args)
	}
}

// TestLicenseScanArgsFullIsOptIn pins the one knob that is a parameter rather
// than a pin, in both directions. Metadata mode never reads the tree's own
// LICENSE (measured: 16 go.mod manifests and no module cache, zero licences),
// so the default being on is what gives a Go tree anything to judge; a consumer
// whose tree makes full mode expensive must still be able to turn it off.
func TestLicenseScanArgsFullIsOptIn(t *testing.T) {
	if hasFlag(trivyLicenseScanArgs(false, "/src"), "--license-full") {
		t.Error("trivyLicenseScanArgs(false) passed --license-full")
	}
	if !hasFlag(trivyLicenseScanArgs(true, "/src"), "--license-full") {
		t.Error("trivyLicenseScanArgs(true) did not pass --license-full")
	}
}

// TestLicenseScanArgsSeparateOutputPath keeps a license scan and a vulnerability
// scan from overwriting each other's report when they share a container.
func TestLicenseScanArgsSeparateOutputPath(t *testing.T) {
	if trivyLicensePath == trivyNativePath || trivyLicensePath == trivyReportPath {
		t.Fatalf("trivyLicensePath %q collides with a vulnerability report path", trivyLicensePath)
	}
	if !hasFlagValue(trivyLicenseScanArgs(false, "/src"), "--output", trivyLicensePath) {
		t.Error("trivyLicenseScanArgs does not write to trivyLicensePath")
	}
}

// TestLicenseScanArgsCarriesNoVulnerabilityPins is the guard against the two
// flag lists being merged back together. trivySeverityPin is a *vulnerability*
// severity scale and --ignore-unfixed describes vulnerability state; a licence
// severity is a projection of its category, so importing those would let a
// licence finding consume a vulnerability gate's budget.
func TestLicenseScanArgsCarriesNoVulnerabilityPins(t *testing.T) {
	args := trivyLicenseScanArgs(true, "/src")
	for _, f := range []string{"--ignore-unfixed", "--ignore-status", "--pkg-types", "--skip-db-update"} {
		if hasFlag(args, f) {
			t.Errorf("trivyLicenseScanArgs carries vulnerability pin %s", f)
		}
	}
	if hasFlagValue(args, "--scanners", "vuln") {
		t.Error("trivyLicenseScanArgs asks for vuln scanning; the license scan must stay a separate invocation")
	}
}

// flagValuePresent reports the value AND whether the flag was there at all.
//
// hasFlagValue cannot express this assertion: flagValue returns "" for a flag
// that is absent as well as for one pinned to the empty string, so
// hasFlagValue(args, "--ignored-licenses", "") passes with the pin deleted —
// a test that guards nothing while reading as though it guards everything.
func flagValuePresent(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
