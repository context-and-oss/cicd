package main

import (
	"strings"
	"testing"
)

// TestTrivyScanArgsAlwaysScansForVulnerabilities is the regression guard for the
// first of the silent false passes: without --scanners vuln, "--format
// cyclonedx" turns Trivy into an SBOM generator with security scanning off, and
// every vulnerability scan reported zero.
func TestTrivyScanArgsAlwaysScansForVulnerabilities(t *testing.T) {
	for _, sub := range []string{"fs", "image", "sbom"} {
		args := trivyScanArgs(sub, "/src")
		if !hasFlagValue(args, "--scanners", "vuln") {
			t.Errorf("trivyScanArgs(%q) = %v, missing --scanners vuln — the scan would be SBOM-only", sub, args)
		}
		if args[0] != "trivy" || args[1] != sub {
			t.Errorf("trivyScanArgs(%q) starts with %v, want trivy %s", sub, args[:2], sub)
		}
		if args[len(args)-1] != "/src" {
			t.Errorf("trivyScanArgs(%q) does not end with the target: %v", sub, args)
		}
	}
}

// TestTrivyScanAsksForNativeJSON pins the format choice. CycloneDX carries a bag
// of per-vendor `ratings[]` and no verdict, so a severity read out of it is a
// guess; measured on 0.70.0, guessing from entry zero found 3 of debian:11.6's 9
// CRITICALs. Native JSON states Severity per finding. Anything that flips this
// back to cyclonedx silently reintroduces the guess.
func TestTrivyScanAsksForNativeJSON(t *testing.T) {
	for _, sub := range []string{"fs", "image", "sbom"} {
		args := trivyScanArgs(sub, "/src")
		if !hasFlagValue(args, "--format", "json") {
			t.Errorf("trivyScanArgs(%q) does not request native json: %v", sub, args)
		}
		if !hasFlagValue(args, "--output", trivyNativePath) {
			t.Errorf("trivyScanArgs(%q) does not write the native report to %s: %v", sub, trivyNativePath, args)
		}
	}
}

// TestTrivyConvertRendersTheSameScan pins the conversion step: the CycloneDX
// document must be a projection of the report already scanned, never a second
// scan, so the SBOM and the severity counts cannot describe different runs.
func TestTrivyConvertRendersTheSameScan(t *testing.T) {
	args := trivyConvertArgs()
	if args[0] != "trivy" || args[1] != "convert" {
		t.Fatalf("trivyConvertArgs starts with %v, want trivy convert", args[:2])
	}
	if !hasFlagValue(args, "--format", "cyclonedx") {
		t.Errorf("conversion does not request cyclonedx: %v", args)
	}
	if args[len(args)-1] != trivyNativePath {
		t.Errorf("conversion input is %q, want the native report at %s", args[len(args)-1], trivyNativePath)
	}
	if !hasFlagValue(args, "--output", trivyReportPath) {
		t.Errorf("conversion does not write to %s: %v", trivyReportPath, args)
	}
	// `convert` is not a scan, so --scanners would be rejected outright.
	for _, a := range args {
		if a == "--scanners" {
			t.Errorf("trivyConvertArgs passes --scanners, which `trivy convert` does not accept: %v", args)
		}
	}
}

// TestTrivyConvertPinsSeverity closes the hole the conversion step would
// otherwise reopen. `trivy convert` accepts --severity and its -c/--config still
// defaults to `trivy.yaml` in the working directory, so pinning the scan alone
// leaves a consumer's `severity: [CRITICAL]` free to filter the converted report
// instead — the same gutting trivyPinnedFlags exists to prevent, one step later.
func TestTrivyConvertPinsSeverity(t *testing.T) {
	got := flagValue(trivyConvertArgs(), "--severity")
	if got == "" {
		t.Fatal("trivyConvertArgs does not pin --severity; a consumer trivy.yaml could filter the converted report")
	}
	for _, level := range []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if !strings.Contains(got, level) {
			t.Errorf("conversion --severity %q omits %s", got, level)
		}
	}
	if got != flagValue(trivyPinnedFlags, "--severity") {
		t.Errorf("scan and conversion pin different severity lists (%q vs %q); they must not drift",
			flagValue(trivyPinnedFlags, "--severity"), got)
	}
}

// TestTrivyKeepsEveryPackageInTheSbom guards the other half of the report: the
// converted CycloneDX is also the SBOM consumers hand to their inventories, so a
// components list narrowed to vulnerable packages would ship a false inventory.
// --list-all-pkgs currently defaults to true; relying on that default is what
// this pins against.
func TestTrivyKeepsEveryPackageInTheSbom(t *testing.T) {
	for name, args := range map[string][]string{
		"scan fs":    trivyScanArgs("fs", "/src"),
		"scan image": trivyScanArgs("image", "--input", "/image.tar"),
		"scan sbom":  trivyScanArgs("sbom", "/sbom/bom.json"),
		"convert":    trivyConvertArgs(),
	} {
		found := false
		for _, a := range args {
			if a == "--list-all-pkgs" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not pin --list-all-pkgs: %v", name, args)
		}
	}
}

// TestTrivyPinnedFlagsNeutraliseConfigFiltering is the reason cicd can honour a
// consumer's trivy.yaml at all. Every key below removes findings from an
// otherwise successful scan; each must be overridden on the command line, which
// beats the config file. Verified against trivy 0.70.0: with severity and
// ignore-unfixed left to a hostile config, a fixture with ten known CVEs
// reported one.
func TestTrivyPinnedFlagsNeutraliseConfigFiltering(t *testing.T) {
	// config key -> the flag that overrides it
	weakening := map[string]string{
		"severity":                     "--severity",
		"vulnerability.ignore-unfixed": "--ignore-unfixed",
		"vulnerability.ignore-status":  "--ignore-status",
		"pkg.types":                    "--pkg-types",
		"db.skip-update":               "--skip-db-update",
		"scan.scanners":                "--scanners",
	}

	joined := strings.Join(trivyPinnedFlags, " ")
	for key, flag := range weakening {
		if !strings.Contains(joined, flag) {
			t.Errorf("trivy.yaml %q can filter findings out of the report and nothing pins %s: %v",
				key, flag, trivyPinnedFlags)
		}
	}
}

// TestTrivySeverityPinIncludesEveryLevel guards against a well-meaning
// narrowing of the pinned severity list. cicd does its own gating from
// findingsBySeverity, so the report has to carry every level — a report filtered
// to CRITICAL makes a --fail-on HIGH gate unfailable.
func TestTrivySeverityPinIncludesEveryLevel(t *testing.T) {
	got := flagValue(trivyPinnedFlags, "--severity")
	for _, level := range []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if !strings.Contains(got, level) {
			t.Errorf("--severity %q omits %s — findings at that level would never reach the gate", got, level)
		}
	}
}

// TestTrivyPinnedFlagsDoNotSuppress proves the boolean pins are set to the
// permissive value. `--ignore-unfixed` and `--skip-db-update` are the two whose
// *presence* would suppress, so they must carry an explicit =false.
func TestTrivyPinnedFlagsDoNotSuppress(t *testing.T) {
	for _, want := range []string{"--ignore-unfixed=false", "--skip-db-update=false"} {
		found := false
		for _, f := range trivyPinnedFlags {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("trivyPinnedFlags is missing %q; a bare flag would suppress findings: %v", want, trivyPinnedFlags)
		}
	}
}

// TestTrivyConfigDirIsTheSourceMount pins the mechanism that makes a consumer's
// trivy.yaml load at all: Trivy reads it from its working directory.
func TestTrivyConfigDirIsTheSourceMount(t *testing.T) {
	if trivyConfigDir != "/src" {
		t.Fatalf("trivyConfigDir = %q — trivy.yaml is auto-loaded from the working directory, "+
			"so this must be the directory the source is mounted at", trivyConfigDir)
	}
}

func hasFlagValue(args []string, flag, value string) bool {
	return flagValue(args, flag) == value
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
