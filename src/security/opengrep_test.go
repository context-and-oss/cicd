//go:build unit_test

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestOpengrepAssetsPerPlatform holds the platform switch: each supported
// platform gets its own binary and wheel with its own digest, a variant is
// ignored, and anything else is refused rather than handed the other
// architecture's asset — whose digest says nothing about this one.
func TestOpengrepAssetsPerPlatform(t *testing.T) {
	cases := []struct {
		platform, binAsset, binSHA, wheel, wheelSHA string
	}{
		{"linux/amd64", opengrepAMD64Asset, opengrepAMD64SHA256, pyyamlAMD64Wheel, pyyamlAMD64SHA256},
		{"linux/arm64", opengrepARM64Asset, opengrepARM64SHA256, pyyamlARM64Wheel, pyyamlARM64SHA256},
		{" linux/arm64/v8\n", opengrepARM64Asset, opengrepARM64SHA256, pyyamlARM64Wheel, pyyamlARM64SHA256},
	}
	for _, c := range cases {
		a, err := opengrepAssetsFor(c.platform)
		if err != nil {
			t.Fatalf("%q: %v", c.platform, err)
		}
		if a.BinURL != opengrepRelease+c.binAsset || a.BinSHA256 != c.binSHA {
			t.Errorf("%q: binary %s / %s", c.platform, a.BinURL, a.BinSHA256)
		}
		if a.WheelName != c.wheel || a.WheelSHA256 != c.wheelSHA || !strings.HasSuffix(a.WheelURL, "/"+c.wheel) {
			t.Errorf("%q: wheel %s / %s / %s", c.platform, a.WheelURL, a.WheelName, a.WheelSHA256)
		}
		if a.WheelPath() != pyyamlWheelDir+"/"+c.wheel {
			t.Errorf("%q: pip reads platform tags from the filename, so the wheel keeps its name: %s", c.platform, a.WheelPath())
		}
	}
	for _, bad := range []string{"", "linux/386", "darwin/arm64", "windows/amd64", "arm64"} {
		if a, err := opengrepAssetsFor(bad); err == nil || !strings.Contains(err.Error(), "SAST did not run") {
			t.Errorf("%q: want a refusal naming the non-run, got %+v / %v", bad, a, err)
		}
	}
}

// TestOpengrepPinsAreWellFormed: a digest that is not 64 lowercase hex can
// never match sha256sum, so every scan would fail as a substituted download —
// a supply-chain accusation produced by a typo. And the two architectures must
// not share a digest, which is what a copy-paste bump looks like.
func TestOpengrepPinsAreWellFormed(t *testing.T) {
	for name, d := range map[string]string{
		"opengrep amd64": opengrepAMD64SHA256, "opengrep arm64": opengrepARM64SHA256,
		"pyyaml amd64": pyyamlAMD64SHA256, "pyyaml arm64": pyyamlARM64SHA256,
	} {
		if !sha256Hex.MatchString(d) {
			t.Errorf("%s digest is not a sha256: %q", name, d)
		}
	}
	if opengrepAMD64SHA256 == opengrepARM64SHA256 || pyyamlAMD64SHA256 == pyyamlARM64SHA256 {
		t.Error("two architectures share one digest")
	}
	if !strings.Contains(opengrepRelease, "/v"+opengrepVersion+"/") {
		t.Errorf("release URL does not carry the pinned version: %s", opengrepRelease)
	}
	// 1.x drops an unparseable file without a notification — the failure the
	// swap exists to close. See specs/swap-semgrep-for-opengrep.md.
	if strings.HasPrefix(opengrepVersion, "0.") || strings.HasPrefix(opengrepVersion, "1.") {
		t.Errorf("opengrep %s is below the 2.0.0 floor", opengrepVersion)
	}
}

// TestPyYAMLWheelFitsTheBase: the wheel is a cp312 build installed with
// --no-index onto pythonImage. A base bump across a minor without new wheels
// would fail pip at scan time; failing here says so at review time instead.
func TestPyYAMLWheelFitsTheBase(t *testing.T) {
	minor := strings.SplitN(pythonTag, "-", 2)[0] // "3.12"
	tag := "cp" + strings.ReplaceAll(minor, ".", "")
	for _, w := range []string{pyyamlAMD64Wheel, pyyamlARM64Wheel} {
		if !strings.HasPrefix(w, "pyyaml-"+pyyamlVersion+"-"+tag+"-"+tag+"-") {
			t.Errorf("wheel %s does not fit python %s (want %s, PyYAML %s)", w, minor, tag, pyyamlVersion)
		}
	}
	if !strings.Contains(pyyamlAMD64Wheel, "x86_64") || !strings.Contains(pyyamlARM64Wheel, "aarch64") {
		t.Error("a wheel is pinned under the wrong architecture")
	}
}

// TestOpengrepVerifyErrorVocabulary: each status reads as its own fact, the
// binary is reported before the wheel, and a status cicd cannot read is
// "missing" — never a mismatch, which accuses the download.
func TestOpengrepVerifyErrorVocabulary(t *testing.T) {
	a, err := opengrepAssetsFor("linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		raw, want, not string
	}{
		{"ok ok\n", "", ""},
		{"mismatch ok", "PINNED DOWNLOAD REJECTED — the opengrep " + opengrepVersion + " binary", ""},
		{"ok mismatch", "PINNED DOWNLOAD REJECTED — PyYAML " + pyyamlVersion, ""},
		{"mismatch mismatch", "the opengrep " + opengrepVersion + " binary", "PyYAML"},
		{"unreadable ok", "could not read it back", "PINNED DOWNLOAD REJECTED"},
		{"ok uninstallable", "pip would not install it", "PINNED DOWNLOAD REJECTED"},
		{"missing ok", "was not in the scan container", "PINNED DOWNLOAD REJECTED"},
		{"", "was not in the scan container", "PINNED DOWNLOAD REJECTED"},
		{"ok", "PyYAML", "PINNED DOWNLOAD REJECTED"},
		{"garbled-status ok", "was not in the scan container", "PINNED DOWNLOAD REJECTED"},
	}
	for _, c := range cases {
		got := opengrepVerifyError(c.raw, a)
		if c.want == "" {
			if got != "" {
				t.Errorf("%q: want no error, got %s", c.raw, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) || (c.not != "" && strings.Contains(got, c.not)) {
			t.Errorf("%q: got %s", c.raw, got)
		}
		if !strings.Contains(got, "SAST did not run") {
			t.Errorf("%q: every verify failure must say SAST did not run: %s", c.raw, got)
		}
	}
	if got := opengrepVerifyError("mismatch ok", a); !strings.Contains(got, a.BinSHA256) || !strings.Contains(got, a.BinURL) {
		t.Errorf("a mismatch must name the URL and the pinned digest: %s", got)
	}
}

// TestOpengrepVerifyScriptRefusesBeforeTheEngineRuns drives the real script
// with the container paths rebased into a temp dir: a binary whose bytes do
// not match, or that is absent, is never executed, the run is classified as a
// non-run (exit 2, empty report), and the status file says which.
func TestOpengrepVerifyScriptRefusesBeforeTheEngineRuns(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is required to run the verify script")
	}
	digest := func(b string) string { h := sha256.Sum256([]byte(b)); return hex.EncodeToString(h[:]) }
	const engine = "#!/bin/sh\necho ran > \"$ENGINE_MARKER\"\n"

	cases := []struct {
		name      string
		place     bool
		pinned    string
		wantState string
	}{
		{"substituted binary", true, digest("something else"), "mismatch missing"},
		{"absent binary", false, digest(engine), "missing missing"},
		{"matching binary, no wheel", true, digest(engine), "ok missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"tmp", "bin"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			bin := filepath.Join(root, "bin", "opengrep")
			if c.place {
				if err := os.WriteFile(bin, []byte(engine), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			rebase := strings.NewReplacer("/tmp/", root+"/tmp/", opengrepBinPath, bin)
			script := rebase.Replace(opengrepVerifyScript) + bin + " scan\n"
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(),
				"ENGINE_MARKER="+filepath.Join(root, "ran"),
				opengrepSHA256Env+"="+c.pinned,
				pyyamlWheelEnv+"="+filepath.Join(root, "absent.whl"),
				pyyamlSHA256Env+"="+digest("wheel"),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			state, _ := os.ReadFile(filepath.Join(root, "tmp", "opengrep.verify"))
			if strings.TrimSpace(string(state)) != c.wantState {
				t.Fatalf("status %q, want %q", state, c.wantState)
			}
			if _, err := os.Stat(filepath.Join(root, "ran")); err == nil {
				t.Fatal("the engine ran although verification failed")
			}
			exit, _ := os.ReadFile(filepath.Join(root, "tmp", "semgrep.exit"))
			if strings.TrimSpace(string(exit)) != "2" {
				t.Errorf("exit status %q, want 2 (a non-run)", exit)
			}
			if report, err := os.ReadFile(filepath.Join(root, "tmp", "report.sarif")); err != nil || len(report) != 0 {
				t.Errorf("report must exist and be empty, got %q / %v", report, err)
			}
		})
	}
}
