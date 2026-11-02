//go:build unit_test

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryModePassesSilent. The packaged scans do not take a flag for this:
// they search the -z string for the literal "-silent", and finding it is the
// only thing that stops them starting ZAP with -addonupdate and hot-upgrading
// the add-on that owns the main proxy. A mode that loses the flag does not fail
// — it downloads seventy-three add-ons, runs a rule set nobody pinned, and
// sometimes dies on a BindException nothing in the evidence explains.
func TestEveryModePassesSilent(t *testing.T) {
	for _, mode := range []string{webModeBaseline, webModeAPI, webModeFull} {
		opts := zapOptions{
			Mode:       mode,
			TargetURL:  "http://app-under-test:8080/",
			ReportPath: "/tmp/report.json",
		}
		if mode == webModeAPI {
			opts.APIFormat = "openapi"
			opts.APITarget = "/tmp/api-spec"
		}
		args, err := zapArgs(opts)
		if err != nil {
			t.Fatalf("%s: zapArgs: %v", mode, err)
		}
		i := indexOf(args, "-z")
		if i < 0 || i+1 >= len(args) {
			t.Fatalf("%s: no -z in %v", mode, args)
		}
		if args[i+1] != zapSilentOption {
			t.Errorf("%s: -z %q, want %q", mode, args[i+1], zapSilentOption)
		}
		// The scans test for the literal string, so it has to survive as one
		// argument. Splitting it across two would pass an equality check on
		// the slice and fail shlex.split's reassembly inside the container.
		if strings.ContainsAny(zapSilentOption, " \t") {
			t.Errorf("%s: zapSilentOption %q would shlex-split into more than one option", mode, zapSilentOption)
		}
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// TestAddOnStatusNeverInventsCertainty. An unreadable or unrecognised status is
// the case this normalisation exists for: cicd not knowing whether six rules
// ran must read as the disclosure, never as the clean answer. The mismatch
// value is checked in the other direction too — a truncated status file must
// not be able to downgrade a substituted artifact into a network blip, which it
// would if "mis" fell through to a prefix match.
func TestAddOnStatusNeverInventsCertainty(t *testing.T) {
	for raw, want := range map[string]string{
		zapAddOnStatusOK:         zapAddOnStatusOK,
		"ok\n":                   zapAddOnStatusOK,
		"  ok  ":                 zapAddOnStatusOK,
		zapAddOnStatusMismatch:   zapAddOnStatusMismatch,
		"mismatch\n":             zapAddOnStatusMismatch,
		zapAddOnStatusMissing:    zapAddOnStatusMissing,
		zapAddOnStatusUnreadable: zapAddOnStatusUnreadable,
		"unreadable\n":           zapAddOnStatusUnreadable,
		"unread":                 zapAddOnStatusMissing,
		"":                       zapAddOnStatusMissing,
		"\n":                     zapAddOnStatusMissing,
		"mis":                    zapAddOnStatusMissing,
		"okay":                   zapAddOnStatusMissing,
		"OK":                     zapAddOnStatusMissing,
		"ok mismatch":            zapAddOnStatusMissing,
		"something else]\x00\n":  zapAddOnStatusMissing,
	} {
		if got := zapAddOnStatus(raw); got != want {
			t.Errorf("zapAddOnStatus(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestAddOnDisclosureSplitsTheTwoFailures. Absent and substituted are opposite
// facts, and only one of them is the scan's problem. A missing add-on narrows
// what was looked for and is disclosed; wrong bytes mean cicd asked for an
// artifact by digest and was handed another, which is a verdict on the supply
// chain and not on the target. Collapsing them either way loses the distinction
// a reader needs to know whose problem it is.
func TestAddOnDisclosureSplitsTheTwoFailures(t *testing.T) {
	if w, e := zapAddOnWarning(zapAddOnStatusOK), zapAddOnError(zapAddOnStatusOK); w != "" || e != "" {
		t.Errorf("a loaded add-on disclosed something: warning=%q error=%q", w, e)
	}
	if zapAddOnError(zapAddOnStatusMissing) != "" {
		t.Error("an add-on that did not arrive was reported as a supply-chain event")
	}
	if zapAddOnWarning(zapAddOnStatusMismatch) != "" {
		t.Error("wrong bytes were reported as a warning, which lets a substituted artifact pass the gate")
	}
	// The third failure, and the reason there is a third. A file cicd could
	// not read says nothing at all about its bytes, so it must never reach
	// the accusation — that is the envelope this code actually shipped once.
	if zapAddOnError(zapAddOnStatusUnreadable) != "" {
		t.Error("an add-on cicd could not read was reported as a substituted artifact")
	}
	unread := zapAddOnWarning(zapAddOnStatusUnreadable)
	if unread == "" {
		t.Fatal("an add-on cicd could not read disclosed nothing, so six rules went missing in silence")
	}
	if unread == zapAddOnWarning(zapAddOnStatusMissing) {
		t.Error("an unreadable add-on and an absent one read identically, so nobody can tell whose problem it is")
	}
	if strings.Contains(unread, zapPscanRulesBetaSHA256) {
		t.Errorf("the unreadable warning quotes a digest it never computed: %s", unread)
	}

	warn := zapAddOnWarning(zapAddOnStatusMissing)
	if warn == "" {
		t.Fatal("a scan that lost six passive rules disclosed nothing")
	}
	// Every rule by name. A count would be a number a reader cannot act on;
	// the point of naming them is that "Source Code Disclosure did not run"
	// is a sentence someone can decide about.
	for _, rule := range zapBetaPassiveRules {
		for _, msg := range []string{warn, unread} {
			if !strings.Contains(msg, rule) {
				t.Errorf("the reduced-rules warning does not name %q: %s", rule, msg)
			}
		}
	}
	if len(zapBetaPassiveRules) == 0 {
		t.Fatal("no rules are named, so the warning names nothing and the loop above proved nothing")
	}

	errMsg := zapAddOnError(zapAddOnStatusMismatch)
	if !strings.Contains(errMsg, zapPscanRulesBetaSHA256) {
		t.Errorf("the rejection does not quote the pin it checked against: %s", errMsg)
	}
	if !strings.Contains(errMsg, zapPscanRulesBetaURL) {
		t.Errorf("the rejection does not say where the artifact came from: %s", errMsg)
	}
}

// TestPinIsAWholePin. The version is the only part meant to be edited; the URL
// and the staged filename are built from it, so a bump that changes one and not
// the others fetches one artifact and checks the digest of another.
func TestPinIsAWholePin(t *testing.T) {
	if !strings.Contains(zapPscanRulesBetaURL, zapPscanRulesBetaVersion) {
		t.Errorf("URL %q does not carry version %q", zapPscanRulesBetaURL, zapPscanRulesBetaVersion)
	}
	if !strings.HasSuffix(zapPscanRulesBetaURL, zapPscanRulesBetaFile) {
		t.Errorf("URL %q does not end in the file it is checked as (%q)", zapPscanRulesBetaURL, zapPscanRulesBetaFile)
	}
	if !strings.HasSuffix(zapAddOnStagePath, zapPscanRulesBetaFile) ||
		!strings.HasSuffix(zapAddOnInstallPath, zapPscanRulesBetaFile) {
		t.Errorf("staged at %q, installed as %q — one of them is not the pinned file %q",
			zapAddOnStagePath, zapAddOnInstallPath, zapPscanRulesBetaFile)
	}
	if len(zapPscanRulesBetaSHA256) != 64 {
		t.Errorf("sha256 %q is not 64 hex characters", zapPscanRulesBetaSHA256)
	}
}

// TestAddOnStaging drives the real shell text.
//
// The three container paths are rewritten to a temp directory and sha256sum is
// replaced by a fake on PATH, so the branches run here exactly as they run in
// the scan container. What this catches that reading cannot: a `cp` that is not
// guarded by the digest check, an `exit` that would abort the scan over a
// missing add-on, and a status file that disagrees with what is on disk.
//
// The fake prints a digest line and does not merely exit, because the case that
// reached production did neither of the two things a boolean fake can express:
// sha256sum could not open the file, which is exit 1 with nothing on stdout —
// indistinguishable from a digest mismatch to any check that reads only the
// status. The unreadable case below is the regression test for an envelope that
// accused GitHub of serving different bytes when the real problem was a mount
// mode.
func TestAddOnStaging(t *testing.T) {
	// sum is what the fake sha256sum does: "match" prints the pinned digest,
	// "differ" prints another one, "unreadable" fails the way a file the scan
	// user cannot open fails — exit 1, nothing on stdout, a reason on stderr.
	for _, tc := range []struct {
		name        string
		stage       bool
		sum         string
		installable bool
		want        string
		wantCopied  bool
	}{
		{name: "digest matches", stage: true, sum: "match", installable: true, want: zapAddOnStatusOK, wantCopied: true},
		{name: "digest does not match", stage: true, sum: "differ", installable: true, want: zapAddOnStatusMismatch},
		{name: "staged but unreadable", stage: true, sum: "unreadable", installable: true, want: zapAddOnStatusUnreadable},
		{name: "nothing was staged", stage: false, sum: "match", installable: true, want: zapAddOnStatusMissing},
		{name: "plugin dir not writable", stage: true, sum: "match", installable: false, want: zapAddOnStatusMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(root, "staged.zap")
			installDir := filepath.Join(root, "plugin")
			install := filepath.Join(installDir, "installed.zap")
			status := filepath.Join(root, "status")

			if tc.stage {
				if err := os.WriteFile(stage, []byte("add-on bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.installable {
				if err := os.MkdirAll(installDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			fake := map[string]string{
				"match":  "#!/bin/sh\necho \"" + zapPscanRulesBetaSHA256 + "  $1\"\n",
				"differ": "#!/bin/sh\necho \"0000000000000000000000000000000000000000000000000000000000000000  $1\"\n",
				// Exactly what coreutils does on a file it cannot open:
				// a reason on stderr, nothing on stdout, exit 1.
				"unreadable": "#!/bin/sh\necho \"sha256sum: $1: Permission denied\" >&2\nexit 1\n",
			}[tc.sum]
			if err := os.WriteFile(filepath.Join(bin, "sha256sum"), []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}

			script := zapAddOnStageScript
			script = strings.ReplaceAll(script, zapAddOnStagePath, stage)
			script = strings.ReplaceAll(script, zapAddOnInstallPath, install)
			script = strings.ReplaceAll(script, zapAddOnStatusPath, status)

			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			// Never non-zero. Prepended to the scan's own script, a failure
			// here would turn a scan that lost six rules into a scan that
			// never happened.
			if err != nil {
				t.Fatalf("staging exited non-zero (%v), aborting the scan it is prepended to: %s", err, out)
			}

			got, readErr := os.ReadFile(status)
			if readErr != nil {
				t.Fatalf("no status written: %v", readErr)
			}
			if strings.TrimSpace(string(got)) != tc.want {
				t.Errorf("status %q, want %q", strings.TrimSpace(string(got)), tc.want)
			}

			_, statErr := os.Stat(install)
			if copied := statErr == nil; copied != tc.wantCopied {
				t.Errorf("add-on present in the plugin dir = %v, want %v", copied, tc.wantCopied)
			}
		})
	}
}

// TestRunScriptStagesBeforeItScans. Order is the whole point: ZAP reads the
// plugin directory once, at startup, so an add-on copied in after the scan
// command has started is an add-on that never loads — and the status file would
// still say ok.
func TestRunScriptStagesBeforeItScans(t *testing.T) {
	stage := strings.Index(zapRunScript, zapAddOnStageScript)
	if stage < 0 {
		t.Fatal("zapRunScript does not stage the pinned add-on at all")
	}
	scan := strings.Index(zapRunScript, `"$@" >`)
	if scan < 0 {
		t.Fatal("zapRunScript does not run the scan")
	}
	if stage > scan {
		t.Error("the add-on is staged after the scan has already started, so it never loads")
	}
}
