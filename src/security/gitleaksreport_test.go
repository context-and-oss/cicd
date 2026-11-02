package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// cleanSARIF is the shape gitleaks writes for a scan that ran and found
// nothing: one run, its rule list, zero results. Measured on v8.30.1 — a
// clean tree still emits runs[0], so "no runs" genuinely means nothing was
// examined, and the rule list is never empty unless no rule loaded.
const cleanSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"aws-access-token"}]}},"results":[]}]}`

// noRulesSARIF is what a .gitleaks.toml with an [allowlist] and no [extend]
// produces: a run, no rules, no results, exit 0.
const noRulesSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[]}},"results":[]}]}`

// The non-git history failure, copied from a real v8.30.1 run with --no-color.
// gitleaks logs the git failure, notes "stderr is not empty", reports 0 commits
// and still exits 0 saying no leaks were found.
const nonGitStderr = `2:11PM ERR [git] fatal: not a git repository (or any parent up to mount point /)
2:11PM ERR [git] Stopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).
2:11PM ERR error="stderr is not empty"
2:11PM INF 0 commits scanned.
2:11PM INF scanned ~0 bytes (0) in 19.2ms
2:11PM INF no leaks found`

// TestGitleaksRunErrorSurfacesNonScans is the regression guard for the silent
// false pass: git-log mode on a tree with no .git exits 0 and reports "no leaks
// found", so every fixture-directory scan read as clean while searching nothing.
func TestGitleaksRunErrorSurfacesNonScans(t *testing.T) {
	cases := []struct {
		name        string
		exit        string
		stderr      string
		report      string
		wantHistory bool
		wantErr     bool
		contains    string
	}{
		{
			name:    "tree scan, clean",
			exit:    "0",
			stderr:  "2:11PM INF scanned ~49 bytes (49 bytes) in 1.9ms\n2:11PM INF no leaks found",
			report:  cleanSARIF,
			wantErr: false,
		},
		{
			name:        "history scan, clean, commits actually scanned",
			exit:        "0",
			stderr:      "2:11PM INF 12 commits scanned.\n2:11PM INF no leaks found",
			report:      cleanSARIF,
			wantHistory: true,
			wantErr:     false,
		},
		{
			// The whole reason this file exists.
			name:        "history scan on a tree with no .git",
			exit:        "0",
			stderr:      nonGitStderr,
			report:      cleanSARIF,
			wantHistory: true,
			wantErr:     true,
			contains:    "examined 0 commits",
		},
		{
			// The same stderr must NOT fail the tree leg: dir mode does not
			// read history, so a missing .git is not a failure there.
			name:    "tree scan is not judged on commit counts",
			exit:    "0",
			stderr:  nonGitStderr,
			report:  cleanSARIF,
			wantErr: false,
		},
		{
			name:        "history scan that reports no commit count at all",
			exit:        "0",
			stderr:      "2:11PM INF no leaks found",
			report:      cleanSARIF,
			wantHistory: true,
			wantErr:     true,
			contains:    "did not report how many commits",
		},
		{
			// Boundary: "10 commits scanned" must not read as a zero count.
			name:        "ten commits is not zero commits",
			exit:        "0",
			stderr:      "2:11PM INF 10 commits scanned.\n2:11PM INF no leaks found",
			report:      cleanSARIF,
			wantHistory: true,
			wantErr:     false,
		},
		{
			name:     "unknown flag, usage text on stderr",
			exit:     "126",
			stderr:   "Error: unknown flag: --no-such-flag\nUsage:\n  gitleaks dir [flags] [path]\n\n  -v, --verbose  show verbose output from scan",
			report:   "",
			wantErr:  true,
			contains: "unknown flag",
		},
		{
			name:     "unreadable config",
			exit:     "1",
			stderr:   "2:09PM FTL unable to load gitleaks config, err: While parsing config: toml: expected character =",
			report:   "",
			wantErr:  true,
			contains: "unable to load gitleaks config",
		},
		{
			name:     "exited zero but wrote nothing",
			exit:     "0",
			report:   "   \n",
			wantErr:  true,
			contains: "wrote no report",
		},
		{
			name:     "report is not SARIF",
			exit:     "0",
			report:   "not json",
			wantErr:  true,
			contains: "not valid SARIF",
		},
		{
			name:     "no runs means nothing was examined",
			exit:     "0",
			report:   `{"version":"2.1.0","runs":[]}`,
			wantErr:  true,
			contains: "no scan runs",
		},
		{
			// cicd's own .gitleaks.toml did this: an [allowlist] with no
			// [extend] replaced 222 default rules with none, and every scan of
			// this repository read clean.
			name:     "no rules loaded means nothing was searched for",
			exit:     "0",
			stderr:   "2:11PM INF scanned ~49 bytes (49 bytes) in 1.9ms\n2:11PM INF no leaks found",
			report:   noRulesSARIF,
			wantErr:  true,
			contains: "loaded no rules",
		},
		{
			name:        "no rules fails the history leg too",
			exit:        "0",
			stderr:      "2:11PM INF 12 commits scanned.\n2:11PM INF no leaks found",
			report:      noRulesSARIF,
			wantHistory: true,
			wantErr:     true,
			contains:    "[extend] useDefault = true",
		},
		{
			name:     "unreadable exit status",
			exit:     "not-a-number",
			report:   cleanSARIF,
			wantErr:  true,
			contains: "unreadable exit status",
		},
		{
			name:        "trailing newline on exit code is tolerated",
			exit:        "0\n",
			stderr:      "2:11PM INF 3 commits scanned.",
			report:      cleanSARIF,
			wantHistory: true,
			wantErr:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := gitleaksRunError(c.exit, c.stderr, c.report, c.wantHistory)
			if c.wantErr && got == "" {
				t.Fatal("expected an error string, got none — a non-scan would pass the gate as clean")
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

// TestFirstGitleaksErrorLine pins the choice of the *first* error line rather
// than the last. cobra prints a usage error followed by the full help text, so
// lastNonEmptyLine — correct for semgrep — would name a flag description as the
// cause of the failure.
func TestFirstGitleaksErrorLine(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "usage error precedes help text",
			in:   "Error: unknown flag: --x\nUsage:\n  gitleaks dir\n  -v, --verbose  show verbose output",
			want: "Error: unknown flag: --x",
		},
		{
			name: "levelled ERR line is picked over the INF lines after it",
			in:   nonGitStderr,
			want: "2:11PM ERR [git] fatal: not a git repository (or any parent up to mount point /)",
		},
		{
			name: "FTL line",
			in:   "2:09PM FTL unable to load gitleaks config",
			want: "2:09PM FTL unable to load gitleaks config",
		},
		{
			name: "no marker falls back to the first line rather than silence",
			in:   "\n  something odd  \nmore",
			want: "something odd",
		},
		{name: "empty", in: "", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstGitleaksErrorLine(c.in); got != c.want {
				t.Errorf("firstGitleaksErrorLine() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestGitleaksCommitCount(t *testing.T) {
	cases := []struct {
		in        string
		want      int
		wantFound bool
	}{
		{in: "2:11PM INF 0 commits scanned.", want: 0, wantFound: true},
		{in: "2:11PM INF 10 commits scanned.", want: 10, wantFound: true},
		{in: "1 commits scanned.", want: 1, wantFound: true},
		{in: "2:11PM INF no leaks found", want: 0, wantFound: false},
		{in: "", want: 0, wantFound: false},
	}
	for _, c := range cases {
		got, found := gitleaksCommitCount(c.in)
		if got != c.want || found != c.wantFound {
			t.Errorf("gitleaksCommitCount(%q) = (%d, %v), want (%d, %v)", c.in, got, found, c.want, c.wantFound)
		}
	}
}

// sarifWith builds a gitleaks-shaped SARIF document from (rule, file, line)
// triples so the merge tests read as locations rather than as JSON.
func sarifWith(results ...[3]string) json.RawMessage {
	var rs []string
	for _, r := range results {
		rs = append(rs, `{"ruleId":"`+r[0]+`","message":{"text":"`+r[0]+` detected secret for file `+r[1]+`."},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+r[1]+`"},`+
			`"region":{"startLine":`+r[2]+`,"snippet":{"text":"REDACTED"}}}}]}`)
	}
	return json.RawMessage(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat"}]}},` +
		`"results":[` + strings.Join(rs, ",") + `]}]}`)
}

func resultKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var out []string
	for _, f := range gitleaksFindings(raw) {
		out = append(out, f.RuleID+":"+f.File)
	}
	return out
}

// TestMergeGitleaksSARIFDeduplicates covers the reason the two legs cannot just
// be concatenated: a secret that is both committed and still in the working
// tree is reported by dir mode *and* by git-log mode, and it is one leak.
func TestMergeGitleaksSARIFDeduplicates(t *testing.T) {
	tree := sarifWith([3]string{"github-pat", "cfg.py", "1"})
	history := sarifWith(
		[3]string{"github-pat", "cfg.py", "1"},    // same leak, seen in a commit
		[3]string{"aws-key", "old/creds.py", "4"}, // history-only: deleted from the tree
	)

	merged := mergeGitleaksSARIF(tree, history)
	got := resultKeys(t, merged)
	if len(got) != 2 {
		t.Fatalf("merged results = %v, want 2 (the shared leak counted once plus the history-only one)", got)
	}

	// The history-only finding must survive: it is the entire value of the leg.
	var foundHistoryOnly bool
	for _, k := range got {
		if k == "aws-key:old/creds.py" {
			foundHistoryOnly = true
		}
	}
	if !foundHistoryOnly {
		t.Errorf("merged results %v dropped the history-only finding", got)
	}

	// One rule catalogue, not two: merging whole documents would duplicate all
	// 222 gitleaks rules into every evidence envelope.
	if n := strings.Count(string(merged), `"rules"`); n != 1 {
		t.Errorf("merged document carries %d rule catalogues, want 1", n)
	}
}

func TestMergeGitleaksSARIFEdgeCases(t *testing.T) {
	tree := sarifWith([3]string{"github-pat", "cfg.py", "1"})

	if got := mergeGitleaksSARIF(tree, nil); string(got) != string(tree) {
		t.Errorf("no history document should leave the tree report untouched")
	}
	if got := mergeGitleaksSARIF(nil, tree); string(got) != string(tree) {
		t.Errorf("no tree document should yield the history report")
	}
	// A same-location, same-rule pair collapses; different lines do not.
	sameLine := mergeGitleaksSARIF(tree, sarifWith([3]string{"github-pat", "cfg.py", "1"}))
	if n := len(gitleaksFindings(sameLine)); n != 1 {
		t.Errorf("identical locations should merge to 1 finding, got %d", n)
	}
	otherLine := mergeGitleaksSARIF(tree, sarifWith([3]string{"github-pat", "cfg.py", "9"}))
	if n := len(gitleaksFindings(otherLine)); n != 2 {
		t.Errorf("a different line is a different finding, got %d", n)
	}
}

// TestGitleaksFindingsMatchTheReport pins the invariant that replaced the second
// gitleaks invocation: findingsCount is derived from the document the envelope
// carries, so the count and the detail rows cannot disagree.
func TestGitleaksFindingsMatchTheReport(t *testing.T) {
	raw := sarifWith(
		[3]string{"github-pat", "cfg.py", "1"},
		[3]string{"aws-key", "deploy/x.tf", "12"},
	)
	findings := gitleaksFindings(raw)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[1].File != "deploy/x.tf" || findings[1].Line != 12 || findings[1].RuleID != "aws-key" {
		t.Errorf("second finding = %+v, want aws-key at deploy/x.tf:12", findings[1])
	}
	// bySeverityFromFindings is what the gate reads.
	if c := bySeverityFromFindings(findings); c[SeverityHigh] != 2 {
		t.Errorf("severity counts = %v, want 2 HIGH", c)
	}

	for _, bad := range []string{"", "   ", "not json", `{"runs":[]}`} {
		if f := gitleaksFindings(json.RawMessage(bad)); len(f) != 0 {
			t.Errorf("gitleaksFindings(%q) = %v, want none", bad, f)
		}
	}
}

// TestGitleaksReportCarriesNoSecret guards the redaction contract from the
// report side: the envelope must never carry a credential value.
func TestGitleaksReportCarriesNoSecret(t *testing.T) {
	// A redacted gitleaks result, as written with --redact.
	raw := sarifWith([3]string{"github-pat", "cfg.py", "1"})
	if strings.Contains(string(raw), "ghp_") {
		t.Fatal("fixture is not redacted, so the assertion below proves nothing")
	}
	for _, f := range gitleaksFindings(raw) {
		if strings.Contains(f.Description, "ghp_") {
			t.Errorf("finding description leaks a credential: %q", f.Description)
		}
	}
}
