package main

import (
	"strings"
	"testing"
)

func TestCheckGitleaksConfigPath(t *testing.T) {
	for _, ok := range []string{"", ".gitleaks.archive.toml", "ci/gitleaks.toml", ".gitleaks.toml"} {
		if err := checkGitleaksConfigPath(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/abs.toml", "../x.toml", "a/../b.toml", "dir/"} {
		err := checkGitleaksConfigPath(bad)
		want := "gitleaks-config " + `"` + bad + `"` + ": must be a file path relative to the source root with no '..' components"
		if err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", bad, err, want)
		}
	}
}

func TestGitleaksConfigConflict(t *testing.T) {
	if err := gitleaksConfigConflict([]string{".gitleaks.toml"}, ""); err != nil {
		t.Errorf("nothing supplied, yet refused: %v", err)
	}
	if err := gitleaksConfigConflict([]string{"index.js", ".gitleaksignore"}, "x.toml"); err != nil {
		t.Errorf("no config in the output root, yet refused: %v", err)
	}
	if err := gitleaksConfigConflict([]string{".gitleaks.toml/"}, "x.toml"); err != nil {
		t.Errorf("a directory of the config's name is not the config: %v", err)
	}
	err := gitleaksConfigConflict([]string{"index.js", ".gitleaks.toml"}, "x.toml")
	want := "gitleaks-config: the build output already carries a .gitleaks.toml at its root; one config per scan — remove it from the build output or drop --gitleaks-config"
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}

func TestGitleaksConfigMissing(t *testing.T) {
	// A listing decides presence: the exact path, never a directory of that
	// name (trailing separator) or a sibling a glob would also match.
	cases := []struct {
		matches []string
		path    string
		want    bool
	}{
		{[]string{".gitleaks.archive.toml"}, ".gitleaks.archive.toml", true},
		{[]string{"ci/gitleaks.toml"}, "ci/gitleaks.toml", true},
		{nil, ".gitleaks.archive.toml", false},
		{[]string{".gitleaks.archive.toml/"}, ".gitleaks.archive.toml", false},
		{[]string{"a1.toml", "a2.toml"}, "a?.toml", false},
	}
	for _, c := range cases {
		if got := gitleaksConfigPresent(c.matches, c.path); got != c.want {
			t.Errorf("present(%v, %q) = %v, want %v", c.matches, c.path, got, c.want)
		}
	}
	err := gitleaksConfigMissing("ci/none.toml")
	want := `gitleaks-config "ci/none.toml": not found in the source tree, or not a file`
	if err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}

// TestGitleaksNamesTheSuppliedArchiveConfig: a config cicd copied from the
// source tree is named with its path in every disclosure that blames it, so
// the acceptance can be opened by whoever reads the envelope.
func TestGitleaksNamesTheSuppliedArchiveConfig(t *testing.T) {
	origin := gitleaksConfigOrigin{present: true, supplied: ".gitleaks.archive.toml"}
	primary := glSARIF([]string{"github-pat"})
	shadow := glSARIF(glDefaults, glResult{"aws-access-token", "leaked.env", 1, 0})
	out, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, origin, "build output")
	want := []string{
		`gitleaks: NARROWED RULES — the gitleaks config supplied from .gitleaks.archive.toml in the source tree loads 1 rule and leaves out 2 of gitleaks' 3 default rules, which searched for nothing: "aws-access-token", "private-key"`,
		`gitleaks: SUPPRESSED — 1 finding in the build output was removed by the gitleaks config supplied from .gitleaks.archive.toml in the source tree (an [allowlist] entry, or a default rule it disables, narrows or does not load) and is not counted: "leaked.env:1 aws-access-token"`,
	}
	if len(warnings) != len(want) {
		t.Fatalf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
	for i := range want {
		if warnings[i] != want[i] {
			t.Errorf("warning %d:\n%s\nwant:\n%s", i, warnings[i], want[i])
		}
	}
	just := suppressedBy(t, out)
	if j := just["aws-access-token:leaked.env"]; !strings.HasPrefix(j, "external removed by the gitleaks config supplied from .gitleaks.archive.toml in the source tree") {
		t.Errorf("justification = %q (all: %v)", j, just)
	}
	if n := len(gitleaksFindings(out)); n != 0 {
		t.Errorf("counted = %d, want 0", n)
	}
	// Without a supplied path the tree's own wording is unchanged.
	own := gitleaksConfigOrigin{present: true}
	if got := own.phrase("the scanned tree's .gitleaks.toml"); got != "the scanned tree's .gitleaks.toml" {
		t.Errorf("phrase = %q", got)
	}
}
