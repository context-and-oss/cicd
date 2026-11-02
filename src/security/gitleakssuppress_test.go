package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// glResult is one gitleaks-shaped SARIF result; end 0 means a single line.
type glResult struct {
	rule, file string
	line, end  int
}

func glSARIF(rules []string, results ...glResult) json.RawMessage {
	var rs, ids []string
	for _, id := range rules {
		ids = append(ids, `{"id":"`+id+`"}`)
	}
	for _, r := range results {
		region := `"startLine":` + itoa(r.line)
		if r.end > 0 {
			region += `,"endLine":` + itoa(r.end)
		}
		rs = append(rs, `{"ruleId":"`+r.rule+`","message":{"text":"`+r.rule+` detected secret"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+r.file+`"},`+
			`"region":{`+region+`,"snippet":{"text":"REDACTED"}}}}]}`)
	}
	return json.RawMessage(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[` +
		strings.Join(ids, ",") + `]}},"results":[` + strings.Join(rs, ",") + `]}]}`)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

var glDefaults = []string{"aws-access-token", "github-pat", "private-key"}

// suppressedBy returns rule:file → the suppression kind and justification of
// every suppressed result.
func suppressedBy(t *testing.T, raw json.RawMessage) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, r := range gitleaksRawResults(raw) {
		var v struct {
			gitleaksSARIFResult
			Suppressions []struct {
				Kind, Status, Justification string
			} `json:"suppressions"`
		}
		if err := json.Unmarshal(r, &v); err != nil {
			t.Fatal(err)
		}
		if len(v.Suppressions) == 1 {
			s := v.Suppressions[0]
			if s.Status != "accepted" {
				t.Errorf("status %q, want accepted", s.Status)
			}
			out[v.RuleID+":"+v.file()] = s.Kind + " " + s.Justification
		}
	}
	return out
}

// TestGitleaksDisclosesEachMechanism is the measured fixture: one finding the
// real scan counts and five a suppression removed, one per mechanism plus a
// multi-line key whose mark sits on its third line. Every suppressed one comes
// back visible, attributed and uncounted.
func TestGitleaksDisclosesEachMechanism(t *testing.T) {
	primary := glSARIF(glDefaults, glResult{"github-pat", "c.go", 1, 0})
	shadow := glSARIF(glDefaults,
		glResult{"github-pat", "c.go", 1, 0},
		glResult{"aws-access-token", "a.go", 2, 0},
		glResult{"aws-access-token", "sp ace/e.go", 2, 0},
		glResult{"github-pat", "b.go", 3, 0},
		glResult{"private-key", "k.pem", 1, 5},
		glResult{"github-pat", "allowed/d.go", 7, 0},
		glResult{"github-pat", "bundle.zip!app/.env", 1, 0},
	)
	ignored := parseGitleaksIgnored("a.go:aws-access-token:2\n\"sp ace/e.go:aws-access-token:2\"\n")
	marks, known := parseGitleaksAllowMarks("./b.go:3:gitleaks:allow\n./k.pem:3:gitleaks:allow\n", "0")
	if !known {
		t.Fatal("marks unknown")
	}

	out, warnings := gitleaksDiscloseSuppressions(primary, shadow, ignored, marks, known, true, "source tree")

	if got := gitleaksFindings(out); len(got) != 1 || got[0].File != "c.go" {
		t.Errorf("counted findings = %+v, want only c.go", got)
	}
	if got := parseSarifSeverities(out); got[SeverityMedium]+got[SeverityHigh] != 1 {
		t.Errorf("severity counts = %v, want the one counted finding", got)
	}
	got := suppressedBy(t, out)
	want := map[string]string{
		"aws-access-token:a.go":          "external removed by a fingerprint in .gitleaksignore",
		"aws-access-token:sp ace/e.go":   "external removed by a fingerprint in .gitleaksignore",
		"github-pat:b.go":                "inSource removed by an inline gitleaks:allow",
		"private-key:k.pem":              "inSource removed by an inline gitleaks:allow",
		"github-pat:allowed/d.go":        "external removed by the scanned tree's .gitleaks.toml",
		"github-pat:bundle.zip!app/.env": "external removed by a suppression cicd could not identify",
	}
	if len(got) != len(want) {
		t.Errorf("suppressed = %v", got)
	}
	for k, prefix := range want {
		if !strings.HasPrefix(got[k], prefix) {
			t.Errorf("%s: %q, want prefix %q", k, got[k], prefix)
		}
	}

	wantWarnings := []string{
		`gitleaks: SUPPRESSED — 2 findings in the source tree were removed by a fingerprint in .gitleaksignore and are not counted: "a.go:2 aws-access-token", "sp ace/e.go:2 aws-access-token"`,
		`gitleaks: SUPPRESSED — 2 findings in the source tree were removed by an inline gitleaks:allow and are not counted: "b.go:3 github-pat", "k.pem:1 private-key"`,
		`gitleaks: SUPPRESSED — 1 finding in the source tree was removed by the scanned tree's .gitleaks.toml`,
		`gitleaks: SUPPRESSED — 1 finding in the source tree was removed by a suppression cicd could not identify`,
	}
	if len(warnings) != len(wantWarnings) {
		t.Fatalf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
	for i, w := range wantWarnings {
		if !strings.HasPrefix(warnings[i], w) {
			t.Errorf("warning %d:\n%s\nwant prefix:\n%s", i, warnings[i], w)
		}
	}
}

// TestGitleaksUnknownMarksBlameNothing: when the mark list could not be read,
// a finding no fingerprint explains is not pinned on the config — an unseen
// mark may be what removed it.
func TestGitleaksUnknownMarksBlameNothing(t *testing.T) {
	primary := glSARIF(glDefaults)
	shadow := glSARIF(glDefaults, glResult{"github-pat", "d.go", 7, 0})
	marks, known := parseGitleaksAllowMarks("./d.go:7:gitleaks:allow\n", "2")
	if known || marks != nil {
		t.Fatalf("exit 2 read as a known list: %v %v", marks, known)
	}
	_, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, marks, known, true, "build output")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "in the build output was removed by a suppression cicd could not identify") {
		t.Errorf("warnings = %v", warnings)
	}
}

// TestGitleaksNamesTheNarrowedRules: a config that loads fewer than the
// default rules is named with what it leaves out; its findings still count.
func TestGitleaksNamesTheNarrowedRules(t *testing.T) {
	primary := glSARIF([]string{"github-pat"}, glResult{"github-pat", "c.go", 1, 0})
	shadow := glSARIF(glDefaults, glResult{"github-pat", "c.go", 1, 0})
	out, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, true, "source tree")
	want := `gitleaks: NARROWED RULES — the source tree's .gitleaks.toml loads 1 rule and leaves out 2 of gitleaks' 3 default rules, which searched for nothing: "aws-access-token", "private-key"`
	if len(warnings) != 1 || warnings[0] != want {
		t.Errorf("warnings = %q", warnings)
	}
	if string(out) != string(primary) {
		t.Errorf("nothing suppressed, yet the report changed")
	}
	// Without a config the shadow's rules are the real scan's: nothing to name.
	if _, w := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, false, "source tree"); len(w) != 0 {
		t.Errorf("no config, warnings = %v", w)
	}
}

// TestGitleaksDisclosureCountsDuplicates: a rule firing twice on one line in
// the shadow and once in the real scan left one finding suppressed.
func TestGitleaksDisclosureCountsDuplicates(t *testing.T) {
	primary := glSARIF(glDefaults, glResult{"github-pat", "c.go", 1, 0})
	shadow := glSARIF(glDefaults, glResult{"github-pat", "c.go", 1, 0}, glResult{"github-pat", "c.go", 1, 0})
	out, warnings := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, true, "source tree")
	if len(suppressedBy(t, out)) != 1 || len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
	if n := len(gitleaksFindings(out)); n != 1 {
		t.Errorf("counted = %d, want 1", n)
	}
}

// TestGitleaksSuppressedTreeResultDoesNotHideHistory: history is not
// shadowed, so a history finding at a suppressed tree location is one gitleaks
// reported, and the merge must count it.
func TestGitleaksSuppressedTreeResultDoesNotHideHistory(t *testing.T) {
	primary := glSARIF(glDefaults)
	shadow := glSARIF(glDefaults, glResult{"github-pat", "d.go", 7, 0})
	tree, _ := gitleaksDiscloseSuppressions(primary, shadow, nil, nil, true, true, "source tree")
	merged := mergeGitleaksSARIF(tree, glSARIF(glDefaults, glResult{"github-pat", "d.go", 7, 0}))
	if n := len(gitleaksFindings(merged)); n != 1 {
		t.Errorf("counted = %d, want the history finding", n)
	}
}

func TestGitleaksShadowNeeded(t *testing.T) {
	cases := []struct {
		config, ignore bool
		marks          []gitleaksMark
		known, want    bool
	}{
		{known: true, want: false},
		{config: true, known: true, want: true},
		{ignore: true, known: true, want: true},
		{marks: []gitleaksMark{{"a.go", 1}}, known: true, want: true},
		{known: false, want: true},
	}
	for _, c := range cases {
		if got := gitleaksShadowNeeded(c.config, c.ignore, c.marks, c.known); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
	config, ignore := gitleaksSuppressionFiles([]string{"go.mod", ".gitleaks.toml/", ".gitleaksignore"})
	if config || !ignore {
		t.Errorf("config %v ignore %v: a directory named .gitleaks.toml is not the config", config, ignore)
	}
}
