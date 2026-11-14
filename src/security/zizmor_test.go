//go:build unit_test

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// zizmorFixtureDir holds both runs of zizmorScript, verbatim from the pinned
// zizmor 1.32.0 image, over testdata/zizmor-workflows materialised (every
// .fixture suffix stripped). See the README beside the capture.
const zizmorFixtureDir = "testdata/zizmor-1.32.0"

func readZizmorFixture(t *testing.T) (primary, shadow zizmorRun) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(zizmorFixtureDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	primary = zizmorRun{SARIF: read("primary.sarif"), Stderr: read("primary.err"), Exit: read("primary.exit")}
	shadow = zizmorRun{SARIF: read("shadow.sarif"), Stderr: read("shadow.err"), Exit: read("shadow.exit")}
	return primary, shadow
}

func zizmorResultsOf(t *testing.T, raw json.RawMessage) []map[string]any {
	t.Helper()
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string           `json:"name"`
					Rules []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			AutomationDetails map[string]any   `json:"automationDetails"`
			Results           []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != zizmorToolName || doc.Runs[0].AutomationDetails["id"] != zizmorToolName {
		t.Fatalf("SARIF run is not identified as zizmor's: %s", raw)
	}
	rules := map[string]bool{}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		rules[r["id"].(string)] = true
	}
	for _, r := range doc.Runs[0].Results {
		if !rules[r["ruleId"].(string)] {
			t.Errorf("result rule %v has no rule entry in the driver", r["ruleId"])
		}
	}
	return doc.Runs[0].Results
}

// TestZizmorReadsTheCollectionLog: the verbose log is the only place zizmor
// says which inputs it registered, which it audited and which audits it ran.
// broken.yml (invalid YAML) and schemabad.yml (valid YAML, not a workflow)
// were registered and never completed; nested/ is below .github/workflows,
// where GitHub runs nothing, so zizmor never registers it at all.
func TestZizmorReadsTheCollectionLog(t *testing.T) {
	primary, _ := readZizmorFixture(t)
	l := parseZizmorLog(primary.Stderr)
	wantCompleted := []string{
		".github/actions/act1/action.yml",
		".github/dependabot.yml",
		".github/workflows/clean.yml",
		".github/workflows/ignored.yml",
		".github/workflows/inject.yml",
		"ignoredir/.github/workflows/c.yml",
		"sub/.github/workflows/clean.yml",
	}
	if !reflect.DeepEqual(l.Completed, wantCompleted) {
		t.Errorf("completed = %v, want %v", l.Completed, wantCompleted)
	}
	if want := []string{".github/workflows/broken.yml", ".github/workflows/schemabad.yml"}; !reflect.DeepEqual(l.Unparsed, want) {
		t.Errorf("unparsed = %v, want %v", l.Unparsed, want)
	}
	if l.Failures != 2 {
		t.Errorf("failures = %d, want 2", l.Failures)
	}
	if want := []string{"impostor-commit", "known-vulnerable-actions", "ref-confusion", "ref-version-mismatch", "stale-action-refs"}; !reflect.DeepEqual(l.Skipped, want) {
		t.Errorf("skipped = %v, want %v", l.Skipped, want)
	}
	if len(l.Audits) < 30 {
		t.Errorf("only %d audits read from the log (%v); the scheduling grammar has changed", len(l.Audits), l.Audits)
	}
	for _, a := range l.Audits {
		for _, s := range l.Skipped {
			if a == s {
				t.Errorf("audit %s is both scheduled and skipped", a)
			}
		}
	}
}

// TestZizmorAnalysesTheCapture drives the whole decision over the real
// capture: the ignored ignoredir/ is audited (--collect all), the two
// unparseable files are a PARTIAL SCAN, the offline audits are named, the
// three findings the configuration and an ignore comment removed come back
// suppressed and uncounted, and unpinned-uses is MEDIUM.
func TestZizmorAnalysesTheCapture(t *testing.T) {
	primary, shadow := readZizmorFixture(t)
	res := analyseZizmor(primary, shadow)
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !res.Present {
		t.Fatal("a tree with workflows must have a row")
	}
	if want := (Examined{Unit: zizmorExamined, Count: 7, Total: 9}); *res.Examined != want {
		t.Errorf("examined = %+v, want %+v", *res.Examined, want)
	}
	if want := map[Severity]int{SeverityHigh: 2, SeverityMedium: 2}; !reflect.DeepEqual(res.BySeverity, want) {
		t.Errorf("bySeverity = %v, want %v", res.BySeverity, want)
	}
	if res.Rules == nil || res.Rules.Count < 30 || !strings.Contains(res.Rules.Pinned, "zizmor "+zizmorVersion) {
		t.Errorf("rules = %+v", res.Rules)
	}

	joined := strings.Join(res.Warnings, "\n")
	for _, want := range []string{
		"PARTIAL SCAN — zizmor could not parse 2 of 9",
		".github/workflows/broken.yml, .github/workflows/schemabad.yml",
		"NARROWED AUDITS — the scan runs offline, so 5 audits that need the GitHub API did not run: impostor-commit",
		"3 findings removed by a zizmor ignore comment or the repository's zizmor configuration are not counted",
		"HIGH dangerous-triggers at .github/workflows/inject.yml:2",
		"HIGH template-injection at .github/workflows/ignored.yml:8",
		"MEDIUM artipacked at .github/workflows/inject.yml:8",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
	// Highest severity first.
	if strings.Index(joined, "MEDIUM artipacked") < strings.Index(joined, "HIGH template-injection") {
		t.Errorf("suppressed findings not ordered by severity:\n%s", joined)
	}

	results := zizmorResultsOf(t, res.SARIF)
	if len(results) != 7 {
		t.Fatalf("SARIF carries %d results, want 4 counted + 3 suppressed", len(results))
	}
	// The SARIF agrees with the counts: the unsuppressed results, read back
	// through the one resolver every SARIF consumer uses, are the row.
	counted := map[Severity]int{}
	suppressed := 0
	for _, r := range results {
		if r["suppressions"] != nil {
			suppressed++
			continue
		}
		counted[severityFromSARIFLevel(r["level"].(string))]++
		if r["ruleId"] == "zizmor/unpinned-uses" && r["level"] != "warning" {
			t.Errorf("unpinned-uses stamped %v, want warning", r["level"])
		}
	}
	if suppressed != 3 || !reflect.DeepEqual(counted, res.BySeverity) {
		t.Errorf("SARIF counts %v (+%d suppressed) disagree with the row %v", counted, suppressed, res.BySeverity)
	}
	if got := parseSarifSeverities(res.SARIF); !reflect.DeepEqual(got, res.BySeverity) {
		t.Errorf("parseSarifSeverities = %v, want %v", got, res.BySeverity)
	}
}

// TestZizmorScriptRunsBothScans: the shadow must disable both the
// configuration and the ignore comments; --no-ignores alone leaves a rule a
// zizmor.yml switched off still off.
func TestZizmorScriptRunsBothScans(t *testing.T) {
	s := zizmorScript()
	lines := strings.Split(s, "\n")
	var primary, shadow string
	for _, l := range lines {
		if strings.HasPrefix(l, "zizmor ") {
			if strings.Contains(l, "--no-config") {
				shadow = l
			} else {
				primary = l
			}
		}
	}
	if primary == "" || shadow == "" {
		t.Fatalf("script must run a primary and a shadow:\n%s", s)
	}
	for _, flag := range []string{"--offline", "--collect all", "--format sarif"} {
		if !strings.Contains(primary, flag) || !strings.Contains(shadow, flag) {
			t.Errorf("both runs need %s:\n%s", flag, s)
		}
	}
	if !strings.Contains(primary, " -v ") {
		t.Error("the primary must be verbose: the collection log is read from it")
	}
	if !strings.Contains(shadow, "--no-ignores") || strings.Contains(primary, "--no-config") || strings.Contains(primary, "--no-ignores") {
		t.Errorf("only the shadow drops configuration and ignores:\n%s", s)
	}
	if !strings.HasSuffix(strings.TrimSpace(s), "exit 0") {
		t.Error("the script must always exit 0 so the status files are readable")
	}
}

const zizmorNoInputs = ` INFO zizmor: 🌈 zizmor v1.32.0
fatal: no audit was performed
error: no inputs collected
  |
  = help: collection yielded no auditable inputs
`

// TestZizmorNoInputsIsNoRow: a tree with nothing zizmor collects has no row,
// as a Go repository has no Roslyn row.
func TestZizmorNoInputsIsNoRow(t *testing.T) {
	res := analyseZizmor(zizmorRun{Stderr: zizmorNoInputs, Exit: "3\n"}, zizmorRun{Exit: "3\n"})
	if res.Present || res.Err != nil {
		t.Errorf("no inputs must be no row, got %+v", res)
	}
}

// TestZizmorNothingParsedIsANonRun: zizmor's exit for "every workflow was
// unparseable" is the same exit 3 as "there were no workflows". The log is
// what tells them apart, and the first must never read as the second.
func TestZizmorNothingParsedIsANonRun(t *testing.T) {
	stderr := `DEBUG collect_inputs: zizmor::registry::input: registering workflow input with key file://./.github/workflows/broken.yml
 WARN collect_inputs: zizmor::registry::input: failed to parse input: did not find expected ',' or ']' at line 5 column 1
` + zizmorNoInputs
	res := analyseZizmor(zizmorRun{Stderr: stderr, Exit: "3"}, zizmorRun{Exit: "3"})
	if !res.Present || res.Err == nil {
		t.Fatalf("nothing parsed must be a non-run with a row, got %+v", res)
	}
	for _, want := range []string{"SAST did not run", "could parse none", ".github/workflows/broken.yml"} {
		if !strings.Contains(res.Err.Error(), want) {
			t.Errorf("error %q missing %q", res.Err, want)
		}
	}
	if res.Examined == nil || res.Examined.Count != 0 || res.Examined.Total != 1 {
		t.Errorf("examined = %+v, want 0 of 1", res.Examined)
	}
}

// TestZizmorFatalExitIsANonRun: any exit but 0 or "no inputs" is a run that
// did not happen, with zizmor's own words in the error.
func TestZizmorFatalExitIsANonRun(t *testing.T) {
	res := analyseZizmor(zizmorRun{Stderr: " INFO zizmor: v\nfatal: no audit was performed\nerror: boom\n", Exit: "1"}, zizmorRun{Exit: "0"})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "exited 1") || !strings.Contains(res.Err.Error(), "error: boom") {
		t.Errorf("err = %v", res.Err)
	}
	if res.BySeverity != nil {
		t.Error("a non-run must count nothing")
	}
}

// TestZizmorShadowFailureIsAnError: without the shadow, a pass may rest on
// an ignore comment nobody can read.
func TestZizmorShadowFailureIsAnError(t *testing.T) {
	primary, shadow := readZizmorFixture(t)
	shadow.Exit = "1"
	shadow.Stderr = "error: shadow broke"
	res := analyseZizmor(primary, shadow)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "acceptance nobody can read") {
		t.Errorf("err = %v", res.Err)
	}
	_, shadow = readZizmorFixture(t)
	shadow.SARIF = "not json"
	if res := analyseZizmor(primary, shadow); res.Err == nil {
		t.Error("an unreadable shadow SARIF must be an error")
	}
}

// TestZizmorLogGrammarChangeIsLoud: a Renovate bump that changes the log's
// wording must not leave the examined count, or the rule count, a guess.
func TestZizmorLogGrammarChangeIsLoud(t *testing.T) {
	primary, shadow := readZizmorFixture(t)
	p := primary
	p.Stderr = strings.ReplaceAll(primary.Stderr, "completed ./", "finished ./")
	if res := analyseZizmor(p, shadow); res.Err == nil || !strings.Contains(res.Err.Error(), "could not read which files zizmor audited") {
		t.Errorf("a finding in a file the log does not name as audited must be an error, got %v", res.Err)
	}
	p = primary
	p.Stderr = strings.ReplaceAll(primary.Stderr, "scheduling ", "queueing ")
	if res := analyseZizmor(p, shadow); res.Err == nil || !strings.Contains(res.Err.Error(), "could not read which audits") {
		t.Errorf("an audited tree with no scheduled audit must be an error, got %v", res.Err)
	}
}

// TestZizmorUnreadableSARIFIsANonRun covers exit 0 with a SARIF cicd cannot
// read: zero findings would otherwise be the reading.
func TestZizmorUnreadableSARIFIsANonRun(t *testing.T) {
	primary, shadow := readZizmorFixture(t)
	primary.SARIF = ""
	if res := analyseZizmor(primary, shadow); res.Err == nil || !strings.Contains(res.Err.Error(), "SAST did not run") {
		t.Errorf("err = %v", res.Err)
	}
}

// TestZizmorShadowDiffIsAMultiset: two identical findings in the shadow and
// one in the primary is one suppression, not zero.
func TestZizmorShadowDiffIsAMultiset(t *testing.T) {
	one := `{"ruleId":"zizmor/template-injection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/a.yml"},"region":{"startLine":3,"startColumn":5}}}]}`
	other := `{"ruleId":"zizmor/template-injection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/a.yml"},"region":{"startLine":9,"startColumn":5}}}]}`
	doc := func(rs ...string) string {
		return `{"runs":[{"tool":{"driver":{"name":"zizmor","rules":[{"id":"zizmor/template-injection"}]}},"results":[` + strings.Join(rs, ",") + `]}]}`
	}
	log := "DEBUG audit: zizmor: scheduling template-injection on file://./.github/workflows/a.yml\n" +
		" INFO audit: zizmor: 🌈 completed ./.github/workflows/a.yml\n"
	res := analyseZizmor(zizmorRun{SARIF: doc(one), Stderr: log, Exit: "0"}, zizmorRun{SARIF: doc(one, one, other), Exit: "0"})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.BySeverity[SeverityHigh] != 1 {
		t.Errorf("bySeverity = %v", res.BySeverity)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "2 findings removed") {
		t.Errorf("want two suppressed (the duplicate at line 3 and line 9), got %v", res.Warnings)
	}
}

func TestZizmorSeverityOverride(t *testing.T) {
	for _, c := range []struct {
		rule, level string
		want        Severity
	}{
		{"zizmor/unpinned-uses", "error", SeverityMedium},
		{"zizmor/template-injection", "error", SeverityHigh},
		{"zizmor/artipacked", "warning", SeverityMedium},
		{"zizmor/self-repository", "note", SeverityLow},
	} {
		if got := zizmorSeverity(c.rule, c.level); got != c.want {
			t.Errorf("%s/%s = %s, want %s", c.rule, c.level, got, c.want)
		}
	}
}

// TestZizmorFileListIsCapped: the cap is stated where it bites.
func TestZizmorFileListIsCapped(t *testing.T) {
	var files []string
	for i := 0; i < zizmorExamplesShown+3; i++ {
		files = append(files, ".github/workflows/w"+string(rune('a'+i))+".yml")
	}
	got := zizmorFileList(files, len(files))
	if !strings.Contains(got, "and 3 more (alphabetical, first 10 shown)") {
		t.Errorf("got %q", got)
	}
	if got := zizmorFileList(nil, 2); !strings.Contains(got, "without naming") {
		t.Errorf("got %q", got)
	}
}
