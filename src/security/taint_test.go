//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The interfile manifest is a strict subset of what ScanSource already pins:
// every row must be a rule the audit or OWASP manifest carries, at the same
// path, or the delta would subtract a baseline the gate never ran.
func TestTaintManifestIsSubsetOfPinnedPacks(t *testing.T) {
	packs, err := loadSemgrepPacks()
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{} // id -> file
	for _, p := range packs {
		if p.Name != "p/security-audit" && p.Name != "p/owasp-top-ten" {
			continue
		}
		for f, ids := range p.ByFile {
			for _, id := range ids {
				pinned[id] = f
			}
		}
	}
	tp, err := parseSemgrepPack(opengrepInterfileManifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(tp.IDs) != 27 {
		t.Fatalf("interfile manifest has %d rules, want 27 (regenerate and update the spec if this is deliberate)", len(tp.IDs))
	}
	for f, ids := range tp.ByFile {
		for _, id := range ids {
			if pinned[id] != f {
				t.Errorf("%s (%s) is not in the pinned audit/OWASP manifests at that path", id, f)
			}
			if strings.HasPrefix(id, "csharp.") {
				t.Errorf("%s: no C# rule is interfile upstream; the spec says so", id)
			}
		}
	}
}

func TestLoadTaintPlan(t *testing.T) {
	plan, err := loadTaintPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Live) != 0 {
		t.Errorf("taint plan fetches live packs: %v", plan.Live)
	}
	if plan.Inline {
		t.Error("taint plan runs the inline-JavaScript pass; it is ScanSource's")
	}
	if !slices.Equal(plan.Pinned, []string{taintPackName}) {
		t.Errorf("Pinned = %v, want [%s]", plan.Pinned, taintPackName)
	}
	if len(plan.Floor) != 27 {
		t.Errorf("floor = %d rules, want 27", len(plan.Floor))
	}
	// Co-located rules the staged files bring must be excluded, or the run
	// would apply rules nobody asked the interfile engine to follow.
	packs, err := loadSemgrepPacks()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		for _, f := range plan.Files {
			for _, id := range p.ByFile[f] {
				if !slices.Contains(plan.Floor, id) && !slices.Contains(plan.Excluded, id) {
					t.Errorf("%s is staged with %s and neither required nor excluded", id, f)
				}
			}
		}
	}
	for _, id := range plan.Excluded {
		if slices.Contains(plan.Floor, id) {
			t.Errorf("%s is both required and excluded", id)
		}
	}
}

func TestValidateTaintGate(t *testing.T) {
	for _, ok := range []string{"gate", "warn"} {
		if err := validateTaintGate(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "off", "WARN", "enforce"} {
		if err := validateTaintGate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateInterfileDepth(t *testing.T) {
	for _, ok := range []int{-1, 1, 3, 10} {
		if err := validateInterfileDepth(ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
	for _, bad := range []int{0, -2, -100} {
		if err := validateInterfileDepth(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
}

func TestTaintInterfileArgsDoesNotAliasPlan(t *testing.T) {
	plan := semgrepPlan{Args: make([]string, 2, 8)}
	plan.Args[0], plan.Args[1] = "--config", "x"
	got := taintInterfileArgs(plan, -1)
	// One argument, not two: Opengrep 2.0.0 exits 2 on "--interfile-depth -1"
	// ("unknown option '-1'") and accepts "--interfile-depth=-1".
	want := []string{"--config", "x", "--enable-interfile", "--interfile-depth=-1"}
	if !slices.Equal(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	// Spare capacity in plan.Args must not let the interfile flags leak into
	// the baseline run's arguments.
	if len(plan.Args) != 2 || slices.Contains(plan.Args[:cap(plan.Args)], "--enable-interfile") {
		t.Fatalf("plan.Args mutated: %v", plan.Args[:cap(plan.Args)])
	}
}

// taintSARIF builds a one-run Opengrep-shaped report. Results carry no level,
// as Opengrep's do; the level comes from the rule's default.
type taintHit struct {
	rule, uri  string
	line, col  int
	suppressed bool
}

func taintSARIF(t *testing.T, ruleIDs []string, hits []taintHit, notes []map[string]any) json.RawMessage {
	t.Helper()
	var rules []map[string]any
	for _, id := range ruleIDs {
		rules = append(rules, map[string]any{"id": id, "defaultConfiguration": map[string]any{"level": "error"}})
	}
	results := []map[string]any{}
	for _, h := range hits {
		r := map[string]any{
			"ruleId": h.rule,
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": h.uri},
				"region":           map[string]any{"startLine": h.line, "startColumn": h.col},
			}}},
		}
		if h.suppressed {
			r["suppressions"] = []any{map[string]any{"kind": "inSource"}}
		}
		results = append(results, r)
	}
	run := map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "Opengrep OSS", "rules": rules}},
		"results": results,
	}
	if notes != nil {
		run["invocations"] = []any{map[string]any{"executionSuccessful": true, "toolExecutionNotifications": notes}}
	}
	raw, err := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{run}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const taintSQL = "go.lang.security.injection.tainted-sql-string.tainted-sql-string"

func taintPlanForTest(t *testing.T) semgrepPlan {
	t.Helper()
	plan, err := loadTaintPlan()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func taintResultKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	rs, err := sarifRunResults(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rs {
		_, uri, _, line := sarifResultKey(r)
		out = append(out, fmt.Sprintf("%s:%d", uri, line))
	}
	slices.Sort(out)
	return out
}

func TestTaintDeltaIsAMultiset(t *testing.T) {
	base := taintSARIF(t, []string{taintSQL}, []taintHit{
		{taintSQL, "go/handlers.go", 10, 7, false},
		{taintSQL, "go/gone.go", 3, 1, false}, // the interfile run does not return it
	}, nil)
	inter := taintSARIF(t, []string{taintSQL}, []taintHit{
		{taintSQL, "go/handlers.go", 10, 7, false},
		{taintSQL, "go/handlers.go", 10, 7, false}, // a second identical finding survives
		{taintSQL, "go/handlers.go", 20, 9, false},
		{taintSQL, "go/repo.go", 6, 9, false},
	}, nil)
	kept, lost, err := taintDelta(base, inter)
	if err != nil {
		t.Fatal(err)
	}
	if lost != 1 {
		t.Errorf("lost = %d, want 1", lost)
	}
	want := []string{"go/handlers.go:10", "go/handlers.go:20", "go/repo.go:6"}
	if got := taintResultKeys(t, kept); !slices.Equal(got, want) {
		t.Errorf("kept = %v, want %v", got, want)
	}
}

func TestTaintDeltaRefusesUnreadableShapes(t *testing.T) {
	one := taintSARIF(t, []string{taintSQL}, nil, nil)
	two := json.RawMessage(`{"runs":[{"results":[]},{"results":[]}]}`)
	for name, c := range map[string][2]json.RawMessage{
		"baseline not json":  {json.RawMessage(`{`), one},
		"interfile not json": {one, json.RawMessage(`{`)},
		"baseline two runs":  {two, one},
		"interfile two runs": {one, two},
		"result not object":  {one, json.RawMessage(`{"runs":[{"results":[1]}]}`)},
	} {
		if _, _, err := taintDelta(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnalyseTaintReportsOnlyTheDelta(t *testing.T) {
	plan := taintPlanForTest(t)
	base := semgrepScan{SARIF: taintSARIF(t, plan.Floor, []taintHit{{taintSQL, "go/handlers.go", 10, 7, false}}, nil)}
	inter := semgrepScan{
		SARIF: taintSARIF(t, plan.Floor, []taintHit{
			{taintSQL, "go/handlers.go", 10, 7, false},
			{taintSQL, "go/handlers.go", 20, 9, false},
			{taintSQL, "go/repo.go", 6, 9, false},
		}, nil),
		Examined: &Examined{Unit: "files", Count: 3},
	}
	res := analyseTaint(base, inter, nil, nil, plan, 3)
	if len(res.Errs) != 0 {
		t.Fatalf("errs = %v", res.Errs)
	}
	if res.BySeverity[SeverityHigh] != 2 || len(res.BySeverity) != 1 {
		t.Errorf("BySeverity = %v, want 2 HIGH", res.BySeverity)
	}
	if res.Rules == nil || res.Rules.Count != 27 {
		t.Errorf("Rules = %+v, want 27", res.Rules)
	}
	if res.Examined == nil || res.Examined.Count != 3 || res.Examined.Partial != 0 {
		t.Errorf("Examined = %+v", res.Examined)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "call depth 3") {
		t.Errorf("no scope warning naming the depth: %v", res.Warnings)
	}
	var doc struct {
		Runs []struct {
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(res.SARIF, &doc); err != nil || len(doc.Runs) != 1 || doc.Runs[0].AutomationDetails.ID != taintToolName {
		t.Errorf("SARIF run not stamped %q: %s", taintToolName, res.SARIF)
	}
}

func TestAnalyseTaintBaselineFailureKeepsFindingsAndFails(t *testing.T) {
	plan := taintPlanForTest(t)
	inter := semgrepScan{SARIF: taintSARIF(t, plan.Floor, []taintHit{
		{taintSQL, "go/handlers.go", 10, 7, false},
		{taintSQL, "go/repo.go", 6, 9, false},
	}, nil)}
	res := analyseTaint(semgrepScan{}, inter, errors.New("opengrep did not run (exit 2)"), nil, plan, 3)
	if len(res.Errs) != 1 || !strings.Contains(res.Errs[0], "single-function baseline") ||
		!strings.Contains(res.Errs[0], "cannot be told apart") {
		t.Fatalf("errs = %v", res.Errs)
	}
	if res.BySeverity[SeverityHigh] != 2 {
		t.Errorf("unfiltered findings dropped: %v", res.BySeverity)
	}
}

func TestAnalyseTaintInterfileFailureIsAnError(t *testing.T) {
	plan := taintPlanForTest(t)
	base := semgrepScan{SARIF: taintSARIF(t, plan.Floor, nil, nil)}
	res := analyseTaint(base, semgrepScan{}, nil, errors.New("opengrep did not run (exit 137)"), plan, 3)
	if len(res.Errs) != 1 || !strings.Contains(res.Errs[0], "interfile run did not complete") ||
		!strings.Contains(res.Errs[0], "out of memory") {
		t.Fatalf("errs = %v", res.Errs)
	}
	if res.SARIF != nil || len(res.BySeverity) != 0 {
		t.Errorf("a run that did not complete produced a report: %s", res.SARIF)
	}
}

func TestAnalyseTaintBelowFloorIsAnError(t *testing.T) {
	plan := taintPlanForTest(t)
	inter := semgrepScan{SARIF: taintSARIF(t, plan.Floor[:20], nil, nil)}
	base := semgrepScan{SARIF: taintSARIF(t, plan.Floor, nil, nil)}
	res := analyseTaint(base, inter, nil, nil, plan, 3)
	if len(res.Errs) != 1 || !strings.Contains(res.Errs[0], "loaded 20 of the 27") {
		t.Fatalf("errs = %v", res.Errs)
	}
}

func TestAnalyseTaintLostAndSuppressed(t *testing.T) {
	plan := taintPlanForTest(t)
	base := semgrepScan{SARIF: taintSARIF(t, plan.Floor, []taintHit{{taintSQL, "a.go", 1, 1, false}}, nil)}
	inter := semgrepScan{SARIF: taintSARIF(t, plan.Floor, []taintHit{{taintSQL, "b.go", 2, 2, true}}, nil)}
	res := analyseTaint(base, inter, nil, nil, plan, 3)
	all := strings.Join(res.Warnings, "\n")
	if !strings.Contains(all, "1 finding(s) the single-function scan") {
		t.Errorf("lost finding not disclosed: %v", res.Warnings)
	}
	if !strings.Contains(all, "1 finding suppressed in source") {
		t.Errorf("suppression not disclosed: %v", res.Warnings)
	}
	if len(res.BySeverity) != 0 && res.BySeverity[SeverityHigh] != 0 {
		t.Errorf("suppressed finding counted: %v", res.BySeverity)
	}
}

// Verbatim from Opengrep 2.0.0 over the deep-chain fixture at depth 3.
const measuredDepthCap = "SemgrepWarning:\n rule go.lang.security.injection.tainted-sql-string.tainted-sql-string: the interfile search stopped at depth 3 with calls beyond it, so a longer chain of calls from a source to a sink is not followed; --interfile-depth raises the depth, -1 removes it"

// Verbatim shape from Opengrep 2.0.0 when a rule's interfile budget runs out:
// the rule is named, no file is, because the analysis spans every file.
const measuredRuleTimeout = "Timeout when running go.lang.security.injection.tainted-url-host.tainted-url-host:\n "

func TestTaintNotificationsDepthCapAndWholeProgramTimeout(t *testing.T) {
	plan := taintPlanForTest(t)
	notes := []map[string]any{
		{"descriptor": map[string]any{"id": "SemgrepWarning"}, "level": "warning", "message": map[string]any{"text": measuredDepthCap}},
		{"descriptor": map[string]any{"id": "Timeout"}, "level": "warning", "message": map[string]any{"text": measuredRuleTimeout}},
	}
	raw := taintSARIF(t, plan.Floor, nil, notes)

	n := parseSemgrepNotifications(raw)
	if !slices.Equal(n.DepthCapped, []string{taintSQL}) || n.Depth != "3" {
		t.Errorf("depth cap = %v at %q", n.DepthCapped, n.Depth)
	}
	if !slices.Equal(n.WholeProgramTimeouts, []string{"go.lang.security.injection.tainted-url-host.tainted-url-host"}) {
		t.Errorf("whole-program timeouts = %v", n.WholeProgramTimeouts)
	}
	if n.Timeouts != 0 || len(n.Unclassified) != 0 || n.partialFiles() != 0 {
		t.Errorf("misfiled: timeouts=%d unclassified=%v partial=%d", n.Timeouts, n.Unclassified, n.partialFiles())
	}

	res := analyseTaint(semgrepScan{SARIF: taintSARIF(t, plan.Floor, nil, nil)},
		semgrepScan{SARIF: raw, Examined: &Examined{Unit: "files", Count: 6}}, nil, nil, plan, 3)
	all := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"DEPTH CAPPED", "stopped at call depth 3", "PARTIAL SCAN", "ran out of time in interfile analysis"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings lack %q:\n%s", want, all)
		}
	}
}

// A file-scoped timeout keeps its old reading: it names the file, and the
// file counts as partly read.
func TestTaintNotificationsFileTimeoutUnchanged(t *testing.T) {
	notes := []map[string]any{{"descriptor": map[string]any{"id": "Timeout"}, "level": "warning",
		"message": map[string]any{"text": "Timeout when running js.rule.x on Client/vendor.js:\n "}}}
	n := parseSemgrepNotifications(taintSARIF(t, nil, nil, notes))
	if n.Timeouts != 1 || len(n.WholeProgramTimeouts) != 0 || n.partialFiles() != 1 {
		t.Errorf("file timeout misfiled: %+v", n)
	}
}

func TestTaintWarningsWording(t *testing.T) {
	if w := taintScopeWarning(-1); !strings.Contains(w, "call depth unlimited") || !strings.Contains(w, "none for C#") {
		t.Errorf("scope warning: %s", w)
	}
	if w := taintAdvisoryWarning(4); !strings.Contains(w, "4 cross-function") || !strings.Contains(w, `"warn"`) {
		t.Errorf("advisory warning: %s", w)
	}
}
