//go:build unit_test

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A rule file under rules/ that no list names is a rule nobody runs, and it
// reads exactly like one that runs and finds nothing.
func TestEveryFirstPartyRuleFileIsWired(t *testing.T) {
	files, err := filepath.Glob("rules/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wired []string
	for _, r := range semgrepFirstPartyRules() {
		wired = append(wired, "rules/"+r.File)
	}
	slices.Sort(files)
	slices.Sort(wired)
	if !slices.Equal(files, wired) {
		t.Fatalf("rule files on disk %v, wired %v", files, wired)
	}
	for _, r := range semgrepFirstPartyRules() {
		raw, err := os.ReadFile("rules/" + r.File)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != r.Body {
			t.Errorf("%s: embedded body differs from the file", r.File)
		}
		if strings.Count(r.Body, "\n  - id: ") != 1 || !strings.Contains(r.Body, "\n  - id: "+r.ID+"\n") {
			t.Errorf("%s: must hold exactly the one rule %s", r.File, r.ID)
		}
		// Interfile is what puts the rule in ScanTaint; the rule's own option
		// is what makes the engine follow it there. They must agree.
		if got := strings.Contains(r.Body, "\n      interfile: true\n"); got != r.Interfile {
			t.Errorf("%s: options.interfile = %v, wired Interfile = %v", r.File, got, r.Interfile)
		}
		if r.What == "" || !strings.HasPrefix(r.Path(), "/"+semgrepCicdRuleDir+"/") {
			t.Errorf("%s: incomplete entry %+v", r.File, r)
		}
	}
}

// The C# rules are measured, not gated: WARNING maps to MEDIUM, under the
// default --fail-on HIGH. Raising one is a decision, not an edit.
func TestCSharpRulesStayBelowTheDefaultGate(t *testing.T) {
	for _, r := range []semgrepFirstParty{semgrepCSharpLogForging, semgrepCSharpSecretInLog} {
		if !strings.Contains(r.Body, "\n    languages: [csharp]\n") || !strings.Contains(r.Body, "\n    severity: WARNING\n") {
			t.Errorf("%s: want a C#-only WARNING rule", r.ID)
		}
		if !strings.Contains(r.Body, "\n    mode: taint\n") {
			t.Errorf("%s: not a taint rule", r.ID)
		}
	}
}

func TestFirstPartyRulesPerPlan(t *testing.T) {
	def := mustPlan(t, defaultSastRulesets)
	if !slices.Equal(ownLoadedIDs(def.Own), ownLoadedIDs(semgrepFirstPartyRules())) {
		t.Fatalf("default plan carries %v, want every first-party rule", ownLoadedIDs(def.Own))
	}

	taint, err := loadTaintPlan()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{semgrepCSharpLogForging.LoadedID(), semgrepCSharpSecretInLog.LoadedID()}
	if !slices.Equal(ownLoadedIDs(taint.Own), want) {
		t.Fatalf("taint plan carries %v, want %v", ownLoadedIDs(taint.Own), want)
	}
	args := strings.Join(taint.Args, " ")
	for _, r := range taint.Own {
		if !strings.Contains(args, "--config "+r.Path()) {
			t.Errorf("taint plan does not pass %s", r.Path())
		}
	}
	if strings.Contains(args, semgrepDOMRule.Path()) {
		t.Error("taint plan passes the DOM rule, which is not interfile")
	}
	// The first-party configs come before the exclusions, with the rest of
	// the --config pairs.
	if i, j := strings.Index(args, semgrepCSharpLogForging.Path()), strings.Index(args, "--exclude-rule"); j >= 0 && i > j {
		t.Error("first-party configs follow the exclusions")
	}
}

// Each first-party rule is required by the plan that adds it, and the error
// names which one did not load.
func TestFirstPartyRuleMustLoad(t *testing.T) {
	for _, plan := range []semgrepPlan{mustPlan(t, defaultSastRulesets), mustTaintPlan(t)} {
		full := append(append(append([]string(nil), plan.Floor...), semgrepGHAFallbackLoadedID), ownLoadedIDs(plan.Own)...)
		if _, err := semgrepRuleSet(sarifWithRules(full...), plan); err != nil {
			t.Fatalf("control: the full set for %v errored: %v", plan.Pinned, err)
		}
		for _, r := range plan.Own {
			without := slices.DeleteFunc(slices.Clone(full), func(id string) bool { return id == r.LoadedID() })
			_, err := semgrepRuleSet(sarifWithRules(without...), plan)
			if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), r.What) {
				t.Errorf("%v without %s: %v", plan.Pinned, r.ID, err)
			}
		}
	}
}

func mustTaintPlan(t *testing.T) semgrepPlan {
	t.Helper()
	plan, err := loadTaintPlan()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
