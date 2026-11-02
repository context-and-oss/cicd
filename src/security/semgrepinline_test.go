package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInlineAdapter(t *testing.T) {
	// Included in the canonical module-unit runner: a Python suite nobody
	// invokes would prove nothing about the adapter shipped in the image.
	cmd := exec.Command("python3", "-B", "-m", "unittest", "semgrep_inline_test", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("inline adapter tests: %v\n%s", err, output)
	}
}

func TestInlineDefaultSelectionAndFloor(t *testing.T) {
	for _, config := range []string{"p/security-audit", "p/owasp-top-ten", "p/security-audit,./custom.yml"} {
		plan := mustPlan(t, config)
		if !plan.Inline || !strings.Contains(strings.Join(plan.Args, " "), semgrepDOMRulePath) {
			t.Fatalf("%s lost inline analysis: %+v", config, plan)
		}
		if !strings.Contains(semgrepInlinePlan(plan), semgrepDOMRuleLoadedID) {
			t.Fatal("inline membership omits the required DOM rule")
		}
		if _, err := semgrepRuleSet(sarifWithRules(plan.Floor...), plan); err == nil {
			t.Fatal("a scan without the required DOM rule passed")
		}
	}
	for _, config := range []string{"p/secrets", "./custom.yml", "p/python"} {
		plan := mustPlan(t, config)
		if plan.Inline || strings.Contains(strings.Join(plan.Args, " "), semgrepDOMRulePath) {
			t.Fatalf("explicit %s was silently widened", config)
		}
	}
	if !strings.Contains(semgrepScript, "|| echo 125 > /tmp/semgrep.exit") {
		t.Fatal("an adapter failure can fall back to the ordinary scan's passing exit")
	}
}
