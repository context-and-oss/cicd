package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGHACurlPipeFallbackTriggersOnlyForTheMeasuredRule(t *testing.T) {
	affected := sarifWithNotifications(syntaxNote(
		".github/workflows/pages.yml",
		63,
		"When parsing a snippet as Bash for metavariable-pattern in rule '"+semgrepGHACurlPipeRuleID+"', `{ github.repository` was unexpected",
	))
	if !semgrepNeedsGHACurlPipeFallback(affected) {
		t.Fatal("the measured gha-curl-pipe-shell parser failure did not trigger the fallback")
	}

	for name, raw := range map[string]json.RawMessage{
		"another syntax failure": sarifWithNotifications(syntaxNote("src/app.cs", 3, "`(int x)` was unexpected")),
		"clean scan":             sarifWithNotifications(),
		"unreadable report":      json.RawMessage(`not json`),
	} {
		t.Run(name, func(t *testing.T) {
			if semgrepNeedsGHACurlPipeFallback(raw) {
				t.Fatal("a notification with no proven equivalent must remain a partial-scan warning")
			}
		})
	}
}

func TestGHACurlPipeFallbackChangesOnlyTheBrokenRule(t *testing.T) {
	in := []string{"--config", "p/security-audit", "--config", "./consumer.yml"}
	got := semgrepGHAFallbackArgs(in)
	wantTail := []string{"--exclude-rule", semgrepGHACurlPipeRuleID, "--config", semgrepGHAFallbackPath}

	if strings.Join(got[:len(in)], "\n") != strings.Join(in, "\n") {
		t.Fatalf("caller configs changed: got %v, want prefix %v", got, in)
	}
	if strings.Join(got[len(in):], "\n") != strings.Join(wantTail, "\n") {
		t.Fatalf("fallback args = %v, want tail %v", got, wantTail)
	}
	got[0] = "mutated"
	if in[0] == "mutated" {
		t.Fatal("fallback args alias the caller's slice")
	}
}

func TestGHACurlPipeRuntimeAdapterHasStableIdentity(t *testing.T) {
	for _, want := range []string{
		`RULE_ID = "` + semgrepGHAFallbackRuleID + `"`,
		"metavariable-regex", "curl|wget", "Modified by cicd",
	} {
		if !strings.Contains(semgrepGHAAdapter, want) {
			t.Errorf("runtime adapter no longer contains %q", want)
		}
	}
	if strings.Contains(semgrepGHAAdapter, "pattern-inside") {
		t.Error("upstream structural expressions must come from the runtime checkout")
	}
}

func TestGHACurlPipeAdapterContracts(t *testing.T) {
	out, err := exec.Command("python3", "semgrep_gha_test.py").CombinedOutput()
	if err != nil {
		t.Fatalf("runtime adapter contracts: %v\n%s", err, out)
	}
}

func TestWorkflowReplacementMustActuallyLoad(t *testing.T) {
	packs, err := loadSemgrepPacks()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := semgrepPlanFor(defaultSastRulesets, packs)
	if err != nil {
		t.Fatal(err)
	}
	ids := append(append([]string{}, plan.Floor...), semgrepDOMRuleLoadedID)
	if _, err := semgrepRuleSet(sarifWithRules(ids...), plan); err == nil || !strings.Contains(err.Error(), "workflow compatibility") {
		t.Fatalf("missing generated replacement must fail: %v", err)
	}
	live := semgrepPlan{Args: semgrepGHAFallbackArgs([]string{"--config", "p/example"})}
	if _, err := semgrepRuleSet(sarifWithRules("synthetic.other"), live); err == nil {
		t.Fatal("a live-only rerun without its replacement passed")
	}
	if _, err := semgrepRuleSet(sarifWithRules(semgrepGHAFallbackLoadedID), live); err != nil {
		t.Fatalf("a loaded live replacement was refused: %v", err)
	}
}

func TestRuntimeRuleGenerationFailsBeforeTheScanner(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(map[bool]string{false: "custom-only", true: "fallback-missing-source"}[selected], func(t *testing.T) {
			root := t.TempDir()
			rebase := strings.NewReplacer("/tmp/", root+"/tmp/", "/cicd-semgrep-pack/", root+"/pack/", "/cicd-rules/", root+"/rules/")
			for _, d := range []string{"tmp", "pack", "bin"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, contents string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(rebase.Replace(semgrepGHAAdapterPath), semgrepGHAAdapter, 0600)
			write(filepath.Join(root, "bin", "semgrep"), "#!/bin/sh\necho called > \"$SCAN_MARKER\"\nprintf '{\"runs\":[{}]}' > \"$TEST_REPORT\"\n", 0700)
			write(filepath.Join(root, "tmp", "report.sarif"), "stale report", 0600)
			config := "./consumer.yml"
			if selected {
				config = rebase.Replace(semgrepGHAFallbackPath)
			}
			cmd := exec.Command("sh", "-c", rebase.Replace(semgrepScript), "sh", "--config", config)
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"), "SCAN_MARKER="+filepath.Join(root, "called"), "TEST_REPORT="+filepath.Join(root, "tmp", "report.sarif"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("classification script: %v\n%s", err, out)
			}
			_, called := os.Stat(filepath.Join(root, "called"))
			code, err := os.ReadFile(filepath.Join(root, "tmp", "semgrep.exit"))
			if err != nil {
				t.Fatal(err)
			}
			if selected {
				if !os.IsNotExist(called) || strings.TrimSpace(string(code)) != "2" {
					t.Fatalf("failed generation ran scanner or passed: called=%v code=%q", called, code)
				}
				report, _ := os.ReadFile(filepath.Join(root, "tmp", "report.sarif"))
				if len(report) != 0 {
					t.Fatal("failed generation retained a stale report")
				}
			} else if called != nil || strings.TrimSpace(string(code)) != "0" {
				t.Fatalf("custom scan required unused upstream data: called=%v code=%q", called, code)
			}
		})
	}
}

func TestGHAFallbackSelectionIsAnExactConfigPair(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--config", "./consumer.yml"}, false},
		{[]string{"--exclude-rule", semgrepGHAFallbackPath}, false},
		{[]string{"--config", semgrepGHAFallbackPath}, true},
	} {
		if got := semgrepUsesGHAFallback(tc.args); got != tc.want {
			t.Errorf("fallback selected for %v = %v, want %v", tc.args, got, tc.want)
		}
	}
}
