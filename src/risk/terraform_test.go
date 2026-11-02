// Proof that Terraform is reported as not assessed, never as clean.
//
// Every risk.azure rule iterates input.resources, the ARM array, and HCL2
// parses to input.resource, so a .tf file handed to those rules passed all of
// them without any being checked: a one-resource main.tf measured
// successes: 24 and read CLEAN. These cases pin the routing that replaced it.

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func terraformWarning(t *testing.T, warnings []string) string {
	t.Helper()
	var found []string
	for _, w := range warnings {
		if strings.Contains(w, "TERRAFORM NOT ASSESSED") {
			found = append(found, w)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one TERRAFORM NOT ASSESSED line, got %d in %q", len(found), warnings)
	}
	return found[0]
}

func TestTerraformIsNeverHandedToTheARMRules(t *testing.T) {
	scan := planInfraScan([]string{"main.tf", "infra/vars.hcl", "infra/b.tf", "stack.tf.json"}, nil, false)
	if len(scan.Groups) != 0 {
		t.Fatalf("groups = %#v: no policy reads HCL2, so conftest must not be run on it", scan.Groups)
	}
	if scan.Candidates != 0 || scan.Scanned != 0 {
		t.Errorf("candidates=%d scanned=%d: a file no policy reads is not a candidate", scan.Candidates, scan.Scanned)
	}
	want := []string{"infra/b.tf", "infra/vars.hcl", "main.tf", "stack.tf.json"}
	if strings.Join(scan.NotAssessed, ",") != strings.Join(want, ",") {
		t.Errorf("NotAssessed = %v, want %v (sorted, so the line is stable between runs)", scan.NotAssessed, want)
	}
}

// A tree holding only Terraform examines nothing. It must not read CLEAN, and
// it must not fail either: the consumer cannot clear it by changing code.
func TestATerraformOnlyTreeIsSkippedAndPassesAtEveryThreshold(t *testing.T) {
	repo := RepoContext{RepoURL: "https://example.com", CommitSHA: "abc", Branch: "main"}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	scan := planInfraScan([]string{"main.tf", "modules/net/main.tf"}, nil, false)
	for _, th := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone} {
		f := newValidateFold()
		f.warnings = append(f.warnings, infraPlanWarnings(scan)...)
		env, err := buildValidateEnvelope(f, scan, repo, th, start)
		if err != nil {
			t.Fatal(err)
		}
		if env.Outcome != OutcomeSkipped || !env.Passed {
			t.Errorf("%s: passed=%v outcome=%v, want SKIPPED and passed", th, env.Passed, env.Outcome)
		}
		if len(env.Errors) != 0 {
			t.Errorf("%s: errors = %v: conftest did not fail, it was not asked", th, env.Errors)
		}
		line := terraformWarning(t, env.Warnings)
		for _, want := range []string{"2 Terraform/HCL file(s) in the tree", "main.tf, modules/net/main.tf", "input.resources"} {
			if !strings.Contains(line, want) {
				t.Errorf("warning is missing %q: %s", want, line)
			}
		}
		var rpt validateReport
		if err := json.Unmarshal(env.GenericReport, &rpt); err != nil {
			t.Fatal(err)
		}
		if len(rpt.InfraFilesNotAssessed) != 2 {
			t.Errorf("payload infraFilesNotAssessed = %v, want both files", rpt.InfraFilesNotAssessed)
		}
	}
}

// Beside files a policy does read, the verdict stays graded: what conftest read
// is real, and a finding in it still fails the gate.
func TestAMixedTreeStaysGradedAndNamesTheTerraform(t *testing.T) {
	repo := RepoContext{RepoURL: "https://example.com", CommitSHA: "abc", Branch: "main"}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	scan := planInfraScan([]string{"ci.yml", "main.tf"}, nil, false)
	if scan.Candidates != 1 || scan.Scanned != 1 || len(scan.Groups) != 1 || scan.Groups[0].Namespace != "risk.pipeline" {
		t.Fatalf("scan = %#v: only ci.yml is a candidate", scan)
	}
	_, mounts := conftestGroupPlan(scan.Groups[0])
	f := newValidateFold()
	f.warnings = append(f.warnings, infraPlanWarnings(scan)...)
	f.addInfraGroup(conftestFailure("/inputs/f0000", "unpinned action", "HIGH", "PIPE-001", "ci.yml"), scan.Groups[0], mounts, nil, start)
	env, err := buildValidateEnvelope(f, scan, repo, SeverityHigh, start)
	if err != nil {
		t.Fatal(err)
	}
	if env.Outcome != OutcomeFindings || env.Passed {
		t.Errorf("passed=%v outcome=%v: a HIGH finding beside Terraform still fails at HIGH", env.Passed, env.Outcome)
	}
	if env.Examined.Count != 1 || env.Examined.Total != 1 {
		t.Errorf("examined = %#v: main.tf is not part of the denominator", env.Examined)
	}
	if line := terraformWarning(t, env.Warnings); !strings.Contains(line, "1 Terraform/HCL file(s) in the tree (main.tf)") {
		t.Errorf("warning does not name the file: %s", line)
	}
}

func TestAChangeScopedScanNamesOnlyTheTerraformItTouched(t *testing.T) {
	tree := []string{"Dockerfile", "main.tf", "net.tf"}

	t.Run("the change touched only Terraform", func(t *testing.T) {
		scan := planInfraScan(tree, map[string]bool{"main.tf": true}, true)
		warnings := infraPlanWarnings(scan)
		if len(warnings) != 2 {
			t.Fatalf("warnings = %q, want NOTHING IN SCOPE and TERRAFORM NOT ASSESSED", warnings)
		}
		// The change did touch infrastructure; it touched none a policy reads.
		if !strings.Contains(warnings[0], "NOTHING IN SCOPE") || !strings.Contains(warnings[0], "no infrastructure file a policy reads") {
			t.Errorf("scope line: %s", warnings[0])
		}
		if line := terraformWarning(t, warnings); !strings.Contains(line, "1 Terraform/HCL file(s) touched by this change (main.tf)") {
			t.Errorf("terraform line: %s", line)
		}
	})

	// net.tf and main.tf were not in scope, so this scan was never asked about
	// them; the tree-scoped commit stage is where they are reported.
	t.Run("the change touched no Terraform", func(t *testing.T) {
		scan := planInfraScan(tree, map[string]bool{"Dockerfile": true}, true)
		for _, w := range infraPlanWarnings(scan) {
			if strings.Contains(w, "TERRAFORM") {
				t.Errorf("unexpected line for Terraform outside the scope: %s", w)
			}
		}
		if len(scan.NotAssessed) != 0 {
			t.Errorf("NotAssessed = %v, want none in scope", scan.NotAssessed)
		}
	})
}

func TestNoTerraformNoLine(t *testing.T) {
	if w := terraformNotAssessedWarning(planInfraScan([]string{"Dockerfile", "azuredeploy.json"}, nil, false)); w != "" {
		t.Errorf("warning on a tree with no Terraform: %s", w)
	}
}
