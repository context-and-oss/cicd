package main

import (
	"strings"
	"testing"
)

func TestInfraFileType(t *testing.T) {
	cases := []struct {
		name     string
		wantType string
		wantNS   string
		wantSkip bool
	}{
		{"Dockerfile", "dockerfile", "risk.docker", false},
		{"Dockerfile.prod", "dockerfile", "risk.docker", false},
		// Terraform is not handed to the ARM rules: planInfraScan reports it as
		// not assessed (see terraform_test.go).
		{"main.tf", "", "", true},
		{"vars.hcl", "", "", true},
		{"main.tf.json", "", "", true},
		{"ci.yml", "yaml", "risk.pipeline", false},
		{"deploy.yaml", "yaml", "risk.pipeline", false},
		{"template.json", "json", "risk.azure", false},
		{"azuredeploy.json", "json", "risk.azure", false},
		{"mainTemplate.json", "json", "risk.azure", false},
		{"infra.arm.json", "json", "risk.azure", false},
		{"deploy.template.json", "json", "risk.azure", false},
		// generic JSON must NOT be matched as ARM
		{"package.json", "", "", true},
		{"tsconfig.json", "", "", true},
		{"findings.json", "", "", true},
		{"decisions.json", "", "", true},
		{"app.bicep", "", "", true},
		{"go.mod", "", "", true},
		{"main.go", "", "", true},
		{"README.md", "", "", true},
	}
	for _, tc := range cases {
		gotType, gotNS := infraFileType(tc.name)
		skipped := gotType == ""
		if skipped != tc.wantSkip {
			t.Errorf("%q: wantSkip=%v but got inputType=%q", tc.name, tc.wantSkip, gotType)
			continue
		}
		if !tc.wantSkip {
			if gotType != tc.wantType {
				t.Errorf("%q: inputType %q, want %q", tc.name, gotType, tc.wantType)
			}
			if gotNS != tc.wantNS {
				t.Errorf("%q: namespace %q, want %q", tc.name, gotNS, tc.wantNS)
			}
		}
	}
}

// The parser itself is proven by diffpaths_test.go, shared with intent; these
// prove what the infra scan does with what it returns.
func TestDiffChangeScope(t *testing.T) {
	t.Run("added and modified files", func(t *testing.T) {
		diff := "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\nindex 111..222 100644\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-old\n+new\n" +
			"diff --git a/Dockerfile b/Dockerfile\nnew file mode 100644\n--- /dev/null\n+++ b/Dockerfile\n@@ -0,0 +1 @@\n+FROM alpine\n"
		got, scoped, err := diffChangeScope(diff)
		if err != nil || !scoped || len(got) != 2 || !got[".github/workflows/ci.yml"] || !got["Dockerfile"] {
			t.Fatalf("changed=%v scoped=%v err=%v", got, scoped, err)
		}
	})

	// The review's regression: a --no-prefix diff that renames one file and
	// edits a Dockerfile produced no paths, and the scan reported NOTHING IN
	// SCOPE over a change that touched infrastructure.
	t.Run("no-prefix diff is refused, not read as touching nothing", func(t *testing.T) {
		diff := "diff --git old.yml new.yml\nsimilarity index 100%\nrename from old.yml\nrename to new.yml\n" +
			"diff --git Dockerfile Dockerfile\nindex 1..2 100644\n--- Dockerfile\n+++ Dockerfile\n@@ -1 +1 @@\n-FROM a\n+FROM b\n"
		got, scoped, err := diffChangeScope(diff)
		if err == nil || !strings.Contains(err.Error(), "carries no b/ prefix") {
			t.Fatalf("changed=%v scoped=%v err=%v, want the no-prefix refusal", got, scoped, err)
		}
	})

	t.Run("deletion-only diff is a known, empty scope", func(t *testing.T) {
		diff := "diff --git a/Dockerfile b/Dockerfile\ndeleted file mode 100644\n--- a/Dockerfile\n+++ /dev/null\n@@ -1 +0,0 @@\n-FROM alpine\n"
		got, scoped, err := diffChangeScope(diff)
		if err != nil || !scoped || len(got) != 0 {
			t.Fatalf("changed=%v scoped=%v err=%v, want a known empty scope", got, scoped, err)
		}
		scan := planInfraScan([]string{"deploy/Dockerfile"}, got, scoped)
		if scan.Scanned != 0 || scan.Candidates != 1 || len(infraScopeWarnings(scan)) != 1 {
			t.Fatalf("scan=%+v, want nothing in scope, said so", scan)
		}
	})

	t.Run("quoted path reaches the scan", func(t *testing.T) {
		diff := "diff --git \"a/infra/my app/Dockerfile\" \"b/infra/my app/Dockerfile\"\n--- \"a/infra/my app/Dockerfile\"\n+++ \"b/infra/my app/Dockerfile\"\n@@ -1 +1 @@\n-a\n+b\n"
		got, scoped, err := diffChangeScope(diff)
		if err != nil || !scoped {
			t.Fatalf("changed=%v scoped=%v err=%v", got, scoped, err)
		}
		if scan := planInfraScan([]string{"infra/my app/Dockerfile"}, got, scoped); scan.Scanned != 1 {
			t.Fatalf("scan=%+v, want the quoted Dockerfile scanned", scan)
		}
	})

	t.Run("empty diff scans the tree", func(t *testing.T) {
		if got, scoped, err := diffChangeScope(""); err != nil || scoped || got != nil {
			t.Fatalf("changed=%v scoped=%v err=%v", got, scoped, err)
		}
	})
}
