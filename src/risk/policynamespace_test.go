package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The infra groups run conftest with --namespace taken from infraFileType, and
// conftest evaluates nothing, silently, for a namespace with no package. The
// fold now reports that as a non-run, but only at run time and only on a
// repository holding such a file; this test fails the rename itself.
func TestEveryNamespaceTheScanAsksForHasAPolicy(t *testing.T) {
	infra := policyPackages(t, "policy/infra")
	for _, name := range []string{"Dockerfile", "Dockerfile.prod", "azuredeploy.json", "ci.yml", "ci.yaml"} {
		_, ns := infraFileType(name)
		if ns == "" {
			t.Fatalf("%s: infraFileType no longer maps it; update this list", name)
		}
		if !infra[ns] {
			t.Errorf("%s: namespace %s has no package under policy/infra (have %v)", name, ns, infra)
		}
	}
	// The findings pass runs --all-namespaces, so it needs at least one
	// package that is not a test package.
	if len(policyPackages(t, "policy/findings")) == 0 {
		t.Error("policy/findings declares no package the findings pass can evaluate")
	}
}

var regoPackage = regexp.MustCompile(`(?m)^package\s+([A-Za-z0-9_.]+)\s*$`)

// policyPackages reads the package of every non-test .rego file in dir, the
// same set loadPolicyDir mounts.
func policyPackages(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil || len(files) == 0 {
		t.Fatalf("%s: no rego files (err %v)", dir, err)
	}
	pkgs := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.rego") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m := regoPackage.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no package line", f)
		}
		pkgs[string(m[1])] = true
	}
	return pkgs
}
