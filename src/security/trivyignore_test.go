package main

import (
	"strings"
	"testing"
)

func TestATrivyignoreAtTheRootIsDisclosed(t *testing.T) {
	msg := trivyIgnoreWarning([]string{"go.mod", ".trivyignore", "README.md"})
	if msg == "" {
		t.Fatal("a committed .trivyignore narrowed the report and nothing said so")
	}
	// The disclosure has one job a reader must be able to act on: say which
	// file to go and read, and say what to use instead.
	for _, want := range []string{".trivyignore", "--vuln-accept"} {
		if !strings.Contains(msg, want) {
			t.Errorf("disclosure does not name %q: %s", want, msg)
		}
	}
	// It must not claim to know what was suppressed. The rows are gone before
	// cicd sees the report, and a sentence implying otherwise is the false
	// precision this whole file exists to avoid.
	if strings.Contains(msg, "identifier(s) accepted") {
		t.Errorf("disclosure claims to know what was suppressed: %s", msg)
	}
}

func TestATreeWithNoSuppressionFileSaysNothing(t *testing.T) {
	if msg := trivyIgnoreWarning([]string{"go.mod", "trivy.yaml", "src/"}); msg != "" {
		t.Errorf("a clean tree got a disclosure: %s", msg)
	}
	if msg := trivyIgnoreWarning(nil); msg != "" {
		t.Errorf("an empty listing got a disclosure: %s", msg)
	}
}

// Trivy auto-loads the ignore file from its working directory only, so a
// .trivyignore anywhere else changes nothing about the report — and Dagger's
// Entries() lists one directory level. A disclosure about a file the scan never
// read is a line a reader learns to skip, which costs the real one its weight.
func TestOnlyTheFileTrivyActuallyLoadsIsDisclosed(t *testing.T) {
	for _, entry := range []string{
		"src/.trivyignore",
		".trivyignore.yaml",
		".trivyignorexyz",
		"my.trivyignore",
	} {
		if msg := trivyIgnoreWarning([]string{entry}); msg != "" {
			t.Errorf("%q is not the file Trivy loads, and was disclosed: %s", entry, msg)
		}
	}
}

// Dagger appends a trailing separator to a directory name, which is the only
// thing distinguishing a directory called .trivyignore from the file. A
// directory suppresses nothing.
func TestADirectoryNamedLikeTheIgnoreFileIsNotOne(t *testing.T) {
	if msg := trivyIgnoreWarning([]string{".trivyignore/"}); msg != "" {
		t.Errorf("a directory was reported as a suppression file: %s", msg)
	}
}
