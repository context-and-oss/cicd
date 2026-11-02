package main

import (
	"fmt"
	"strings"
	"testing"
)

// replacementDiff uses real unified-diff structure, not header-only fixtures:
// the edit-aware rule must prove which text preceded the current document.
func replacementDiff(path, before, after string) string {
	oldLines, newLines := documentLines(before), documentLines(after)
	out := fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -%s +%s @@\n", path, path, path, path,
		testRange(len(oldLines)), testRange(len(newLines)))
	for _, side := range []struct {
		prefix string
		lines  []string
	}{{"-", oldLines}, {"+", newLines}} {
		for _, line := range side.lines {
			out += side.prefix + line
			if !strings.HasSuffix(line, "\n") {
				out += "\n\\ No newline at end of file\n"
			}
		}
	}
	return out
}

func testRange(n int) string {
	if n == 0 {
		return "0,0"
	}
	return fmt.Sprintf("1,%d", n)
}

func TestArtifactCouplingRegressionWasAWholeTextFailure(t *testing.T) {
	const path = "specs/history.md"
	before := "Because legacy.go scanned 123 files.\n"
	after := "Because legacy.go scanned about 100 files.\n"
	diff := replacementDiff(path, before, after)
	if got := checkRefsCoupling(path, extractText(after, path), diff); len(got) != 1 {
		t.Fatalf("original whole-artifact rule must reproduce failure, got %+v", got)
	}
	got, narrowed, err := runArtifactRules(path, after, diff)
	if err != nil || !narrowed {
		t.Fatalf("narrowed=%v err=%v", narrowed, err)
	}
	for _, f := range got {
		if f.Rule == "refs-infer-coupling" {
			t.Fatalf("historical reference misread as new: %+v", f)
		}
	}
	if warning := couplingScopeWarning(2); !strings.Contains(warning, "2 modified artifact(s)") || !strings.Contains(warning, "whole artifacts") {
		t.Fatalf("scope disclosure lost: %s", warning)
	}
}

func TestArtifactCouplingGradesIntroducedReferences(t *testing.T) {
	const path = "specs/history.md"
	for _, tt := range []struct {
		name, path, before, after, changed string
		want                               int
	}{
		{"round count on same line as old reference", path, "Because legacy.go scanned 123 files.\n", "Because legacy.go scanned about 100 files.\n", "README.md", 0},
		{"reflow across lines", path, "Because legacy.go had an old defect.\n", "Because legacy.go\nhad an old defect.\n", "README.md", 0},
		{"remove a reference", path, "Because legacy.go had a defect.\n", "Because a module had a defect.\n", "README.md", 0},
		{"new unrelated reference", path, "Because legacy.go had a defect.\n", "Because legacy.go and unrelated.go had a defect.\n", "README.md", 1},
		{"new coupled reference", path, "Because legacy.go had a defect.\n", "Because legacy.go and current.go had a defect.\n", "src/current.go", 0},
		{"old coupling witness cannot clear unrelated addition", path, "Because current.go had a defect.\n", "Because current.go and unrelated.go had a defect.\n", "src/current.go", 1},
		{"new literal witness outside regex", path, "Because legacy.go had a defect.\n", "Because legacy.go and unrelated.go need Makefile.\n", "Makefile", 0},
		{"new dotfile witness", path, "Because legacy.go had a defect.\n", "Because unrelated.go needs .nvmrc rather than legacy.go.\n", ".nvmrc", 0},
		{"old literal witness cannot clear addition", path, "Because Makefile had a defect.\n", "Because Makefile and unrelated.go had a defect.\n", "Makefile", 1},
		{"capsule block context with colon", ".capsules/history.yaml", "intent: >\n  Because legacy.go had a defect: 123 files.\n", "intent: >\n  Because legacy.go had a defect: about 100 files.\n", "README.md", 0},
		{"capsule new path with colon", ".capsules/history.yaml", "intent: >\n  Because legacy.go had a defect: 123 files.\n", "intent: >\n  Because unrelated.go had a defect: about 100 files.\n", "README.md", 1},
		{"markdown frontmatter context", path, "---\nwhy: >\n  Because legacy.go had a defect.\n---\nBody\n", "---\nwhy: >\n  Because unrelated.go had a defect.\n---\nBody\n", "README.md", 1},
		{"no newline at EOF", path, "Because legacy.go scanned 123 files.", "Because legacy.go scanned about 100 files.", "README.md", 0},
		{"org rename inside a URL path", path, "Because https://example.com/old-org/tool/blob/main/legacy.go had a defect.\n", "Because https://example.com/new-org/tool/blob/main/legacy.go had a defect.\n", "README.md", 0},
		{"bare slug rename", path, "Because old-org/tool pinned it.\n", "Because new-org/tool pinned it.\n", "README.md", 0},
		{"rename keeps the file it names", path, "Because src/old/legacy.go had a defect.\n", "Because src/old/unrelated.go had a defect.\n", "README.md", 1},
		{"two segments changed is a new reference", path, "Because old-org/tool/legacy.go had a defect.\n", "Because new-org/other/legacy.go had a defect.\n", "README.md", 1},
		{"kept reference cannot explain a renamed copy", path, "Because old-org/tool pinned it.\n", "Because old-org/tool and new-org/tool pinned it.\n", "README.md", 1},
		{"one removal explains one rename", path, "Because old-org/tool pinned it.\n", "Because new-org/tool and other-org/tool pinned it.\n", "README.md", 1},
		{"CRLF payload", path, "Because legacy.go scanned 123 files.\r\n", "Because legacy.go scanned about 100 files.\r\n", "README.md", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			diff := replacementDiff(tt.path, tt.before, tt.after) + diffTouching(tt.changed)
			findings, narrowed, err := runArtifactRules(tt.path, tt.after, diff)
			if err != nil || !narrowed {
				t.Fatalf("narrowed=%v err=%v", narrowed, err)
			}
			var count int
			for _, f := range findings {
				if f.Rule == "refs-infer-coupling" {
					count++
				}
			}
			if count != tt.want {
				t.Fatalf("coupling findings=%d want=%d: %+v", count, tt.want, findings)
			}
		})
	}
}

func TestArtifactCouplingKeepsWholeDocumentProseChecks(t *testing.T) {
	const path = "specs/history.md"
	before := "TODO Because legacy.go had a defect and it is simple.\n"
	after := "TODO Because legacy.go had a prior defect and it is simple.\n"
	findings, _, err := runArtifactRules(path, after, replacementDiff(path, before, after))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Rule] = true
	}
	for _, rule := range []string{"no-tbd", "no-weasel-words", "min-length"} {
		if !seen[rule] {
			t.Errorf("whole-document rule %s did not run: %+v", rule, findings)
		}
	}
	// Causality must still be judged over the resulting full document.
	after = "legacy.go had a prior defect.\n"
	findings, _, err = runArtifactRules(path, after, replacementDiff(path, before, after))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Rule == "min-causal-language" {
			return
		}
	}
	t.Fatal("missing causal-language violation")
}

func TestArtifactCouplingStillReadsUntouchedProse(t *testing.T) {
	const path = "specs/history.md"
	// The placeholder, qualifier and causality are outside the zero-context
	// hunk. Grading all rules on added lines would silently lose them.
	after := "TODO Because legacy.go is simple.\nabout 100 files\n"
	diff := "diff --git a/specs/history.md b/specs/history.md\n--- a/specs/history.md\n+++ b/specs/history.md\n@@ -2 +2 @@\n-123 files\n+about 100 files\n"
	findings, narrowed, err := runArtifactRules(path, after, diff)
	if err != nil || !narrowed {
		t.Fatalf("narrowed=%v err=%v", narrowed, err)
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Rule] = true
	}
	if !seen["no-tbd"] || !seen["no-weasel-words"] || seen["min-causal-language"] {
		t.Fatalf("untouched prose was not graded: %+v", findings)
	}
}

func TestArtifactCouplingDoesNotExemptNewOrMovedRationales(t *testing.T) {
	const path = "specs/new.md"
	const text = "Because unrelated.go had a defect.\n"
	for name, diff := range map[string]string{
		"new":       "diff --git a/specs/new.md b/specs/new.md\nnew file mode 100644\n--- /dev/null\n+++ b/specs/new.md\n@@ -0,0 +1 @@\n+Because unrelated.go had a defect.\n",
		"rename":    "diff --git a/specs/old.md b/specs/new.md\nsimilarity index 100%\nrename from specs/old.md\nrename to specs/new.md\n",
		"copy":      "diff --git a/specs/old.md b/specs/new.md\nsimilarity index 100%\ncopy from specs/old.md\ncopy to specs/new.md\n",
		"mode only": "diff --git a/specs/new.md b/specs/new.md\nold mode 100644\nnew mode 100755\n",
		"binary":    "diff --git a/specs/new.md b/specs/new.md\nBinary files a/specs/new.md and b/specs/new.md differ\n",
	} {
		t.Run(name, func(t *testing.T) {
			findings, narrowed, err := runArtifactRules(path, text, diff)
			if err != nil || narrowed {
				t.Fatalf("narrowed=%v err=%v", narrowed, err)
			}
			for _, f := range findings {
				if f.Rule == "refs-infer-coupling" {
					return
				}
			}
			t.Fatal("unrelated rationale was exempted")
		})
	}
	findings, narrowed, err := runArtifactRules(path, text, "")
	if err != nil || narrowed {
		t.Fatalf("no-diff audit: narrowed=%v err=%v", narrowed, err)
	}
	for _, f := range findings {
		if f.Rule == "refs-infer-coupling" {
			t.Fatal("no-diff audit unexpectedly coupled")
		}
	}
}
