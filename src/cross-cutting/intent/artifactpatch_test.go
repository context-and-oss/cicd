package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactPatchRefusesUnknownEdits(t *testing.T) {
	const path = "specs/history.md"
	good := replacementDiff(path, "Because legacy.go was read.\n", "Because legacy.go is read.\n")
	for name, diff := range map[string]string{
		"truncated":          strings.TrimSuffix(good, "+Because legacy.go is read.\n"),
		"too many lines":     good + "+extra\n",
		"bad range":          strings.Replace(good, "@@ -1,1 +1,1 @@", "@@ broken @@", 1),
		"nonempty at zero":   strings.Replace(good, "@@ -1,1 +1,1 @@", "@@ -0,1 +1,1 @@", 1),
		"overflow":           strings.Replace(good, "@@ -1,1 +1,1 @@", "@@ -99999999999999999999999,1 +1,1 @@", 1),
		"outside file":       strings.Replace(good, "@@ -1,1 +1,1 @@", "@@ -50,1 +50,1 @@", 1),
		"positions disagree": strings.Replace(good, "@@ -1,1 +1,1 @@", "@@ -2,1 +1,1 @@", 1),
		"unknown payload":    good + "garbage\n",
		"repeat marker":      strings.TrimSuffix(good, "\n") + "\n\\ No newline at end of file\n\\ No newline at end of file\n",
		"context mismatch":   strings.Replace(good, "+Because legacy.go is read.", " Because legacy.go was read.", 1),
		"addition mismatch":  strings.Replace(good, "+Because legacy.go is read.", "+Because unrelated.go is read.", 1),
		"overlap":            good + "@@ -1,1 +1,1 @@\n-Because legacy.go was read.\n+Because legacy.go is read.\n",
		"duplicate sections": good + good,
		"empty hunk":         "diff --git a/specs/history.md b/specs/history.md\n--- a/specs/history.md\n+++ b/specs/history.md\n@@ -0,0 +0,0 @@\n",
		"no textual change":  strings.Replace(good, "-Because legacy.go was read.", "-Because legacy.go is read.", 1),
		"artifact absent":    diffTouching("README.md"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runArtifactRules(path, "Because legacy.go is read.\n", diff); err == nil {
				t.Fatal("unreadable edit was not refused")
			}
		})
	}
	// This patch has matching counts, but contradicts EOF on its old side.
	diff := "diff --git a/specs/history.md b/specs/history.md\n--- a/specs/history.md\n+++ b/specs/history.md\n@@ -1,2 +1,2 @@\n-before\n\\ No newline at end of file\n-more\n+after\n+more\n"
	if _, _, err := runArtifactRules(path, "after\nmore\n", diff); err == nil {
		t.Fatal("old payload after EOF was not refused")
	}
}

// Git is the producer, not a second hand-written rendering of its format.
// Reverse patches at both default and zero context, including edits with
// multiple hunks, empty ranges, unusual path names and missing final newlines.
func TestArtifactPatchRoundTripsGit(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&body, "line %d because legacy.go is named\n", i)
	}
	base := body.String()
	for _, context := range []string{"0", "3"} {
		for _, tt := range []struct {
			name, before, after string
		}{
			{"replace", "before\n", "after\n"},
			{"insert head", base, "new\n" + base},
			{"insert tail", base, base + "new\n"},
			{"remove head", "old\n" + base, base},
			{"remove tail", base + "old\n", base},
			{"multiple hunks", base, strings.ReplaceAll(strings.ReplaceAll(base, "line 2 ", "replacement "), "line 33 ", "second\nreplacement ")},
			{"empty before", "", "new\n"},
			{"empty after", "old\n", ""},
			{"no EOF newline on both", "before", "after"},
			{"add EOF newline", "before", "before\n"},
			{"remove EOF newline", "before\n", "before"},
			{"CRLF", "before\r\ncontext\r\n", "after\r\ncontext\r\n"},
			{"content resembles header", "before\n", "++ b/not-a-header\n"},
		} {
			t.Run(context+"/"+tt.name, func(t *testing.T) {
				dir := t.TempDir()
				const path = "specs/a quoted\tname.md"
				fullPath := filepath.Join(dir, path)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
					t.Fatal(err)
				}
				git := func(args ...string) string {
					t.Helper()
					cmd := exec.Command("git", append([]string{"-c", "core.autocrlf=false", "-c", "core.safecrlf=false"}, args...)...)
					cmd.Dir = dir
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("git %v: %v\n%s", args, err, out)
					}
					return string(out)
				}
				git("init", "-q")
				if err := os.WriteFile(fullPath, []byte(tt.before), 0o644); err != nil {
					t.Fatal(err)
				}
				git("add", "--", path)
				if err := os.WriteFile(fullPath, []byte(tt.after), 0o644); err != nil {
					t.Fatal(err)
				}
				diff := git("diff", "--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", "--unified="+context)
				paths, _, err := parseDiffPaths(diff)
				if err != nil || len(paths.files) != 1 {
					t.Fatalf("sections=%d err=%v\n%s", len(paths.files), err, diff)
				}
				if paths.files[0].newPath != path {
					t.Fatalf("resolved path=%q, want %q", paths.files[0].newPath, path)
				}
				before, textual, err := previousArtifact(tt.after, paths.files[0].lines)
				if err != nil || !textual || before != tt.before {
					t.Fatalf("reconstructed=%q want=%q textual=%v err=%v\n%s", before, tt.before, textual, err, diff)
				}
			})
		}
	}
}
