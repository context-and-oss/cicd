// Byte-identical in src/cross-cutting/intent and src/risk, beside the parser it
// proves (synced_files in scripts/repo-inventory.json).
package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseDiffPathsRetainsResolvedSections(t *testing.T) {
	first := "diff --git \"a/specs/my spec.md\" \"b/specs/my spec.md\"\n--- \"a/specs/my spec.md\"\n+++ \"b/specs/my spec.md\"\n@@ -1 +1 @@\n-a\n+++ not a header\n"
	second := "diff --git a/specs/my.md b/specs/copy.md\ncopy from specs/my.md\ncopy to specs/copy.md\n"
	third := "diff --git a/specs/new.md b/specs/new.md\nnew file mode 100644\n--- /dev/null\n+++ b/specs/new.md\n@@ -0,0 +1 @@\n+body\n"
	paths, known, err := parseDiffPaths(first + second + third)
	if err != nil || !known || len(paths.files) != 3 {
		t.Fatalf("known=%v sections=%d err=%v", known, len(paths.files), err)
	}
	for i, want := range []diffFilePaths{
		{oldPath: "specs/my spec.md", newPath: "specs/my spec.md"},
		{oldPath: "specs/my.md", newPath: "specs/copy.md", copied: true},
		{newPath: "specs/new.md"},
	} {
		got := paths.files[i]
		if got.oldPath != want.oldPath || got.newPath != want.newPath || got.copied != want.copied {
			t.Errorf("section %d: %+v, want %+v", i, got, want)
		}
	}
	if got := strings.Join(paths.files[0].lines, "\n"); got != strings.TrimSuffix(first, "\n") {
		t.Fatalf("patch bytes changed: %q", got)
	}
}

func TestParseDiffPathsReadsEveryHeaderGitWrites(t *testing.T) {
	for _, tt := range []struct {
		name      string
		diff      string
		surviving []string
		touched   []string
	}{
		{
			name:      "modified",
			diff:      "diff --git a/specs/x.md b/specs/x.md\nindex 1..2 100644\n--- a/specs/x.md\n+++ b/specs/x.md\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"specs/x.md"},
			touched:   []string{"specs/x.md"},
		},
		{
			name:      "added",
			diff:      "diff --git a/specs/new.md b/specs/new.md\nnew file mode 100644\n--- /dev/null\n+++ b/specs/new.md\n@@ -0,0 +1 @@\n+a\n",
			surviving: []string{"specs/new.md"},
			touched:   []string{"specs/new.md"},
		},
		{
			name:    "deleted",
			diff:    "diff --git a/specs/x.md b/specs/x.md\ndeleted file mode 100644\n--- a/specs/x.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n",
			touched: []string{"specs/x.md"},
		},
		{
			name:      "pure rename",
			diff:      "diff --git a/specs/old.md b/specs/new.md\nsimilarity index 100%\nrename from specs/old.md\nrename to specs/new.md\n",
			surviving: []string{"specs/new.md"},
			touched:   []string{"specs/new.md", "specs/old.md"},
		},
		{
			name:      "copy leaves its source untouched",
			diff:      "diff --git a/a.yml b/b.yml\nsimilarity index 100%\ncopy from a.yml\ncopy to b.yml\n",
			surviving: []string{"b.yml"},
			touched:   []string{"b.yml"},
		},
		{
			name:      "quoted path with a space",
			diff:      "diff --git \"a/specs/my spec.md\" \"b/specs/my spec.md\"\nindex 1..2 100644\n--- \"a/specs/my spec.md\"\n+++ \"b/specs/my spec.md\"\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"specs/my spec.md"},
			touched:   []string{"specs/my spec.md"},
		},
		{
			name:      "quoted tab in path with git header delimiter",
			diff:      "diff --git \"a/specs/a\\tname.md\" \"b/specs/a\\tname.md\"\n--- \"a/specs/a\\tname.md\"\t\n+++ \"b/specs/a\\tname.md\"\t\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"specs/a\tname.md"},
			touched:   []string{"specs/a\tname.md"},
		},
		{
			name:      "unquoted space in path with git header delimiter",
			diff:      "diff --git a/specs/my spec.md b/specs/my spec.md\n--- a/specs/my spec.md\t\n+++ b/specs/my spec.md\t\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"specs/my spec.md"},
			touched:   []string{"specs/my spec.md"},
		},
		{
			name:      "quoted non-ASCII path",
			diff:      "diff --git \"a/specs/\\303\\244.md\" \"b/specs/\\303\\244.md\"\n--- \"a/specs/\\303\\244.md\"\n+++ \"b/specs/\\303\\244.md\"\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"specs/ä.md"},
			touched:   []string{"specs/ä.md"},
		},
		{
			name:      "unquoted path with a space, no ---/+++ lines",
			diff:      "diff --git a/run me.sh b/run me.sh\nold mode 100644\nnew mode 100755\n",
			surviving: []string{"run me.sh"},
			touched:   []string{"run me.sh"},
		},
		{
			name:      "binary artifact added",
			diff:      "diff --git a/specs/x.pdf b/specs/x.pdf\nnew file mode 100644\nindex 0..1\nBinary files /dev/null and b/specs/x.pdf differ\n",
			surviving: []string{"specs/x.pdf"},
			touched:   []string{"specs/x.pdf"},
		},
		{
			name:    "binary deleted",
			diff:    "diff --git a/logo.png b/logo.png\ndeleted file mode 100644\nindex 1..0\nBinary files a/logo.png and /dev/null differ\n",
			touched: []string{"logo.png"},
		},
		{
			name:      "binary patch payload is not read as headers",
			diff:      "diff --git a/logo.png b/logo.png\nindex 1..2 100644\nGIT binary patch\nliteral 3\n+++ b/not-a-header\n\nliteral 0\n",
			surviving: []string{"logo.png"},
			touched:   []string{"logo.png"},
		},
		{
			name:      "mode only",
			diff:      "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n",
			surviving: []string{"run.sh"},
			touched:   []string{"run.sh"},
		},
		{
			name:      "an added content line is not a header",
			diff:      "diff --git a/src/a.go b/src/a.go\n--- a/src/a.go\n+++ b/src/a.go\n@@ -1 +1,3 @@\n-a\n+++ b/specs/old.md\n+rename to specs/other.md\n",
			surviving: []string{"src/a.go"},
			touched:   []string{"src/a.go"},
		},
		{
			name:      "CRLF line endings",
			diff:      "diff --git a/x.md b/x.md\r\n--- a/x.md\r\n+++ b/x.md\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n",
			surviving: []string{"x.md"},
			touched:   []string{"x.md"},
		},
		{
			name:      "preamble before the first header is ignored",
			diff:      "commit abc\n\n    +++ b/specs/msg.md\n\ndiff --git a/x.md b/x.md\n--- a/x.md\n+++ b/x.md\n@@ -1 +1 @@\n-a\n+b\n",
			surviving: []string{"x.md"},
			touched:   []string{"x.md"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, known, err := parseDiffPaths(tt.diff)
			if err != nil || !known {
				t.Fatalf("known=%v err=%v, want a known change set", known, err)
			}
			var surviving []string
			for p := range got.surviving {
				surviving = append(surviving, p)
			}
			sort.Strings(surviving)
			if !reflect.DeepEqual(surviving, tt.surviving) && (len(surviving) != 0 || len(tt.surviving) != 0) {
				t.Errorf("surviving = %q, want %q", surviving, tt.surviving)
			}
			if !reflect.DeepEqual(got.touched, tt.touched) {
				t.Errorf("touched = %q, want %q", got.touched, tt.touched)
			}
		})
	}
}

func TestParseDiffPathsRefusesWhatItCannotRead(t *testing.T) {
	for _, tt := range []struct{ name, diff, reason string }{
		{"not a diff", "hello\n", "no `diff --git` header"},
		{"diffstat", " specs/x.md | 2 +-\n 1 file changed\n", "no `diff --git` header"},
		{"plain diff", "--- a/x.md\n+++ b/x.md\n@@ -1 +1 @@\n-a\n+b\n", "no `diff --git` header"},
		{"no-prefix", "diff --git x.md x.md\n--- x.md\n+++ x.md\n@@ -1 +1 @@\n-a\n+b\n", "carries no b/ prefix"},
		{"no-prefix, path with a space", "diff --git my x.md my x.md\n--- my x.md\n+++ my x.md\n", "carries no b/ prefix"},
		{"mnemonic prefixes", "diff --git c/x.md w/x.md\n--- c/x.md\n+++ w/x.md\n", "carries no b/ prefix"},
		{"no-prefix under a b/ directory", "diff --git b/x.md b/x.md\n--- b/x.md\n+++ b/x.md\n", "carries no a/ prefix"},
		{"quoted no-prefix", "diff --git \"my x.md\" \"my x.md\"\n", "carries no b/ prefix"},
		{"no-prefix second file", "diff --git a/x.md b/x.md\n--- a/x.md\n+++ b/x.md\n@@ -1 +1 @@\n-a\n+b\ndiff --git y.go y.go\n--- y.go\n+++ y.go\n", "carries no b/ prefix"},
		{"broken quoting", "diff --git \"a/x.md \"b/x.md\"\n", "cannot be read"},
		{"no path anywhere", "diff --git a/x y b/z w\n", "names no path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, known, err := parseDiffPaths(tt.diff)
			if err == nil || known {
				t.Fatalf("known=%v err=%v, want a refusal", known, err)
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("err = %v, want it to name %q", err, tt.reason)
			}
		})
	}
}

func TestParseDiffPathsKnowsAnEmptyDiffStatesNoChangeSet(t *testing.T) {
	for _, diff := range []string{"", " \n", "\n\n"} {
		got, known, err := parseDiffPaths(diff)
		if err != nil || known || got.surviving != nil || got.touched != nil {
			t.Errorf("%q: got=%v known=%v err=%v, want an unknown change set and no error", diff, got, known, err)
		}
	}
}

// git quotes each side of a `diff --git` line on its own, so a rename can carry
// one quoted and one bare path, in either order. Every shape is pinned here,
// because the parser's own table reaches most of them only through headers
// that also carry `rename from`/`rename to`, which would hide a wrong split.
func TestSplitGitHeaderReadsEveryQuotingGitWrites(t *testing.T) {
	for _, tt := range []struct {
		name, rest       string
		oldSide, newSide string
		split            bool
		errPart          string
	}{
		{name: "bare", rest: "a/x.md b/x.md", oldSide: "a/x.md", newSide: "b/x.md", split: true},
		{name: "bare rename", rest: "a/x.md b/y.md", oldSide: "a/x.md", newSide: "b/y.md", split: true},
		{name: "bare, unrenamed path with spaces splits at the middle", rest: "a/my x.md b/my x.md", oldSide: "a/my x.md", newSide: "b/my x.md", split: true},
		{name: "bare rename with spaces is left to rename from/to", rest: "a/my x.md b/your y.md"},
		{name: "both quoted", rest: `"a/my\tx.md" "b/my\tx.md"`, oldSide: "a/my\tx.md", newSide: "b/my\tx.md", split: true},
		{name: "octal escapes are bytes", rest: `"a/\303\251.md" "b/\303\251.md"`, oldSide: "a/é.md", newSide: "b/é.md", split: true},
		{name: "escaped quote and backslash", rest: `"a/say \"hi\\" "b/say \"hi\\"`, oldSide: `a/say "hi\`, newSide: `b/say "hi\`, split: true},
		{name: "only the old side quoted", rest: `"a/my\tx.md" b/plain.md`, oldSide: "a/my\tx.md", newSide: "b/plain.md", split: true},
		{name: "only the new side quoted", rest: `a/plain.md "b/my\tx.md"`, oldSide: "a/plain.md", newSide: "b/my\tx.md", split: true},
		{name: "bare old side with a space, quoted new side", rest: `a/my x.md "b/my\tx.md"`, oldSide: "a/my x.md", newSide: "b/my\tx.md", split: true},
		{name: "quoted old side never closes", rest: `"a/x.md b/x.md`, errPart: "invalid syntax"},
		{name: "nothing after the quoted old side", rest: `"a/x.md"`, errPart: "no second path"},
		{name: "quoted sides run together", rest: `"a/x.md""b/x.md"`, errPart: "no second path"},
		{name: "quoted new side never closes", rest: `"a/x.md" "b/x.md`, errPart: "invalid syntax"},
		{name: "trailing quote that opens nothing", rest: `a/x.md b/x.md"`, errPart: "unterminated quoted path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oldSide, newSide, split, err := splitGitHeader(tt.rest)
			if tt.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errPart) || split {
					t.Fatalf("split=%v err=%v, want a refusal naming %q", split, err, tt.errPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if split != tt.split || oldSide != tt.oldSide || newSide != tt.newSide {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)", oldSide, newSide, split, tt.oldSide, tt.newSide, tt.split)
			}
		})
	}
}
