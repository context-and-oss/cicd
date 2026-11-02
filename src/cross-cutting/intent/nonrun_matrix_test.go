package main

import (
	"strings"
	"testing"
	"time"
)

// The founding rule for the intent gate: a change set it could not read must
// never fall back to the full-tree audit that passes on the repository's
// existing artifacts, and an artifact search that failed must never pass, at
// any --fail-on.

const modifiedSpec = "diff --git a/specs/x.md b/specs/x.md\nindex 1..2 100644\n--- a/specs/x.md\n+++ b/specs/x.md\n@@ -1 +1 @@\n-a\n+b\n"

func TestNonRunMatrixChangeScopeRefusesWhatItCannotRead(t *testing.T) {
	for name, diff := range map[string]string{
		"not a diff":  "hello\n",
		"diffstat":    " specs/x.md | 2 +-\n 1 file changed\n",
		"plain diff":  "--- a/specs/x.md\n+++ b/specs/x.md\n@@ -1 +1 @@\n-a\n+b\n",
		"no-prefix":   "diff --git specs/x.md specs/x.md\n--- specs/x.md\n+++ specs/x.md\n@@ -1 +1 @@\n-a\n+b\n",
		"mnemonic w/": "diff --git c/specs/x.md w/specs/x.md\n--- c/specs/x.md\n+++ w/specs/x.md\n@@ -1 +1 @@\n-a\n+b\n",
		"second file": modifiedSpec + "diff --git src/a.go src/a.go\n--- src/a.go\n+++ src/a.go\n@@ -1 +1 @@\n-a\n+b\n",
	} {
		if _, known, err := changeScope(diff); err == nil || known {
			t.Errorf("%s: known=%v err=%v, want a refusal", name, known, err)
		}
	}
}

func TestNonRunMatrixChangeScopeKnowsAChangeThatTouchesNoArtifact(t *testing.T) {
	for name, tt := range map[string]struct {
		diff      string
		surviving []string
	}{
		"deletion only": {diff: "diff --git a/specs/x.md b/specs/x.md\ndeleted file mode 100644\nindex 1..0\n--- a/specs/x.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n"},
		// A binary or mode-only change still names the file it changed: these
		// used to read as touching nothing, which is how a binary artifact
		// added by a PR went missing from presence.
		"binary only": {diff: "diff --git a/logo.png b/logo.png\nindex 1..2 100644\nBinary files a/logo.png and b/logo.png differ\n", surviving: []string{"logo.png"}},
		"mode only":   {diff: "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n", surviving: []string{"run.sh"}},
	} {
		changed, known, err := changeScope(tt.diff)
		if err != nil || !known || len(changed) != len(tt.surviving) {
			t.Errorf("%s: changed=%v known=%v err=%v, want a known change set naming %v", name, changed, known, err, tt.surviving)
		}
		for _, p := range tt.surviving {
			if !changed[p] {
				t.Errorf("%s: changed=%v, want %s in it", name, changed, p)
			}
		}
		// Scoped to that change set, no artifact is in scope, so presence
		// is judged instead of the tree being audited.
		if got := filterToChanged([]string{"specs/x.md"}, changed); len(got) != 0 {
			t.Errorf("%s: scoped %v, want none", name, got)
		}
	}
}

func TestNonRunMatrixChangeScopeControls(t *testing.T) {
	if changed, known, err := changeScope(" \n"); err != nil || known || changed != nil {
		t.Fatalf("empty diff: changed=%v known=%v err=%v, want the documented full audit", changed, known, err)
	}
	changed, known, err := changeScope(modifiedSpec)
	if err != nil || !known || !changed["specs/x.md"] {
		t.Fatalf("a git diff: changed=%v known=%v err=%v", changed, known, err)
	}
	// An added line that itself starts with "++ " is hunk content, not a header.
	withPlusLine := strings.Replace(modifiedSpec, "+b\n", "+b\n+++ not a header\n", 1)
	if _, known, err := changeScope(withPlusLine); err != nil || !known {
		t.Fatalf("hunk line read as a header: known=%v err=%v", known, err)
	}
}

func TestNonRunMatrixArtifactSearchFailure(t *testing.T) {
	for _, failOn := range []string{"error", "warn", "never", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		env := buildEnvelope("sha", "main", "https://example.com", nil, failOn, time.Second)
		markNonRun(env, []string{"intent-gate: artifact search failed for specs/*.md: boom"})
		if env.Passed || env.Outcome != OutcomeError || len(env.Errors) != 1 {
			t.Errorf("--fail-on %s: passed=%v outcome=%s errors=%q, want a non-run", failOn, env.Passed, env.Outcome, env.Errors)
		}
	}
	env := buildEnvelope("sha", "main", "https://example.com", nil, "error", time.Second)
	markNonRun(env, nil)
	if !env.Passed || env.Outcome != OutcomeClean {
		t.Fatalf("control: no search error: passed=%v outcome=%s", env.Passed, env.Outcome)
	}
}
