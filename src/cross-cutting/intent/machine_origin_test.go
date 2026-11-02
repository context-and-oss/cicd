package main

import (
	"reflect"
	"strings"
	"testing"
)

// TestPathToken guards the extension-prefix collision: Go's RE2
// alternation is leftmost-first, so a shorter extension listed before a
// longer one sharing its prefix (ts/tsx, js/jsx/json) — or a wholly absent
// entry (css, previously only matched via the unrelated "cs" C# extension) —
// must not truncate the match. Every supported extension must be captured
// in full, in the surrounding-prose position it actually appears in.
func TestPathToken(t *testing.T) {
	text := "touches config.json, Component.jsx, Component.tsx, app.js, app.ts, Program.cs, and styles.css directly"
	want := []string{
		"config.json", "Component.jsx", "Component.tsx", "app.js", "app.ts", "Program.cs", "styles.css",
	}
	got := pathToken.FindAllString(text, -1)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pathToken.FindAllString() = %v, want %v", got, want)
	}
}

// TestPathTokenNoCollision proves each extension individually, isolating the
// specific truncation regressions it caused: tsx->ts, jsx/json->js,
// css->cs.
func TestPathTokenNoCollision(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"json not truncated to js", "see config.json here", "config.json"},
		{"jsx not truncated to js", "see Component.jsx here", "Component.jsx"},
		{"tsx not truncated to ts", "see Component.tsx here", "Component.tsx"},
		{"js matches in full", "see app.js here", "app.js"},
		{"ts matches in full", "see app.ts here", "app.ts"},
		{"cs matches in full (not swallowed by css)", "see Program.cs here", "Program.cs"},
		{"css not truncated to cs", "see styles.css here", "styles.css"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathToken.FindAllString(tt.text, -1)
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("pathToken.FindAllString(%q) = %v, want [%q]", tt.text, got, tt.want)
			}
		})
	}
}

func machineOriginDiff(hunk string) string {
	return "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n" +
		"index 1111111..2222222 100644\n" +
		"--- a/.github/workflows/ci.yml\n" +
		"+++ b/.github/workflows/ci.yml\n" +
		"@@ -10,7 +10,7 @@ jobs:\n" +
		hunk
}

// TestMachineOrigin covers the approved Dependabot GitHub Actions pin-bump
// path (specs/harden-workflow-supply-chain.md): accepted only when every
// changed hunk is exclusively a `uses:` SHA and adjacent version-comment
// update; anything else (structural, non-workflow, mixed, added, deleted,
// renamed, unparsable) must be rejected — the caller must never be able to
// satisfy this by trusting an actor flag without diff validation.
func TestMachineOrigin(t *testing.T) {
	t.Run("accepted: sha and version comment bump only", func(t *testing.T) {
		diff := machineOriginDiff(
			"     steps:\n" +
				"-      - uses: actions/checkout@a12b3c4d5e6f7890123456789012345678901234 # v4.1.0\n" +
				"+      - uses: actions/checkout@b23c4d5e6f7890123456789012345678901234a1 # v4.1.1\n",
		)
		got := validateMachineOriginDiff(diff)
		if !got.Accepted {
			t.Fatalf("Accepted = false, want true (reason: %s)", got.Reason)
		}
	})

	t.Run("accepted: multiple workflow files, each sha-only", func(t *testing.T) {
		diff := machineOriginDiff(
			"     steps:\n"+
				"-      - uses: actions/checkout@a12b3c4d5e6f7890123456789012345678901234\n"+
				"+      - uses: actions/checkout@b23c4d5e6f7890123456789012345678901234a1\n",
		) + "diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml\n" +
			"index 3333333..4444444 100644\n" +
			"--- a/.github/workflows/release.yml\n" +
			"+++ b/.github/workflows/release.yml\n" +
			"@@ -5,6 +5,6 @@ jobs:\n" +
			"     steps:\n" +
			"-      - uses: actions/setup-node@c34d5e6f7890123456789012345678901234a1b2 # v4\n" +
			"+      - uses: actions/setup-node@d45e6f7890123456789012345678901234a1b2c3 # v4\n"
		got := validateMachineOriginDiff(diff)
		if !got.Accepted {
			t.Fatalf("Accepted = false, want true (reason: %s)", got.Reason)
		}
	})

	t.Run("rejected: structural change alongside the pin bump", func(t *testing.T) {
		diff := machineOriginDiff(
			"     steps:\n" +
				"+      - run: echo hi\n" +
				"-      - uses: actions/checkout@a12b3c4d5e6f7890123456789012345678901234 # v4.1.0\n" +
				"+      - uses: actions/checkout@b23c4d5e6f7890123456789012345678901234a1 # v4.1.1\n",
		)
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (structural line added, not just a pin bump)")
		}
	})

	t.Run("rejected: non-workflow file changed", func(t *testing.T) {
		diff := "diff --git a/src/main.go b/src/main.go\n" +
			"index 1111111..2222222 100644\n" +
			"--- a/src/main.go\n" +
			"+++ b/src/main.go\n" +
			"@@ -1,1 +1,1 @@\n" +
			"-foo\n" +
			"+bar\n"
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (not a workflow file)")
		}
	})

	t.Run("rejected: mixed workflow pin-bump and non-workflow change", func(t *testing.T) {
		diff := machineOriginDiff(
			"     steps:\n"+
				"-      - uses: actions/checkout@a12b3c4d5e6f7890123456789012345678901234\n"+
				"+      - uses: actions/checkout@b23c4d5e6f7890123456789012345678901234a1\n",
		) + "diff --git a/src/main.go b/src/main.go\n" +
			"index 1111111..2222222 100644\n" +
			"--- a/src/main.go\n" +
			"+++ b/src/main.go\n" +
			"@@ -1,1 +1,1 @@\n" +
			"-foo\n" +
			"+bar\n"
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (mixed diff must not satisfy machine-origin)")
		}
	})

	t.Run("rejected: added workflow file", func(t *testing.T) {
		diff := "diff --git a/.github/workflows/new.yml b/.github/workflows/new.yml\n" +
			"new file mode 100644\n" +
			"index 0000000..1111111\n" +
			"--- /dev/null\n" +
			"+++ b/.github/workflows/new.yml\n" +
			"@@ -0,0 +1,2 @@\n" +
			"+name: new\n" +
			"+on: push\n"
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (added file)")
		}
	})

	t.Run("rejected: deleted workflow file", func(t *testing.T) {
		diff := "diff --git a/.github/workflows/old.yml b/.github/workflows/old.yml\n" +
			"deleted file mode 100644\n" +
			"index 1111111..0000000\n" +
			"--- a/.github/workflows/old.yml\n" +
			"+++ /dev/null\n" +
			"@@ -1,2 +0,0 @@\n" +
			"-name: old\n" +
			"-on: push\n"
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (deleted file)")
		}
	})

	t.Run("rejected: renamed workflow file", func(t *testing.T) {
		diff := "diff --git a/.github/workflows/old.yml b/.github/workflows/new.yml\n" +
			"similarity index 100%\n" +
			"rename from .github/workflows/old.yml\n" +
			"rename to .github/workflows/new.yml\n"
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (renamed file)")
		}
	})

	t.Run("rejected: action reference changed, not just its pin", func(t *testing.T) {
		diff := machineOriginDiff(
			"     steps:\n" +
				"-      - uses: actions/checkout@a12b3c4d5e6f7890123456789012345678901234 # v4.1.0\n" +
				"+      - uses: actions/setup-node@b23c4d5e6f7890123456789012345678901234a1 # v4\n",
		)
		got := validateMachineOriginDiff(diff)
		if got.Accepted {
			t.Fatal("Accepted = true, want false (action reference itself changed)")
		}
	})

	t.Run("rejected: unparsable diff", func(t *testing.T) {
		got := validateMachineOriginDiff("not a diff at all, just some prose text")
		if got.Accepted {
			t.Fatal("Accepted = true, want false (no parseable file sections)")
		}
		if !strings.Contains(got.Reason, "no parseable file sections") {
			t.Errorf("Reason = %q, want it to explain the diff couldn't be parsed", got.Reason)
		}
	})

	t.Run("rejected: empty diff", func(t *testing.T) {
		got := validateMachineOriginDiff("")
		if got.Accepted {
			t.Fatal("Accepted = true, want false (empty diff has nothing to validate)")
		}
	})
}
