package main

import (
	"reflect"
	"strings"
	"testing"
)

// diffTouching renders a minimal unified diff header for each path, which is
// all extractDiffPaths reads.
func diffTouching(paths ...string) string {
	var out string
	for _, p := range paths {
		out += "diff --git a/" + p + " b/" + p + "\n" +
			"--- a/" + p + "\n" +
			"+++ b/" + p + "\n"
	}
	return out
}

// TestPathTokenMultiDotStems covers the extension-prefix tokens whose stems contain a
// hyphen or a second dot, so the fix is proven for real dependency-manifest
// names and not only for the single-word stems TestPathTokenNoCollision uses.
func TestPathTokenMultiDotStems(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"bare package.json is not truncated to package.js", "bumps package.json only", []string{"package.json"}},
		{"hyphenated package-lock.json survives intact", "bumps package-lock.json only", []string{"package-lock.json"}},
		{"both manifests in one sentence", "bumps package.json and package-lock.json", []string{"package.json", "package-lock.json"}},
		{"a mid-sentence .css is not clipped to .cs", "edit tokens.css and Program.cs", []string{"tokens.css", "Program.cs"}},
		// Characterisation, not an aspiration: the bare-filename alternation
		// disallows dots inside the stem, so a multi-dot name is matched from
		// its last stem segment. The extension is still complete — which is
		// what the extension-prefix bug was about — and checkRefsCoupling's suffix match
		// still couples the token to the real path (see TestCheckRefsCoupling).
		{"multi-dot stem still yields a complete extension", "edit vite.config.tsx here", []string{"config.tsx"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathToken.FindAllString(tt.text, -1); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pathToken.FindAllString(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// TestCheckRefsCoupling exercises the rule end to end rather than the regex in
// isolation: the extension-prefix truncation surfaced to users as a false
// refs-infer-coupling error, because a mention truncated to "package.js" no
// longer matched the changed "package.json" by equality or by either suffix
// direction. The mismatch cases are the positive control — without them a
// checkRefsCoupling that never reports anything would satisfy this test.
func TestCheckRefsCoupling(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		changed      []string
		wantFindings int
	}{
		{
			name:         "bare package.json mention couples to a changed package.json",
			text:         "The dependency update changes package.json.",
			changed:      []string{"package.json"},
			wantFindings: 0,
		},
		{
			name:         "package-lock.json mention couples to a changed lockfile",
			text:         "Regenerates package-lock.json after the bump.",
			changed:      []string{"package-lock.json"},
			wantFindings: 0,
		},
		{
			name:         "bare mention couples to a nested changed path",
			text:         "The dependency update changes package.json.",
			changed:      []string{"web/app/package.json"},
			wantFindings: 0,
		},
		{
			name:         "multi-dot filename couples despite partial tokenisation",
			text:         "Switches vite.config.tsx to the new plugin API.",
			changed:      []string{"web/vite.config.tsx"},
			wantFindings: 0,
		},
		{
			name:         "tsx mention couples to a changed tsx file",
			text:         "Rewrites store.tsx to use the new reducer.",
			changed:      []string{"src/store.tsx"},
			wantFindings: 0,
		},
		{
			name:         "jsx mention couples to a changed jsx file",
			text:         "Rewrites Gallery.jsx to lazy-load thumbnails.",
			changed:      []string{"src/Gallery.jsx"},
			wantFindings: 0,
		},
		{
			name:         "css mention couples to a changed css file",
			text:         "Restyles theme.css for the dark palette.",
			changed:      []string{"styles/theme.css"},
			wantFindings: 0,
		},
		{
			name:         "js mention still couples to a changed js file",
			text:         "Rewrites server.js to read the port from the environment.",
			changed:      []string{"server.js"},
			wantFindings: 0,
		},
		{
			name:         "positive control: json mention with an unrelated changed file",
			text:         "The dependency update changes package.json.",
			changed:      []string{"README.md"},
			wantFindings: 1,
		},
		{
			name:         "positive control: a tsx mention does not couple to the ts file",
			text:         "Rewrites store.tsx to use the new reducer.",
			changed:      []string{"docs/architecture.md"},
			wantFindings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkRefsCoupling("specs/change/purpose.md", tt.text, diffTouching(tt.changed...))
			if len(got) != tt.wantFindings {
				t.Fatalf("checkRefsCoupling() = %v (%d findings), want %d", got, len(got), tt.wantFindings)
			}
			for _, f := range got {
				if f.Rule != "refs-infer-coupling" {
					t.Errorf("finding rule = %q, want refs-infer-coupling", f.Rule)
				}
			}
		})
	}
}

// TestCheckNoWeaselWordsWholeToken covers the compound-word false positives.
// checkNoWeaselWords used to be a bare strings.Contains, so any weasel word
// buried inside a longer word fired. The blocking case was real: the intent gate
// failed specs/classify-a-refused-release-push.md for "fast" because git's own
// rejection reason is "non-fast-forward", a term that spec cannot avoid — it is
// the string the classifier greps for.
func TestCheckNoWeaselWordsWholeToken(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		// The regressions.
		{"git's non-fast-forward is not the word fast", "the push was rejected (non-fast-forward)", nil},
		{"bare fast-forward is not the word fast", "only a fast-forward conflict retries", nil},
		{"robustness is not robust", "this reads as more robustness than it has", nil},
		{"inflexible is not flexible", "the schedule is inflexible", nil},
		{"simpler is not simple", "the simpler path was rejected", nil},
		{"oversimplified is not simple", "the model is oversimplified", nil},
		{"unbetterable prefix is not better", "a debtor is not a weasel", nil},

		// Still caught, or the rule would be worthless.
		{"a standalone weasel word is found", "the new path is fast", []string{"fast"}},
		{"trailing punctuation still delimits", "it is robust, mostly", []string{"robust"}},
		{"parenthesised still delimits", "(simple) by design", []string{"simple"}},
		{"quote marks still delimit", `the "elegant" approach`, []string{"elegant"}},
		{"sentence-initial and sentence-final", "Easy. Now it is powerful", []string{"easy", "powerful"}},
		{"case is ignored", "a ROBUST design", []string{"robust"}},
		{"a hyphenated entry matches as its own token", "a world-class, cutting-edge idea", []string{"world-class", "cutting-edge"}},
		{"state-of-the-art matches whole", "state-of-the-art tooling", []string{"state-of-the-art"}},
		{"a multi-word entry matches adjacent tokens", "we followed best practice here", []string{"best practice"}},
		{"multi-word entry split across punctuation does not match", "the best. practice was poor", nil},
		{"underscores keep a token whole", "the fast_path helper", nil},
		{"several distinct words are all reported", "a simple, elegant, powerful design", []string{"simple", "powerful", "elegant"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkNoWeaselWords("a.md", tt.text)
			if tt.want == nil {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %q", got[0].Message)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want exactly one finding, got %d", len(got))
			}
			for _, w := range tt.want {
				if !strings.Contains(got[0].Message, w) {
					t.Errorf("finding does not name %q: %s", w, got[0].Message)
				}
			}
			// The message must not name a word the text does not contain as a token.
			for _, w := range weaselWords {
				named := strings.Contains(got[0].Message, w)
				wanted := false
				for _, x := range tt.want {
					if x == w {
						wanted = true
					}
				}
				if named && !wanted {
					t.Errorf("finding names %q, which is not a whole token in %q", w, tt.text)
				}
			}
		})
	}
}

// TestCheckNoWeaselWordsIgnoresQuotedMaterial covers the second half of the same
// defect: the rule judges the author's prose, so quoted material must not count.
// Without this, a spec explaining the rule is blocked by naming its own entries,
// and any artifact quoting a tool message that contains a listed word is blocked
// too.
func TestCheckNoWeaselWordsIgnoresQuotedMaterial(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		found bool
	}{
		{"a code span is not a claim", "the list holds `best practice` as one entry", false},
		{"several spans on one line", "entries `world-class`, `cutting-edge` and `elegant`", false},
		{"a quoted tool message", "the remote said `error: this is not simple`", false},
		{"a fenced block is not a claim", "example:\n```\nthis path is fast and easy\n```\ndone", false},
		{"a flag in a span", "pass `--fast` to skip the check", false},
		{"prose outside a span still counts", "the `--fast` flag makes it simple", true},
		{"prose before a fenced block still counts", "this is elegant:\n```\ncode\n```", true},
		{"an unclosed span does not swallow the rest", "a stray ` tick then simple prose", true},
		{"a span does not join its neighbours into a phrase", "the best `x` practice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkNoWeaselWords("a.md", tt.text)
			if tt.found && len(got) == 0 {
				t.Fatalf("want a finding, got none")
			}
			if !tt.found && len(got) != 0 {
				t.Fatalf("want no finding, got %q", got[0].Message)
			}
		})
	}
}

// TestPathTokenShortYAMLStems covers the refs-coupling fix's narrow half: the 3-char stem
// minimum made ci.yml and cd.yml — the two most frequently changed workflow
// filenames in this repository — invisible to pathToken, so an artifact that
// named the only file it changed contributed no token at all.
//
// The negative controls are the point of the test. The minimum exists to keep
// bare extension words out of prose, and "ci" and "cd" appear as bare words far
// more often than as filenames, so the exemption must be the extension carrying
// it and nothing else.
func TestPathTokenShortYAMLStems(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"ci.yml is a token", "the two sibling sites in ci.yml gain a comment", []string{"ci.yml"}},
		{"cd.yml is a token", "cd.yml failed on every run for four days", []string{"cd.yml"}},
		{"ci.yaml is a token", "renames ci.yaml to ci.yml", []string{"ci.yaml", "ci.yml"}},
		{"cd.yaml is a token", "cd.yaml is not used here", []string{"cd.yaml"}},
		{"a longer yml stem still matches once", "edits precommit.yml only", []string{"precommit.yml"}},
		// Negative controls.
		{"bare ci and cd stay invisible", "we ran ci and then cd by hand", nil},
		{"a one-char yml stem is still refused", "there is no a.yml here", nil},
		{"bare extension words are still refused", "written in go, documented in md, typed in ts", nil},
		{"yml as a bare word is refused", "the yml is malformed", nil},
		{"a two-char stem on a non-yaml extension is still refused", "see ci.go and cd.md", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathToken.FindAllString(tt.text, -1); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pathToken.FindAllString(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// TestMentionsLiterally covers the boundary rules of the reverse coupling check
// one at a time, because each rejection is a specific measured collision rather
// than a symmetry: "domain.gov" contains "main.go", and a coupling built on that
// would suppress a finding the rule got right.
func TestMentionsLiterally(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		needle string
		want   bool
	}{
		{"plain mention", "this edits Makefile only", "Makefile", true},
		{"at the very start", "Makefile grew a target", "Makefile", true},
		{"at the very end", "the target moved to Makefile", "Makefile", true},
		{"followed by a full stop", "the depth now lives in markers.go.", "markers.go", true},
		{"followed by a comma", "cliff.toml, then the workflow", "cliff.toml", true},
		{"preceded by a slash", "see src/quality/include.go for the argument", "include.go", true},
		{"preceded by a dot", "switches vite.config.tsx over", "config.tsx", true},
		{"an unlisted extension is reachable", "cliff.toml sets filter_unconventional", "cliff.toml", true},
		{"a dotfile is reachable", "reads .nvmrc at run time", ".nvmrc", true},
		// Negative controls: a longer word must not be read as containing a name.
		{"a preceding letter disqualifies", "hosted at domain.gov", "main.go", false},
		{"a following letter disqualifies", "the include.golden fixture", "include.go", false},
		{"a following hyphen disqualifies", "the ci.yml-shaped file", "ci.yml", false},
		{"a following slash disqualifies", "under include.go/nested", "include.go", false},
		{"an absent name is absent", "nothing to see", "Makefile", false},
		{"an empty needle never matches", "anything at all", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mentionsLiterally(tt.text, tt.needle); got != tt.want {
				t.Fatalf("mentionsLiterally(%q, %q) = %v, want %v", tt.text, tt.needle, got, tt.want)
			}
		})
	}
}

// TestChangedNameMentioned asserts which name the reverse check coupled on, not
// merely that it coupled: a helper that returned true for the wrong file would
// satisfy checkRefsCoupling and be invisible from there.
func TestChangedNameMentioned(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		changed []string
		want    string
		wantOK  bool
	}{
		{
			name:    "full path wins over the basename",
			text:    "documented in .github/workflows/ci.yml",
			changed: []string{".github/workflows/ci.yml"},
			want:    ".github/workflows/ci.yml",
			wantOK:  true,
		},
		{
			name:    "basename couples when only it is named",
			text:    "the two sibling sites in ci.yml gain a comment",
			changed: []string{".github/workflows/ci.yml"},
			want:    "ci.yml",
			wantOK:  true,
		},
		{
			name:    "an extensionless root file couples",
			text:    "Makefile drops the duplicate module list",
			changed: []string{"Makefile"},
			want:    "Makefile",
			wantOK:  true,
		},
		{
			name:    "an extension pathToken has never heard of couples",
			text:    "cliff.toml sets filter_unconventional = true",
			changed: []string{"cliff.toml"},
			want:    "cliff.toml",
			wantOK:  true,
		},
		{
			name:    "the first changed file named wins, in diff order",
			text:    "edits both markers.go and archive.go",
			changed: []string{"src/build/archive.go", "src/build/markers.go"},
			want:    "archive.go",
			wantOK:  true,
		},
		// Negative controls.
		{
			name:    "no changed name appears",
			text:    "this is about the release pipeline in general",
			changed: []string{"src/quality/include.go"},
			wantOK:  false,
		},
		{
			name:    "a root name below the length floor is not searched",
			text:    "we ran ci by hand to check",
			changed: []string{"ci"},
			wantOK:  false,
		},
		{
			name:    "a coincidental substring does not couple",
			text:    "the service is hosted at domain.gov",
			changed: []string{"src/quality/main.go"},
			wantOK:  false,
		},
		{
			name:    "an empty changed set couples to nothing",
			text:    "edits ci.yml",
			changed: nil,
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := changedNameMentioned(tt.text, tt.changed)
			if ok != tt.wantOK {
				t.Fatalf("changedNameMentioned(...) ok = %v, want %v (got %q)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("changedNameMentioned(...) coupled on %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckRefsCouplingSeesNamesPathTokenCannot is the refs-coupling fix end to end. The
// first case is the measured reproduction: CAPS-012's intent block named ci.yml
// in prose and also named, correctly, three files it deliberately did not
// change, so `mentioned` was non-empty, contained only unchanged paths, and the
// rule reported "artifact may describe a different change" about an artifact
// describing exactly that change.
//
// The remaining pass cases are the reason the fix is not a wider extension list:
// each name is one pathToken structurally cannot tokenise, and each would
// otherwise have been the next issue.
func TestCheckRefsCouplingSeesNamesPathTokenCannot(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		changed      []string
		wantFindings int
	}{
		{
			name: "measured: CAPS-012 named ci.yml alongside three unchanged paths",
			text: "The two sibling passed sites in ci.yml gain a comment naming which " +
				"strength each is. The masked non-run lives in src/security/ and is " +
				"filed separately; comment.md inside the same artifact already " +
				"rendered Failed, and buildCombined in " +
				"src/cross-cutting/evidence/main.go derives the two separately.",
			changed:      []string{".capsules/CAPS-012-composite-smoke-assert-passed.capsule.yaml", ".github/workflows/ci.yml"},
			wantFindings: 0,
		},
		{
			name:         "an extensionless changed file is reachable",
			text:         "Makefile drops the duplicate list; scripts/test-module-units.sh already had it.",
			changed:      []string{"Makefile"},
			wantFindings: 0,
		},
		{
			name:         "an unlisted extension is reachable",
			text:         "cliff.toml sets filter_unconventional = true, which is why scripts/release_drift.py cannot see it.",
			changed:      []string{"cliff.toml"},
			wantFindings: 0,
		},
		{
			name:         "a dotfile is reachable",
			text:         ".nvmrc is read at run time, so src/build/toolchain.go cannot pin it.",
			changed:      []string{".nvmrc"},
			wantFindings: 0,
		},
		// Positive controls: the rule must still fire on an artifact that names
		// paths and is about some other change, or none of the above proves
		// anything.
		{
			name:         "positive control: every mention is unchanged and no changed name appears",
			text:         "Explains the call site in src/quality/lint.go and the rejected option in src/build/markers.go.",
			changed:      []string{".github/workflows/cd.yml"},
			wantFindings: 1,
		},
		{
			name:         "positive control: a coincidental substring does not rescue it",
			text:         "The service is hosted at domain.gov, described in docs/reference/index.md.",
			changed:      []string{"src/quality/main.go"},
			wantFindings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkRefsCoupling(".capsules/CAPS-999-x.capsule.yaml", tt.text, diffTouching(tt.changed...))
			if len(got) != tt.wantFindings {
				t.Fatalf("checkRefsCoupling() = %v (%d findings), want %d", got, len(got), tt.wantFindings)
			}
			for _, f := range got {
				if f.Rule != "refs-infer-coupling" {
					t.Errorf("finding rule = %q, want refs-infer-coupling", f.Rule)
				}
				// The old message asserted the opposite of the truth whenever the
				// cause was a name pathToken could not see. Pin the corrected
				// wording so it cannot quietly regress.
				if !strings.Contains(f.Message, "no changed filename appears in the artifact") {
					t.Errorf("message does not state both directions were checked: %q", f.Message)
				}
				if !strings.Contains(f.Message, "name a file this change touches") {
					t.Errorf("message does not say what closes the finding: %q", f.Message)
				}
			}
		})
	}
}
