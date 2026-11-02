package main

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	RuleSeverityError = "error"
	RuleSeverityWarn  = "warn"
	RuleSeverityInfo  = "info"
)

// IntentFinding is a single rule violation found in an intent artifact.
type IntentFinding struct {
	Rule         string `json:"rule"`
	Severity     string `json:"severity"`
	ArtifactPath string `json:"artifactPath,omitempty"`
	Message      string `json:"message"`
	Excerpt      string `json:"excerpt,omitempty"`
}

var (
	// \b word boundaries don't work with ??? (non-word chars), so it gets its own alternation.
	tbdPattern = regexp.MustCompile(`(?i)\b(?:TBD|TODO|FIXME)\b|\?\?\?`)

	weaselWords = []string{
		"scalable", "robust", "fast", "easy", "simple", "better", "improved",
		"optimized", "seamless", "intuitive", "best practice", "world-class",
		"cutting-edge", "state-of-the-art", "efficient", "powerful", "flexible",
		"lightweight", "comprehensive", "elegant",
	}

	// weaselPunctuation and weaselSpace tokenise prose for checkNoWeaselWords so
	// that a weasel word only counts when it stands on its own as a whole word.
	//
	// \b cannot express this. A hyphen is a non-word character, so it *is* a word
	// boundary: `\bfast\b` matches the "fast" inside git's own
	// "non-fast-forward", and `\brobust\b` was never the problem — plain
	// substring matching also flagged "robustness". Both fired against
	// specs/classify-a-refused-release-push.md, whose entire subject is that git
	// term. RE2 has no lookbehind, so the boundary is enforced by tokenising
	// rather than by the pattern.
	//
	// Hyphens and underscores stay inside a token, so "non-fast-forward" and
	// "fast_path" are each one word that is not "fast". Punctuation becomes an
	// explicit barrier token rather than plain whitespace, so the one multi-word
	// entry ("best practice") cannot match across a sentence boundary in
	// "the best. practice was poor".
	weaselPunctuation = regexp.MustCompile(`[^\w\s-]+`)
	weaselSpace       = regexp.MustCompile(`\s+`)

	// weaselFenced and weaselSpan remove quoted material before the weasel check,
	// which judges the author's own prose. A fenced block or a code span is a
	// quotation — a tool's output, a flag, an identifier, or the rule's own word
	// list — and the author is not claiming it. Without this the rule cannot be
	// documented: naming an entry in order to explain it is itself a finding, and
	// any spec quoting an error message that contains a listed word is blocked.
	//
	// Applied to this rule only. checkRefsCoupling must keep code spans, because
	// that is where artifacts name the paths it couples against.
	weaselFenced = regexp.MustCompile("(?s)```.*?```")
	weaselSpan   = regexp.MustCompile("`[^`]*`")

	causalMarkers = []string{
		"because", "since", "in order to", "so that", "therefore",
		"as a result", "due to", "given that", "the reason", "this is why",
		"we chose", "we decided", "instead of", "rather than",
	}

	// pathToken matches relative paths and filenames with source extensions.
	// Requires a stem of at least 3 chars before the extension to avoid matching
	// bare extension words ("go", "md", "ts") that appear in normal prose.
	//
	// The extension alternation needs a trailing \b: Go's RE2 engine matches
	// alternatives leftmost-first, not leftmost-longest, so without a boundary
	// "ts" (listed before "tsx") would truncate "app.tsx" to a match on
	// "app.ts", and "js" would truncate "app.jsx"/"app.json" to "app.js" (issue
	// the extension-prefix bug). \b forces backtracking into the longer alternative when the short
	// one doesn't land on a token boundary, making the fix order-independent.
	//
	// yaml/yml sit in their own alternation with a 2-char minimum, because the
	// 3-char minimum made `ci.yml` and `cd.yml` — the two most frequently
	// changed workflow filenames in this repository — invisible to the rule,
	// so an artifact that correctly named the only file it changed was treated
	// as naming no file at all. The minimum stays 3 everywhere
	// else: "go", "md" and "ts" are ordinary English-adjacent tokens, while a
	// 2-char stem followed by a YAML extension is not something anyone writes
	// meaning something other than that file. It is not lowered to 1, since
	// nothing here is named `a.yml` and a shorter stem buys no real filename.
	pathToken = regexp.MustCompile(
		`(?:[\w][\w\-]*/)+[\w\-./]+` +
			`|[\w][\w\-]{2,}\.(?:go|tsx|ts|jsx|js|py|cs|css|tf|hcl|json|md|sh|sql)\b` +
			`|[\w][\w\-]{1,}\.(?:yaml|yml)\b`,
	)
)

// runRules executes all tier-2 semantic rules against the extracted text of one artifact.
// diffContent may be empty — coupling check is skipped when no diff is provided.
func runRules(artifactPath, text, diffContent string) []IntentFinding {
	var findings []IntentFinding
	findings = append(findings, checkNoTBD(artifactPath, text)...)
	findings = append(findings, checkNoWeaselWords(artifactPath, text)...)
	findings = append(findings, checkCausalLanguage(artifactPath, text)...)
	findings = append(findings, checkMinLength(artifactPath, text)...)
	if diffContent != "" {
		findings = append(findings, checkRefsCoupling(artifactPath, text, diffContent)...)
	}
	return findings
}

func checkNoTBD(path, text string) []IntentFinding {
	matches := tbdPattern.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	return []IntentFinding{{
		Rule:         "no-tbd",
		Severity:     RuleSeverityError,
		ArtifactPath: path,
		Message:      fmt.Sprintf("artifact contains placeholder text: %s", strings.Join(uniqueStrings(matches), ", ")),
	}}
}

func checkNoWeaselWords(path, text string) []IntentFinding {
	// Rebuild the prose as space-delimited whole tokens, then look for each
	// weasel word with its own delimiters attached. Sentinel spaces let the
	// first and last token match the same way as any other. A multi-word entry
	// ("best practice") still works: its words are adjacent tokens, so the
	// joined form contains the phrase verbatim.
	prose := weaselSpan.ReplaceAllString(weaselFenced.ReplaceAllString(strings.ToLower(text), " | "), " | ")
	barred := weaselPunctuation.ReplaceAllString(prose, " | ")
	haystack := " " + strings.Join(weaselSpace.Split(barred, -1), " ") + " "
	var found []string
	for _, w := range weaselWords {
		if strings.Contains(haystack, " "+w+" ") {
			found = append(found, w)
		}
	}
	if len(found) == 0 {
		return nil
	}
	return []IntentFinding{{
		Rule:         "no-weasel-words",
		Severity:     RuleSeverityWarn,
		ArtifactPath: path,
		Message:      fmt.Sprintf("artifact uses unmeasurable qualifiers: %s", strings.Join(found, ", ")),
	}}
}

func checkCausalLanguage(path, text string) []IntentFinding {
	lower := strings.ToLower(text)
	for _, m := range causalMarkers {
		if strings.Contains(lower, m) {
			return nil
		}
	}
	return []IntentFinding{{
		Rule:         "min-causal-language",
		Severity:     RuleSeverityError,
		ArtifactPath: path,
		Message:      "artifact contains no causal language (because, since, in order to, we chose, instead of…); WHY is missing",
	}}
}

func checkMinLength(path, text string) []IntentFinding {
	if len(strings.Fields(text)) >= 30 {
		return nil
	}
	return []IntentFinding{{
		Rule:         "min-length",
		Severity:     RuleSeverityWarn,
		ArtifactPath: path,
		Message:      fmt.Sprintf("artifact has only %d words; a rationale needs at least 30", len(strings.Fields(text))),
	}}
}

// checkRefsCoupling verifies that any path-like tokens mentioned in the artifact
// overlap with the set of files actually changed in the diff. Skipped when the
// artifact contains no path-shaped tokens (high-level rationale is fine).
func checkRefsCoupling(path, text, diffContent string) []IntentFinding {
	mentioned := pathToken.FindAllString(text, -1)
	if len(mentioned) == 0 {
		return nil
	}
	changed := extractDiffPaths(diffContent)
	if len(changed) == 0 {
		return nil
	}

	// Build lookup: full path and bare filename of each changed file.
	lookup := make(map[string]bool, len(changed)*2)
	for _, p := range changed {
		lookup[p] = true
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			lookup[p[idx+1:]] = true
		}
	}

	for _, tok := range mentioned {
		if lookup[tok] {
			return nil
		}
		// Suffix/prefix partial match.
		for cp := range lookup {
			if strings.HasSuffix(cp, tok) || strings.HasSuffix(tok, cp) {
				return nil
			}
		}
	}

	// Ask the question the other way round before reporting: does the artifact
	// contain a changed file's name verbatim, whether or not pathToken can
	// tokenise it?
	//
	// This is the structural half of the refs-coupling fix. The loop above can only couple
	// on names pathToken recognised, so it punishes an artifact for the
	// pattern's blind spots rather than for anything the author did: `ci.yml`
	// was one instance, and the pattern is blind to every extensionless name
	// (Makefile, Dockerfile, go.work's siblings), every extension absent from
	// its list (cliff.toml, .nvmrc) and every dotfile. In each case an artifact
	// that named its changed file AND, correctly, some file it deliberately did
	// not change — a call site it explains, a rejected option — reported
	// "artifact may describe a different change" about an artifact describing
	// exactly this change. Widening the extension list instead would fix one
	// filename at a time forever, and the sentences it costs are the ones worth
	// keeping: the cheapest way to silence the rule was to delete the mentions
	// of unchanged files, which is this gate working against the min-length and
	// min-causal-language rules beside it.
	//
	// A verbatim occurrence of a changed file's name is coupling under any
	// reading, so this can only remove findings, never add one. It is also why
	// the severity stays error rather than dropping to warn when the mentions
	// resolve to real files (the rejected soften-to-warn option): after this, a remaining
	// error means the artifact named paths, none of them is in this diff, and
	// none of this diff's names appears in the artifact — which is precisely
	// the "describes a different change" signal the rule exists for, and
	// softening it there would cost real bite for no remaining false failure.
	// The matched name is returned but discarded here: the rule reports nothing
	// on a pass, and the tests assert on it directly so that a helper which
	// coupled on the wrong file would still be caught.
	if _, ok := changedNameMentioned(text, changed); ok {
		return nil
	}

	preview := func(ss []string, n int) string {
		if len(ss) > n {
			ss = ss[:n]
		}
		return strings.Join(ss, ", ")
	}

	return []IntentFinding{{
		Rule:         "refs-infer-coupling",
		Severity:     RuleSeverityError,
		ArtifactPath: path,
		// The old wording — "artifact may describe a different change" — was the
		// opposite of the truth whenever the cause was a name pathToken could
		// not see, and it sent the reviewer back to re-read a correct artifact
		// looking for an error that was not in it. Say what the check actually
		// established, in both directions, and say what closes it.
		Message: "artifact mentions specific files, but none of them is in this diff and no changed filename appears in the artifact — name a file this change touches, or the artifact may describe a different change",
		Excerpt: fmt.Sprintf("mentioned: %s | changed: %s", preview(mentioned, 3), preview(changed, 3)),
	}}
}

// minLiteralBasename is the shortest bare filename changedNameMentioned will
// look for. A path carrying a directory separator is searched in full at any
// length, because it cannot collide with prose; a bare basename is a plain
// substring search, so a very short one ("a.c", or a root file literally named
// "ci") would suppress a finding on a coincidence. Nothing in this repository is
// named in three characters or fewer, and `ci.yml` — the name that motivated
// the refs-coupling fix — is six.
const minLiteralBasename = 4

// changedNameMentioned reports whether text names any of the changed paths
// verbatim, and which one. Full path first, then the bare basename, mirroring
// the equality-then-suffix order of the token loop above.
func changedNameMentioned(text string, changed []string) (string, bool) {
	for _, p := range changed {
		idx := strings.LastIndex(p, "/")
		if idx < 0 {
			if len(p) >= minLiteralBasename && mentionsLiterally(text, p) {
				return p, true
			}
			continue
		}
		if mentionsLiterally(text, p) {
			return p, true
		}
		if base := p[idx+1:]; len(base) >= minLiteralBasename && mentionsLiterally(text, base) {
			return base, true
		}
	}
	return "", false
}

// mentionsLiterally reports whether needle occurs in text as its own token.
//
// The boundary rules are asymmetric on purpose, and each side is a measured
// hazard rather than a symmetry:
//
//   - A preceding letter, digit or underscore disqualifies the match, because
//     "domain.gov" contains "main.go" and coupling an artifact to a changed
//     main.go on that basis would suppress a correct finding.
//   - A preceding '/', '.' or '-' is fine: "src/quality/include.go" and
//     "vite.config.tsx" are mentions of include.go and config.tsx, which is the
//     same relation the suffix match above already accepts.
//   - A following letter, digit, underscore, '-' or '/' disqualifies it, for the
//     mirror-image reason ("include.golden", "include.go/…").
//   - A following '.' is deliberately allowed, because a filename at the end of
//     a sentence is followed by a full stop far more often than by another
//     extension.
func mentionsLiterally(text, needle string) bool {
	if needle == "" {
		return false
	}
	for from := 0; from+len(needle) <= len(text); {
		i := strings.Index(text[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		beforeOK := start == 0 || !isWordByte(text[start-1])
		afterOK := end == len(text) || !isTailByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		from = start + 1
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

func isTailByte(b byte) bool {
	return isWordByte(b) || b == '-' || b == '/'
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
