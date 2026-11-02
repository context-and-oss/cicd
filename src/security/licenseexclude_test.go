package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustExcluder(t *testing.T, patterns ...string) *licenseExcluder {
	t.Helper()
	ex, err := newLicenseExcluder(patterns)
	if err != nil {
		t.Fatalf("newLicenseExcluder(%q): %v", patterns, err)
	}
	return ex
}

// The shapes a consumer will actually type, matched against the paths Trivy
// actually reports. Each case names a real intent rather than a regexp
// property, because the regexp is an implementation detail and the intent is
// the contract.
func TestAPatternMatchesTheTreeItsAuthorMeant(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		match   []string
		miss    []string
	}{
		{
			name:    "a subtree named by its prefix",
			pattern: "docs/**",
			match:   []string{"docs/package-lock.json", "docs/site/node_modules/x/LICENSE", "docs/a"},
			// "docs" alone is a file, not the tree: `docs/**` says "under docs".
			miss: []string{"docs", "src/docs/package.json", "documentation/x"},
		},
		{
			name:    "a directory name anywhere in the tree",
			pattern: "**/node_modules/**",
			match:   []string{"node_modules/lodash/LICENSE", "Client/node_modules/lodash/LICENSE", "a/b/node_modules/c/d"},
			miss:    []string{"node_modules", "src/node_modules_old/x"},
		},
		{
			name:    "one segment, not the separators around it",
			pattern: "vendor/*/LICENSE",
			match:   []string{"vendor/acme/LICENSE"},
			miss:    []string{"vendor/LICENSE", "vendor/acme/sub/LICENSE"},
		},
		{
			name:    "a suffix across the whole tree",
			pattern: "**/*.min.js",
			match:   []string{"a.min.js", "dist/a.min.js", "a/b/c.min.js"},
			miss:    []string{"a.js", "a.min.jsx"},
		},
		{
			name:    "one character",
			pattern: "docs/v?/LICENSE",
			match:   []string{"docs/v1/LICENSE"},
			miss:    []string{"docs/v/LICENSE", "docs/v10/LICENSE"},
		},
		{
			name:    "an exact path",
			pattern: "internal/site/package-lock.json",
			match:   []string{"internal/site/package-lock.json"},
			miss:    []string{"internal/site/package.json", "x/internal/site/package-lock.json"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, p := range c.match {
				if !mustExcluder(t, c.pattern).match(p) {
					t.Errorf("pattern %q should exclude %q, did not", c.pattern, p)
				}
			}
			for _, p := range c.miss {
				if mustExcluder(t, c.pattern).match(p) {
					t.Errorf("pattern %q should not exclude %q, did", c.pattern, p)
				}
			}
		})
	}
}

// Rule 1: patterns narrow scope, never findings. A pattern is a path pattern,
// so nothing in it can reach a license name or a category. The guard is that
// every non-wildcard character is quoted: a pattern cannot smuggle in a regexp
// that matches more than its author read it to.
func TestAPatternCannotSmuggleInARegexp(t *testing.T) {
	cases := []struct {
		pattern string
		match   string
		miss    []string
	}{
		{pattern: "docs[a-z]/x", match: "docs[a-z]/x", miss: []string{"docsa/x", "docsz/x"}},
		{pattern: "a+/x", match: "a+/x", miss: []string{"aa/x", "a/x"}},
		{pattern: "a.b", match: "a.b", miss: []string{"axb"}},
		{pattern: "(a|b)/x", match: "(a|b)/x", miss: []string{"a/x", "b/x"}},
		{pattern: "^a$", match: "^a$", miss: []string{"a"}},
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			if !mustExcluder(t, c.pattern).match(c.match) {
				t.Errorf("pattern %q should match its own literal %q, did not", c.pattern, c.match)
			}
			for _, p := range c.miss {
				if mustExcluder(t, c.pattern).match(p) {
					t.Errorf("pattern %q was read as a regexp: it matched %q", c.pattern, p)
				}
			}
		})
	}
}

// A malformed pattern errors rather than being dropped, because a dropped
// pattern is an exclusion that silently did not happen — or, worse, a pattern
// whose author believes a subtree was excluded when it was scanned.
func TestAMalformedPatternIsRejectedAndSaysWhy(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    string
	}{
		{name: "empty", pattern: "", want: "empty pattern"},
		{name: "whitespace only", pattern: "   ", want: "empty pattern"},
		{name: "absolute", pattern: "/etc/**", want: "is absolute"},
		{name: "escapes the root", pattern: "../other/**", want: "contains '..'"},
		{name: "escapes mid-path", pattern: "docs/../../**", want: "contains '..'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newLicenseExcluder([]string{c.pattern})
			if err == nil {
				t.Fatalf("pattern %q was accepted; it must be rejected", c.pattern)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not say %q", err, c.want)
			}
		})
	}
}

// Rejection is per-list, not per-pattern: one bad entry fails the run rather
// than leaving the good entries to produce a report that looks complete.
func TestOneBadPatternFailsTheWholeList(t *testing.T) {
	if _, err := newLicenseExcluder([]string{"docs/**", "/etc/**"}); err == nil {
		t.Fatal("a list with one absolute pattern was accepted")
	}
}

func TestPatternsAreNormalisedNotRejected(t *testing.T) {
	ex := mustExcluder(t, " docs/** ", "./docs/**", "docs/**")
	if len(ex.patterns) != 1 {
		t.Fatalf("three spellings of one pattern became %d patterns: %q", len(ex.patterns), ex.patterns)
	}
	if ex.patterns[0] != "docs/**" {
		t.Errorf("pattern normalised to %q, want %q", ex.patterns[0], "docs/**")
	}
	if !ex.match("./docs/x") {
		t.Error("a path Trivy wrote as ./docs/x was not matched by docs/**")
	}
}

// A declaration with no path at all cannot be judged by a path pattern.
// Excluding it on a guess would drop a license nobody asked to drop.
func TestAPathlessDeclarationIsNeverExcluded(t *testing.T) {
	ex := mustExcluder(t, "**")
	for _, p := range []string{"", "   ", "./"} {
		if ex.match(p) {
			t.Errorf("a declaration with path %q was excluded by %q", p, "**")
		}
	}
}

func TestNoPatternsExcludesNothing(t *testing.T) {
	ex := mustExcluder(t)
	if !ex.empty() {
		t.Error("an excluder built from no patterns is not empty")
	}
	if ex.match("docs/x") {
		t.Error("an excluder with no patterns excluded a path")
	}
	if s := licenseExcludeSummary(ex, 0); s != "" {
		t.Errorf("an unconfigured filter reported %q; it should say nothing", s)
	}
	if w := ex.inertWarnings(); len(w) != 0 {
		t.Errorf("an unconfigured filter warned: %q", w)
	}
}

// A nil excluder is the shape every existing caller passes. It must behave as
// "no filter" rather than panicking, because evaluateLicenses is reached from
// paths that never configured one.
func TestANilExcluderIsNoFilter(t *testing.T) {
	var ex *licenseExcluder
	if ex.match("docs/x") {
		t.Error("a nil excluder excluded a path")
	}
	if !ex.empty() {
		t.Error("a nil excluder is not empty")
	}
	if s := licenseExcludeSummary(ex, 0); s != "" {
		t.Errorf("a nil excluder reported %q", s)
	}
	if w := ex.inertWarnings(); w != nil {
		t.Errorf("a nil excluder warned: %q", w)
	}
}

// Rule 3. The two readings that must never collapse into one.
func TestAPatternThatMatchedNothingSaysSo(t *testing.T) {
	ex := mustExcluder(t, "docs/**", "vendor/**")
	ex.match("docs/package-lock.json")

	warns := ex.inertWarnings()
	if len(warns) != 1 {
		t.Fatalf("want exactly one inert pattern reported, got %d: %q", len(warns), warns)
	}
	if !strings.Contains(warns[0], `"vendor/**"`) {
		t.Errorf("the inert warning does not name vendor/**: %q", warns[0])
	}
	if strings.Contains(warns[0], `"docs/**"`) {
		t.Errorf("a pattern that did match was reported as inert: %q", warns[0])
	}
}

// The mistake worth catching: `--license-exclude docs` reads like a directory
// and matches only a file called exactly "docs". The hint fires for a pattern
// with no wildcard, and only then — a wildcard pattern that matched nothing is
// far likelier to be a tree that is genuinely absent.
func TestAWildcardlessPatternGetsTheHint(t *testing.T) {
	ex := mustExcluder(t, "docs")
	warns := ex.inertWarnings()
	if len(warns) != 1 {
		t.Fatalf("want one warning, got %q", warns)
	}
	if !strings.Contains(warns[0], `"docs/**"`) {
		t.Errorf("the hint does not suggest docs/**: %q", warns[0])
	}

	ex = mustExcluder(t, "docs/**")
	warns = ex.inertWarnings()
	if len(warns) != 1 {
		t.Fatalf("want one warning, got %q", warns)
	}
	if strings.Contains(warns[0], "needs a wildcard") {
		t.Errorf("a pattern that already has a wildcard got the wildcard hint: %q", warns[0])
	}
}

// Rule 2. The summary is emitted whenever a filter was configured, including
// when it removed nothing: "no filter" and "a filter that found nothing" are
// different runs and must read differently.
func TestAConfiguredFilterAlwaysSaysWhatItDid(t *testing.T) {
	ex := mustExcluder(t, "docs/**")
	s := licenseExcludeSummary(ex, 0)
	if s == "" {
		t.Fatal("a configured filter that removed nothing said nothing")
	}
	if !strings.Contains(s, "0 license declaration(s) excluded") {
		t.Errorf("the summary does not report the count: %q", s)
	}
	if !strings.Contains(s, "docs/**") {
		t.Errorf("the summary does not name the pattern that produced the count: %q", s)
	}

	if s := licenseExcludeSummary(ex, 42); !strings.Contains(s, "42 license declaration(s) excluded") {
		t.Errorf("the summary does not report the count: %q", s)
	}
}

// The end-to-end contract: an excluded declaration is not scanned against the
// policy, is not a finding, and is still counted.
func TestAnExcludedDeclarationIsCountedAndNotJudged(t *testing.T) {
	doc := licenseDoc(
		`{"Severity":"HIGH","Category":"restricted","PkgName":"gpl-thing","FilePath":"docs/site/package-lock.json","Name":"GPL-3.0","Confidence":1}`,
		mitEntry,
	)

	// Without the filter the restricted license is a finding.
	before, err := evaluateLicenses(doc, defaultPolicy(t), nil, nil)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if before.Scanned != 2 || before.Excluded != 0 {
		t.Fatalf("unfiltered: scanned %d excluded %d, want 2 and 0", before.Scanned, before.Excluded)
	}
	if len(before.Findings) == 0 {
		t.Fatal("the restricted license was not a finding before the filter; the case proves nothing")
	}

	after, err := evaluateLicenses(doc, defaultPolicy(t), mustExcluder(t, "docs/**"), nil)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if after.Excluded != 1 {
		t.Errorf("excluded %d, want 1", after.Excluded)
	}
	// Scanned is what the policy judged, and Scanned+Excluded is everything
	// Trivy reported: the excluded one is not subtracted out of existence.
	if after.Scanned != 1 {
		t.Errorf("scanned %d, want 1", after.Scanned)
	}
	if after.Scanned+after.Excluded != before.Scanned {
		t.Errorf("scanned %d + excluded %d != the %d Trivy reported",
			after.Scanned, after.Excluded, before.Scanned)
	}
	if len(after.Findings) != 0 {
		t.Errorf("the excluded restricted license is still a finding: %d", len(after.Findings))
	}
}

// A license read from package metadata carries no FilePath of its own. The
// manifest it came from is the only path it has, and a pattern naming a
// vendored subtree has to be able to reach it — otherwise "exclude the doc
// site" excludes some of the doc site.
func TestADeclarationWithNoFilePathFallsBackToItsTarget(t *testing.T) {
	doc := json.RawMessage(`{"SchemaVersion":2,"Results":[
	  {"Target":"docs/site/package-lock.json","Class":"license","Licenses":[
	    {"Severity":"HIGH","Category":"restricted","PkgName":"gpl-thing","Name":"GPL-3.0","Confidence":1}]}]}`)

	res, err := evaluateLicenses(doc, defaultPolicy(t), mustExcluder(t, "docs/**"), nil)
	if err != nil {
		t.Fatalf("evaluateLicenses: %v", err)
	}
	if res.Excluded != 1 || res.Scanned != 0 {
		t.Errorf("scanned %d excluded %d, want 0 and 1: the Target was not used as the path",
			res.Scanned, res.Excluded)
	}
}
