//go:build unit_test

package main

import (
	"strconv"
	"strings"
	"testing"
)

// TestResolveIncludeNames_Accepted covers every spelling detectLanguages has ever
// accepted. A name that used to work and now errors is a break for a consumer who
// did nothing wrong, which is the one failure mode this change could introduce.
func TestResolveIncludeNames_Accepted(t *testing.T) {
	cases := map[string]string{
		"go": "go", "GO": "go", " go ": "go",
		"node": "node", "nodejs": "node", "typescript": "node", "ts": "node",
		"Node": "node", "TypeScript": "node",
		"python": "python", "py": "python", "PYTHON": "python",
		"dotnet": "dotnet", "csharp": "dotnet", "c#": "dotnet", "DotNet": "dotnet",
	}
	for in, want := range cases {
		got, err := resolveIncludeNames([]string{in})
		if err != nil {
			t.Fatalf("resolveIncludeNames(%q): unexpected error: %v", in, err)
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("resolveIncludeNames(%q) = %v, want [%s]", in, got, want)
		}
	}
}

// TestResolveIncludeNames_Unrecognised is the defect. `--include golang` used to
// resolve to an empty set, the leg loop never iterated, and the gate reported
// passed=true having linted nothing.
func TestResolveIncludeNames_Unrecognised(t *testing.T) {
	for _, in := range []string{"golang", "gopher", "jav", "", "  ", "rust", "javascript", "js", ".net", "node.js"} {
		got, err := resolveIncludeNames([]string{in})
		if err == nil {
			t.Errorf("resolveIncludeNames(%q) = %v, want an error: an unrecognised "+
				"name that resolves to nothing is a green gate over no work", in, got)
			continue
		}
		if got != nil {
			t.Errorf("resolveIncludeNames(%q) returned %v alongside its error; a "+
				"caller reading the slice would run a partial scan", in, got)
		}
		if !strings.Contains(err.Error(), "accepted names are") {
			t.Errorf("error for %q does not list the accepted set: %v", in, err)
		}
	}
}

// A caller who mistyped two entries should learn both from one run: each round
// trip costs a pipeline.
func TestResolveIncludeNames_ReportsEveryUnrecognisedName(t *testing.T) {
	_, err := resolveIncludeNames([]string{"go", "jav", "pyton", "node"})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{`"jav"`, `"pyton"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
}

// One unrecognised name in an otherwise valid list must not resolve to a partial
// scan reported as a full one — that is the same silence with a smaller blast
// radius: `--include node,jav` used to scan Node only and say nothing.
func TestResolveIncludeNames_PartialListIsRefusedWhole(t *testing.T) {
	got, err := resolveIncludeNames([]string{"node", "jav"})
	if err == nil {
		t.Fatalf("resolveIncludeNames = %v, want an error", got)
	}
}

func TestResolveIncludeNames_DedupedAndCanonicallyOrdered(t *testing.T) {
	got, err := resolveIncludeNames([]string{"dotnet", "ts", "go", "nodejs", "csharp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"go", "node", "dotnet"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("resolveIncludeNames = %v, want %v: the same set must produce the "+
			"same evidence whatever order it was asked in", got, want)
	}
}

// The invariant the zero-language verdict in Check depends on: a non-empty
// include either errors or resolves to at least one language. If this ever stops
// holding, a caller mistake can reach a passing gate again.
func TestResolveIncludeNames_NonEmptyInputNeverResolvesToNothing(t *testing.T) {
	for _, in := range [][]string{
		{"go"}, {"jav"}, {""}, {"go", "jav"}, {"", ""}, {"c#", "py"},
	} {
		got, err := resolveIncludeNames(in)
		if err == nil && len(got) == 0 {
			t.Errorf("resolveIncludeNames(%v) = empty set with no error: this is the "+
				"state that reports passed=true over no lint and no tests", in)
		}
	}
}

func TestAcceptedIncludeNames_ListsEveryAlias(t *testing.T) {
	listed := acceptedIncludeNames()
	for alias := range languageAliases {
		if !strings.Contains(listed, alias) {
			t.Errorf("acceptedIncludeNames() omits %q, so an error message would "+
				"tell a caller a working name is not accepted: %s", alias, listed)
		}
	}
	// Canonical order, so the message reads the way every other language list in
	// the module does.
	idx := -1
	for _, canonical := range canonicalLanguages {
		at := strings.Index(listed, canonical)
		if at < 0 {
			t.Fatalf("acceptedIncludeNames() omits the canonical name %q: %s", canonical, listed)
		}
		if at < idx {
			t.Errorf("acceptedIncludeNames() is not in canonical order: %s", listed)
		}
		idx = at
	}
}

func TestLanguageAliases_EveryTargetIsCanonical(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range canonicalLanguages {
		valid[c] = true
	}
	for alias, target := range languageAliases {
		if !valid[target] {
			t.Errorf("alias %q maps to %q, which is not a canonical language: it "+
				"would resolve to a language with no lint leg, i.e. to nothing", alias, target)
		}
	}
	// Every canonical language must be reachable by name, or it can be detected
	// and never deliberately requested.
	for _, c := range canonicalLanguages {
		if languageAliases[c] != c {
			t.Errorf("canonical language %q is not accepted as its own --include name", c)
		}
	}
}

// TestExcludedLanguageWarnings is the disclosure gap: `--include go` on a repo
// containing package.json used to produce an envelope byte-identical to one from
// a repo that only contains Go.
func TestExcludedLanguageWarnings(t *testing.T) {
	markers := map[string]string{
		"go":     "go.mod",
		"node":   "web/package.json",
		"dotnet": "svc/Api.csproj",
	}
	got := excludedLanguageWarnings([]string{"go"}, []string{"go", "node", "dotnet"}, markers)
	if len(got) != 2 {
		t.Fatalf("want one warning per excluded language, got %d: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"NOT SCANNED", "node", "web/package.json", "dotnet", "svc/Api.csproj", "--include go",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings omit %q: %v", want, got)
		}
	}
	if strings.Contains(joined, "— go detected") {
		t.Errorf("go was included and must not be reported as excluded: %v", got)
	}
}

func TestExcludedLanguageWarnings_NothingExcluded(t *testing.T) {
	markers := map[string]string{"go": "go.mod"}
	if got := excludedLanguageWarnings([]string{"go", "node"}, []string{"go"}, markers); got != nil {
		t.Errorf("want no warnings when every detected language is included, got %v", got)
	}
}

// A language named in --include but absent from the tree is not a warning: the
// caller asked for it deliberately and its leg runs. Warning here would make the
// common `--include go` on a Go repo noisy, and noise is how a real disclosure
// gets skipped.
func TestExcludedLanguageWarnings_IncludedButUndetectedIsSilent(t *testing.T) {
	if got := excludedLanguageWarnings([]string{"go", "python"}, []string{"go"}, map[string]string{"go": "go.mod"}); got != nil {
		t.Errorf("want no warnings, got %v", got)
	}
}

// Auto-detection passes no include list, and every detected language runs, so
// there is nothing to disclose.
func TestExcludedLanguageWarnings_AutoDetectIsSilent(t *testing.T) {
	if got := excludedLanguageWarnings(nil, []string{"go", "node"}, map[string]string{"go": "go.mod"}); got != nil {
		t.Errorf("want no warnings on the auto-detect path, got %v", got)
	}
}

// A detected language whose marker path went missing still gets its warning: the
// exclusion is the fact that matters, and dropping the warning for want of a
// filename would restore the silence.
func TestExcludedLanguageWarnings_MissingMarkerStillWarns(t *testing.T) {
	got := excludedLanguageWarnings([]string{"go"}, []string{"go", "node"}, map[string]string{})
	if len(got) != 1 {
		t.Fatalf("want one warning, got %v", got)
	}
	if !strings.Contains(got[0], "node") || !strings.Contains(got[0], "NOT SCANNED") {
		t.Errorf("warning does not name the excluded language: %q", got[0])
	}
}

func TestExcludedLanguageWarnings_CanonicalOrder(t *testing.T) {
	markers := map[string]string{"node": "package.json", "python": "pyproject.toml", "dotnet": "App.sln"}
	got := excludedLanguageWarnings([]string{"go"}, []string{"dotnet", "python", "node"}, markers)
	if len(got) != 3 {
		t.Fatalf("want three warnings, got %v", got)
	}
	for i, want := range []string{"node", "python", "dotnet"} {
		if !strings.Contains(got[i], want) {
			t.Errorf("warning %d is not about %s: %q", i, want, got[i])
		}
	}
}

// The zero-language warning has to be actionable and has to state the search it
// actually performed — a message quoting a depth the find did not use is a lie
// dressed as a diagnostic.
func TestNoLanguageDetectedWarning(t *testing.T) {
	warning := noLanguageDetectedWarning()
	for _, want := range []string{
		"NO LANGUAGE DETECTED", "nothing was linted", "--include",
		strconv.Itoa(markerSearchDepth),
	} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning omits %q: %s", want, warning)
		}
	}
	for _, marker := range markerFileNames {
		if !strings.Contains(warning, marker) {
			t.Errorf("warning does not name the marker %q it searched for: %s", marker, warning)
		}
	}
}

// The depth in the message and the depth in the find(1) invocation are the same
// value by construction. This asserts the construction, because the previous
// arrangement had the depth as a literal in the command string where nothing
// could compare it to anything.
func TestMarkerFindArgs_CarriesTheSearchDepth(t *testing.T) {
	args := markerFindArgs()
	if !strings.Contains(args, "-maxdepth "+strconv.Itoa(markerSearchDepth)) {
		t.Errorf("markerFindArgs() does not apply markerSearchDepth: %s", args)
	}
	if !strings.Contains(args, markerFindExpr()) {
		t.Errorf("markerFindArgs() dropped the name predicate: %s", args)
	}
	if !strings.Contains(noLanguageDetectedWarning(), strconv.Itoa(markerSearchDepth)) {
		t.Error("the warning and the search no longer quote the same depth")
	}
}

// The accepted set is carried in four places: this map, the shell guard in
// .github/workflows/precommit.yml, templates/azure-devops/precommit.yml
// and docs/reference/index.md. Two copies of a list that can drift is this
// repository's recurring defect — .slnx was missing from two of three marker
// lists for exactly as long as nothing tested the pair together. Nothing here can
// read a workflow file, so this pins the set literally: changing it fails, which
// is the prompt to change the other three in the same commit.
func TestLanguageAliases_MatchTheDocumentedSet(t *testing.T) {
	want := map[string]string{
		"go":         "go",
		"node":       "node",
		"nodejs":     "node",
		"typescript": "node",
		"ts":         "node",
		"python":     "python",
		"py":         "python",
		"dotnet":     "dotnet",
		"csharp":     "dotnet",
		"c#":         "dotnet",
	}
	for alias, target := range want {
		if languageAliases[alias] != target {
			t.Errorf("accepted set lost %q -> %q; the shell guard in "+
				"precommit.yml still accepts it, so the workflow would pass an "+
				"input the module now refuses", alias, target)
		}
	}
	for alias := range languageAliases {
		if _, ok := want[alias]; !ok {
			t.Errorf("accepted set gained %q; the shell guard in precommit.yml "+
				"refuses it, so the module and the workflow now disagree about the "+
				"same input. Widen all four copies together, on purpose", alias)
		}
	}
}
