//go:build unit_test

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The .NET scope warning had THREE owners: dotnetreport.go writes it, the
// `module-test` cell for src/quality greps it with jq, and
// scripts/smoke/dotnet-runner-shapes.sh greps it again for the MTP fixture.
// When CAPS-024 reworded it from "ran N test project(s)" to "ran N of M .csproj
// found under the source root", both assertions still pinned the old wording —
// so `Test src/quality` went red on a change that had broken nothing, and the
// reason was eight minutes of Dagger away from the edit that caused it. Fixing
// only the first owner cost a second full CI cycle to discover the third, which
// is the argument for this test scanning every owner rather than the one that
// happened to fail. That is the held-twice drift check_include_language_set
// solves, and it gets the same treatment: the assertion files own the patterns,
// and this test proves the code satisfies them.
//
// Deliberately narrow — it covers the two scope-warning patterns, not every
// assertion in that cell. A general "every jq test() in ci.yml matches
// something a module can emit" check would have to reconstruct strings the Go
// source builds by concatenation, and would be long on false positives.
//
// It reads ci.yml through a relative path, and a missing or unreadable file is
// a failure rather than a skip: a cross-check that quietly did not run is the
// thing this repository refuses everywhere else.
func TestScopeWarningSatisfiesTheCIAssertions(t *testing.T) {
	// Every file that greps this warning out of the evidence. A new one has to
	// be added here; nothing discovers them, which is why the list is asserted
	// non-empty per file below.
	owners := []string{
		"../../.github/workflows/ci.yml",
		"../../scripts/smoke/dotnet-runner-shapes.sh",
	}

	// jq string literals escape the backslash, so `\\.csproj` in an assertion is
	// the regex `\.csproj` by the time jq's test() sees it.
	jqTest := regexp.MustCompile(`test\("((?:[^"\\]|\\.)*)"\)`)
	var want []string
	for _, path := range owners {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read %s, so the cross-check did not run: %v", path, err)
		}
		found := 0
		for _, m := range jqTest.FindAllStringSubmatch(string(raw), -1) {
			pat := strings.ReplaceAll(m[1], `\\`, `\`)
			if strings.Contains(pat, ".csproj found under the source root") ||
				strings.Contains(pat, "no test marker in the project file itself") {
				want = append(want, pat)
				found++
			}
		}
		// A zero here is the interesting failure: it means an owner stopped
		// asserting the scope warning, either because the assertion was reworded
		// out from under this test or because it was quietly dropped.
		if found == 0 {
			t.Errorf("%s pins no scope-warning pattern — if the assertion moved, move "+
				"this list with it rather than deleting the entry", path)
		}
	}
	if len(want) == 0 {
		t.Fatal("no owner pins the scope warning, so this test proves nothing")
	}

	// testdata/dotnet-app and testdata/dotnet-mtp-app share this shape, which is
	// what both owners run against: two .csproj found, one classified as a test
	// project.
	d := dotnetDiscovery{Projects: []string{"dotnet-app.csproj", "tests/dotnet-app.Tests.csproj"}}
	got := dotnetTestScopeWarning("project", d, []string{"tests/dotnet-app.Tests.csproj"})
	if got == "" {
		t.Fatal("the project branch produced no scope warning at all")
	}
	for _, pat := range want {
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Fatalf("ci.yml pins a pattern Go cannot compile (%q): %v", pat, err)
		}
		if !re.MatchString(got) {
			t.Errorf("an owner asserts /%s/ against the evidence and the warning does "+
				"not match it, so that cell is red on wording alone.\nwarning: %s", pat, got)
		}
	}
}

// The singular is asserted separately because the fixture the CI cell uses skips
// exactly one project, so "The other 1 carry" is the sentence a reader would
// actually have seen.
func TestScopeWarningAgreesWithItselfOnNumber(t *testing.T) {
	one := dotnetTestScopeWarning("project",
		dotnetDiscovery{Projects: []string{"a.csproj", "b.csproj"}},
		[]string{"b.csproj"})
	if !strings.Contains(one, "The other 1 carries no test marker") {
		t.Errorf("one skipped project must read \"carries\": %s", one)
	}
	many := dotnetTestScopeWarning("project",
		dotnetDiscovery{Projects: []string{"a.csproj", "b.csproj", "c.csproj"}},
		[]string{"c.csproj"})
	if !strings.Contains(many, "The other 2 carry no test marker") {
		t.Errorf("two skipped projects must read \"carry\": %s", many)
	}
}
