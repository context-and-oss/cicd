package main

// Unit tests for what a BYO test leg's evidence says about the part of the tree
// it did not witness. Run with:
//
//	go test -tags unit_test -run TestDotnetLegScope ./...

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func discovery(projects, testProjects int) dotnetDiscovery {
	d := dotnetDiscovery{}
	for i := 0; i < projects; i++ {
		d.Projects = append(d.Projects, "p"+strconv.Itoa(i)+".csproj")
	}
	for i := 0; i < testProjects; i++ {
		d.TestProjects = append(d.TestProjects, "p"+strconv.Itoa(i)+".csproj")
	}
	return d
}

func TestLegsDeclare(t *testing.T) {
	legs := []testLeg{{Label: "web", Language: "node"}, {Label: "api", Language: "dotnet"}}
	if !legsDeclare(legs, "dotnet") {
		t.Error("a leg naming dotnet must be found")
	}
	if legsDeclare(legs, "go") {
		t.Error("no leg names go")
	}
	// A leg with no language at all must not answer for one. The sweep it would
	// trigger costs a container, and the denominator it produced would be
	// attributed to a leg that never claimed the language.
	if legsDeclare([]testLeg{{Label: "only", Language: ""}}, "dotnet") {
		t.Error("an unlabelled-language leg must not declare dotnet")
	}
}

// TestLegScopeQualifierFollowsLegPrefix keeps the caller-built line in step with
// the leg-returned ones: one leg keeps the wording a --test-cmd consumer always
// had, several name the leg.
func TestLegScopeQualifierFollowsLegPrefix(t *testing.T) {
	if got := legScopeQualifier("dotnet", 1); got != "byo-test" {
		t.Errorf("single leg qualifier = %q, want byo-test", got)
	}
	if got := legScopeQualifier("api", 3); got != "test-leg api" {
		t.Errorf("multi-leg qualifier = %q, want %q", got, "test-leg api")
	}
}

// TestDotnetLegScopeStatesBothNumbersAndRefusesTheRatio is the defect this file
// exists for. A command running about two thirds of a consumer's dozen-odd
// projects produced no warning at all, because witnessing is per language: dotnet was witnessed, so
// the envelope read as complete.
//
// Both numbers must appear, and the division of one by the other must not —
// cicd cannot know how many projects the command should have run, and a ratio
// would be a false accusation on a command that merges its reports.
func TestDotnetLegScopeStatesBothNumbersAndRefusesTheRatio(t *testing.T) {
	merged := 7
	msg := dotnetLegScopeWarning("byo-test", discovery(12, 10), &merged)

	for _, want := range []string{"merged 7 coverage document(s)", "12 .csproj", "10 of which carry"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must state %q, got: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "states no ratio") {
		t.Errorf("the refusal must be explicit, got: %s", msg)
	}
	// The two shapes of ratio that would be wrong: merged against the project
	// count and merged against the test-project count.
	for _, forbidden := range []string{"7 of 12", "7 of 10", "58%", "70%"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("message must not compute a ratio (%q), got: %s", forbidden, msg)
		}
	}
	// Both explanations for a mismatch are named, so the line is never read as
	// an accusation.
	if !strings.Contains(msg, "one report per test project") ||
		!strings.Contains(msg, "merges its reports into one") {
		t.Errorf("both explanations must be named, got: %s", msg)
	}
}

// TestDotnetLegScopeSeparatesNoHarvestFromEmptyHarvest holds the nil/zero
// distinction. A leg that ran no patterned harvest and a leg whose harvest
// merged nothing are different states, and collapsing them would report "merged
// 0 documents" about a leg that was never asked for one.
func TestDotnetLegScopeSeparatesNoHarvestFromEmptyHarvest(t *testing.T) {
	zero := 0
	none := dotnetLegScopeWarning("byo-test", discovery(12, 10), nil)
	empty := dotnetLegScopeWarning("byo-test", discovery(12, 10), &zero)

	if none == empty {
		t.Fatal("no harvest and an empty harvest must not render identically")
	}
	if strings.Contains(none, "merged") {
		t.Errorf("a leg with no patterned harvest must claim no document count, got: %s", none)
	}
	if !strings.Contains(none, "exit status") {
		t.Errorf("the one attestation left must be named, got: %s", none)
	}
	if !strings.Contains(empty, "merged 0 coverage document(s)") {
		t.Errorf("a harvest that merged nothing must say so, got: %s", empty)
	}
}

// TestDotnetLegScopeQuotesTheDepthItSearched keeps the number in the sentence
// tied to the number in the find. markers.go's own header names this drift class
// ("quoting a second literal 4 in a message is the drift this file exists to
// prevent"), and dotnetexec.go carried three copies of it.
func TestDotnetLegScopeQuotesTheDepthItSearched(t *testing.T) {
	depth := strconv.Itoa(markerSearchDepth)
	merged := 2
	for name, msg := range map[string]string{
		"with a harvest":    dotnetLegScopeWarning("byo-test", discovery(4, 2), &merged),
		"without a harvest": dotnetLegScopeWarning("byo-test", discovery(4, 2), nil),
		"with no projects":  dotnetLegScopeWarning("byo-test", dotnetDiscovery{}, &merged),
	} {
		if !strings.Contains(msg, depth+" directory levels") {
			t.Errorf("%s: message must quote the search depth %s, got: %s", name, depth, msg)
		}
	}
}

// TestDotnetSweepQuotesNoDepthLiteral is the other half of the same guard, and
// the reason it reads a file: dotnetexec.go is //go:build !unit_test, so its
// find strings cannot be called from here. A re-introduced literal is exactly
// how the three copies got there.
func TestDotnetSweepQuotesNoDepthLiteral(t *testing.T) {
	raw, err := os.ReadFile("dotnetexec.go")
	if err != nil {
		t.Fatalf("dotnetexec.go must be readable for this guard to mean anything: %v", err)
	}
	literal := regexp.MustCompile(`-maxdepth [0-9]`)
	if hit := literal.FindString(string(raw)); hit != "" {
		t.Errorf("dotnetexec.go holds a depth literal (%q); use markerSearchDepth so the "+
			"depth a warning quotes is the depth the sweep used", hit)
	}
	if !strings.Contains(string(raw), "markerSearchDepth") {
		t.Error("dotnetexec.go no longer references markerSearchDepth; the sweep and the " +
			"message have come apart")
	}
}

// TestDotnetLegScopeNoteFiresOnlyOnAMismatch keeps the caveat off the run where
// it says nothing, and keeps the wrong remedy out of it entirely.
func TestDotnetLegScopeNoteFiresOnlyOnAMismatch(t *testing.T) {
	merged := 4
	mixed := dotnetLegScopeWarning("byo-test", discovery(12, 10), &merged)
	allTests := dotnetLegScopeWarning("byo-test", discovery(4, 4), &merged)

	// The count is read by a person, so it agrees with itself grammatically.
	if one := dotnetLegScopeWarning("byo-test", discovery(2, 1), &merged); !strings.Contains(one, "1 of which carries") {
		t.Errorf("a single test project must not read as %q, got: %s", "1 of which carry", one)
	}
	if !strings.Contains(mixed, "greps each project file on its own") {
		t.Errorf("a tree holding non-test projects must carry the caveat, got: %s", mixed)
	}
	if strings.Contains(allTests, "greps each") {
		t.Errorf("a tree whose every project is a test project needs no caveat, got: %s", allTests)
	}
	// dotnetTextualClassificationNote ends by telling the reader to commit a
	// solution, which is a real remedy on cicd's own .NET leg and does nothing
	// here: the command already chose its scope. A remedy that cannot work is
	// the small version of the lie this file removes.
	if strings.Contains(mixed, "Committing a solution") {
		t.Errorf("the BYO note must not offer the solution remedy, got: %s", mixed)
	}
	// The caveat names the number the miss produces, not the possibility of one.
	// Measured on a real dozen-project tree carrying its markers in BOTH
	// test/Directory.Build.props and every .csproj: the count is right only
	// because of the redundant per-project copy. Hoisting IsTestProject into the
	// shared file is a tidy-up a reviewer would approve, and it takes the count
	// to 0 with passed=true. A caveat reading "may read as a non-test project"
	// invites a nod; one reading "reports 0 test projects" invites a check.
	if !strings.Contains(mixed, "reports 0 test projects here") {
		t.Errorf("the caveat must name the inverted count, not hint at it, got: %s", mixed)
	}
	if !strings.Contains(mixed, "without changing anything the command runs") {
		t.Errorf("the caveat must say the tidy-up changes no behaviour, got: %s", mixed)
	}
}

// TestDotnetLegScopeUnknownIsNotAnEmptyTree separates a sweep that failed from a
// tree with nothing in it. Passing dotnetDiscovery{} into the warning on a sweep
// error would have reported "found no .csproj" about a tree nobody looked at.
func TestDotnetLegScopeUnknownIsNotAnEmptyTree(t *testing.T) {
	failed := dotnetLegScopeUnknownWarning("byo-test", errors.New("resolve image: no such host"))
	if strings.Contains(failed, "found no .csproj") {
		t.Errorf("a failed sweep must not read as an empty tree, got: %s", failed)
	}
	if !strings.Contains(failed, "no such host") {
		t.Errorf("the reason must survive into the evidence, got: %s", failed)
	}
	if !strings.Contains(failed, "not because the tree is empty") {
		t.Errorf("the distinction must be stated, got: %s", failed)
	}
	// A nil error must not render as "<nil>" or an empty parenthesis.
	nilErr := dotnetLegScopeUnknownWarning("byo-test", nil)
	if strings.Contains(nilErr, "<nil>") || strings.Contains(nilErr, "()") {
		t.Errorf("a nil reason must still read as prose, got: %s", nilErr)
	}
}

// TestDotnetLegScopeMessagesCarryNoBacktick holds every line in this file to the
// constraint notify imposes: each warnings[] entry is rendered as a markdown
// code span, so a backtick closes it early and the rest of the sentence lands in
// the reader's prose (CAPS-027).
func TestDotnetLegScopeMessagesCarryNoBacktick(t *testing.T) {
	merged := 3
	msgs := []string{
		dotnetLegScopeWarning("byo-test", discovery(12, 10), &merged),
		dotnetLegScopeWarning("test-leg api", discovery(12, 10), nil),
		dotnetLegScopeWarning("byo-test", dotnetDiscovery{}, nil),
		dotnetLegScopeUnknownWarning("byo-test", errors.New("boom")),
		dotnetBYOClassificationNote,
	}
	for _, m := range msgs {
		if strings.Contains(m, "`") {
			t.Errorf("message carries a backtick and would break its code span: %s", m)
		}
		// The doubled leg label CAPS-026 removed: these lines are built by the
		// caller, so they carry their own qualifier and must not be prefixed
		// again — a message holding two is the shape that shipped once.
		if strings.Count(m, "test-leg") > 1 {
			t.Errorf("message names the leg twice: %s", m)
		}
	}
}

// TestDotnetLegScopeHoistInvertsOnlyTheTreeCount pins the props-file inversion as
// behaviour rather than as wording.
//
// The two assertions above it check that the caveat *says* the count goes to 0.
// This one checks what the leg actually emits on either side of the refactor the
// caveat describes, because a sentence that names a number is not evidence the
// number moves that way.
//
// Measured by running one change's head twice against one real consumer export
// of over fifty projects, about a dozen of them test projects, differing by
// exactly one commit — <IsTestProject>true</IsTestProject> hoisted out of every
// test .csproj into test/Directory.Build.props, which is the tidy-up the caveat
// names. Between the two runs testProjectsDiscovered went from the test-project
// count to 0, while projectsDiscovered, coverageDocumentsMerged, passed, errors
// and coveragePercent (to 14 decimal places) did not move. The figures below
// are synthetic with the same shape.
//
// So the claim is stronger than "roughly the same run": every other signal in the
// envelope holds still, which is what makes the moving integer worth a caveat.
//
// It is NOT unreadable, and the first version of this comment said it was.
// projectsDiscovered held still and it counts every .csproj including the test
// ones, so it is a denominator this refactor cannot touch and a real deletion
// must — deleting the test projects lowers it by their number, the hoist leaves
// it where it was. The two states are separable from fields already in the
// envelope, for runs close enough together that one change separates them.
//
// The assertion is a substitution rather than a pair of Contains checks, because
// "one integer apart" is the whole property. A future change that made the 0 case
// read differently — a louder sentence, a dropped caveat, a hedge — would break
// this and should, since the reader's only handle on the difference is that
// integer.
func TestDotnetLegScopeHoistInvertsOnlyTheTreeCount(t *testing.T) {
	merged := 8
	asIs := dotnetLegScopeWarning("test-leg dotnet", discovery(50, 12), &merged)
	hoisted := dotnetLegScopeWarning("test-leg dotnet", discovery(50, 0), &merged)

	if asIs == hoisted {
		t.Fatal("the hoist must change the reported count; the whole caveat is that it does")
	}
	if got := strings.Replace(asIs, " 12 of which carry", " 0 of which carry", 1); got != hoisted {
		t.Errorf("the hoist must move exactly one integer and nothing else.\n as-is: %s\nhoisted: %s", got, hoisted)
	}
	// Both sides carry the caveat: 0 < 50 as surely as 12 < 50, and a run whose
	// count has already been inverted is the run that needs the sentence most.
	for name, msg := range map[string]string{"as-is": asIs, "hoisted": hoisted} {
		if !strings.Contains(msg, "greps each project file on its own") {
			t.Errorf("%s: the caveat must fire, got: %s", name, msg)
		}
		if !strings.Contains(msg, "merged 8 coverage document(s)") {
			t.Errorf("%s: the command-scoped count must not move under a tree refactor, got: %s", name, msg)
		}
	}
	// Why this stays a caveat and does not become a diagnostic, given that the
	// inference above is sound for adjacent runs. NOT because cicd cannot hold an
	// earlier envelope — it can and does: Test takes --baseline and
	// parseBaselineCoverage accepts a full evidence envelope, so the module has
	// reasoned across two runs since ADR-003, reading coverageByLanguage and
	// nothing else from it. The constraint is narrower and is enough: THIS
	// function is composed from one run, and a message written on the single-run
	// path must not assert a conclusion that requires two. That is the founding
	// doctrine in a new direction — a claim made by something that never looked.
	if !strings.Contains(hoisted, "0 of which carry a test marker") {
		t.Errorf("the inverted tree count must be stated plainly, got: %s", hoisted)
	}
}
