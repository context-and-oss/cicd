// What a BYO test leg's evidence says about the part of the tree it did not
// witness.
//
// Deliberately untagged (no //go:build !unit_test): deciding what to say about
// a leg's scope needs no Dagger, and the include.go precedent is the reason it
// matters — a `default`-less switch survived in an untagged-adjacent file for
// exactly as long as nothing in it was testable.
package main

import (
	"fmt"
	"strconv"
	"strings"
)

// legsDeclare reports whether any leg names this language. Used to decide
// whether a scope sweep is worth running at all: one sweep for the run, not one
// per leg, because the answer is a property of the source tree.
func legsDeclare(legs []testLeg, language string) bool {
	for _, leg := range legs {
		if leg.Language == language {
			return true
		}
	}
	return false
}

// legScopeQualifier is how a caller-built line about one leg names that leg.
//
// It follows legPrefix: with several legs the label earns its space, with one it
// does not and the line keeps the `byo-test` prefix every other whole-run
// message uses. Distinct from the strings a leg itself returns, which are
// prefixed by the caller — a leg-returned message containing "test-leg" is the
// doubled label CAPS-026 removed, and a test asserts it stays removed.
func legScopeQualifier(label string, legCount int) string {
	if p := legPrefix(label, legCount); p != "" {
		return p
	}
	return "byo-test"
}

// dotnetBYOClassificationNote is the textual-marker caveat, worded for the BYO
// path.
//
// It is not dotnetTextualClassificationNote, and the difference is the remedy,
// not the prose. That note ends by telling the reader to commit a solution,
// because on cicd's own .NET leg a solution makes dotnetTestTargets skip the
// per-project classification entirely and lets MSBuild resolve what a grep
// cannot see. Here the classification is not deciding anything: a
// consumer-supplied command already chose its own scope, and committing a
// solution would not change one thing about what that command runs. Reusing the
// other note would have handed a reader a remedy that does nothing, which is a
// smaller version of the lie this file exists to remove.
//
// The wording names the shape rather than calling it an edge case, because it is
// not one. A shared Directory.Build.props can supply test dependencies while
// each .csproj carries its own <IsTestProject>true</IsTestProject>. The count
// then reads the right number because of the redundant per-project marker,
// not because the shared props file was read. Hoisting IsTestProject into the
// shared props file beside the other test configuration and deleting the
// duplicates is a normal tidy-up that any reviewer would approve. It would take
// testProjectsDiscovered to 0 and leave passed=true. So the failure mode
// is not an exotic layout, it is a commit that makes the repository tidier and
// the evidence inverted, which is why the sentence says 0 out loud instead of
// "may read as".
//
// No backticks: notify renders each errors[] and warnings[] entry as a markdown
// code span.
const dotnetBYOClassificationNote = " Note that the test-marker count greps each " +
	"project file on its own, so a test SDK or IsTestProject arriving from a " +
	"Directory.Build.props is invisible to it: a tree that declares its markers only " +
	"in a shared props file reports 0 test projects here, and hoisting a per-project " +
	"IsTestProject into one is a tidy-up that would invert this count without " +
	"changing anything the command runs. That is a caveat on the number, not a " +
	"remedy: cicd is describing the tree, and the command decided its own scope " +
	"before either was read."

// dotnetLegScopeWarning states what a .NET BYO leg's evidence covers, and states
// it on every such run.
//
// The gap it closes. witnessedLanguages and unwitnessedLanguages work per
// *language*: one leg naming dotnet makes dotnet witnessed, and the envelope then
// reads as complete for .NET however much of the tree the command actually
// touched. A consumer command running only a subset of the solution produced
// no warning about that partial scope. That is the partial-reads-as-complete
// failure testlegs.go's own header names, one level
// down — from "which languages were witnessed" to "how much of a language was".
//
// Why no ratio, ever. cicd cannot know how many projects a consumer's own
// command should have run; that is the whole nature of a BYO leg, exactly as
// coverageSetWarnings cannot know how many documents a consumer's command should
// have written. The honest thing is the same in both places: state the numbers,
// name what they do and do not license, and refuse the division. A ratio here
// would be a false accusation on the two legitimate shapes — a command that
// merges its reports into one, and a command deliberately scoped to a subset.
//
// Why on every run and not only on a mismatch. The mismatch cannot be computed
// (see above), so "only when it looks wrong" has nothing to fire on. And the
// silent case is the dangerous one: a repository whose numbers happen to agree
// and a repository nobody checked are the same envelope. This is the branch
// dotnetTestScopeWarning's solution arm already settles for cicd's own leg —
// it reports no ratio and says why, precisely so a solution repository is not
// "silent in a way indistinguishable from a repository whose classification had
// been checked and found complete". A BYO leg was the third, still-silent case.
//
// It is a warning and never an error, for notWitnessedWarning's reason: nothing
// failed to run, a partial scope is a legitimate choice, and --fail-on NONE
// cannot clear a non-run — so failing here would be a permanent red with no
// remedy on a repository doing nothing wrong.
//
// merged is the count of coverage documents this leg's harvest actually folded
// into a reading, or nil when the leg ran no patterned harvest — either because
// it declared no coverage report or because it named exactly one. Nil is not
// zero: zero is a harvest that ran and merged nothing, which is a different
// state and gets a different sentence.
func dotnetLegScopeWarning(qualifier string, d dotnetDiscovery, merged *int) string {
	depth := strconv.Itoa(markerSearchDepth)
	if len(d.Projects) == 0 {
		// A leg declares dotnet and the sweep found no project file. Saying so
		// beats saying nothing: it is the one case where the denominator is
		// absent rather than inconvenient, and the reason is almost always that
		// the projects sit deeper than the search goes.
		return qualifier + ": a consumer-supplied command witnesses dotnet and cicd " +
			"found no .csproj within " + depth + " directory levels of the source root, " +
			"so this evidence states no project count beside this leg and the command's " +
			"scope is attested by its exit status alone."
	}

	// Pluralised for the same reason dotnetTestScopeWarning bothers: this
	// sentence is read by a consumer, and "1 of which carry" is the wart that
	// makes evidence look machine-generated and unreviewed.
	carry := "of which carry"
	if len(d.TestProjects) == 1 {
		carry = "of which carries"
	}
	tree := "the source tree holds " + strconv.Itoa(len(d.Projects)) + " .csproj, " +
		strconv.Itoa(len(d.TestProjects)) + " " + carry + " a test marker in the " +
		"project file itself (searched " + depth + " directory levels deep)"

	var msg string
	if merged == nil {
		msg = qualifier + ": a consumer-supplied command witnesses dotnet and produced " +
			"no per-document coverage count, so its scope is attested by the command's " +
			"exit status and at most one named report, while " + tree + ". Nothing here " +
			"distinguishes a run over every one of those projects from a run over one."
	} else {
		msg = qualifier + ": merged " + strconv.Itoa(*merged) + " coverage document(s) " +
			"while " + tree + ". A consumer-supplied command chooses its own scope, so " +
			"cicd applies no classification to that choice and states no ratio: one " +
			"report per test project makes these numbers comparable by hand, and a " +
			"command that merges its reports into one does not."
	}

	if len(d.TestProjects) < len(d.Projects) {
		msg += dotnetBYOClassificationNote
	}
	return msg
}

// dotnetLegScopeUnknownWarning is what a .NET BYO leg says when the sweep that
// would have supplied its denominator could not run.
//
// A sweep that failed must not read like a tree with nothing in it, which is
// what returning dotnetDiscovery{} into dotnetLegScopeWarning would have
// produced: "found no .csproj", about a tree nobody managed to look at. Same
// distinction the harvest draws between a pattern that matched nothing and a
// pattern cicd could not expand.
func dotnetLegScopeUnknownWarning(qualifier string, err error) string {
	reason := "no reason reported"
	if err != nil {
		reason = strings.TrimSpace(err.Error())
	}
	return fmt.Sprintf(
		"%s: a consumer-supplied command witnesses dotnet and cicd could not sweep the "+
			"source tree for project files (%s), so this evidence states no project count "+
			"beside this leg — the count is missing because the sweep failed, not because "+
			"the tree is empty.", qualifier, reason)
}
