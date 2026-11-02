//go:build unit_test

package main

import (
	"strings"
	"testing"
)

const restoreMount = "/src"

// TestDotnetRestoreNeededFiresOnTheTreeThatHidesTheHole is the trigger half of
// the fallback, on exactly the shape ecosystems_test calls out: a mixed tree
// where npm resolves and .NET does not, so every consumer-facing signal reads
// normal while the whole C# supply chain is absent from the scan.
func TestDotnetRestoreNeededFiresOnTheTreeThatHidesTheHole(t *testing.T) {
	files := []string{
		"/src/web/package.json",
		"/src/web/package-lock.json",
		"/src/Api/Api.csproj",
		"/src/Domain/Domain.csproj",
		"/src/Solution.sln",
	}
	markers := dotnetRestoreNeeded(restoreMount, files)
	if len(markers) != 3 {
		t.Fatalf("expected the three .NET markers, got %d: %v", len(markers), markers)
	}
	if markers[0] != "Api/Api.csproj" {
		t.Errorf("markers should be mount-relative, got %q", markers[0])
	}
}

// TestDotnetRestoreNeededSilentWhenTrivyHasAnInput proves the fallback never
// runs where it has nothing to add. Each of these is a graph Trivy reads on its
// own, and restoring over one would spend a container to arrive at the same
// answer — and would overwrite a committed graph with one resolved now, which is
// the weaker of the two.
func TestDotnetRestoreNeededSilentWhenTrivyHasAnInput(t *testing.T) {
	for _, input := range []string{
		"/src/Api/packages.lock.json",
		"/src/Api/packages.config",
		"/src/Api/bin/Debug/net8.0/Api.deps.json",
	} {
		files := []string{"/src/Api/Api.csproj", input}
		if markers := dotnetRestoreNeeded(restoreMount, files); markers != nil {
			t.Errorf("%s is a resolvable input; restore must not fire, got %v", input, markers)
		}
	}
}

// TestDotnetRestoreNeededSilentWithoutDotnet keeps the fallback to the ecosystem
// it was scoped to. A node or python tree with no lockfile has the same hole and
// a different remedy; firing a .NET restore at it would be a wasted container and
// a message about the wrong language.
func TestDotnetRestoreNeededSilentWithoutDotnet(t *testing.T) {
	files := []string{"/src/package.json", "/src/pyproject.toml", "/src/go.mod"}
	if markers := dotnetRestoreNeeded(restoreMount, files); markers != nil {
		t.Errorf("no .NET marker present; restore must not fire, got %v", markers)
	}
}

// TestDotnetRestoreNeededAgreesWithTheVerdict pins the two halves to one table.
// A restore triggered by one list of filenames and judged by another is how a
// tree gets restored and still reported unresolved — or, far worse, judged
// resolved on a lockfile the fallback never looked for.
func TestDotnetRestoreNeededAgreesWithTheVerdict(t *testing.T) {
	files := []string{"/src/Api/Api.csproj"}

	if markers := dotnetRestoreNeeded(restoreMount, files); len(markers) == 0 {
		t.Fatal("restore did not fire on a tree the verdict reports")
	}
	msgs := unresolvedEcosystemErrors(restoreMount, files, nil)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "dotnet") {
		t.Fatalf("verdict and trigger disagree about the same tree: %v", msgs)
	}
}

// TestDotnetRestorePartialFailureIsAnError is the load-bearing test of this
// file. Nineteen of twenty projects restoring leaves nineteen packages.lock.json
// files in the tree — a resolvable input, so the reconciliation goes quiet, and
// the twentieth project's dependencies are simply absent from a green verdict.
// That is the exact false pass the whole ecosystems.go check exists to close,
// re-introduced by its own remedy. Only this message separates the two states.
func TestDotnetRestorePartialFailureIsAnError(t *testing.T) {
	out := dotnetRestoreOutcome{
		Band:     dotnetSDK80Band,
		FindExit: "0\n",
		Projects: []string{"Api/Api.csproj", "Domain/Domain.csproj", "Legacy/Legacy.csproj"},
		Failed:   []string{"Legacy/Legacy.csproj"},
		Stderr:   "error NU1101: Unable to find package Contoso.Internal.\nmore banner\n",
	}
	msg := dotnetRestoreRunError(out)
	if msg == "" {
		t.Fatal("a project that did not restore must never read as restored")
	}
	for _, want := range []string{
		"1 of 3",
		"Legacy/Legacy.csproj",
		"not examined",
		"NU1101",
		"--nuget-feed-url",
		dotnetBandsLabel(),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "more banner") {
		t.Error("only the first stderr line belongs in a single errors[] entry")
	}
}

// TestDotnetRestoreSweepFailureIsAnError: `find` failing means the project list
// is a claim about an unknown set, so "every project restored" cannot be said.
// The empty case is separate because a missing exit status is not a zero one —
// that conflation is the founding false pass in miniature.
func TestDotnetRestoreSweepFailureIsAnError(t *testing.T) {
	for name, out := range map[string]dotnetRestoreOutcome{
		"nonzero": {Band: dotnetSDK80Band, FindExit: "1\n", Stderr: "find: /src/x: Permission denied"},
		"absent":  {Band: dotnetSDK80Band, FindExit: ""},
	} {
		msg := dotnetRestoreRunError(out)
		if msg == "" {
			t.Errorf("%s: an unwalkable tree must not read as a complete restore", name)
		}
		if !strings.Contains(msg, "unknown") {
			t.Errorf("%s: message must say the answer is unknown, got %q", name, msg)
		}
	}
}

// TestDotnetRestoreNoProjectsIsAnError. The markers that fired the fallback were
// solutions, or every project sits under bin/ or obj/. Restoring nothing and
// reporting success hands the caller a graph-free tree it believes was restored —
// and the reconciliation would then be told a restore happened.
func TestDotnetRestoreNoProjectsIsAnError(t *testing.T) {
	msg := dotnetRestoreRunError(dotnetRestoreOutcome{Band: dotnetSDK80Band, FindExit: "0"})
	if msg == "" {
		t.Fatal("restoring zero projects must not read as a restored tree")
	}
	if !strings.Contains(msg, "not a clean verdict") {
		t.Errorf("message must refuse the zero, got %q", msg)
	}
}

// TestDotnetRestoreCleanSweepIsSilent — the fallback did its job, so the only
// thing left to say is the warning, not an error.
func TestDotnetRestoreCleanSweepIsSilent(t *testing.T) {
	out := dotnetRestoreOutcome{
		Band:     dotnetSDK80Band,
		FindExit: "0\n",
		Projects: []string{"Api/Api.csproj", "tests/Tests.csproj"},
		Stderr:   "  \n",
	}
	if msg := dotnetRestoreRunError(out); msg != "" {
		t.Fatalf("a complete restore must produce no error, got %q", msg)
	}
}

// TestDotnetRestoreWarningStatesTheGapAndTheRemedy. A restored graph and a
// committed one produce identical-looking findings, so the difference has to be
// stated or it does not exist for the reader. And a warning a consumer cannot act
// on is one they learn to scroll past, which is why the remedy is asserted.
func TestDotnetRestoreWarningStatesTheGapAndTheRemedy(t *testing.T) {
	out := dotnetRestoreOutcome{
		Band:     dotnetSDK80Band,
		BandNote: "SDK band 8.0 (requested by global.json)",
		Projects: []string{"Api/Api.csproj", "tests/Tests.csproj"},
	}
	msg := dotnetRestoreWarning(out)
	for _, want := range []string{
		"packages.lock.json",
		"restored the NuGet graph itself",
		"mcr.microsoft.com/dotnet/sdk:8.0",
		"2 project(s)",
		"floating version range",
		"RestorePackagesWithLockFile",
		"dotnet restore --use-lock-file",
		out.BandNote,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning missing %q:\n%s", want, msg)
		}
	}
}

// TestDotnetRestoreAttemptedNoteSaysCicdAlreadyTried. Without it the unresolved
// verdict reads as though cicd never tried, and the first thing a consumer does
// about it is exactly what cicd already did.
func TestDotnetRestoreAttemptedNoteSaysCicdAlreadyTried(t *testing.T) {
	note := dotnetRestoreAttemptedNote(dotnetSDK100Band)
	if !strings.Contains(note, "mcr.microsoft.com/dotnet/sdk:10.0") {
		t.Errorf("note must name the SDK that tried, got %q", note)
	}
	if !strings.Contains(note, "attempted") {
		t.Errorf("note must say a restore was attempted, got %q", note)
	}
}

// TestDotnetRestoreScriptNeverSplicesAConsumerPath. Project paths come from the
// consumer's tree, so they are read from a file and passed as a quoted argument.
// A path is an argument here, never shell source — the same rule the ADO
// templates are held to, applied to cicd's own generated shell.
func TestDotnetRestoreScriptNeverSplicesAConsumerPath(t *testing.T) {
	script := dotnetRestoreScript(restoreMount, "/root/.nuget/packages")

	if !strings.Contains(script, `dotnet restore "$p" --use-lock-file`) {
		t.Error("the project path must reach dotnet as a quoted argument")
	}
	if strings.Contains(script, "restore $p") {
		t.Error("an unquoted $p is a consumer path parsed as shell words")
	}
	if !strings.Contains(script, "while IFS= read -r p") {
		t.Error("read -r with IFS cleared is what keeps a path with spaces intact")
	}
	for _, want := range []string{
		"-not -path '*/bin/*'",
		"-not -path '*/obj/*'",
		dotnetRestoreFailedPath,
		dotnetRestoreFindPath,
		"exit 0",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	for _, pattern := range dotnetRestoreProjectPatterns {
		if !strings.Contains(script, "-name '"+pattern+"'") {
			t.Errorf("script does not sweep for %s", pattern)
		}
	}
}

// TestDotnetRestorePatternsAreShellSafe is what makes the single-quoting in
// dotnetRestoreScript sound. The patterns are cicd constants today; this fails
// the moment one grows a quote, a backslash or a $ and turns the rendered body
// into something other than a glob.
func TestDotnetRestorePatternsAreShellSafe(t *testing.T) {
	for _, pattern := range dotnetRestoreProjectPatterns {
		if strings.ContainsAny(pattern, "'\"$`\\\n;&|<>()") {
			t.Errorf("%q cannot be single-quoted into a shell word safely", pattern)
		}
	}
}

// TestSplitProbeLinesDropsBlanksAndRelativises. A trailing newline is not a
// project, and an absolute container path is not something a consumer can find in
// their editor.
func TestSplitProbeLinesDropsBlanksAndRelativises(t *testing.T) {
	got := splitProbeLines(restoreMount, "/src/Api/Api.csproj\n\n/src/tests/Tests.csproj\n")
	want := []string{"Api/Api.csproj", "tests/Tests.csproj"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expected %q, got %q", want[i], got[i])
		}
	}
	if splitProbeLines(restoreMount, "\n \n") != nil {
		t.Error("an empty probe must yield no entries, not one blank one")
	}
}
