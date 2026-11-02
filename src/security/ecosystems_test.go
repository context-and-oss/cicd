//go:build unit_test

package main

import (
	"errors"
	"strings"
	"testing"
)

const probeMount = "/src"

// unresolvedEcosystemErrors is the message-only view of unresolvedEcosystems,
// for the tests that assert on wording and not on which ecosystem said it.
func unresolvedEcosystemErrors(mount string, files, resolvedTypes []string) []string {
	var msgs []string
	for _, v := range unresolvedEcosystems(mount, files, resolvedTypes) {
		msgs = append(msgs, v.Message)
	}
	return msgs
}

func TestResultlessDependencyScanApplicability(t *testing.T) {
	wrappedNoTargets := errors.New("outer: " + errTrivyNoTargets.Error())
	cases := []struct {
		name  string
		files []string
		err   error
		want  bool
	}{
		{"static tree", []string{""}, errTrivyNoTargets, true},
		{"nil probe output", nil, errTrivyNoTargets, true},
		{"declared node ecosystem", []string{"/src/package.json"}, errTrivyNoTargets, false},
		{"resolvable go input", []string{"/src/go.mod"}, errTrivyNoTargets, false},
		{"different scan error", nil, errors.New("trivy crashed"), false},
		// Merely repeating the sentinel's text does not grant the N/A path. The
		// typed condition comes only from parsing a structurally valid report.
		{"same text without identity", nil, wrappedNoTargets, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resultlessDependencyScanIsNotApplicable(tc.files, tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDependencyNotApplicableResultStatesBothSkippedConcerns(t *testing.T) {
	result, ok := dependencyNotApplicableResult(nil, errTrivyNoTargets, []string{"scan narrowing unknown"})
	if !ok || !result.Skipped {
		t.Fatalf("result = %+v, ok = %v; want an explicit skipped result", result, ok)
	}
	if result.Examined != nil || len(result.CycloneDX) != 0 {
		t.Errorf("result = %+v; a skipped scan must claim neither examination nor inventory", result)
	}
	if len(result.Warnings) != 2 || result.Warnings[0] != "scan narrowing unknown" || result.Warnings[1] != dependencyNotApplicableWarning {
		t.Errorf("dependency warnings = %v, want preserved scan warning plus N/A reason", result.Warnings)
	}
	if len(result.InventoryWarnings) != 1 || result.InventoryWarnings[0] != inventoryNotApplicableWarning {
		t.Errorf("inventory warnings = %v, want its own N/A reason", result.InventoryWarnings)
	}

	if result, ok := dependencyNotApplicableResult([]string{"/src/package.json"}, errTrivyNoTargets, nil); ok || result.Skipped {
		t.Errorf("declared ecosystem became N/A: result = %+v, ok = %v", result, ok)
	}
}

// TestUnresolvedEcosystemsReportsDeclaredButUnresolved is the regression proof for
// the false pass this file exists to close: a mixed C#/npm tree where npm resolves
// and .NET does not, which is the shape that hides the hole. Trivy's report is
// structurally valid, its vulnerability count is real for the packages it read,
// and its CycloneDX lists npm components only — nothing in that output says the
// twenty .csproj files were never examined.
func TestUnresolvedEcosystemsReportsDeclaredButUnresolved(t *testing.T) {
	files := []string{
		"/src/web/package.json",
		"/src/web/package-lock.json",
		"/src/Api/Api.csproj",
		"/src/Domain/Domain.csproj",
		"/src/Infra/Infra.csproj",
		"/src/Solution.sln",
	}
	msgs := unresolvedEcosystemErrors(probeMount, files, []string{"npm"})

	if len(msgs) != 1 {
		t.Fatalf("expected exactly the dotnet ecosystem reported, got %d: %v", len(msgs), msgs)
	}
	msg := msgs[0]
	for _, want := range []string{
		"dotnet",
		"Api/Api.csproj",
		"packages.lock.json",
		"RestorePackagesWithLockFile",
		"not a clean verdict",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q, so a consumer cannot act on it:\n%s", want, msg)
		}
	}
	// The mount prefix is a cicd implementation detail. A consumer looking for
	// /src/Api in their own checkout finds nothing.
	if strings.Contains(msg, "/src/") {
		t.Errorf("message leaks the container mount path:\n%s", msg)
	}
	// Four .csproj/.sln markers were found; naming all of them in one error
	// string would be unreadable at twenty.
	if !strings.Contains(msg, "4 project/solution file(s)") {
		t.Errorf("message does not state how many markers were found:\n%s", msg)
	}
}

// TestUnresolvedEcosystemsInverseFalsePositive is the other half, and the half
// that decides whether this check survives contact with real consumers. A project
// that has committed a resolvable input has been *looked at*; zero findings there
// is a genuine pass, and failing it would get the whole check switched off.
func TestUnresolvedEcosystemsInverseFalsePositive(t *testing.T) {
	cases := []struct {
		name  string
		files []string
	}{
		{
			// NuGet writes this only when a project opts in — the reason the
			// .NET gap is so wide — but when it is there, Trivy reads it.
			name:  "dotnet with packages.lock.json",
			files: []string{"/src/Api/Api.csproj", "/src/Api/packages.lock.json"},
		},
		{
			name:  "dotnet with packages.config",
			files: []string{"/src/Api/Api.csproj", "/src/Api/packages.config"},
		},
		{
			name:  "dotnet with a build deps manifest",
			files: []string{"/src/Api/Api.csproj", "/src/Api/bin/Release/Api.deps.json"},
		},
		{
			name:  "node with a yarn lockfile",
			files: []string{"/src/package.json", "/src/yarn.lock"},
		},
		{
			name:  "node with a pnpm lockfile",
			files: []string{"/src/package.json", "/src/pnpm-lock.yaml"},
		},
		{
			name:  "python with a poetry lockfile",
			files: []string{"/src/pyproject.toml", "/src/poetry.lock"},
		},
		{
			name:  "python with pinned requirements only",
			files: []string{"/src/setup.py", "/src/requirements.txt"},
		},
		{
			// An empty tree declares nothing, so there is nothing to reconcile.
			// This must not become "everything is unresolved".
			name:  "no dependency files at all",
			files: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Trivy resolved nothing at all — the harshest input. Only the
			// presence of the resolvable input can clear these.
			if msgs := unresolvedEcosystemErrors(probeMount, tc.files, nil); len(msgs) > 0 {
				t.Fatalf("false alarm on a tree cicd could see the graph for: %v", msgs)
			}
		})
	}
}

// TestUnresolvedEcosystemsLockfileAnywhereClears documents a deliberate
// limitation rather than asserting an ideal. Presence is checked tree-wide, not
// per project, so one lockfile among twenty projects clears .NET entirely. The
// alternative — pairing each project with a lockfile in its own directory — needs
// a model of solution layout, Directory.Packages.props and multi-targeting that
// cicd does not have, and would produce false alarms on valid repositories. The
// coarse check still turns the common all-or-nothing case from silent to loud.
func TestUnresolvedEcosystemsLockfileAnywhereClears(t *testing.T) {
	files := []string{
		"/src/One/One.csproj",
		"/src/Two/Two.csproj",
		"/src/Two/packages.lock.json",
	}
	if msgs := unresolvedEcosystemErrors(probeMount, files, nil); len(msgs) > 0 {
		t.Fatalf("known limitation changed behaviour; update the docs with it: %v", msgs)
	}
}

// TestUnresolvedEcosystemsTrivyOutputOnlyExculpates pins the asymmetry that keeps
// the check honest. Trivy resolving packages for an ecosystem clears it even with
// no lockfile on disk (a committed node_modules tree is real, and Trivy's node-pkg
// analyser reads it); Trivy reporting nothing can never on its own cause a report,
// because an empty report is exactly the signal that cannot tell the two states
// apart.
func TestUnresolvedEcosystemsTrivyOutputOnlyExculpates(t *testing.T) {
	vendored := []string{
		"/src/package.json",
		"/src/node_modules/left-pad/package.json",
	}
	if msgs := unresolvedEcosystemErrors(probeMount, vendored, []string{"node-pkg"}); len(msgs) > 0 {
		t.Fatalf("trivy resolved node packages, so this is a scanned tree: %v", msgs)
	}
	if msgs := unresolvedEcosystemErrors(probeMount, vendored, nil); len(msgs) != 1 {
		t.Fatalf("no lockfile and nothing resolved must be reported, got %v", msgs)
	}
	// A type from a *different* ecosystem must not clear this one — the bug in
	// the defect is precisely one ecosystem's success covering another's silence.
	if msgs := unresolvedEcosystemErrors(probeMount, vendored, []string{"gomod", "nuget"}); len(msgs) != 1 {
		t.Fatalf("another ecosystem's success must not clear node, got %v", msgs)
	}
}

// TestGoEcosystemCannotFire is the answer to "is this .NET-specific" in its
// negative form. go.mod is both the marker and the input Trivy's gomod analyser
// reads, so a detected Go module is always a resolvable one. If a future edit
// makes this test fail, the table has been split in a way that manufactures a
// false alarm on every Go repository a consumer scans.
func TestGoEcosystemCannotFire(t *testing.T) {
	for _, e := range depEcosystems() {
		if e.name != "go" {
			continue
		}
		for _, marker := range e.markers {
			if !matchesAnyBase(marker, e.inputs) {
				t.Fatalf("go marker %q is not also a resolvable input, so a Go repo can now "+
					"be reported unresolved", marker)
			}
		}
		files := []string{"/src/go.mod", "/src/go.sum"}
		if msgs := unresolvedEcosystemErrors(probeMount, files, nil); len(msgs) > 0 {
			t.Fatalf("go must never be reportable: %v", msgs)
		}
		return
	}
	t.Fatal("the go ecosystem is missing from the table; its immunity is a documented claim")
}

// TestEveryEcosystemIsReportable is the mirror image: every *other* entry must be
// able to fire on a marker-only tree. An ecosystem whose markers all happen to be
// listed as inputs too is dead weight that reads like coverage.
func TestEveryEcosystemIsReportable(t *testing.T) {
	for _, e := range depEcosystems() {
		if e.name == "go" {
			continue
		}
		t.Run(e.name, func(t *testing.T) {
			fired := false
			for _, marker := range e.markers {
				name := strings.Replace(marker, "*", "Sample", 1)
				msgs := unresolvedEcosystemErrors(probeMount, []string{"/src/" + name}, nil)
				if len(msgs) == 1 && strings.Contains(msgs[0], e.name) {
					fired = true
				}
			}
			if !fired {
				t.Errorf("no marker of %q can report a non-run, so the entry gates nothing", e.name)
			}
			if strings.TrimSpace(e.remedy) == "" {
				t.Errorf("%q has no remedy; a message a consumer cannot act on gets suppressed, "+
					"not fixed", e.name)
			}
		})
	}
}

// TestPythonRequirementsIsBothMarkerAndInput records that requirements.txt is
// deliberately in both sets: it declares Python dependencies and Trivy reads it,
// so its presence must never be reported as a gap.
func TestPythonRequirementsIsBothMarkerAndInput(t *testing.T) {
	if msgs := unresolvedEcosystemErrors(probeMount, []string{"/src/requirements.txt"}, nil); len(msgs) > 0 {
		t.Fatalf("requirements.txt is a resolvable input: %v", msgs)
	}
	// pyproject.toml alone is not: poetry/uv/pdm all declare there and lock
	// elsewhere, and Trivy cannot resolve a dependency graph from the declaration.
	msgs := unresolvedEcosystemErrors(probeMount, []string{"/src/pyproject.toml"}, nil)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "python") {
		t.Fatalf("pyproject.toml with no lockfile must be reported, got %v", msgs)
	}
}

// TestDotnetMarkersCoverFSharpAndVisualBasic pins the deliberate divergence from
// src/internal/detect, which looks only for .csproj and .sln. A pure-F# repository
// is exactly as unscanned as a C# one; the question this file asks is whether
// NuGet was resolved, not which linter to run. A solution file alone declares no
// package and is TestSolutionsWithoutProjects' case.
func TestDotnetMarkersCoverFSharpAndVisualBasic(t *testing.T) {
	for _, file := range []string{
		"/src/Api/Api.csproj",
		"/src/Api/Api.fsproj",
		"/src/Api/Api.vbproj",
	} {
		msgs := unresolvedEcosystemErrors(probeMount, []string{file}, nil)
		if len(msgs) != 1 || !strings.Contains(msgs[0], "dotnet") {
			t.Errorf("%s did not report an unresolved dotnet ecosystem: %v", file, msgs)
		}
	}
}

func TestMatchesAnyBase(t *testing.T) {
	cases := []struct {
		base     string
		patterns []string
		want     bool
	}{
		{"go.mod", []string{"go.mod"}, true},
		{"go.mod.bak", []string{"go.mod"}, false},
		{"Api.csproj", []string{"*.csproj"}, true},
		// A wildcard pattern describes "<something>.csproj". A file literally
		// named ".csproj" is not a project, and matching it would let an editor
		// or tooling artefact stand in for a real marker.
		{".csproj", []string{"*.csproj"}, false},
		{"Api.deps.json", []string{"*.deps.json"}, true},
		{".deps.json", []string{"*.deps.json"}, false},
		{"deps.json", []string{"*.deps.json"}, false},
		{"package.json", []string{"*.csproj", "package.json"}, true},
		{"anything", nil, false},
	}
	for _, tc := range cases {
		if got := matchesAnyBase(tc.base, tc.patterns); got != tc.want {
			t.Errorf("matchesAnyBase(%q, %v) = %v, want %v", tc.base, tc.patterns, got, tc.want)
		}
	}
}

func TestMatchDependencyFilesTrimsMountAndBlanks(t *testing.T) {
	// find's output ends in a trailing newline, so the split always yields a
	// final empty element. It must not become a match or a bare "" path.
	lines := []string{"/src/a/Api.csproj", "", "  ", "/src/b/Web.csproj", ""}
	got := matchDependencyFiles("/src", lines, []string{"*.csproj"})
	if len(got) != 2 || got[0] != "a/Api.csproj" || got[1] != "b/Web.csproj" {
		t.Fatalf("unexpected matches: %#v", got)
	}
}

// TestDependencyProbeRunError is the doctrine test for the probe itself. A probe
// that could not walk the tree must not be read as a tree with nothing in it.
func TestDependencyProbeRunError(t *testing.T) {
	if msg := dependencyProbeRunError("0\n", ""); msg != "" {
		t.Errorf("a successful find must not be an error: %s", msg)
	}
	if msg := dependencyProbeRunError("0\n", "find: /src/x: Permission denied\n"); msg != "" {
		t.Errorf("find exits 0 on a complete walk; stderr alone is not a failure: %s", msg)
	}

	msg := dependencyProbeRunError("1\n", "find: /src/proc: Permission denied\nfind: more\n")
	if msg == "" {
		t.Fatal("a non-zero find must fail the gate: an unknown tree is not an empty one")
	}
	if !strings.Contains(msg, "exited 1") || !strings.Contains(msg, "Permission denied") {
		t.Errorf("message must carry the status and the reason: %s", msg)
	}
	// Only the first stderr line: find can emit thousands, and an errors[] entry
	// that long is unreadable in a PR comment.
	if strings.Contains(msg, "find: more") {
		t.Errorf("message should carry only the first stderr line: %s", msg)
	}

	// The exit file itself missing or empty is the same class of unknown. A
	// missing WithExec output would otherwise parse as "not 0-or-error".
	if msg := dependencyProbeRunError("", ""); msg == "" {
		t.Error("a probe with no recorded exit status must fail the gate")
	}
}

// TestDependencyProbeScriptDoctrine guards the shell body against the three
// habits this repository has already been burned by, and against splicing.
func TestDependencyProbeScriptDoctrine(t *testing.T) {
	script := dependencyProbeScript("/src")

	for _, forbidden := range []string{"|| true", "2>/dev/null", "|| echo", "-maxdepth"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("probe script contains %q, which turns an unreadable tree into an empty "+
				"one:\n%s", forbidden, script)
		}
	}
	for _, required := range []string{
		"find /src -type f",
		"2>" + depProbeErrPath,
		"echo $? > " + depProbeExitPath,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("probe script is missing %q:\n%s", required, script)
		}
	}
	// Every pattern the table declares must actually be searched for, or the
	// verdict reasons about files the probe never looked for.
	for _, pattern := range depProbePatterns() {
		if !strings.Contains(script, "-name '"+pattern+"'") {
			t.Errorf("probe does not search for %q:\n%s", pattern, script)
		}
	}
}

// TestDepProbePatternsAreShellSafe is what makes single-quoting the patterns
// sound. They are all cicd constants today; this refuses a future entry that
// contains a quote, a space or a shell metacharacter, which would break the
// command line rather than merely look untidy.
func TestDepProbePatternsAreShellSafe(t *testing.T) {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.*_-"
	for _, pattern := range depProbePatterns() {
		if pattern == "" {
			t.Error("empty pattern would make find match nothing and say nothing")
			continue
		}
		for _, r := range pattern {
			if !strings.ContainsRune(allowed, r) {
				t.Errorf("pattern %q contains %q, which is not safe to single-quote into the "+
					"probe's shell body", pattern, r)
			}
		}
	}
}

func TestDepProbePatternsAreDeduplicated(t *testing.T) {
	seen := map[string]bool{}
	for _, pattern := range depProbePatterns() {
		if seen[pattern] {
			t.Errorf("pattern %q is repeated; find would report each match twice", pattern)
		}
		seen[pattern] = true
	}
	// requirements.txt is in both the python markers and the python inputs, so
	// the deduplication above is load-bearing, not defensive.
	if !seen["requirements.txt"] || !seen["go.mod"] {
		t.Error("the probe must search for files that are both marker and input")
	}
}

func TestJoinEcosystemErrors(t *testing.T) {
	if got := joinEcosystemErrors(nil); got != "" {
		t.Errorf("no messages must join to the empty string, got %q", got)
	}
	got := joinEcosystemErrors([]string{"first.", "second."})
	if got != "first. second." {
		t.Errorf("unexpected join: %q", got)
	}
	// notify renders each errors[] entry as one markdown list item; a newline
	// splits the item in the PR comment.
	if strings.Contains(got, "\n") {
		t.Errorf("joined message must stay single-line: %q", got)
	}
}

func TestFirstNTruncatesWithAMarker(t *testing.T) {
	got := firstN([]string{"a", "b", "c", "d"}, 3)
	if len(got) != 4 || got[3] != "…" {
		t.Fatalf("truncation must be visible, got %#v", got)
	}
	if in := []string{"a", "b"}; len(firstN(in, 3)) != 2 {
		t.Error("a short list must not be marked truncated")
	}
}

// TestSolutionsWithoutProjects is the tree a solution fixture or a build entry
// point leaves: solution files and no project anywhere. Both dependency rows
// reported it as an ERROR the consumer could not clear — a restore with nothing
// to restore, and an ecosystem "present" with no graph — when there is no graph
// to miss. The controls hold the other side: a project anywhere, even one under
// bin/, keeps the restore and every error it can raise.
func TestSolutionsWithoutProjects(t *testing.T) {
	cases := []struct {
		name       string
		files      []string
		solutions  int
		restore    bool
		unresolved []string
		notApp     bool
		declared   []string
	}{
		{
			name:      "one slnx",
			files:     []string{"/src/detect/testdata/slnx-solution-only/App.slnx"},
			solutions: 1,
			notApp:    true,
		},
		{
			name:      "sln and slnx",
			files:     []string{"/src/App.sln", "/src/App.slnx"},
			solutions: 2,
			notApp:    true,
		},
		{
			name:       "a project beside the solution",
			files:      []string{"/src/App.slnx", "/src/Api/Api.csproj"},
			restore:    true,
			unresolved: []string{"dotnet"},
			declared:   []string{"App.slnx", "Api/Api.csproj"},
		},
		{
			// The probe walks bin/ and obj/; the restore does not. This tree
			// must reach the restore, whose no-project error names the gap.
			name:       "a project only under bin",
			files:      []string{"/src/App.sln", "/src/Api/bin/Debug/Api.csproj"},
			restore:    true,
			unresolved: []string{"dotnet"},
			declared:   []string{"App.sln", "Api/bin/Debug/Api.csproj"},
		},
		{
			name:       "a solution beside an unlocked node project",
			files:      []string{"/src/App.slnx", "/src/web/package.json"},
			solutions:  1,
			unresolved: []string{"node"},
			declared:   []string{"web/package.json"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dotnetSolutionsWithoutProjects(probeMount, tc.files); len(got) != tc.solutions {
				t.Errorf("solutions without projects: got %v, want %d", got, tc.solutions)
			}
			if got := len(dotnetRestoreNeeded(probeMount, tc.files)) > 0; got != tc.restore {
				t.Errorf("dependency restore: got %v, want %v", got, tc.restore)
			}
			if got := len(dotnetLicenceRestoreNeeded(probeMount, tc.files)) > 0; got != tc.restore {
				t.Errorf("licence restore: got %v, want %v", got, tc.restore)
			}
			var names []string
			for _, v := range unresolvedEcosystems(probeMount, tc.files, nil) {
				names = append(names, v.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.unresolved, ",") {
				t.Errorf("unresolved: got %v, want %v", names, tc.unresolved)
			}
			if got := resultlessDependencyScanIsNotApplicable(tc.files, errTrivyNoTargets); got != tc.notApp {
				t.Errorf("not applicable: got %v, want %v", got, tc.notApp)
			}
			if got := dependencyDeclarations(probeMount, tc.files); strings.Join(got, ",") != strings.Join(tc.declared, ",") {
				t.Errorf("declarations: got %v, want %v", got, tc.declared)
			}
		})
	}
}

// TestSolutionsWithoutProjectsWarning names the files, the row and the one
// thing the stand-down cannot see: a project type cicd does not restore.
func TestSolutionsWithoutProjectsWarning(t *testing.T) {
	sln := []string{"a.sln", "b.sln", "c.slnx", "d.slnx"}
	got := dotnetSolutionsWithoutProjectsWarning("Dependency licences", sln)
	for _, want := range []string{
		"Dependency licences: SOLUTION WITHOUT PROJECTS",
		"4 solution file(s) (a.sln, b.sln, c.slnx, …)",
		"*.csproj, *.fsproj, *.vbproj",
		".sqlproj",
		"packages.lock.json",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "vulnerabilit") {
		t.Errorf("the licence row's warning speaks about vulnerabilities:\n%s", got)
	}
	if got := dotnetSolutionsWithoutProjectsWarning("Dependency licences", sln[:1]); strings.Contains(got, "…") {
		t.Errorf("a complete list must not read as a sample:\n%s", got)
	}
}
