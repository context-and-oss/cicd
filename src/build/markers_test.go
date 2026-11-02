//go:build unit_test

// Verbatim copy of src/quality/markers_test.go, mirroring the verbatim copy of
// markers.go it covers. A copied implementation with no copied test is how the
// .slnx miss survived in the first place.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// markerSample turns a find(1) -name pattern into a path the search would have
// returned for it.
func markerSample(pattern string) string {
	return "/src/nested/" + strings.ReplaceAll(pattern, "*", "App")
}

// TestMarkerFindExprNamesEveryMarker is the drift guard. The find expression and
// the classifier used to be two independent literals, and `.slnx` was added to
// neither while discoverDotnetTargets globbed it — a solution-only .NET repo was
// silently not a .NET repo. Both halves now come from markerFileNames, and this
// asserts the search names every entry and the classifier understands every
// entry, so adding one and forgetting the other fails here.
func TestMarkerFindExprNamesEveryMarker(t *testing.T) {
	expr := markerFindExpr()

	if !strings.HasPrefix(expr, `\( `) || !strings.HasSuffix(expr, ` \)`) {
		t.Fatalf("find expression is not a single grouped predicate: %s", expr)
	}
	if got, want := strings.Count(expr, " -o "), len(markerFileNames)-1; got != want {
		t.Errorf("find expression has %d alternations, want %d: %s", got, want, expr)
	}

	for _, name := range markerFileNames {
		if !strings.Contains(expr, `-name '`+name+`'`) {
			t.Errorf("find expression does not search for %q (quoted): %s", name, expr)
		}
		if lang := markerLanguage(markerSample(name)); lang == "" {
			t.Errorf("marker %q is searched for but classified as no language", name)
		}
	}
}

// TestMarkerFileNamesCoverDotnetSolutionFormats states the regression in the
// terms the issue did: both solution extensions are searched for, not just the
// pre-SDK-9 one.
func TestMarkerFileNamesCoverDotnetSolutionFormats(t *testing.T) {
	for _, want := range []string{"*.csproj", "*.sln", "*.slnx"} {
		found := false
		for _, name := range markerFileNames {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("markerFileNames is missing %q: %v", want, markerFileNames)
		}
	}
}

// TestMarkerFindExprRunsAsShell puts the generated predicate through a real
// `sh -c` and a real find(1), because the module hands it to a shell and the
// consequence of malforming it is silent. The search ends in `2>/dev/null ||
// true`, so a broken predicate does not fail the step: find writes nothing,
// stderr is discarded, the exit status is forced to 0, and detection concludes
// the repository has no languages. That is the "a tool that could not run must
// never read as clean" failure, arrived at from the shell side, and no
// string-inspection test can see it.
//
// This proves POSIX shape, not busybox specifically: the module runs the
// expression under alpine's find, a third implementation. Grouping and -name
// are POSIX, and the escaping under `sh -c` is what this exercises.
func TestMarkerFindExprRunsAsShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("no sh on PATH, so the predicate cannot be proven runnable: %v", err)
	}
	if _, err := exec.LookPath("find"); err != nil {
		t.Fatalf("no find on PATH, so the predicate cannot be proven runnable: %v", err)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{}
	for _, name := range markerFileNames {
		rel := filepath.Join("nested", strings.ReplaceAll(name, "*", "App"))
		if err := os.WriteFile(filepath.Join(dir, rel), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		want[rel] = false
	}
	// Files the predicate must not return. Foo.slnnope is the substring trap.
	for _, rel := range []string{"README.md", "nested/Foo.slnnope", "nested/notes.slnx.txt"} {
		if err := os.WriteFile(filepath.Join(dir, rel), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(sh, "-c", `find . -maxdepth 4 `+markerFindExpr())
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("find rejected the generated predicate: %v\nexpr: %s\nstderr: %s",
			err, markerFindExpr(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("find wrote to stderr, which the module discards: %s", stderr.String())
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rel := strings.TrimPrefix(line, "./")
		if rel == "" {
			continue
		}
		if _, ok := want[rel]; !ok {
			t.Errorf("find returned %q, which is not a marker file", rel)
			continue
		}
		want[rel] = true
	}
	for rel, found := range want {
		if !found {
			t.Errorf("find did not return marker %q\nexpr: %s", rel, markerFindExpr())
		}
	}
}

func TestMarkerLanguage(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/src/go.mod", "go"},
		{"/src/backend/go.mod", "go"},
		{"/src/package.json", "node"},
		{"/src/pyproject.toml", "python"},
		{"/src/requirements.txt", "python"},
		{"/src/App/App.csproj", "dotnet"},
		{"/src/App.sln", "dotnet"},
		// .slnx is the XML solution format of .NET SDK 9.0.200 and later.
		// HasSuffix(path, ".sln") is false for it, which is the whole bug.
		{"/src/App.slnx", "dotnet"},
		{"/src/nested/App.slnx", "dotnet"},
		// A substring test for ".sln" would call these .NET. They are not.
		{"/src/Foo.slnnope", ""},
		{"/src/notes.slnx.txt", ""},
		{"/src/App.sln.bak", ""},
		{"/src/README.md", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := markerLanguage(c.path); got != c.want {
			t.Errorf("markerLanguage(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
