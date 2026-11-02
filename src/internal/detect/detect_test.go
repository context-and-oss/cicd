package detect_test

import (
	"errors"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/context-and-oss/cicd/internal/detect"
)

func TestDetect_Go(t *testing.T) {
	fsys := fstest.MapFS{
		"go.mod":  &fstest.MapFile{},
		"main.go": &fstest.MapFile{},
		"go.sum":  &fstest.MapFile{},
	}
	langs, err := detect.Detect(fsys)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 1 || langs[0] != detect.Go {
		t.Errorf("expected [go], got %v", langs)
	}
}

func TestDetect_MultiLanguage(t *testing.T) {
	fsys := fstest.MapFS{
		"backend/go.mod":           &fstest.MapFile{},
		"frontend/package.json":    &fstest.MapFile{},
		"scripts/requirements.txt": &fstest.MapFile{},
	}
	langs, err := detect.Detect(fsys)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 3 {
		t.Errorf("expected 3 languages, got %d: %v", len(langs), langs)
	}
}

func TestDetect_Dotnet(t *testing.T) {
	fsys := fstest.MapFS{
		"App/App.csproj": &fstest.MapFile{},
	}
	langs, err := detect.Detect(fsys)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 1 || langs[0] != detect.Dotnet {
		t.Errorf("expected [dotnet], got %v", langs)
	}
}

// TestDetect_DotnetMarkerSuffixes pins the exact set of .NET marker suffixes,
// including .slnx (the XML solution format of SDK 9.0.200 and later). This
// classification is duplicated in src/quality/markers.go and
// src/build/markers.go because Dagger modules are isolated; the copies drifted
// on .slnx precisely because no test in any of them named the extension.
//
// The negative cases matter as much as the positive ones: the naive fix for
// .slnx is a substring test, and "Foo.slnnope" contains ".sln".
func TestDetect_DotnetMarkerSuffixes(t *testing.T) {
	cases := []struct {
		path   string
		dotnet bool
	}{
		{"App/App.csproj", true},
		{"App.sln", true},
		{"App.slnx", true},
		{"nested/dir/App.slnx", true},
		{"Foo.slnnope", false},
		{"notes.slnx.txt", false},
		{"solution.sln.bak", false},
		{"README.md", false},
	}
	for _, c := range cases {
		fsys := fstest.MapFS{c.path: &fstest.MapFile{}}
		langs, err := detect.Detect(fsys)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		got := len(langs) == 1 && langs[0] == detect.Dotnet
		if got != c.dotnet {
			t.Errorf("Detect(%q) = %v, want dotnet=%v", c.path, langs, c.dotnet)
		}
	}
}

// TestDetect_SlnxSolutionOnlyFixture drives the same path over a real on-disk
// .slnx, so the fixture that a future Dagger-level case can point at is proven
// to be detected today. See the comment inside the file for why it lives six
// path segments from the repo root.
func TestDetect_SlnxSolutionOnlyFixture(t *testing.T) {
	langs, err := detect.Detect(os.DirFS("testdata/slnx-solution-only"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 1 || langs[0] != detect.Dotnet {
		t.Errorf("expected [dotnet] for a solution-only .slnx repo, got %v", langs)
	}
}

func TestDetect_Empty(t *testing.T) {
	fsys := fstest.MapFS{"README.md": &fstest.MapFile{}}
	langs, err := detect.Detect(fsys)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 0 {
		t.Errorf("expected no languages, got %v", langs)
	}
}

func TestParse(t *testing.T) {
	langs, unknown := detect.Parse([]string{"go", "node", "PYTHON", "dotnet"})
	if len(langs) != 4 {
		t.Errorf("expected 4 langs, got %d", len(langs))
	}
	if len(unknown) != 0 {
		t.Errorf("expected no unknowns, got %v", unknown)
	}

	_, unknown = detect.Parse([]string{"rust", "java"})
	if len(unknown) != 2 {
		t.Errorf("expected 2 unknowns, got %v", unknown)
	}
}

func TestDetect_StableOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"package.json": &fstest.MapFile{},
		"go.mod":       &fstest.MapFile{},
	}
	langs, err := detect.Detect(fsys)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// Should always return go before node regardless of walk order.
	if len(langs) != 2 || langs[0] != detect.Go || langs[1] != detect.Node {
		t.Errorf("expected [go node], got %v", langs)
	}
}

// brokenFS is a tree whose root lists fine but whose one subdirectory cannot
// be opened: the shape of a permission error or a dangling mount under a
// consumer's checkout. Before Detect returned the walk error, this tree
// reported no languages — the same answer as a tree with no markers.
type brokenFS struct{ fstest.MapFS }

// fs.WalkDir lists through ReadDirFS when the tree implements it, which
// MapFS does, so that is the method the fault has to sit on.
func (b brokenFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "broken" {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrPermission}
	}
	return b.MapFS.ReadDir(name)
}

func TestDetect_ReportsADirectoryItCouldNotWalk(t *testing.T) {
	fsys := brokenFS{fstest.MapFS{
		"broken/go.mod": &fstest.MapFile{},
		"README.md":     &fstest.MapFile{},
	}}
	langs, err := detect.Detect(fsys)
	if err == nil {
		t.Fatalf("expected an error for an unreadable directory, got languages %v", langs)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("error %v does not wrap the walk's cause", err)
	}
	if langs != nil {
		t.Errorf("a failed walk must return no languages, got %v", langs)
	}
}
