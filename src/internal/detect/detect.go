package detect

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

type Language string

const (
	Go     Language = "go"
	Node   Language = "node"
	Python Language = "python"
	Dotnet Language = "dotnet"
)

// All returns every supported language in canonical order.
func All() []Language {
	return []Language{Go, Node, Python, Dotnet}
}

// Parse converts a string slice from --include params into Language values.
// Returns an error string for any unrecognised value.
func Parse(names []string) ([]Language, []string) {
	var langs []Language
	var unknown []string
	for _, n := range names {
		switch strings.ToLower(n) {
		case "go":
			langs = append(langs, Go)
		case "node", "nodejs", "typescript", "ts":
			langs = append(langs, Node)
		case "python", "py":
			langs = append(langs, Python)
		case "dotnet", "csharp", "c#", "cs":
			langs = append(langs, Dotnet)
		default:
			unknown = append(unknown, n)
		}
	}
	return langs, unknown
}

// Detect returns the languages present in the given filesystem root.
// It walks the tree looking for canonical indicator files.
//
// A directory the walk could not read is an error, not a directory holding no
// marker: the two produce the same empty answer, and only one of them means
// the tree has no Go, Node, Python or .NET in it.
func Detect(root fs.FS) ([]Language, error) {
	seen := map[Language]bool{}

	walkErr := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		switch {
		case name == "go.mod":
			seen[Go] = true
		case name == "package.json":
			seen[Node] = true
		case name == "pyproject.toml" || name == "setup.py" || name == "requirements.txt":
			seen[Python] = true
		// Both solution extensions are matched explicitly. HasSuffix(name,
		// ".sln") is false for "App.slnx" — the XML solution format of SDK
		// 9.0.200 and later — so a repo whose only .NET marker is a .slnx was
		// not detected as .NET at all, while the quality module's
		// discoverDotnetTargets globbed it happily. A substring test would fix
		// that case and invent another: "Foo.slnnope" contains ".sln".
		case strings.HasSuffix(name, ".csproj") ||
			strings.HasSuffix(name, ".sln") ||
			strings.HasSuffix(name, ".slnx"):
			seen[Dotnet] = true
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	var langs []Language
	// Return in stable canonical order.
	for _, l := range All() {
		if seen[l] {
			langs = append(langs, l)
		}
	}
	return langs, nil
}
