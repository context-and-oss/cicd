// Go module and workspace resolution.
//
// Deliberately untagged (no //go:build !unit_test): deciding which directories
// golangci-lint runs in is pure path arithmetic over the marker-file search
// output plus a go.work parse, so goproject_test.go can drive it with
// `go test -tags unit_test ./...`.
package main

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// goModuleLimit bounds how many Go modules one Check lints when the tree
// declares no workspace.
//
// Each module costs its own dependency download and full type-check, so this is
// a real cost ceiling. Eight covers the layouts that legitimately have several
// modules and no go.work — api/ + worker/ + shared/, a tools/ module beside the
// main one. Beyond that the repository is a monorepo, and Go's own answer to
// "which modules are in scope" is a go.work; the error below says so. Exceeding
// the limit is an error rather than a truncated lint: linting 8 of 40 modules
// and reporting "no findings" is the false pass this module exists to prevent.
const goModuleLimit = 8

// goSkipDirs are path segments the Go toolchain itself refuses to walk, so a
// go.mod inside one is never part of `./...` for the surrounding module.
// Mirroring the toolchain is deliberate: if `go build ./...` ignores it, a
// linter that reports on it is describing code the build never sees.
//
//   - vendor/ holds a flattened copy of dependencies.
//   - testdata/ is ignored by every go command by convention, which is exactly
//     why this repository keeps its fixture apps there.
//   - Segments beginning with "." or "_" are skipped by the go tool as well;
//     they are handled by hasGoSkipSegment rather than listed here.
var goSkipDirs = map[string]bool{
	"vendor":   true,
	"testdata": true,
}

// goModuleDirs resolves which directories golangci-lint should run in from the
// output of the marker-file search, as paths relative to root ("." for root
// itself), sorted and deduplicated.
//
// Every go.mod is its own project — unlike nodeProjectDirs, which suppresses a
// package directory when another discovered package directory is its ancestor.
// The difference is not a style choice. A go.mod is a module boundary and `./...`
// stops dead at one: from a parent module, `go list ./...` does not descend into
// a nested module at all. So where a root package.json legitimately governs every
// package beneath it, a root go.mod governs nothing beneath a nested go.mod.
// Keeping only top-level modules would leave every nested module unlinted while
// reporting success — the same false pass in a new costume.
//
// Workspaces are handled separately by goWorkspaceDirs, because go.work is the
// consumer's own declaration of scope and outranks discovery.
func goModuleDirs(root string, lines []string) []string {
	found := map[string]bool{}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || path.Base(line) != "go.mod" {
			continue
		}
		rel, ok := relativeToRoot(root, path.Dir(line))
		if !ok || hasGoSkipSegment(rel) {
			continue
		}
		found[rel] = true
	}

	dirs := make([]string, 0, len(found))
	for d := range found {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// hasGoSkipSegment reports whether any segment of rel is one the go tool
// refuses to walk: an explicit skip directory, or a name starting with "." or
// "_".
func hasGoSkipSegment(rel string) bool {
	if rel == "." {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if goSkipDirs[seg] || strings.HasPrefix(seg, ".") || strings.HasPrefix(seg, "_") {
			return true
		}
	}
	return false
}

// goWorkspaceDirs parses the `use` directives of a root go.work into directories
// relative to the mount root, sorted and deduplicated. It returns nil when the
// content declares no usable directory, which the caller must treat as "no
// workspace" rather than "a workspace with nothing in it".
//
// Why go.work outranks discovery: it is Go's native statement of which modules
// belong to this tree, written by the consumer. Honouring it is the same
// principle the Node leg applies when a root package.json wins — the repository
// gets to say what its project is, and cicd does not second-guess it. It is also
// what makes this repository's own tree linted correctly rather than
// catastrophically: the root go.work lists only src/internal because the Dagger
// modules cannot type-check until `dagger develop` has generated their SDK, so
// discovery would produce fifteen modules' worth of typecheck failures that say
// nothing about the code.
//
// The trade-off is real and belongs in the record: a go.work that omits a module
// leaves that module unlinted. That is the consumer's declaration to make, and
// the envelope names every directory that was linted so the scope is auditable
// rather than implied.
// The `use` directives are read by parseGoWorkUse (goworkspace.go), which the
// Go *test* leg already relies on. Sharing it is deliberate: two parsers would
// eventually disagree about which modules are in scope, and then the lint leg
// and the test leg would describe different repositories from the same tree.
// That the test leg already had to solve this — its doc comment records the very
// "directory prefix . does not contain modules listed in go.work" error the lint
// leg was measured hitting — is why the parser was there to reuse.
func goWorkspaceDirs(root, content string) []string {
	found := map[string]bool{}
	for _, operand := range parseGoWorkUse(content) {
		addGoWorkUse(found, root, operand)
	}

	if len(found) == 0 {
		return nil
	}
	dirs := make([]string, 0, len(found))
	for d := range found {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// addGoWorkUse records one `use` operand. Operands are relative to the go.work
// file, which lives at the mount root, so "./src/internal" becomes
// "src/internal". An operand escaping the root is dropped: it names a module
// outside the tree cicd was handed, and linting it is impossible rather than
// merely awkward.
func addGoWorkUse(found map[string]bool, root, operand string) {
	operand = strings.TrimSpace(operand)
	if operand == "" {
		return
	}
	rel, ok := relativeToRoot(root, path.Join(root, operand))
	if !ok {
		return
	}
	found[rel] = true
}

// goModuleLimitError reports the modules that would have gone unlinted, or ""
// when the set is within the limit. The remedy names go.work first because it is
// both the Go-native fix and the one that makes the scope explicit forever,
// rather than a flag the next caller forgets.
func goModuleLimitError(dirs []string) string {
	if len(dirs) <= goModuleLimit {
		return ""
	}
	return "golangci-lint: " + strconv.Itoa(len(dirs)) + " Go modules found (" +
		strings.Join(dirs, ", ") + ") — more than cicd will type-check in one run (" +
		strconv.Itoa(goModuleLimit) + "). Add a go.work declaring the modules in scope," +
		" point --src at one module, or drop \"go\" from --include so cicd does not" +
		" claim to lint this repo"
}

// goModuleLabel prefixes a diagnostic with the module it came from. Root stays
// unprefixed so the single-module case reads exactly as before.
func goModuleLabel(dir, msg string) string {
	if dir == "." {
		return msg
	}
	return dir + ": " + msg
}

// mergeGolangciVersions summarises the golangci-lint versions that actually ran.
// cicd pins one image so every module reports the same version, but the envelope
// must describe what ran rather than what was configured, and reporting the set
// keeps that true if the leg ever runs more than one binary.
func mergeGolangciVersions(raw []string) string {
	seen := map[string]bool{}
	var versions []string
	for _, r := range raw {
		v := golangciVersionLabel(r)
		if v == "unknown" || seen[v] {
			continue
		}
		seen[v] = true
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return "unknown"
	}
	sort.Strings(versions)
	return strings.Join(versions, ",")
}
