// Language marker files: the one list of what cicd looks for, and the one
// classification of what it finds.
//
// Deliberately untagged (no //go:build !unit_test): naming marker files and
// classifying a path by suffix needs no Dagger, so markers_test.go can drive it
// with `go test -tags unit_test ./...` (the nodeproject.go / dotnetreport.go
// precedent in quality).
//
// This file exists because the search and the classification used to be two
// independent literals, and a marker could be added to one without the other:
// `.slnx`, the XML solution format of .NET SDK 9.0.200 and later, was globbed
// by quality's discoverDotnetTargets, absent from the find below, and absent
// from the suffix switch — so a solution-only .NET repo was silently not a
// .NET repo to quality, and build resolved it no toolchain while telling it,
// by name, about markers it did not have. The find expression is now generated
// from markerFileNames, and markers_test.go asserts every name in that list
// classifies to a language, so the two halves cannot drift apart without a
// test failing.
//
// The same logic is carried in three places, because Dagger modules are
// isolated and there is no shared Go module (schema.go / toolchain.go
// precedent):
//
//   - src/quality/markers.go and src/build/markers.go — byte-identical copies,
//     held equal by a synced_files group in scripts/repo-inventory.json
//     (`make check-surface` fails the moment they diverge)
//   - src/internal/detect/detect.go — the canonical fs.FS walker (same suffixes,
//     exact-name matching instead of find patterns), kept in step by hand
//
// Change the marker set in all three.
package main

import (
	"strconv"
	"strings"
)

// markerFileNames are the find(1) -name patterns for every language marker file
// detection recognises, in the order the search names them.
var markerFileNames = []string{
	"go.mod",
	"package.json",
	"pyproject.toml",
	"requirements.txt",
	"*.csproj",
	"*.sln",
	"*.slnx",
}

// markerFindExpr renders markerFileNames as a find(1) name predicate, so the
// search and markerLanguage are fed from the same list.
func markerFindExpr() string {
	preds := make([]string, 0, len(markerFileNames))
	for _, n := range markerFileNames {
		preds = append(preds, `-name '`+n+`'`)
	}
	return `\( ` + strings.Join(preds, " -o ") + ` \)`
}

// markerSearchDepth is how many directory levels the marker search descends.
// A repository whose marker file sits deeper is not detected, so anything that
// reports "no language found" has to be able to state the limit it searched
// under — quoting a second literal 4 in a message is the drift this file exists
// to prevent, one field over.
const markerSearchDepth = 4

// markerFindArgs renders the depth limit and the name predicate as one find(1)
// argument list, so a message quoting the depth cannot disagree with the search
// that produced the result being described.
func markerFindArgs() string {
	return "-maxdepth " + strconv.Itoa(markerSearchDepth) + " " + markerFindExpr()
}

// markerLanguage classifies one marker path into a language name, or "" when
// the path is not a marker. It returns a plain string rather than a module
// language type: those are declared in Dagger-importing files that the
// unit_test tag excludes, and a plain string keeps this file copyable verbatim
// between modules.
//
// Both .NET solution extensions are listed explicitly. HasSuffix(path, ".sln")
// is false for "App.slnx", and a substring test would fix that case while
// inventing another — "Foo.slnnope" contains ".sln".
func markerLanguage(path string) string {
	switch {
	case strings.HasSuffix(path, "go.mod"):
		return "go"
	case strings.HasSuffix(path, "package.json"):
		return "node"
	case strings.HasSuffix(path, "pyproject.toml") || strings.HasSuffix(path, "requirements.txt"):
		return "python"
	case strings.HasSuffix(path, ".csproj") ||
		strings.HasSuffix(path, ".sln") ||
		strings.HasSuffix(path, ".slnx"):
		return "dotnet"
	default:
		return ""
	}
}
