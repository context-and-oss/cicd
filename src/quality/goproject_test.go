//go:build unit_test

package main

import (
	"strings"
	"testing"
)

func TestGoModuleDirs(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name:  "single module at root",
			lines: []string{"/src/go.mod"},
			want:  []string{"."},
		},
		{
			// The property that separates this from nodeProjectDirs. A root go.mod
			// does not govern a nested module: `go list ./...` stops at the
			// boundary, so keeping only the shallowest would leave tools/ unlinted
			// while reporting success.
			name:  "nested module is kept alongside the root",
			lines: []string{"/src/go.mod", "/src/tools/go.mod"},
			want:  []string{".", "tools"},
		},
		{
			name:  "siblings with no root module",
			lines: []string{"/src/api/go.mod", "/src/worker/go.mod"},
			want:  []string{"api", "worker"},
		},
		{
			name:  "vendored modules are skipped",
			lines: []string{"/src/go.mod", "/src/vendor/example.com/dep/go.mod"},
			want:  []string{"."},
		},
		{
			// testdata is ignored by every go command, which is why this
			// repository keeps its fixture apps there. A linter reporting on code
			// the build never sees is describing nothing.
			name:  "testdata is skipped",
			lines: []string{"/src/go.mod", "/src/testdata/go-app/go.mod"},
			want:  []string{"."},
		},
		{
			name:  "dot and underscore directories are skipped",
			lines: []string{"/src/.cache/go.mod", "/src/_scratch/go.mod", "/src/keep/go.mod"},
			want:  []string{"keep"},
		},
		{
			name:  "non-go markers and blanks are ignored",
			lines: []string{"", "/src/package.json", "/src/go.mod", "  ", "/src/app.csproj"},
			want:  []string{"."},
		},
		{
			name:  "paths outside the mount are dropped",
			lines: []string{"/elsewhere/go.mod", "/src/go.mod"},
			want:  []string{"."},
		},
		{
			name:  "duplicates collapse",
			lines: []string{"/src/api/go.mod", "/src/api/go.mod"},
			want:  []string{"api"},
		},
		{
			name:  "no modules at all",
			lines: []string{"/src/package.json"},
			want:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := goModuleDirs("/src", tc.lines)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("goModuleDirs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGoWorkspaceDirs(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			// The exact shape of this repository's root go.work, comment and all.
			name: "single use with a comment",
			content: `go 1.26.2

// Only internal/ shared packages are in this workspace.
use ./src/internal
`,
			want: []string{"src/internal"},
		},
		{
			name: "block form",
			content: `go 1.24.0

use (
	./api
	./worker
)
`,
			want: []string{"api", "worker"},
		},
		{
			name:    "use . is the root",
			content: "go 1.24.0\n\nuse .\n",
			want:    []string{"."},
		},
		{
			name:    "replace directives are not use directives",
			content: "go 1.24.0\n\nuse ./a\n\nreplace example.com/x => example.com/x v1.0.0\n",
			want:    []string{"a"},
		},
		{
			// A go.work naming a module outside the tree cicd was handed cannot be
			// linted. Dropping it is honest; rewriting the path would not be.
			name:    "operand escaping the mount is dropped",
			content: "go 1.24.0\n\nuse (\n\t../outside\n\t./inside\n)\n",
			want:    []string{"inside"},
		},
		{
			name:    "commented-out use is not a use",
			content: "go 1.24.0\n\n// use ./ghost\nuse ./real\n",
			want:    []string{"real"},
		},
		{
			// nil, not an empty slice: the caller must treat this as "no usable
			// workspace" and fall back to discovery rather than lint nothing.
			name:    "no use directives",
			content: "go 1.24.0\n",
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := goWorkspaceDirs("/src", tc.content)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("goWorkspaceDirs = %v, want nil", got)
				}
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("goWorkspaceDirs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGoModuleLimitError(t *testing.T) {
	within := make([]string, goModuleLimit)
	for i := range within {
		within[i] = "m" + string(rune('a'+i))
	}
	if msg := goModuleLimitError(within); msg != "" {
		t.Fatalf("at the limit should be allowed, got %q", msg)
	}

	over := append(within, "one-too-many")
	msg := goModuleLimitError(over)
	if msg == "" {
		t.Fatal("over the limit must be an error, not a truncated lint")
	}
	// The remedy must name go.work: it is the Go-native way to declare scope, and
	// a message that only says "too many" leaves the reader with no move.
	if !strings.Contains(msg, "go.work") {
		t.Fatalf("limit error must offer go.work as the remedy, got %q", msg)
	}
	if !strings.Contains(msg, "one-too-many") {
		t.Fatalf("limit error must name the modules, got %q", msg)
	}
}

func TestGoModuleLabel(t *testing.T) {
	if got := goModuleLabel(".", "boom"); got != "boom" {
		t.Fatalf("root must stay unprefixed, got %q", got)
	}
	if got := goModuleLabel("api", "boom"); got != "api: boom" {
		t.Fatalf("goModuleLabel = %q", got)
	}
}

func TestMergeGolangciVersions(t *testing.T) {
	const real = "golangci-lint has version 2.12.2 built with go1.26.2 from c0d3ddc9 on 2026-05-06T11:07:58Z"

	if got := mergeGolangciVersions([]string{real, real}); got != "2.12.2" {
		t.Fatalf("identical versions must collapse, got %q", got)
	}
	if got := mergeGolangciVersions(nil); got != "unknown" {
		t.Fatalf("no readings must be unknown, never a pin, got %q", got)
	}
	if got := mergeGolangciVersions([]string{"garbage"}); got != "unknown" {
		t.Fatalf("unparseable must be unknown, got %q", got)
	}
}
