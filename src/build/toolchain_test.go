package main

// Mirrors src/internal/detect/toolchain_test.go — the canonical precedence
// tests for the local ResolveToolchain copy (ADR-004). Run with:
//
//	go test -tags unit_test -run TestToolchain ./...
//
// The unit_test tag excludes the Dagger-importing files (main.go, archive.go)
// so the plain-Go helpers compile without a Dagger session.

import (
	"testing"
	"testing/fstest"
)

func TestToolchain_Precedence(t *testing.T) {
	cases := []struct {
		name     string
		lang     string
		explicit string
		files    fstest.MapFS
		want     string
	}{
		{
			name:     "explicit param wins over present .nvmrc",
			lang:     "node",
			explicit: "registry.invalid/node:22@sha256:abc",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("18")}},
			want:     "registry.invalid/node:22@sha256:abc",
		},
		{
			name:     "explicit param wins over present global.json",
			lang:     "dotnet",
			explicit: "mcr.microsoft.com/dotnet/sdk:9.0",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"8.0.100"}}`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:9.0",
		},
		{
			name:  "detected version beats pinned default",
			lang:  "node",
			files: fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("22")}},
			want:  "node:22-alpine",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveToolchain(tc.lang, tc.explicit, tc.files)
			if got != tc.want {
				t.Errorf("ResolveToolchain(%q, %q) = %q, want %q", tc.lang, tc.explicit, got, tc.want)
			}
		})
	}
}

func TestToolchain_Nvmrc(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"partial major version", "22", "node:22-alpine"},
		{"full version with leading v", "v22.4.1", "node:22-alpine"},
		{"surrounding whitespace", "  20.11.0\n", "node:20-alpine"},
		{"lts alias falls through", "lts/iron", "node:22-alpine"},
		{"junk falls through", "not a version", "node:22-alpine"},
		{"empty file falls through", "", "node:22-alpine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte(tc.content)}}
			got := ResolveToolchain("node", "", fsys)
			if got != tc.want {
				t.Errorf(".nvmrc %q resolved to %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

func TestToolchain_GlobalJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"sdk version maps to major.minor", `{"sdk":{"version":"8.0.100"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"newer sdk version", `{"sdk":{"version":"9.0.203"}}`, "mcr.microsoft.com/dotnet/sdk:9.0"},
		{"malformed JSON falls through", `{"sdk":`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"missing sdk key falls through", `{"tools":{"dotnet":"8.0.100"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"non-numeric version falls through", `{"sdk":{"version":"latest"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"major-only version falls through", `{"sdk":{"version":"8"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(tc.content)}}
			got := ResolveToolchain("dotnet", "", fsys)
			if got != tc.want {
				t.Errorf("global.json %q resolved to %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

func TestToolchain_Defaults(t *testing.T) {
	cases := []struct {
		lang string
		want string
	}{
		{"go", "golang:1.26-alpine"},
		{"node", "node:22-alpine"},
		{"python", "python:3.12-slim"},
		{"dotnet", "mcr.microsoft.com/dotnet/sdk:8.0"},
	}
	empty := fstest.MapFS{"README.md": &fstest.MapFile{}}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			got := ResolveToolchain(tc.lang, "", empty)
			if got != tc.want {
				t.Errorf("default for %s = %q, want %q", tc.lang, got, tc.want)
			}
		})
	}
}

func TestToolchain_NoVersionFileConventionForGoPython(t *testing.T) {
	// go and python have no version-file convention wired — a stray .nvmrc or
	// global.json must not leak into their resolution.
	fsys := fstest.MapFS{
		".nvmrc":      &fstest.MapFile{Data: []byte("22")},
		"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"9.0.100"}}`)},
	}
	if got := ResolveToolchain("go", "", fsys); got != "golang:1.26-alpine" {
		t.Errorf("go resolved to %q, want pinned default", got)
	}
	if got := ResolveToolchain("python", "", fsys); got != "python:3.12-slim" {
		t.Errorf("python resolved to %q, want pinned default", got)
	}
}
