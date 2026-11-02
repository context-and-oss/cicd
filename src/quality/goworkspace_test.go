package main

import (
	"reflect"
	"testing"
)

// Regression for the dogfood failure where `go test ./...` from the cicd
// repo root errored with "directory prefix . does not contain modules
// listed in go.work" — the workspace declares ./internal but `./...` from
// the workspace root does not expand to it. Each `use` member must be
// named explicitly.
func TestGoTestArgs_workspaceExpandsEachUseMember(t *testing.T) {
	work := `go 1.26.2

use ./internal
`
	if got, want := goTestArgs(work), "'./internal/...'"; got != want {
		t.Fatalf("goTestArgs single-use mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGoTestArgs_blockFormMultipleMembers(t *testing.T) {
	work := `go 1.26.2

use (
    ./internal
    ./pkg/a
    "./pkg/b"
)
`
	got := goTestArgs(work)
	want := "'./internal/...' './pkg/a/...' './pkg/b/...'"
	if got != want {
		t.Fatalf("goTestArgs block-form mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGoTestArgs_noWorkfileReturnsDefault(t *testing.T) {
	if got, want := goTestArgs(""), "./..."; got != want {
		t.Fatalf("goTestArgs empty mismatch:\n got: %q\nwant: %q", got, want)
	}
	if got, want := goTestArgs("   \n  \n"), "./..."; got != want {
		t.Fatalf("goTestArgs whitespace mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGoTestArgs_workfileWithoutUseFallsBack(t *testing.T) {
	work := `go 1.26.2
// no use directives — degenerate but valid input
`
	if got, want := goTestArgs(work), "./..."; got != want {
		t.Fatalf("goTestArgs no-use mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGoTestArgs_dotMemberNormalisesToTripleDot(t *testing.T) {
	work := `go 1.26.2

use .
`
	if got, want := goTestArgs(work), "'./...'"; got != want {
		t.Fatalf("goTestArgs dot-member mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// The selector is spliced into `sh -c` in test.go, and a `use` member is
// consumer-authored text. Each case is a member that the shell would have
// interpreted, asserted in the literal quoted form the shell receives.
func TestGoTestArgs_quotesEveryMemberForTheShell(t *testing.T) {
	cases := []struct {
		member string
		want   string
	}{
		{"./a b", "'./a b/...'"},
		{"./x;rm -rf /", "'./x;rm -rf /...'"}, // one trailing slash is trimmed before /... is appended
		{"./$(id)", "'./$(id)/...'"},
		{"./`id`", "'./`id`/...'"},
		{"./it's", `'./it'\''s/...'`},
		{"./plain", "'./plain/...'"},
	}
	for _, c := range cases {
		work := "go 1.26.2\n\nuse \"" + c.member + "\"\n"
		if got := goTestArgs(work); got != c.want {
			t.Errorf("goTestArgs(use %q):\n got: %s\nwant: %s", c.member, got, c.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":  "'plain'",
		"a b":    "'a b'",
		"it's":   `'it'\''s'`,
		"$(id)":  "'$(id)'",
		"":       "''",
		"two''s": `'two'\'''\''s'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseGoWorkUse_stripsCommentsAndQuotes(t *testing.T) {
	work := `go 1.26.2

// header comment
use (
    ./alpha    // inline comment
    "./beta"
    // standalone comment
    ./gamma
)
`
	got := parseGoWorkUse(work)
	want := []string{"./alpha", "./beta", "./gamma"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGoWorkUse mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}
