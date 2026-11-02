package source

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelect_excludesGeneratedAndTestFiles(t *testing.T) {
	entries := []string{
		"dagger.gen.go",
		"foo_test.go",
		"helper_test.go",
		"main.go",
		"extra.go",
		"README.md",
		"contract.json",
	}
	got := Select(entries)
	want := []string{"main.go", "extra.go"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Select(%v) = %v, want %v", entries, got, want)
	}
}

// Regression for the multi-file parsing contract: when the target function
// lives in a file that is not main.go, the verifier must still find it.
// The previous implementation only looked at main.go, which prevented
// modules like notify/ (entry funcs in teams.go, github.go, ado.go) from
// being verifiable at all.
func TestFuncParams_findsFunctionInNonMainFile(t *testing.T) {
	sources := map[string]string{
		"main.go":  "package main\n",
		"teams.go": "package main\n\nfunc (m *Notify) Teams(ctx Context, summary File, webhook Secret) (File, error) { return nil, nil }\n",
	}
	got, err := FuncParams("Teams", sources)
	if err != nil {
		t.Fatalf("FuncParams: %v", err)
	}
	want := map[string]string{
		"ctx":     "Context",
		"summary": "File",
		"webhook": "Secret",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// When the same function name appears in multiple files, alphabetical order
// wins. Documents the tie-breaker so a future refactor can't silently change it.
func TestFuncParams_alphabeticalFileWinsOnDuplicate(t *testing.T) {
	sources := map[string]string{
		"b_late.go":  "package main\n\nfunc Foo(b int) {}\n",
		"a_first.go": "package main\n\nfunc Foo(a string) {}\n",
	}
	got, err := FuncParams("Foo", sources)
	if err != nil {
		t.Fatalf("FuncParams: %v", err)
	}
	want := map[string]string{"a": "string"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFuncParams_returnsErrorWhenMissing(t *testing.T) {
	sources := map[string]string{
		"main.go": "package main\n\nfunc Bar() {}\n",
	}
	_, err := FuncParams("Foo", sources)
	if err == nil {
		t.Fatal("expected error for missing function, got nil")
	}
	if !strings.Contains(err.Error(), "Foo") {
		t.Errorf("error %q should mention the missing function name", err)
	}
}
