package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripMarkdownFences(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"no fences", `{"findings":[]}`, `{"findings":[]}`},
		{"json fences", "```json\n{\"findings\":[]}\n```", `{"findings":[]}`},
		{"plain fences", "```\n{\"findings\":[]}\n```", `{"findings":[]}`},
		{"leading whitespace", "  ```json\n{\"findings\":[]}\n```  ", `{"findings":[]}`},
		{"no closing fence", "```json\n{\"findings\":[]}", `{"findings":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripMarkdownFences(tc.input)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildPrompt_includesPriorityFiles(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "README.md"), []byte("# hello"))
	mustWriteFile(t, filepath.Join(dir, "go.mod"), []byte("module test"))
	files, err := collectWorkspaceFiles(dir, 80*1024)
	if err != nil {
		t.Fatalf("collectWorkspaceFiles: %v", err)
	}
	found := map[string]bool{}
	for _, f := range files {
		found[f.Path] = true
	}
	if !found["README.md"] {
		t.Error("expected README.md in results")
	}
	if !found["go.mod"] {
		t.Error("expected go.mod in results")
	}
}

func TestBuildPrompt_respectsBudget(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "big.txt"), make([]byte, 200*1024))
	files, err := collectWorkspaceFiles(dir, 80*1024)
	if err != nil {
		t.Fatalf("collectWorkspaceFiles: %v", err)
	}
	total := 0
	for _, f := range files {
		total += len(f.Content)
	}
	if total > 80*1024 {
		t.Fatalf("budget exceeded: %d bytes", total)
	}
}

func TestBuildPrompt_skipsBinary(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "README.md"), []byte("hello\x00world"))
	files, err := collectWorkspaceFiles(dir, 80*1024)
	if err != nil {
		t.Fatalf("collectWorkspaceFiles: %v", err)
	}
	for _, f := range files {
		if f.Path == "README.md" {
			t.Error("expected binary file to be skipped")
		}
	}
}

type fakeConversation struct {
	replies []string
	calls   []string
	idx     int
}

func (f *fakeConversation) send(_ context.Context, msg string) (string, error) {
	f.calls = append(f.calls, msg)
	if f.idx >= len(f.replies) {
		return "", fmt.Errorf("no more replies")
	}
	r := f.replies[f.idx]
	f.idx++
	return r, nil
}

func TestCallLLMWithRetry_validFirstTry(t *testing.T) {
	conv := &fakeConversation{replies: []string{`{"findings":[]}`}}
	got, err := callLLMWithRetry(context.Background(), conv, "prompt", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `{"findings":[]}` {
		t.Fatalf("got %q", got)
	}
	if len(conv.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(conv.calls))
	}
}

func TestCallLLMWithRetry_badThenGood(t *testing.T) {
	conv := &fakeConversation{replies: []string{"not json", `{"findings":[]}`}}
	got, err := callLLMWithRetry(context.Background(), conv, "prompt", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `{"findings":[]}` {
		t.Fatalf("got %q", got)
	}
	if len(conv.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(conv.calls))
	}
	if !strings.Contains(conv.calls[1], "not valid JSON") {
		t.Fatalf("correction message should mention invalid JSON, got: %q", conv.calls[1])
	}
}

func TestCallLLMWithRetry_alwaysBad(t *testing.T) {
	conv := &fakeConversation{replies: []string{"bad", "bad", "still bad"}}
	got, err := callLLMWithRetry(context.Background(), conv, "prompt", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "still bad" {
		t.Fatalf("expected last reply returned, got %q", got)
	}
}

func TestCallLLMWithRetry_errorOnFirstCall(t *testing.T) {
	conv := &fakeConversation{replies: nil}
	_, err := callLLMWithRetry(context.Background(), conv, "prompt", 2)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFilterFindings_dropsLowConfidence(t *testing.T) {
	raw := []rawFinding{
		{Category: "compliance", Severity: "high", Confidence: 0.9, Title: "keep",
			Evidence: Evidence{File: "a.go", StartLine: 1}},
		{Category: "compliance", Severity: "low", Confidence: 0.5, Title: "drop",
			Evidence: Evidence{File: "b.go", StartLine: 2}},
		{Category: "data_governance", Severity: "medium", Confidence: 0.6, Title: "boundary",
			Evidence: Evidence{File: "c.go", StartLine: 3}},
	}
	got := filterFindings(raw, 0.6)
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	if got[0].Title != "keep" {
		t.Errorf("first finding: want 'keep', got %q", got[0].Title)
	}
	if got[1].Title != "boundary" {
		t.Errorf("second finding: want 'boundary', got %q", got[1].Title)
	}
}

func TestFilterFindings_assignsIDs(t *testing.T) {
	raw := []rawFinding{
		{Category: "compliance", Severity: "high", Confidence: 0.8, Title: "t",
			Evidence: Evidence{File: "x.go", StartLine: 10}},
	}
	got := filterFindings(raw, 0.0)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].ID == "" {
		t.Error("expected non-empty ID")
	}
	want := hashFinding("compliance", "x.go", 10)
	if got[0].ID != want {
		t.Errorf("ID = %q, want %q", got[0].ID, want)
	}
}

func TestFilterFindings_emptyInput(t *testing.T) {
	got := filterFindings(nil, 0.6)
	if len(got) != 0 {
		t.Fatalf("want 0 findings, got %d", len(got))
	}
}

func TestCallLLMWithRetry_zeroRetries(t *testing.T) {
	conv := &fakeConversation{replies: []string{"not json"}}
	got, err := callLLMWithRetry(context.Background(), conv, "prompt", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "not json" {
		t.Fatalf("expected first reply returned unchanged, got %q", got)
	}
	if len(conv.calls) != 1 {
		t.Fatalf("expected exactly 1 call, got %d", len(conv.calls))
	}
}

// mustWriteFile is a fixture writer that fails the test instead of leaving a
// missing file to be misread as "the walker skipped it".
func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}
