//go:build unit_test

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceOutputCarriesTheEnvelopeBytes(t *testing.T) {
	want := []byte(`{"moduleName":"security","genericReport":{"bytes":"kept"}}`)
	dir, err := writeEvidenceOutput(t.TempDir(), want)
	if err != nil {
		t.Fatalf("writeEvidenceOutput: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, evidenceFileName))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("evidence changed in transit: got %q, want %q", got, want)
	}
}

func TestEvidenceOutputCannotReturnAStaleFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, evidenceDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stale.json"), []byte("old run"), 0o644); err != nil {
		t.Fatal(err)
	}

	want := []byte(`{"run":"current"}`)
	gotDir, err := writeEvidenceOutput(root, want)
	if err != nil {
		t.Fatalf("writeEvidenceOutput: %v", err)
	}
	if _, err := os.Stat(filepath.Join(gotDir, "stale.json")); !os.IsNotExist(err) {
		t.Fatalf("stale output survived: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(gotDir, evidenceFileName))
	if err != nil {
		t.Fatalf("read current evidence: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("current evidence changed: got %q, want %q", got, want)
	}
}
