package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const evidenceFileName = "evidence.json"
const evidenceDirName = "security-evidence"

func writeEvidenceOutput(root string, data []byte) (string, error) {
	dir := filepath.Join(root, evidenceDirName)
	// A module workdir may be reused. Clear the fixed output directory first so
	// an interrupted earlier invocation can never be returned as this run.
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clear evidence directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create evidence directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidenceFileName), data, 0o644); err != nil {
		return "", fmt.Errorf("write evidence: %w", err)
	}
	return dir, nil
}
