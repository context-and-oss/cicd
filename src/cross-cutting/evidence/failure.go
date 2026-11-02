//go:build !unit_test

package main

import (
	"dagger/evidence/internal/dagger"
	"encoding/json"
	"fmt"
	"time"
)

// Failure records a stage that could not produce its own envelope. It lets an
// orchestrator preserve completed evidence while recording the missing work.
func (m *Evidence) Failure(module, tool, concern, message, commitSha, branch, repoUrl string) (*dagger.File, error) {
	if message == "" {
		return nil, fmt.Errorf("failure message is required")
	}
	e := envelope{SchemaVersion: evidenceSchemaVersion, ModuleName: module, Stage: "commit",
		Tool: toolInfo{Name: tool}, Repo: repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch},
		TimestampUTC: time.Now().UTC(), Passed: false, Outcome: OutcomeError, Concern: Concern(concern), Errors: []string{message}}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithNewFile("evidence.json", string(b)).File("evidence.json"), nil
}
