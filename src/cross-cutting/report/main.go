//go:build !unit_test

package main

import (
	"context"
	"dagger/report/internal/dagger"
	"fmt"
)

// Report is the Dagger module that extracts the native tool document (SARIF,
// CycloneDX or a generic JSON payload) back out of an evidence envelope, for
// consumers whose tooling wants the tool's own format rather than cicd's.
type Report struct{}

// Report extracts the native tool report embedded inside an evidence envelope and
// returns it as a standalone file in its original format.
//
// Priority: sarifReport → cyclonedxReport → genericReport.
// Returns an error if no report field is populated in the envelope.
func (r *Report) Report(
	ctx context.Context,
	// Evidence envelope produced by any security, quality, or build module function.
	evidence *dagger.File,
) (*dagger.File, error) {
	content, err := evidence.Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}

	data, filename, err := extractFromJSON(content)
	if err != nil {
		return nil, err
	}

	return dag.Directory().WithNewFile(filename, string(data)).File(filename), nil
}
