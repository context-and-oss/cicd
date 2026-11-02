//go:build !unit_test

package main

import (
	"context"
	"fmt"

	"dagger/pages/internal/dagger"
)

// Pages generates a static GitHub Pages site from pipeline evidence.
type Pages struct{}

// Build generates a self-contained index.html from a combined-evidence.json file.
// Returns a directory ready for deployment to GitHub Pages via actions/deploy-pages.
func (m *Pages) Build(ctx context.Context, evidence *dagger.File) (*dagger.Directory, error) {
	contents, err := evidence.Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading evidence: %w", err)
	}

	html, err := renderPage(htmlTemplate, contents)
	if err != nil {
		return nil, err
	}

	return dag.Directory().WithNewFile("index.html", html), nil
}
