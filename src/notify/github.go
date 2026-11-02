//go:build !unit_test

package main

import (
	"context"
	"dagger/notify/internal/dagger"
	"fmt"
)

// Github posts a pipeline status comment to a GitHub pull request.
func (m *Notify) Github(
	ctx context.Context,
	// combined-evidence.json from cross-cutting/evidence.
	summary *dagger.File,
	// Human-readable pipeline name (e.g. "precommit", "commit").
	pipelineName string,
	// Full repository path: "owner/repo".
	repo string,
	// Pull request number.
	prNumber int,
	// GitHub token with repo write access.
	token *dagger.Secret,
	// CI run URL shown as a link in the comment.
	// +optional
	runUrl string,
) error {
	env, err := parseEvidence(ctx, summary)
	if err != nil {
		return err
	}
	tok, err := token.Plaintext(ctx)
	if err != nil {
		return fmt.Errorf("resolve token: %w", err)
	}
	body := buildMarkdown(pipelineName, runUrl, env)
	return newDelivery(tok).upsertGitHubComment(ctx, tok, repo, prNumber, pipelineName, body)
}

// GithubBuildComment returns the formatted PR comment as a markdown file.
func (m *Notify) GithubBuildComment(
	ctx context.Context,
	// combined-evidence.json from cross-cutting/evidence.
	summary *dagger.File,
	// Human-readable pipeline name.
	pipelineName string,
	// +optional
	runUrl string,
) (*dagger.File, error) {
	env, err := parseEvidence(ctx, summary)
	if err != nil {
		return nil, err
	}
	body := buildMarkdown(pipelineName, runUrl, env)
	return dag.Directory().WithNewFile("comment.md", body).File("comment.md"), nil
}
