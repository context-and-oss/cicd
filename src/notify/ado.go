//go:build !unit_test

package main

import (
	"context"
	"dagger/notify/internal/dagger"
	"fmt"
)

// Ado posts a pipeline status comment to an Azure DevOps pull request.
func (m *Notify) Ado(
	ctx context.Context,
	// combined-evidence.json from cross-cutting/evidence.
	summary *dagger.File,
	// Human-readable pipeline name (e.g. "precommit", "commit").
	pipelineName string,
	// Azure DevOps organisation name (e.g. "my-company").
	org string,
	// Azure DevOps team project name (e.g. "payments").
	project string,
	// Repository name or GUID.
	repoId string,
	// Pull request ID (use $(System.PullRequest.PullRequestId) in ADO pipelines).
	prId int,
	// ADO access token or PAT.
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
	return newDelivery(tok).postADOComment(ctx, tok, org, project, repoId, prId, body)
}

// AdoBuildComment returns the formatted PR comment as a markdown file.
func (m *Notify) AdoBuildComment(
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
