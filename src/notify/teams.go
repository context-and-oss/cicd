//go:build !unit_test

package main

import (
	"context"
	"dagger/notify/internal/dagger"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Teams posts a pipeline status card to a Microsoft Teams channel via incoming
// webhook and returns an evidence envelope describing what happened to it.
//
// It returns an envelope rather than a bare error because the three states a
// notification can end in are not distinguishable from outside, and two of them
// used to be invisible. A composite guarded the call with `webhook != nil`,
// which is true for every consumer under GitHub Actions `secrets: inherit` or
// Azure DevOps `$(TEAMS_WEBHOOK)` whether or not the secret exists, so cicd
// POSTed to the empty string on every run of every repository that had not set
// Teams up — and wrote `unsupported protocol scheme ""` to stderr, where it sat
// for months inside a twenty-minute log while the run reported success. The
// same treatment awaited a channel that *was* configured and whose webhook was
// later rotated: green runs, no cards, one line nobody reads. A notifier that
// could not notify must not report a delivered run.
//
// Delivery never fails the pipeline (Passed is true in all three states — see
// teamsEvidence), and the returned file is the record. Errors returned here are
// cicd's own faults, not the channel's: evidence this module cannot read, or a
// secret the engine cannot resolve.
//
// Laziness matters at the call site. A module function returning *dagger.File
// gets a generated client method with no ctx, so nothing in this body runs
// until something reads the file. A caller that drops the returned file sends
// no card at all.
func (m *Notify) Teams(
	ctx context.Context,
	// Teams incoming webhook URL.
	webhookUrl *dagger.Secret,
	// combined-evidence.json file from cross-cutting/evidence.
	summary *dagger.File,
	// Human-readable pipeline name (e.g. "precommit", "commit").
	pipelineName string,
	// CI pipeline run URL for the "View run" button.
	// +optional
	runUrl string,
) (*dagger.File, error) {
	start := time.Now()
	env, err := parseEvidence(ctx, summary)
	if err != nil {
		return nil, err
	}
	webhookSecret, err := webhookUrl.Plaintext(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve webhook: %w", err)
	}
	card := buildTeamsCard(pipelineName, runUrl, env)
	// The webhook URL *is* the credential — register it, and its path, so no
	// error can echo it (see teamsScrubValues).
	attempted, unconfiguredReason, deliverErr := deliverTeamsCard(
		ctx, newTeamsDelivery(webhookSecret), webhookSecret, card)

	// The repo context is taken from the evidence this card reports on rather
	// than from three new parameters: the delivery belongs to that run, and a
	// second source for the same three values is a second thing that can drift.
	out := teamsEvidence(start, env.Repo, pipelineName, attempted, unconfiguredReason, deliverErr)
	for _, w := range out.Warnings {
		// Also on stderr, so the reason is in the job log beside the step that
		// produced it and not only in an artifact somebody has to download.
		fmt.Fprintln(os.Stderr, w)
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}

// BuildCard assembles the Teams adaptive card from a combined-evidence.json and returns
// it as a JSON file. Useful for verifying card output without a real webhook endpoint.
func (m *Notify) BuildCard(
	ctx context.Context,
	// combined-evidence.json file from cross-cutting/evidence.
	summary *dagger.File,
	// Human-readable pipeline name (e.g. "precommit", "commit").
	pipelineName string,
	// CI pipeline run URL shown in the "View run" button.
	// +optional
	runUrl string,
) (*dagger.File, error) {
	env, err := parseEvidence(ctx, summary)
	if err != nil {
		return nil, err
	}
	card := buildTeamsCard(pipelineName, runUrl, env)
	data, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("marshal card: %w", err)
	}
	return dag.Directory().WithNewFile("card.json", string(data)).File("card.json"), nil
}
