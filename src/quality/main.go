//go:build !unit_test

package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"encoding/json"
	"fmt"
	"time"
)

// Quality is the Dagger module for the source gate's code-quality legs: lint
// and native unit tests per auto-detected language (Check), a witnessed
// consumer-owned test command with its coverage harvest (Test), a consumer-owned
// lint or SBOM command (Collect), and the prepared toolchain container the
// others can share (Prepare).
type Quality struct{}

// Check runs lint and unit tests on source code.
// Returns an aggregated evidence envelope.
func (m *Quality) Check(
	ctx context.Context,
	// Source directory to check.
	src *dagger.Directory,
	// Languages to include: go, node, python, dotnet (repeatable, optional).
	// +optional
	include []string,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Internal npm registry URL.
	// +optional
	npmFeedUrl string,
	// How the npm feed is applied: "registry" (default) makes it the registry
	// for every package; "npmrc" binds only its token and leaves routing to
	// the project's .npmrc, for a feed with no upstream to the public registry.
	// +optional
	npmFeedRouting string,
	// Auth token for internal npm registry.
	// +optional
	npmToken *dagger.Secret,
	// Internal NuGet feed URL.
	// +optional
	nugetFeedUrl string,
	// Auth token for internal NuGet feed.
	// +optional
	nugetToken *dagger.Secret,
	// Minimum coverage percentage (0–100) to pass the gate. 0 disables the check.
	// +default="0"
	// +optional
	minCoverage float64,
	// Skip the coverage gate for a language that has fewer coverable lines/statements than this.
	// +default="0"
	// +optional
	coverageMinLines int,
	// Run lint only — skip the per-language test step entirely. For repos
	// that execute their own test command via Test (BYO test, ADR-002), this
	// keeps the vanilla lint baseline without a redundant test run.
	// +optional
	lintOnly bool,
	// +optional
	prepared *dagger.Container,
	// node or dotnet; the language whose linter uses prepared dependencies.
	// +optional
	preparedLanguage string,
	// Maximum independent Node projects to lint/test. No project is silently omitted.
	// +default=4
	nodeProjectLimit int,
) (*dagger.File, error) {
	if err := validateCheckInputs(prepared != nil, lintOnly, preparedLanguage, nodeProjectLimit,
		npmFeedUrl, npmFeedRouting, npmToken != nil, nugetFeedUrl, nugetToken != nil); err != nil {
		return nil, err
	}
	start := time.Now()
	threshold := Severity(failOn)
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	langs, detectWarnings, err := detectLanguages(ctx, src, include)
	if err != nil {
		return nil, fmt.Errorf("language detection: %w", err)
	}
	names := make([]string, 0, len(langs))
	for _, lang := range langs {
		names = append(names, string(lang))
	}

	// Every decision below the container calls lives in checkfold.go, untagged
	// and under test; this loop only runs the legs and hands their results in.
	fold := newCheckFold(names, detectWarnings)
	for _, lang := range langs {
		var lintBase *dagger.Container
		if string(lang) == preparedLanguage {
			lintBase = prepared
		}
		lintEnv, lintRan, lintErr := lintLanguage(ctx, lang, src, threshold, repo, npmFeedUrl, npmFeedRouting, npmToken, nugetFeedUrl, nugetToken, lintBase, nodeProjectLimit)
		fold.addLint(string(lang), lintEnv, lintRan, lintErr)

		if lintOnly {
			continue
		}

		testEnv, testRan, testErr := testLanguage(ctx, lang, src, threshold, repo, npmFeedUrl, npmFeedRouting, npmToken, nugetFeedUrl, nugetToken, nodeProjectLimit)
		fold.addTest(string(lang), testEnv, testRan, testErr)
	}
	fold.foldCoverage(names, lintOnly, minCoverage, coverageMinLines)

	env := buildCheckEnvelope(fold, names, repo, threshold, start)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}
