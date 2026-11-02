//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"dagger/risk/internal/dagger"
)

// Scan runs AI analysis on the repository.
// Returns a directory with findings.json and decisions.json to commit to the repo.
//
// LLM mode (pick one):
//   - --use-claude-cli --llm-token env:CICD_RISK_PROXY_TOKEN
//     → connect to a locally running claude-proxy.js on port 4000. Uses your
//     Claude CLI auth (subscription/OAuth, no API key needed). Start the proxy
//     first with the same token — see the error message for the setup.
//   - --llm-url http://host:4000 [--llm-token ...] → any OpenAI-compatible proxy
//     (enterprise gateway)
//   - (neither)                       → dag.LLM() native, requires ANTHROPIC_API_KEY env var
//
// What reaches the model: the files collect.go lists — git's view of the tree
// minus the credential and metadata classes in sensitivePathParts — in full,
// up to the prompt budget. scan-manifest.json names every one of them.
func (m *Risk) Scan(
	ctx context.Context,
	// Source directory to scan.
	source *dagger.Directory,
	// Connect to a locally running claude-proxy.js on port 4000.
	// Uses your existing Claude CLI auth — no API key required.
	// Needs --llm-token; start the proxy first ('risk proxy' exports it).
	// +optional
	useClaudeCLI bool,
	// OpenAI-compatible proxy URL for custom/enterprise setups.
	// Mutually exclusive with --use-claude-cli.
	// +optional
	llmURL string,
	// Maximum JSON-correction retries when the AI returns invalid JSON.
	// +optional
	// +default=2
	maxLLMRetries int,
	// Bearer token for the LLM endpoint, as a secret
	// (--llm-token env:CICD_RISK_PROXY_TOKEN). Required with --use-claude-cli:
	// claude-proxy.js refuses every request without it. Optional with --llm-url.
	// +optional
	llmToken *dagger.Secret,
) (*dagger.Directory, error) {
	llmMode, endpoint, err := resolveLLMEndpoint(useClaudeCLI, llmURL, llmToken != nil)
	if err != nil {
		return nil, err
	}
	token := ""
	if llmToken != nil {
		if token, err = llmToken.Plaintext(ctx); err != nil {
			return nil, fmt.Errorf("read --llm-token: %w", err)
		}
	}

	// Collect all file contents in ONE container exec (avoids N Dagger API round-trips).
	rawLines, err := dag.Container().
		From(collectorImage).
		WithoutEntrypoint().
		WithMountedDirectory(collectRoot, source).
		WithExec(collectArgs(collectRoot)).
		Stdout(ctx)
	if err != nil {
		// The collector's refusal (a worktree whose metadata is not mounted, a
		// git that could not list the tree) is on stderr; say it, not the exit code.
		if reason := strings.TrimSpace(execStderr(err)); reason != "" {
			return nil, fmt.Errorf("collect files: %s", reason)
		}
		return nil, fmt.Errorf("collect files: %w", err)
	}
	collected := parseCollected(rawLines)
	if err := collected.usable(); err != nil {
		return nil, err
	}
	files := collected.files

	const findingsSchema = `{
  "id": "string (8-char hash, assigned by caller)",
  "category": "compliance|data_governance|trust_boundary|lifecycle_risk",
  "severity": "critical|high|medium|low",
  "confidence": "float 0.0-1.0",
  "title": "string",
  "description": "string",
  "evidence": {
    "file": "relative path",
    "start_line": "integer",
    "end_line": "integer",
    "snippet": "string"
  }
}`
	prompt := buildScanPrompt(files, findingsSchema)

	var conv llmConversation
	switch llmMode {
	case llmModeClaudeCLI, llmModeLLMURL:
		conv = newDirectConversation(endpoint, token)
	default:
		conv = newNativeConversation()
	}

	reply, err := callLLMWithRetry(ctx, conv, prompt, maxLLMRetries)
	if err != nil {
		if llmMode == llmModeClaudeCLI {
			return nil, fmt.Errorf("%s\n\nUnderlying error: %w", claudeProxyInstructions, err)
		}
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	cleaned := stripMarkdownFences(reply)
	var raw struct {
		Findings []rawFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		// Truncate reply to avoid leaking full repo content in error messages.
		const maxSnippet = 200
		snippet := cleaned
		if len(snippet) > maxSnippet {
			snippet = snippet[:maxSnippet] + "…"
		}
		return nil, fmt.Errorf("parse AI response: %w (reply prefix: %s)", err, snippet)
	}

	// findings.json is meant to be committed (README workflow), so we MUST
	// strip raw secret values from snippets before writing. Otherwise the
	// "client secret committed" finding ships the secret back into git
	// alongside the warning about it.
	findings := redactFindings(filterFindings(raw.Findings, 0.6))

	ts, err := dag.Container().From(alpineImage).
		WithExec([]string{"date", "-u", "+%Y-%m-%dT%H:%M:%SZ"}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("get timestamp: %w", err)
	}

	ff := FindingsFile{
		SchemaVersion: "1.0",
		ScannedAt:     strings.TrimSpace(ts),
		Findings:      findings,
	}
	findingsData, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}
	decisionsData, err := json.MarshalIndent(scaffoldDecisions(findings), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal decisions: %w", err)
	}

	manifest := buildScanManifest(collected, llmMode, strings.TrimSpace(ts))
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	return dag.Directory().
		WithNewFile("findings.json", string(findingsData)).
		WithNewFile("decisions.json", string(decisionsData)).
		WithNewFile("scan-manifest.json", string(manifestData)), nil
}

// Check runs Validate and returns an error if any policy violations are found.
// Registered as a dagger check — runs automatically via `dagger check`.
//
// +check
func (m *Risk) Check(
	ctx context.Context,
	// +defaultPath="."
	source *dagger.Directory,
) error {
	// No diff context in a `dagger check` run — say so by asking for the tree
	// scope explicitly, rather than relying on a nil diff to mean it.
	f, err := m.Validate(ctx, source, "HIGH", "", "", "", nil, infraScopeTree)
	if err != nil {
		return err
	}
	contents, err := f.Contents(ctx)
	if err != nil {
		return fmt.Errorf("read evidence: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal([]byte(contents), &env); err != nil {
		return fmt.Errorf("parse evidence: %w", err)
	}
	if !env.Passed {
		return fmt.Errorf("risk policy violations detected (%d finding(s))", env.FindingsCount)
	}
	return nil
}

// Report renders a markdown report from findings.json and decisions.json,
// auto-discovered anywhere in the source tree.
func (m *Risk) Report(ctx context.Context, source *dagger.Directory) (*dagger.File, error) {
	findingsPath, decisionsPath, err := findRiskFiles(ctx, source)
	if errors.Is(err, errNoRiskFiles) {
		return nil, fmt.Errorf("no risk files found — run 'dagger -m github.com/context-and-oss/cicd/src/risk call scan' first")
	}
	if err != nil {
		return nil, err
	}
	findingsJSON, err := source.File(findingsPath).Contents(ctx)
	if err != nil {
		return nil, err
	}
	decisionsJSON, err := source.File(decisionsPath).Contents(ctx)
	if err != nil {
		return nil, err
	}
	var ff FindingsFile
	if err := json.Unmarshal([]byte(findingsJSON), &ff); err != nil {
		return nil, fmt.Errorf("parse %s: %w", findingsPath, err)
	}
	var dd map[string]Decision
	if err := json.Unmarshal([]byte(decisionsJSON), &dd); err != nil {
		return nil, fmt.Errorf("parse %s: %w", decisionsPath, err)
	}
	md := renderReport(ff.Findings, dd)
	return dag.Directory().WithNewFile("report.md", md).File("report.md"), nil
}

// Proxy exports the bundled claude-proxy.js.
// Run this once to get the script, then keep it running alongside
// dagger call scan --use-claude-cli --llm-token env:CICD_RISK_PROXY_TOKEN.
//
// Usage:
//
//	dagger -m ./src/risk call proxy export --path ./claude-proxy.js
//	npm install -g @anthropic-ai/claude-code             # once
//	export CICD_RISK_PROXY_TOKEN="$(openssl rand -hex 32)"
//	node claude-proxy.js                                 # keep running
func (m *Risk) Proxy() *dagger.File {
	return dag.CurrentModule().Source().File("claude-proxy.js")
}
