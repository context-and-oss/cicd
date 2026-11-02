//go:build !unit_test

package main

import (
	"context"
	"dagger/precommit/internal/dagger"
)

// Precommit wraps the stage-2 source gate with evidence aggregation and
// notification for the pre-commit pipeline.
type Precommit struct{}

// Run executes all stage-2 checks via a single dag.Stage2().Run call: quality
// (lint + test), security source scan, risk validation, and — behind the opt-in
// --require-intent — the change-intent gate. Evidence is aggregated and a Teams
// notification is posted if a webhook is provided.
// Returns the audit directory containing combined-evidence.json, findings.sarif, sbom.cdx.json.
func (m *Precommit) Run(
	ctx context.Context,
	// Source directory to check.
	src *dagger.Directory,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Languages to include: go, node, python, dotnet (repeatable, optional).
	// +optional
	include []string,
	// Semgrep rulesets for SAST (e.g. "p/security-audit,p/owasp-top-ten").
	// "auto" is rejected by the security module — see security/CLAUDE.md.
	// +default="p/security-audit"
	sastRulesets string,
	// Teams incoming webhook URL for notifications.
	// +optional
	teamsWebhook *dagger.Secret,
	// CI pipeline run URL shown in the Teams notification.
	// +optional
	runUrl string,
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
	// Output of `git diff origin/main...HEAD`. Scopes the intent gate (coupling
	// checks) and the risk infra scan to the files this change touches.
	// +optional
	diff *dagger.File,
	// Which infrastructure files the risk scan evaluates: "changed" (only the
	// ones in --diff) or "tree" (every one in the checkout).
	//
	// The default is right for a pull request gate and is why this is exposed
	// rather than pinned: the scan should judge the change under review, and
	// debt in a file the author did not touch is the previous run's problem.
	// A team whose infrastructure is rarely edited can ask for "tree" here and
	// have every parseable file judged on every pull request. The commit
	// pipeline does not offer the choice — it pins "tree", because a push that
	// has already merged has no author left to ask.
	// +default="changed"
	// +optional
	infraScope string,
	// Glob patterns for intent artifacts. Uses built-in defaults when omitted.
	// +optional
	intentGlobs []string,
	// Minimum coverage percentage gate (0 disables). See quality.Check.
	// +default="0"
	// +optional
	minCoverage float64,
	// Skip coverage gate for a language when coverable lines are below this threshold.
	// +default="0"
	// +optional
	coverageMinLines int,
	// Consumer-owned test command for witnessed BYO test execution (quality.Test).
	// When set, quality.Check runs lint-only and quality.Test runs the command;
	// both evidence files feed the audit. When empty, existing behavior is unchanged.
	// +optional
	testCmd string,
	// Witnessed test legs as a JSON array — one object per leg with the keys
	// label, language (go|node|python|dotnet), cmd, and optionally coveragePath
	// and toolchainImage. The polyglot form of testCmd: one command, container
	// and coverage report per language instead of one for the whole repository.
	// Mutually exclusive with testCmd. See quality.Test.
	// +optional
	testLegs string,
	// Path of the coverage report the test command writes — absolute, or relative
	// to the source root. Applies to testCmd only; a leg names its own.
	// See quality.Test.
	// +optional
	coveragePath string,
	// Baseline coverage document for the ratchet: a prior combined-evidence.json /
	// evidence envelope, or a bare {"coverageByLanguage": {...}} map (sniffed).
	// +optional
	baseline *dagger.File,
	// Allowed per-language coverage drop (percentage points) before the ratchet trips.
	// +default=1.0
	tolerance float64,
	// Ratchet mode: "gate" fails the envelope on a tripped ratchet, "warn" only warns.
	// +default="gate"
	coverageGate string,
	// License policy mode: "gate" fails the envelope on a license outside the
	// allowlist, "warn" reports without enforcing.
	// +default="warn"
	licenseGate string,
	// Licence categories and individual licences the policy permits. Empty uses
	// cicd's default policy (permissive, notice, unencumbered). Naming a
	// category replaces the defaults; naming a licence keeps them and allows
	// that declaration as well. "unknown" is not an allowable category — allow
	// the declarations you have read, by their exact text: globally when it is
	// an SPDX expression (BlueOak-1.0.0), or scoped to one package when it is
	// not (example-sdk=SEE LICENSE IN LICENSE).
	// +optional
	licenseAllow []string,
	// Vulnerability findings to accept, each as "<id>=<reason>" — e.g.
	// "CVE-2026-81871=the exporter only reaches the Dagger engine's own
	// telemetry endpoint on the runner". The row leaves the severity counts,
	// findings[] and the gate, and is disclosed in warnings[] with the reason
	// given; it stays in the CycloneDX report. A reason is mandatory, patterns
	// are refused, and an acceptance that matches nothing warns, so a stale one
	// is visible rather than a standing permission. ONE PER LINE: the separator
	// is a newline and never a comma, because a reason is prose that contains
	// commas. See src/security/vulnallow.go.
	// +optional
	vulnAccept string,
	// Glob patterns whose license declarations are reported but not judged
	// against the policy, e.g. "docs/**". It narrows scope, never findings.
	// +optional
	licenseExclude []string,
	// Read licenses from source headers and LICENSE files as well as from
	// package metadata.
	// +default=true
	licenseFull bool,
	// Toolchain container image override for the BYO test command (ADR-004).
	// Applies to testCmd only; a leg names its own.
	// +optional
	toolchainImage string,
	// Asserts diff is a pull_request whose actor is exactly dependabot[bot],
	// enabling intent's approved GitHub Actions pin-bump path in place of a
	// human intent artifact. The caller must verify the actor itself; intent
	// independently re-validates every diff hunk and never trusts this alone.
	// Never set for commit/push execution (dependabot origin cannot be
	// inferred after merge).
	// +optional
	dependabotActionsPin bool,
	// Requires this change to carry a change-intent artifact (capsule, spec,
	// *.intent.md, …) and fails the gate at --fail-on when it does not. Opt-in,
	// and only offered here: pre-commit is where an author can still answer the
	// question, since the artifact is part of the change under review. Left off,
	// the audit records that intent was not checked rather than staying silent.
	// +optional
	requireIntent bool,
	// Maximum independent Node projects; never truncates.
	// +default=4
	nodeProjectLimit int,
	// Maximum independent source check groups, and declared test legs, in flight, 1–4.
	// +default=1
	parallelism int,
	// Prepared state supplied by a caller-owned Dagger pipeline.
	// +optional
	prepared *dagger.Container,
	// +optional
	preparedLanguage string,
	// +optional
	preparedTestLabel string,
	// +optional
	preparedImage string,
) (*dagger.Directory, error) {
	if err := validatePrecommitInputs(parallelism, nodeProjectLimit); err != nil {
		return nil, err
	}

	// Source gate: quality, security, risk and (opt-in) intent all run via one
	// dag.Stage2().Run call — the same composition stage-2 itself owns, so
	// precommit and stage-2 cannot silently drift apart (see
	// scripts/smoke/stage-orchestrators.sh's equivalence guard).
	srcGateFiles, err := dag.Stage2().Run(
		ctx,
		src, commitSha, branch, repoUrl,
		dagger.Stage2RunOpts{
			FailOn:               failOn,
			Include:              include,
			SastRulesets:         sastRulesets,
			NpmFeedURL:           npmFeedUrl,
			NpmFeedRouting:       npmFeedRouting,
			NpmToken:             npmToken,
			NugetFeedURL:         nugetFeedUrl,
			NugetToken:           nugetToken,
			Diff:                 diff,
			InfraScope:           infraScope,
			IntentGlobs:          intentGlobs,
			MinCoverage:          minCoverage,
			CoverageMinLines:     coverageMinLines,
			TestCmd:              testCmd,
			TestLegs:             testLegs,
			CoveragePath:         coveragePath,
			Baseline:             baseline,
			Tolerance:            tolerance,
			CoverageGate:         coverageGate,
			LicenseGate:          licenseGate,
			LicenseAllow:         licenseAllow,
			VulnAccept:           vulnAccept,
			LicenseExclude:       licenseExclude,
			LicenseFull:          licenseFull,
			ToolchainImage:       toolchainImage,
			DependabotActionsPin: dependabotActionsPin,
			RequireIntent:        requireIntent,
			NodeProjectLimit:     nodeProjectLimit,
			Parallelism:          parallelism,
			Prepared:             prepared,
			PreparedLanguage:     preparedLanguage,
			PreparedTestLabel:    preparedTestLabel,
			PreparedImage:        preparedImage,
		},
	)
	if err != nil {
		return nil, err
	}
	evidenceFiles := make([]*dagger.File, len(srcGateFiles))
	for i := range srcGateFiles {
		evidenceFiles[i] = &srcGateFiles[i]
	}

	return finishAudit(evidenceFiles, "precommit", auditOpts{
		commitSha:    commitSha,
		branch:       branch,
		repoUrl:      repoUrl,
		runUrl:       runUrl,
		teamsWebhook: teamsWebhook,
	}), nil
}
