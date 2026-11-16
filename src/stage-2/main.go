//go:build !unit_test

package main

import (
	"context"
	"dagger/stage-2/internal/dagger"
	"encoding/json"
	"time"
)

// Stage2 is the source-gate orchestrator of the CD model: it runs quality,
// source security, licence, risk and intent checks against one commit and
// returns their evidence files for cross-cutting/evidence to aggregate. It
// decides the leg set and the parallelism; the legs themselves live in the
// domain modules.
type Stage2 struct{}

// Run executes all pre-commit checks: quality (lint + test), security source scan,
// risk validation, and — when the caller opts in with requireIntent — the intent
// gate. Returns a slice of evidence files — one per domain module. Pass these to
// cross-cutting/evidence to produce combined-evidence.json. Intent is in the
// slice either way: opted out, it reports that it checked nothing.
func (m *Stage2) Run(
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
	// SAST rulesets in Semgrep rule syntax, run by Opengrep
	// (e.g. "p/security-audit,p/owasp-top-ten").
	// "auto" is rejected by the security module — see security/CLAUDE.md.
	// +default="p/security-audit"
	sastRulesets string,
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
	// checks), and the risk infra scan when infra-scope is "changed".
	// +optional
	diff *dagger.File,
	// Which infrastructure files the risk scan evaluates: "changed" (only the
	// ones in --diff) or "tree" (every one in the checkout).
	//
	// It is a parameter and never inferred, because the two stages that call
	// this orchestrator want opposite answers and neither is a default anyone
	// should have to guess. A pull request gate scans the pull request: debt in
	// a file the author did not touch is the previous run's problem. A push to
	// the default branch has no author left to ask, and it is the stage this
	// repository tells consumers to adopt as the whole-repository gate — where
	// scoping to one push means a file is scanned on the commit that edits it
	// and never again, and a misconfiguration that predates the scan, or that
	// became one when a policy was added rather than when the file changed, is
	// invisible forever. Every other concern on that stage already reads the
	// whole tree; the risk scan was the one exception.
	//
	// With no --diff there is no change set, so "changed" scans the whole tree
	// anyway — that is risk.Validate's own contract and not a second rule here.
	// Validation lives there too; forwarding an unknown value fails the run.
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
	// both evidence files are returned. When empty, existing behavior is unchanged.
	// +optional
	testCmd string,
	// JSON array of per-language witnessed test legs, each with its own command,
	// toolchain image and coverage report — the polyglot form of testCmd, and
	// mutually exclusive with it. See quality.Test.
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
	// allowlist, "warn" reports without enforcing. Defaults to "warn" so the
	// step reports every consumer's real exposure before anyone is blocked by
	// it. There is deliberately no "off" — see src/security/licensereport.go.
	// +default="warn"
	licenseGate string,
	// Licence categories and individual licences the policy permits. Empty uses
	// cicd's default policy (permissive, notice, unencumbered). Naming a
	// category replaces the defaults; naming a licence keeps them and allows
	// that declaration as well. Anything else outside the policy is a finding.
	// "unknown" is not an allowable category — it means Trivy could not
	// classify a declaration, so allowing it would allow every future one too.
	// Allow the declarations you have read instead, by their exact text:
	// globally when it is an SPDX expression (BlueOak-1.0.0), or scoped to one
	// package when it is not (example-sdk=SEE LICENSE IN LICENSE).
	// +optional
	licenseAllow []string,
	// Glob patterns whose license declarations are reported but not judged
	// against the policy, e.g. "docs/**". It narrows scope, never findings:
	// there is no way to exclude a license by name. See
	// src/security/licenseexclude.go.
	// +optional
	licenseExclude []string,
	// Read licenses from source headers and LICENSE files as well as from
	// package metadata. On by default because metadata-only mode never reads
	// the tree's own LICENSE, which in ecosystems whose manifests carry no
	// license field (Go among them) can be all there is to read. Dependency
	// licences come from installed package metadata in either mode.
	// +default=true
	licenseFull bool,
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
	// Toolchain container image override for the BYO test command (ADR-004).
	// Applies to testCmd only; a leg names its own.
	// +optional
	toolchainImage string,
	// Asserts diff is a pull_request whose actor is exactly dependabot[bot],
	// enabling intent's approved GitHub Actions pin-bump path in place of a
	// human intent artifact. The caller must verify the actor itself — intent
	// independently re-validates every diff hunk and never trusts this alone.
	// Never set for commit/push execution (dependabot origin cannot be
	// inferred after merge).
	// +optional
	dependabotActionsPin bool,
	// Requires this change to carry a change-intent artifact (capsule, spec,
	// *.intent.md, …). Opt-in: the intent gate asks whether a team practice was
	// followed, not whether the code is safe, and a team that keeps its change
	// rationale somewhere else should not be told its pipeline failed. Left off,
	// intent still reports — with `required: false` and a warning — so an audit
	// can tell an unasked gate from a clean one.
	// +optional
	requireIntent bool,
	// Maximum independent check groups, and declared test legs, in flight; tool-internal parallelism is separate.
	// +default=1
	parallelism int,
	// Maximum independent Node projects; exceeding this fails rather than truncates.
	// +default=4
	nodeProjectLimit int,
	// +optional
	prepared *dagger.Container,
	// +optional
	preparedLanguage string,
	// +optional
	preparedTestLabel string,
	// +optional
	preparedImage string,
) ([]*dagger.File, error) {
	// Either input means the consumer owns test execution, so the vanilla test
	// leg in Check is redundant (ADR-002); see stage2plan.go for the rules.
	byoTest := byoTestRequested(testCmd, testLegs)
	if err := validateStage2Inputs(parallelism, nodeProjectLimit, prepared != nil, byoTest); err != nil {
		return nil, err
	}

	qualityEvidence := dag.Quality().Check(
		src, commitSha, branch, repoUrl,
		dagger.QualityCheckOpts{
			Include:          include,
			FailOn:           failOn,
			NpmFeedURL:       npmFeedUrl,
			NpmFeedRouting:   npmFeedRouting,
			NpmToken:         npmToken,
			NugetFeedURL:     nugetFeedUrl,
			NugetToken:       nugetToken,
			MinCoverage:      minCoverage,
			CoverageMinLines: coverageMinLines,
			LintOnly:         byoTest,
			NodeProjectLimit: nodeProjectLimit,
			Prepared:         prepared,
			PreparedLanguage: preparedLanguage,
		},
	)

	var testEvidence *dagger.File
	if byoTest {
		// testCmd is optional on quality.Test now (exactly one of it and
		// testLegs must be set, which no static signature can express), so it
		// travels in the opts struct rather than as a positional argument.
		testEvidence = dag.Quality().Test(
			src, commitSha, branch, repoUrl,
			dagger.QualityTestOpts{
				TestCmd:           testCmd,
				Prepared:          prepared,
				PreparedTestLabel: preparedTestLabel,
				PreparedImage:     preparedImage,
				PreparedLanguage:  preparedLanguage,
				TestLegs:          testLegs,
				CoveragePath:      coveragePath,
				Baseline:          baseline,
				Tolerance:         tolerance,
				CoverageGate:      coverageGate,
				ToolchainImage:    toolchainImage,
				Include:           include,
				NpmFeedURL:        npmFeedUrl,
				NpmFeedRouting:    npmFeedRouting,
				NpmToken:          npmToken,
				NugetFeedURL:      nugetFeedUrl,
				NugetToken:        nugetToken,
				// The same bound the groups run under. Peak containers are
				// therefore up to 2p-1: the test group's p legs beside the
				// other p-1 groups, never p squared, because no other group
				// fans out.
				Parallelism: parallelism,
			},
		)
	}

	securityEvidence := dag.Security().ScanSource(
		src, commitSha, branch, repoUrl,
		dagger.SecurityScanSourceOpts{
			SastRulesets: sastRulesets,
			FailOn:       failOn,
			// The same feed credentials quality's .NET legs restore with. The
			// security scan needs them for the lockfile-free dependency-graph
			// fallback: a .NET tree with no committed packages.lock.json is
			// restored so there is a graph to scan, and a restore that cannot
			// reach the consumer's private feed produces none.
			NugetFeedURL: nugetFeedUrl,
			NugetToken:   nugetToken,
			VulnAccept:   vulnAccept,
		},
	)

	// A separate envelope from ScanSource, not a fourth leg inside it: a license
	// finding is a compliance judgement with no CVE and no fix version, and
	// merging it into the security counts would let a copyleft dependency
	// consume the budget of a gate that exists to stop exploitable code
	// shipping. See src/security/main.go's ScanLicenses.
	//
	// It always reports, for the reason the intent gate always reports: a gate
	// missing from an audit and a gate that passed look identical afterwards.
	// Warn mode is how it stays advisory, which keeps the envelope present.
	licenseEvidence := dag.Security().ScanLicenses(
		src, commitSha, branch, repoUrl,
		dagger.SecurityScanLicensesOpts{
			LicenseGate:    licenseGate,
			LicenseAllow:   licenseAllow,
			LicenseExclude: licenseExclude,
			LicenseFull:    licenseFull,
			FailOn:         failOn,
			// The licence scan restores the NuGet graph to read each
			// package's .nuspec, so it needs the same feed the dependency scan
			// restores from; without it a private package reads no licence.
			NugetFeedURL: nugetFeedUrl,
			NugetToken:   nugetToken,
		},
	)

	// The scope is forwarded rather than acted on here: risk owns the rule, so
	// there is one place that decides what "tree" means and one place a test can
	// reach it. An unrecognised value is risk's hard error, not a silent
	// narrowing — this orchestrator deliberately does not pre-validate it, which
	// would be a second copy of the accepted set to drift out of agreement.
	riskEvidence := dag.Risk().Validate(
		src, commitSha, branch, repoUrl,
		dagger.RiskValidateOpts{FailOn: failOn, Diff: diff, InfraScope: infraScope},
	)

	// The intent gate is opt-in, but it always reports: NotRequired makes it
	// record that nothing was checked instead of vanishing from the evidence,
	// because a gate missing from an audit and a gate that passed look identical
	// afterwards. Note the inversion — Dagger's generated client drops optional
	// arguments holding their zero value, so only the non-default state can be
	// transmitted, and this is the state that must survive the wire.
	intentEvidence := dag.Intent().Check(
		src, commitSha, branch, repoUrl,
		dagger.IntentCheckOpts{
			FailOn:               failOn,
			Diff:                 diff,
			Globs:                intentGlobs,
			DependabotActionsPin: dependabotActionsPin,
			NotRequired:          !requireIntent,
		},
	)

	legs := stage2Legs(byoTest, qualityEvidence, testEvidence, securityEvidence, licenseEvidence, riskEvidence, intentEvidence)
	files := make([]*dagger.File, len(legs))
	for i, leg := range legs {
		files[i] = leg.value
	}

	// Sequential by default: large consumers previously exhausted runner disk.
	// Bound independent domain groups only; quality's own legs stay sequential.
	// A failed module becomes failed evidence so other completed checks survive.
	errs := RunBounded(ctx, len(files), parallelism, func(i int) error {
		synced, err := files[i].Sync(ctx)
		if err == nil {
			files[i] = synced
		}
		return err
	})
	for i, err := range errs {
		if err == nil {
			continue
		}
		e := unusableEvidence(legs[i].name, repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}, time.Now().UTC())
		data, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			return nil, marshalErr
		}
		files[i] = dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json")
	}

	return files, nil
}
