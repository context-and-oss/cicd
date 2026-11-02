//go:build !unit_test

package main

import (
	"context"
	"dagger/commit/internal/dagger"
	"fmt"
)

// Commit wires the source gate (every stage-2 code check) and an artifact tail
// into a single, artifact-agnostic commit-stage pipeline.
type Commit struct{}

// Run executes the full commit stage for any repo shape (ADR-005). The source
// gate — quality, SAST, secrets, dependency-vuln and risk — runs for EVERY
// shape via a single dag.Stage2().Run call. The artifact tail is selected
// explicitly with --artifact (never auto-detected):
//
//   - container → build the OCI image, SBOM it, and image-scan it (with an
//     opt-in live-verified secrets pass via --verify-secrets);
//   - archive   → run the consumer build command in a toolchain container and
//     secrets-scan the built output (requires --build-cmd and --output-path);
//   - none      → no build; the SBOM comes from stage-2's scan-source Trivy-FS
//     CycloneDX (source lockfiles), and the audit carries an explicit
//     "artifact: NOT ATTESTED" record so a run that attested no artifact cannot
//     read as one that attested a clean artifact (build.NoArtifact).
//
// The artifact is built and scanned but never published — each consumer repo
// owns its own deployment. Evidence from the source gate and the artifact tail
// is aggregated and a Teams notification is posted if a webhook is provided.
// Returns the audit directory containing combined-evidence.json, findings.sarif,
// sbom.cdx.json.
// With app-id, explicit app legs replace repository discovery and only evidence
// is produced. Shared scanners and artifact builders are reused directly.
func (m *Commit) Run(
	ctx context.Context,
	// Source directory to scan (and, for the container/archive shapes, build).
	src *dagger.Directory,
	// Git commit SHA — used as the image tag and for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Artifact shape: container|archive|none. Always explicit (ADR-001 — cicd
	// never auto-detects the build).
	// +default="container"
	artifact string,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// --- source gate (passthrough to dag.Stage2().Run) ---
	// Languages to include: go, node, python, dotnet (repeatable, optional).
	// +optional
	include []string,
	// Semgrep rulesets for SAST (e.g. "p/security-audit,p/owasp-top-ten").
	// Never pass empty, and never "auto" — both mean semgrep applies no rules.
	// The security module now fails the gate instead of reporting zero findings
	// (see security/CLAUDE.md).
	// +default="p/security-audit"
	sastRulesets string,
	// Output of `git diff <base>...HEAD`. Carries the change set to the intent
	// gate's coupling checks, which report here without gating. It does **not**
	// scope the risk infra scan: this stage runs on the push that already
	// merged, and scans the whole tree.
	// +optional
	diff *dagger.File,
	// Minimum coverage percentage gate (0 disables). See quality.Check.
	// +default="0"
	// +optional
	minCoverage float64,
	// Skip coverage gate for a language when coverable lines are below this threshold.
	// +default="0"
	// +optional
	coverageMinLines int,
	// Consumer-owned test command for witnessed BYO test execution (quality.Test).
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
	// Not forwarded in application mode (--app-id): that path runs ScanSource
	// code-only and ScanArchive artifact-only, so no vulnerability leg runs and
	// there is nothing to accept. Forwarding it there would warn UNUSED on
	// every app run.
	// Glob patterns whose license declarations are reported but not judged
	// against the policy, e.g. "docs/**". It narrows scope, never findings.
	// +optional
	licenseExclude []string,
	// Read licenses from source headers and LICENSE files as well as from
	// package metadata.
	// +default=true
	licenseFull bool,
	// Toolchain container image override for the BYO test command and the archive
	// build — the only digest-pinnable level (ADR-004). On the test side it
	// applies to testCmd only; a leg names its own.
	// +optional
	toolchainImage string,
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
	// --- container shape ---
	// Path to Dockerfile relative to src.
	// +default="Dockerfile"
	dockerfile string,
	// Target platform.
	// +default="linux/amd64"
	platform string,
	// --- archive shape ---
	// Build command, run via `sh -c` in the toolchain container (always explicit,
	// never auto-detected). Required for --artifact archive.
	// +optional
	buildCmd string,
	// Path of the build output directory, relative to the source root (e.g. "dist").
	// Required for --artifact archive.
	// +optional
	outputPath string,
	// --- heavier secrets ---
	// Restrict image secrets findings to live-verified credentials (adds
	// TruffleHog's --only-verified). Opt-in "heavier secrets" gate; container shape only.
	// +default=false
	verifySecrets bool,
	// --- delivery ---
	// Teams incoming webhook URL for notifications.
	// +optional
	teamsWebhook *dagger.Secret,
	// CI pipeline run URL shown in the Teams notification.
	// +optional
	runUrl string,
	// Optional app identity selects evidence-only application execution.
	// +optional
	appId string,
	// Literal checkout-relative files/folders belonging to the application.
	// +optional
	sourcePaths []string,
	// JSON array of witnessed lint commands and native report locations.
	// +optional
	lintLegs string,
	// Maximum independent check groups, and declared test legs, in flight, 1–4. Default preserves sequential execution.
	// +default=1
	parallelism int,
	// Maximum independent Node projects in repository mode. No truncation.
	// +default=4
	nodeProjectLimit int,
	// Restore/install and optionally compile once; tests and packaging share the resulting state.
	// Requires toolchain-image, prepare-language, and witnessed BYO tests.
	// +optional
	prepareCmd string,
	// Language using prepared dependencies: node or dotnet.
	// +optional
	prepareLanguage string,
	// Test leg that uses prepared state; required with test-legs, omitted with test-cmd.
	// +optional
	prepareTestLabel string,
) (*dagger.Directory, error) {
	// The refusals and their order live in commitinputs.go.
	shape, err := validateCommitInputs(commitInputs{
		parallelism: parallelism, nodeProjectLimit: nodeProjectLimit, artifact: artifact,
		buildCmd: buildCmd, outputPath: outputPath,
		prepareCmd: prepareCmd, prepareLanguage: prepareLanguage, toolchainImage: toolchainImage,
		prepareTestLabel: prepareTestLabel, testCmd: testCmd, testLegs: testLegs,
	})
	if err != nil {
		return nil, err
	}
	if err := appModeRefusal(appModeInputs{
		appID: appId, sourcePathCount: len(sourcePaths), lintLegs: lintLegs,
		testCmd: testCmd, hasBaseline: baseline != nil, hasTeamsWebhook: teamsWebhook != nil,
		includeCount: len(include), minCoverage: minCoverage, coverageMinLines: coverageMinLines,
		coveragePath: coveragePath, tolerance: tolerance, coverageGate: coverageGate,
		licenseExclude: len(licenseExclude), licenseFull: licenseFull, verifySecrets: verifySecrets,
		nodeProjectLimit: nodeProjectLimit,
	}); err != nil {
		return nil, err
	}
	var prepared *dagger.Container
	if prepareCmd != "" {
		prepared = dag.Quality().Prepare(src, prepareCmd, toolchainImage, repoUrl, dagger.QualityPrepareOpts{
			NpmFeedURL: npmFeedUrl, NpmFeedRouting: npmFeedRouting, NpmToken: npmToken, NugetFeedURL: nugetFeedUrl, NugetToken: nugetToken})
	}
	if appId != "" {
		config, err := parseAppConfig(appId, sourcePaths, lintLegs, testLegs)
		if err != nil {
			return nil, err
		}
		return runApp(ctx, src, config, appRunOptions{artifact: artifact, failOn: failOn, sastRulesets: sastRulesets,
			commitSha: commitSha, branch: branch, repoUrl: repoUrl,
			buildCmd: buildCmd, outputPath: outputPath, toolchainImage: toolchainImage,
			npmFeedURL: npmFeedUrl, npmFeedRouting: npmFeedRouting, npmToken: npmToken, nugetFeedURL: nugetFeedUrl, nugetToken: nugetToken,
			licenseGate: licenseGate, licenseAllow: licenseAllow, parallelism: parallelism, prepared: prepared, prepareLanguage: prepareLanguage, prepareTestLabel: prepareTestLabel, runURL: runUrl})
	}
	// Source gate: every code check runs for every shape via one stage-2 call.
	//
	// The change-intent gate is deliberately not among them, and this composite
	// exposes no --require-intent to turn it on. Intent asks whether the author
	// wrote down why the change exists — a question only answerable while the
	// change is still being reviewed. Commit runs on the push that already
	// merged, where a failure blocks nothing that can still be amended: it turns
	// main red over a document, and the artifact this stage exists to build and
	// scan never gets built. Quality, SAST, secrets, vuln and risk earn their
	// place here because they can find a defect in the code being shipped;
	// intent cannot. Opt in from the pre-commit pipeline instead.
	//
	// Stage2.Run returns a list of File objects, so the generated client takes a
	// ctx and returns ([]dagger.File, error). The artifact tail and finishAudit
	// work in []*dagger.File, so convert the value slice to pointers below.
	srcGateFiles, err := dag.Stage2().Run(
		ctx,
		src, commitSha, branch, repoUrl,
		dagger.Stage2RunOpts{
			FailOn:            failOn,
			Parallelism:       parallelism,
			NodeProjectLimit:  nodeProjectLimit,
			Prepared:          prepared,
			PreparedLanguage:  prepareLanguage,
			PreparedTestLabel: prepareTestLabel,
			PreparedImage:     preparedImageRef(prepared != nil, toolchainImage),
			Include:           include,
			SastRulesets:      sastRulesets,
			NpmFeedURL:        npmFeedUrl,
			NpmFeedRouting:    npmFeedRouting,
			NpmToken:          npmToken,
			NugetFeedURL:      nugetFeedUrl,
			NugetToken:        nugetToken,
			Diff:              diff,
			// Whole-tree infra scan. See stage-2's --infra-scope: the intent
			// gate still wants the change set, so the diff is still passed —
			// only the risk scan stops narrowing by it.
			InfraScope:       "tree",
			MinCoverage:      minCoverage,
			CoverageMinLines: coverageMinLines,
			TestCmd:          testCmd,
			TestLegs:         testLegs,
			CoveragePath:     coveragePath,
			Baseline:         baseline,
			Tolerance:        tolerance,
			CoverageGate:     coverageGate,
			LicenseGate:      licenseGate,
			LicenseAllow:     licenseAllow,
			VulnAccept:       vulnAccept,
			LicenseExclude:   licenseExclude,
			LicenseFull:      licenseFull,
			ToolchainImage:   toolchainImage,
		},
	)
	if err != nil {
		return nil, err
	}
	srcGate := make([]*dagger.File, len(srcGateFiles))
	for i := range srcGateFiles {
		srcGate[i] = &srcGateFiles[i]
	}

	// Artifact tail: shape-specific evidence appended to the source gate.
	var artifactEvidence []*dagger.File
	var payload *dagger.File
	switch shape {
	case artifactContainer:
		// Build the image once; SBOM and scan share the same lazy reference.
		buildSource := src
		if prepared != nil {
			buildSource = prepared.Directory("/src")
		}
		image := dag.Build().Build(
			buildSource, commitSha, branch, repoUrl,
			dagger.BuildBuildOpts{Dockerfile: dockerfile, Platform: platform},
		)
		if _, buildErr := image.Sync(ctx); buildErr != nil {
			artifactEvidence = []*dagger.File{dag.Evidence().Failure("build", "container", "", "Build failed; inspect the execution log.", commitSha, branch, repoUrl)}
			break
		}
		payload = image.AsTarball()
		artifactEvidence = []*dagger.File{
			dag.Build().Sbom(image, commitSha, branch, repoUrl),
			dag.Security().ScanImage(
				image, commitSha, branch, repoUrl,
				dagger.SecurityScanImageOpts{FailOn: failOn, VerifySecrets: verifySecrets, VulnAccept: vulnAccept},
			),
		}
	case artifactArchive:
		// Build the artifact once; the scan shares the same lazy directory reference.
		output := dag.Build().BuildArchive(
			src, buildCmd, outputPath, commitSha, branch, repoUrl,
			dagger.BuildBuildArchiveOpts{ToolchainImage: toolchainImage, Prepared: prepared, NpmFeedURL: npmFeedUrl, NpmFeedRouting: npmFeedRouting, NpmToken: npmToken, NugetFeedURL: nugetFeedUrl, NugetToken: nugetToken},
		)
		if _, buildErr := output.Sync(ctx); buildErr != nil {
			artifactEvidence = []*dagger.File{dag.Evidence().Failure("build", "archive", "", "Build failed; inspect the execution log.", commitSha, branch, repoUrl)}
			break
		}
		payload = dag.Build().Bundle(output)
		artifactEvidence = []*dagger.File{
			dag.Security().ScanArchive(
				src, output, commitSha, branch, repoUrl,
				dagger.SecurityScanArchiveOpts{
					FailOn: failOn,
					// The same credentials stage-2 handed ScanSource. ScanArchive
					// runs its own Trivy-FS leg over the same `src`, so omitting
					// them here would not merely skip a feature: the lockfile-free
					// .NET restore would run a second time, anonymously, and fail
					// against the private feed the first one reached. Identical
					// inputs make it a cache hit instead.
					NugetFeedURL: nugetFeedUrl,
					NugetToken:   nugetToken,
					VulnAccept:   vulnAccept,
				},
			),
		}
	case artifactNone:
		// No artifact build. The SBOM comes from stage-2's scan-source Trivy-FS
		// CycloneDX (source lockfiles), already present in srcGate.
		//
		// And that absence is stated rather than left to be inferred. This
		// branch used to be the comment above and nothing else, so the audit of
		// a repository shipping a dozen deployables and the audit of a
		// repository shipping none were byte-identical — same passed=true, same
		// sbom.cdx.json, no record anywhere that no artifact had been built,
		// SBOM'd or scanned. That is the founding doctrine (a tool that could
		// not run must never read as clean) on the artifact side, reached
		// through a selector value instead of a crashed scanner, and it is the
		// same failure mode as an opt-in gate that is switched off.
		//
		// build.NoArtifact is a warned pass, not a failure: a library or an
		// infra repo genuinely has nothing deployable, and --fail-on NONE does
		// not suppress a non-run, so failing here would be a permanent red with
		// no remedy. See src/build/noartifact.go.
		artifactEvidence = []*dagger.File{
			dag.Build().NoArtifact(commitSha, branch, repoUrl),
		}
	default:
		// Unreachable: parseArtifactShape admits only the three arms above.
		// Kept as a refusal rather than a silent fall-through, so a fourth
		// shape added to the type without an arm here is loud.
		return nil, fmt.Errorf("invalid --artifact %q: want container|archive|none", artifact)
	}

	audit := finishAudit(append(srcGate, artifactEvidence...), "commit", auditOpts{
		commitSha:    commitSha,
		branch:       branch,
		repoUrl:      repoUrl,
		runUrl:       runUrl,
		teamsWebhook: teamsWebhook,
	})
	artifactPlatform := ""
	if shape == artifactContainer {
		artifactPlatform = platform
	}
	return retainArtifact(audit, payload, string(shape), commitSha, branch, repoUrl, runUrl, "", toolchainImage, artifactPlatform), nil
}
