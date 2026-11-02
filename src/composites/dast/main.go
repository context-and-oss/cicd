//go:build !unit_test

package main

import (
	"context"

	"dagger/dast/internal/dagger"
)

// pipelineName is the label notify renders into the comment and the Teams
// card. It is not "commit" and not "acceptance": DAST runs on its own cadence
// — baseline on mainline and nightly, full on demand and weekly — so a reader
// seeing this name knows which run they are looking at.
const pipelineName = "dast"

// Dast scans running applications, then packages the detached evidence in a
// separate call. It runs on its own cadence — not inside the commit stage.
type Dast struct{}

// Scan scans a running application and returns its evidence file.
//
// One entry point, shape as a parameter (ADR-005). --app selects which of the
// three sources ScanWeb is given, and it is always explicit:
//
//   - url       → the consumer runs the application somewhere the engine can
//     reach, and passes --target. cicd built none of it, so the
//     evidence states that the running code's provenance is not
//     attested.
//   - service   → the consumer runs the application on the CI runner (a
//     compose stack, a dotnet run) and passes
//     --service=tcp://localhost:5000. cicd binds it under a fixed
//     alias and composes the address itself. Same provenance
//     caveat: it is the consumer's process.
//   - container → cicd builds the image from --src and --dockerfile, starts it
//     inside the engine and scans that. This is the only shape
//     whose evidence can say the scanned code is the code this
//     commit produced.
//
// The application is never deployed and never published — the same ADR-001
// line the commit stage holds. cicd starts a container only for --app
// container, and starts nothing else beside it: no database, no sidecar, no
// host Docker socket. An application that needs a stack around it is the
// consumer's to start, which is what --app service is for.
//
// The gate is ScanWeb's: findings at or above --fail-on fail the run, and a
// readiness probe that never got a served response fails it at every
// threshold including NONE, because a target that was never reached produces a
// report of zero alerts that is otherwise byte-identical to a clean scan.
//
// A service-shaped result must be exported immediately as a single File. The
// reusable workflow writes it to the runner, then passes that detached file to
// Package in a fresh Dagger call. Returning a Directory retains the service
// graph, while transporting a large File through `contents` can leave the CLI
// waiting after both calls report DONE.
func (m *Dast) Scan(
	ctx context.Context,
	// Git commit SHA — used to label the built image and for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,

	// --- shape ---
	// Which source the scan runs against: url|service|container. Always
	// explicit (ADR-001 — cicd never auto-detects the shape).
	// +default="url"
	app string,
	// Source directory holding the Dockerfile. Required for --app container,
	// and refused for the other two shapes, which build nothing.
	// +optional
	src *dagger.Directory,
	// Path to the Dockerfile relative to src.
	// +default="Dockerfile"
	dockerfile string,
	// Target platform for the built image.
	// +default="linux/amd64"
	platform string,
	// Full HTTP/S URL of a running target the engine can reach. Required for
	// --app url.
	// +optional
	target string,
	// A service to bind and scan, e.g. --service=tcp://localhost:5000 for an
	// application the workflow started on the runner. Required for --app service.
	// +optional
	service *dagger.Service,

	// --- address (--app service and --app container; --app url carries its own) ---
	// Port the application answers on.
	// +default=8080
	port int,
	// http or https.
	// +default="http"
	scheme string,
	// Path the application is served under.
	// +default="/"
	basePath string,
	// Path the readiness probe requests. Defaults to the base path.
	// +optional
	healthPath string,
	// How long to wait for the application to answer before recording a non-run.
	// +default=120
	readyTimeoutSeconds int,

	// --- scan ---
	// Scan mode: baseline (passive) | api (from a document) | full (active).
	// +default="baseline"
	mode string,
	// API document to drive --mode api from. Mutually exclusive with
	// --api-spec-path.
	// +optional
	apiSpec *dagger.File,
	// Path the application serves its API document on, e.g.
	// /swagger/v1/swagger.json. Mutually exclusive with --api-spec.
	// +optional
	apiSpecPath string,
	// Format of the API document: openapi | soap | graphql.
	// +default="openapi"
	apiFormat string,
	// ZAP rule configuration (-c). Every rule it names is reported in the
	// evidence, including any that raised no alert.
	// +optional
	ruleConfig *dagger.File,
	// Cap the whole scan at this many minutes (ZAP -T). 0 means no cap; an
	// uncapped active scan against a slow target can run for hours.
	// +default=0
	maxDurationMinutes int,
	// The configuration the application ran under, e.g. "Staging". Recorded
	// in the evidence and never interpreted — cicd cannot check the claim.
	// +optional
	profile string,
	// Set when the scan exercised a real login. Absent means the findings
	// describe the anonymous surface only, and the evidence says so.
	// +optional
	authenticated bool,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE.
	// ZAP's maximum risk is High, so CRITICAL can never fail over findings and
	// the evidence warns when it is used.
	// +default="HIGH"
	failOn string,

) (*dagger.File, error) {
	// Everything decidable without starting a container is decided first, and
	// a failure here returns an error rather than an audit directory. An audit
	// directory is a thing a consumer reads as a verdict.
	if err := validateApp(app, appInputs{
		Target:     target,
		HasService: service != nil,
		HasSrc:     src != nil,
		Port:       port,
		Mode:       mode,
	}); err != nil {
		return nil, err
	}

	scanOpts := dagger.SecurityScanWebOpts{
		Mode:                mode,
		Port:                port,
		Scheme:              scheme,
		BasePath:            basePath,
		HealthPath:          healthPath,
		ReadyTimeoutSeconds: readyTimeoutSeconds,
		APISpec:             apiSpec,
		APISpecPath:         apiSpecPath,
		APIFormat:           apiFormat,
		RuleConfig:          ruleConfig,
		MaxDurationMinutes:  maxDurationMinutes,
		Profile:             profile,
		Authenticated:       authenticated,
		FailOn:              failOn,
	}

	switch app {
	case appURL:
		scanOpts.Target = target
	case appService:
		scanOpts.Service = service
	case appContainer:
		// build.Build returns the lazy container reference, exactly as the
		// commit composite hands one to build.Sbom and security.ScanImage.
		// ScanWeb exposes the port and calls AsService() on it, so the image
		// under test is started by the module that scans it and by nothing
		// else.
		scanOpts.Container = dag.Build().Build(
			src, commitSha, branch, repoUrl,
			dagger.BuildBuildOpts{Dockerfile: dockerfile, Platform: platform},
		)
	}

	return dag.Security().ScanWeb(commitSha, branch, repoUrl, scanOpts), nil
}

// Package wraps a detached scan evidence file, writes the GitHub comment, and
// optionally sends the Teams notification. It deliberately accepts no Service:
// callers persist Scan's File on the host first, so exporting the returned
// Directory cannot retain or wait on a live runner tunnel.
func (m *Dast) Package(
	ctx context.Context,
	// Evidence file produced by Scan and detached onto the caller's filesystem.
	evidence *dagger.File,
	// Git commit SHA used for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Teams incoming webhook URL for notifications.
	// +optional
	teamsWebhook *dagger.Secret,
	// CI pipeline run URL shown in the notification.
	// +optional
	runUrl string,
) (*dagger.Directory, error) {
	return finishAudit([]*dagger.File{evidence}, pipelineName, auditOpts{
		commitSha:    commitSha,
		branch:       branch,
		repoUrl:      repoUrl,
		runUrl:       runUrl,
		teamsWebhook: teamsWebhook,
	}), nil
}
