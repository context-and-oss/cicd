//go:build !unit_test

package main

import (
	"dagger/stage-4/internal/dagger"
)

// Stage4 is the artifact-gate orchestrator of the CD model: it builds the OCI
// image, writes its SBOM and scans the image, sharing one lazy container
// reference across the three so every step attests the same bytes. It holds no
// decisions of its own; scripts/smoke/stage-orchestrators.sh is its proof.
type Stage4 struct{}

// Run executes the full commit stage: build OCI image, generate SBOM, and run image security scan.
// Returns a slice of evidence files — one from build/sbom and one from security/scan-image.
// Pass these to cross-cutting/evidence to produce combined-evidence.json.
func (m *Stage4) Run(
	// Source directory (must contain a Dockerfile).
	src *dagger.Directory,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Path to Dockerfile relative to src.
	// +default="Dockerfile"
	dockerfile string,
	// Target platform.
	// +default="linux/amd64"
	platform string,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
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
) []*dagger.File {
	image := dag.Build().Build(
		src, commitSha, branch, repoUrl,
		dagger.BuildBuildOpts{
			Dockerfile: dockerfile,
			Platform:   platform,
		},
	)

	sbomEvidence := dag.Build().Sbom(image, commitSha, branch, repoUrl)

	securityEvidence := dag.Security().ScanImage(
		image, commitSha, branch, repoUrl,
		dagger.SecurityScanImageOpts{
			FailOn:     failOn,
			VulnAccept: vulnAccept,
		},
	)

	return []*dagger.File{sbomEvidence, securityEvidence}
}
