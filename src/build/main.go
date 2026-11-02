//go:build !unit_test

package main

import (
	"context"
	"dagger/build/internal/dagger"
	"encoding/json"
	"fmt"
	"time"
)

// Build is the Dagger module that produces the deployable: an OCI image from a
// Dockerfile (Build), a CycloneDX SBOM of it (Sbom), a built archive from a
// consumer command (BuildArchive), or the attested absence of one (NoArtifact);
// Bundle and ArtifactManifest bind an archive output to its evidence. It never
// publishes what it builds (ADR-001). moduleName and moduleStage live
// in noartifact.go, which is untagged, so the -tags unit_test suite can build an
// envelope with the identity that ships.
type Build struct{}

// Build builds a container image from a Dockerfile and returns the built container.
// The returned container can be passed directly to Sbom or security.ScanImage.
func (m *Build) Build(
	ctx context.Context,
	// Source directory (must contain a Dockerfile).
	src *dagger.Directory,
	// Path to Dockerfile relative to src.
	// +default="Dockerfile"
	dockerfile string,
	// Target platform.
	// +default="linux/amd64"
	platform string,
	// Git commit SHA — used to label the image.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
) (*dagger.Container, error) {
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if platform == "" {
		platform = "linux/amd64"
	}
	ctr := src.DockerBuild(dagger.DirectoryDockerBuildOpts{
		Dockerfile: dockerfile,
		Platform:   dagger.Platform(platform),
	}).
		WithLabel("org.opencontainers.image.revision", commitSha).
		WithLabel("org.opencontainers.image.source", repoUrl).
		WithLabel("org.opencontainers.image.ref.name", branch)
	if _, err := ctr.Sync(ctx); err != nil {
		return nil, fmt.Errorf("docker build failed: %w", err)
	}
	return ctr, nil
}

// Sbom generates a CycloneDX SBOM from a container image using Trivy.
// Returns an evidence envelope containing the CycloneDX JSON report.
func (m *Build) Sbom(
	ctx context.Context,
	// Built container image to analyse.
	image *dagger.Container,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
) (*dagger.File, error) {
	start := time.Now()
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	cdxRaw, err := runTrivySbom(ctx, image)
	fold := foldSbom(cdxRaw, err)

	env := &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool:          toolInfo{Name: "trivy", Version: trivyVersion},
		Repo:          repo,
		TimestampUTC:  start.UTC(),
		DurationMS:    time.Since(start).Milliseconds(),
		Passed:        fold.ran,
		// An SBOM either came back or it did not; there is no findings count to
		// report and no subject that can fail on its own. A failed scan is
		// ERROR, not CLEAN, which is the whole distinction: an absent SBOM must
		// not read as an image with nothing in it.
		Outcome:  scanOutcome(fold.ran, 0),
		Examined: fold.examined,
		// The inventory itself, not the vulnerabilities in it. Trivy appears
		// under two concerns across this pipeline and the tool name cannot
		// tell them apart — here it is generating the component list, in
		// security it is scanning one. Precisely the ambiguity a derived
		// concern would have resolved wrongly.
		Concern:         ConcernSBOM,
		CycloneDXReport: fold.report,
		Errors:          fold.errs,
		Warnings:        fold.warnings,
	}

	data, err2 := json.Marshal(env)
	if err2 != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err2)
	}
	return dag.Directory().WithNewFile("evidence.json", string(data)).File("evidence.json"), nil
}

// runTrivySbom exports the container as a tarball and scans it with Trivy in CycloneDX format.
func runTrivySbom(ctx context.Context, image *dagger.Container) (string, error) {
	tarFile := image.AsTarball()

	out, err := dag.Container().
		From(trivyImage).
		WithMountedFile("/image.tar", tarFile).
		WithExec([]string{
			"trivy", "image",
			"--format", "cyclonedx",
			"--output", "/tmp/sbom.cdx.json",
			"--exit-code", "0",
			"--input", "/image.tar",
		}).
		File("/tmp/sbom.cdx.json").
		Contents(ctx)

	if err != nil {
		return "", fmt.Errorf("trivy sbom: %w", err)
	}
	return out, nil
}

// NoArtifact returns the evidence envelope for a pipeline run that built and
// attested no artifact — the record behind `--artifact none`.
//
// It is the only function in this module that runs no tool, and that is the
// point: an artifact tail that did not run leaves an audit indistinguishable
// from an artifact tail that ran and found nothing, so the run says so instead.
// The envelope passes (a repository with no deployable artifact is legitimate)
// and carries the disclosure in warnings, which notify renders verbatim into
// the PR comment, plus `genericReport.artifactAttested: false` for machines.
// The wording and the reasoning live in noartifact.go.
func (m *Build) NoArtifact(
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Application mode has deferred dependency assessment and emits no SBOM.
	// +optional
	sbomDisabled bool,
) (*dagger.File, error) {
	data, err := noArtifactEvidence(commitSha, branch, repoUrl, time.Now())
	if sbomDisabled {
		e, envelopeErr := noArtifactEnvelope(commitSha, branch, repoUrl, time.Now())
		if envelopeErr != nil {
			return nil, envelopeErr
		}
		e.Warnings = []string{"artifact: NOT ATTESTED — artifact=none selected. No deployable was built or scanned. SBOM generation and dependency assessment are disabled for this application run."}
		e.GenericReport = json.RawMessage(`{"artifactAttested":false,"artifactShape":"none","sbomGenerated":false}`)
		b, marshalErr := json.Marshal(e)
		data, err = string(b), marshalErr
	}
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithNewFile("evidence.json", data).File("evidence.json"), nil
}
