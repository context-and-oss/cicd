//go:build !unit_test

package main

import (
	"context"
	"dagger/build/internal/dagger"
	"encoding/json"
	"fmt"
	"strings"
)

// Bundle retains an archive-shaped output, including dotfiles, symlinks and
// executable modes. No build command runs during this transport operation.
func (m *Build) Bundle(outputDir *dagger.Directory) *dagger.File {
	return dag.Container().From(alpineImage).
		WithMountedDirectory("/input", outputDir).
		WithExec([]string{"tar", "-czf", "/application.tar.gz", "-C", "/input", "."}).
		File("/application.tar.gz")
}

// ArtifactManifest binds exact transport bytes to exact combined evidence.
// An OCI tar checksum is a transport identity, not a registry manifest digest.
func (m *Build) ArtifactManifest(
	ctx context.Context,
	payload, evidence *dagger.File,
	kind, name, commitSha, branch, repoUrl string,
	// +optional
	runUrl string,
	// +optional
	appId string,
	// +optional
	toolchainImage string,
	// +optional
	platform string,
) (*dagger.File, error) {
	checksums, err := dag.Container().From(alpineImage).
		WithMountedFile("/payload", payload).WithMountedFile("/evidence", evidence).
		WithExec([]string{"sha256sum", "/payload", "/evidence"}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("hash artifact and evidence: %w", err)
	}
	fields := strings.Fields(checksums)
	if len(fields) != 4 {
		return nil, fmt.Errorf("could not read artifact checksums")
	}
	raw, err := evidence.Contents(ctx)
	if err != nil {
		return nil, err
	}
	manifest, err := makeArtifactManifest([]byte(raw), kind, name, fields[0], fields[2], commitSha, branch, repoUrl, runUrl, appId, toolchainImage, platform)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithNewFile("artifact-manifest.json", string(data)+"\n").File("artifact-manifest.json"), nil
}
