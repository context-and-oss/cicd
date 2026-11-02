//go:build !unit_test

package main

import "dagger/commit/internal/dagger"

// The public directory keeps existing evidence paths and adds a separate
// artifacts subtree. Workflows upload it independently from audit reports.
func retainArtifact(audit *dagger.Directory, payload *dagger.File, kind, commitSha, branch, repoUrl, runUrl, appID, image, platform string) *dagger.Directory {
	if payload == nil {
		return audit
	}
	name := "application.tar.gz"
	if kind == "container" {
		name = "image.tar"
	}
	evidence := audit.File("combined-evidence.json")
	manifest := dag.Build().ArtifactManifest(payload, evidence, kind, name, commitSha, branch, repoUrl,
		dagger.BuildArtifactManifestOpts{RunURL: runUrl, AppID: appID, ToolchainImage: image, Platform: platform})
	artifacts := dag.Directory().WithFile(name, payload).WithFile("artifact-manifest.json", manifest).WithFile("combined-evidence.json", evidence)
	return audit.WithFile("artifact-manifest.json", manifest).WithDirectory("artifacts", artifacts)
}
