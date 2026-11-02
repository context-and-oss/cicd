//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
)

// runTrivyImage runs Trivy against a container image.
// The image is exported to a tar archive and scanned with trivy image --input.
//
// The shared flag policy is in trivyflags.go — notably --scanners vuln, whose
// absence combined with "--format cyclonedx" turned the image scan into SBOM
// generation with security scanning switched off, so the stage-4 image gate
// reported zero vulnerabilities no matter what the image contained. No source
// tree is mounted here, so no consumer trivy.yaml is in play; the same flags are
// pinned anyway so the two scans cannot drift apart.
func runTrivyImage(ctx context.Context, image *dagger.Container, accepted *vulnAccepter) (trivyResult, error) {
	// Export the container image as a tar archive.
	tarFile := image.AsTarball()

	ctr := dag.Container().
		From(trivyImage).
		WithMountedCache(trivyCachePath, dag.CacheVolume(trivyCacheVolume)).
		WithMountedFile("/image.tar", tarFile).
		WithExec(trivyScanArgs("image", "--input", "/image.tar")).
		WithExec(trivyConvertArgs())

	res, err := readTrivyResult(ctx, ctr, accepted)
	if err != nil {
		return trivyResult{}, fmt.Errorf("trivy image: %w", err)
	}
	return res, nil
}
