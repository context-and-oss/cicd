//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
)

// runTrivySbom rescans an existing CycloneDX document with trivy sbom.
//
// The shared flag policy is in trivyflags.go, the same pins the fs and image
// scans carry — notably --scanners vuln and the severity/status/pkg-type
// un-filters. No source tree is mounted here, so no consumer trivy.yaml is in
// play; the flags are pinned anyway so the three scans cannot drift apart.
// The convert step re-renders the document from the scan's own native report,
// so the CycloneDX in the envelope describes this rescan, not the input.
func runTrivySbom(ctx context.Context, sbom *dagger.File, accepted *vulnAccepter) (trivyResult, error) {
	ctr := dag.Container().
		From(trivyImage).
		WithMountedCache(trivyCachePath, dag.CacheVolume(trivyCacheVolume)).
		WithMountedFile("/sbom/bom.json", sbom).
		WithExec(trivyScanArgs("sbom", "/sbom/bom.json")).
		WithExec(trivyConvertArgs())

	res, err := readTrivyResult(ctx, ctr, accepted)
	if err != nil {
		return trivyResult{}, fmt.Errorf("trivy sbom: %w", err)
	}
	return res, nil
}
