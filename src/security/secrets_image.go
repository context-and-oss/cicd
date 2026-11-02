//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"fmt"
	"strings"
)

// runTrufflehog scans a container image's filesystem for secrets using TruffleHog.
// It mounts the container's root filesystem and scans it with trufflehog filesystem mode.
// Everything it does with the output — argument shape, parsing, SARIF — lives in
// trufflehogreport.go, untagged, so the unit suite actually runs it.
func runTrufflehog(ctx context.Context, image *dagger.Container, verifySecrets bool) (json.RawMessage, []finding, error) {
	out, err := dag.Container().
		From(trufflehogImage).
		WithMountedDirectory(trufflehogMountRoot, image.Rootfs()).
		WithExec(trufflehogArgs(verifySecrets)).
		Stdout(ctx)

	findings, errs := parseTrufflehogOutput(out, err)
	if len(errs) > 0 {
		return nil, nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	// Build a minimal SARIF document from findings.
	sarifRaw := buildTrufflehogSARIF(findings)
	return sarifRaw, findings, nil
}
