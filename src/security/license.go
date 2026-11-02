//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"dagger/security/internal/dagger"
)

// runTrivyLicense runs a Trivy license scan over src and returns its native
// JSON report.
//
// The container mirrors runTrivyFS deliberately: same pinned image, same cache
// volume, and the same /src working directory, which is what makes a
// consumer-owned trivy.yaml take effect for *scope* — its skip-dirs should
// narrow a license scan exactly as it narrows a vulnerability scan. What that
// file must not be able to narrow is the findings, and licenseflags.go pins the
// flags that would let it.
//
// This is a separate invocation from the vulnerability scan rather than a second
// scanner on the same command line. licenseflags.go carries the full reasoning;
// the short version is that `--scanners vuln` is a security pin with a
// documented silent-zero interaction with output formats, and the license report
// is a third output shape.
//
// No report file is not zero findings. A Trivy that could not run leaves nothing
// at trivyLicensePath, and the file read fails — which reaches the caller as an
// error and sets ran=false, rather than as an empty Licenses[] that would read
// downstream as a policy nothing violated.
//
// nuspecs, when set, is the restore's .nuspec snapshot (licencenuget.go),
// mounted where Trivy looks NuGet packages up (a directory mount is
// copy-on-write, so nothing Trivy writes there reaches the snapshot). Without it a .NET tree
// yields no NuGet licence at all, lockfile or not.
//
// gopath, when set, is the Go module snapshot (licencegomod.go), a GOPATH root
// Trivy reads $GOPATH/pkg/mod from. Without it a Go tree yields no module
// licence at all: go.mod and go.sum name versions, not licences.
func runTrivyLicense(ctx context.Context, src *dagger.Directory, full bool, nuspecs, gopath *dagger.Directory) (json.RawMessage, error) {
	ctr := dag.Container().
		From(trivyImage).
		WithMountedCache(trivyCachePath, dag.CacheVolume(trivyCacheVolume)).
		WithMountedDirectory("/src", src)
	if nuspecs != nil {
		ctr = ctr.WithMountedDirectory(nugetPackagesPath, nuspecs)
	}
	if gopath != nil {
		// Trivy looks a Go module's licence up under $GOPATH/pkg/mod.
		ctr = ctr.
			WithMountedDirectory(trivyGopathMount, gopath).
			WithEnvVariable("GOPATH", trivyGopathMount)
	}
	ctr = ctr.
		WithWorkdir(trivyConfigDir).
		WithExec(trivyLicenseScanArgs(full, "/src"))

	raw, err := ctr.File(trivyLicensePath).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("security license scan: Trivy left no license report, so which "+
			"licenses the dependency tree carries is unknown: %w", err)
	}
	return json.RawMessage(raw), nil
}

func runTrivyLicenseSbom(ctx context.Context, sbom *dagger.File) (json.RawMessage, error) {
	raw, err := sbom.Contents(ctx)
	if err != nil {
		return nil, err
	}
	if msg := sbomInputError(raw); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}
	args := trivyLicenseScanArgs(false, "/sbom/bom.json")
	args[1] = "sbom"
	ctr := dag.Container().From(trivyImage).
		WithMountedCache(trivyCachePath, dag.CacheVolume(trivyCacheVolume)).
		WithMountedFile("/sbom/bom.json", sbom).WithExec(args)
	result, err := ctr.File(trivyLicensePath).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("trivy SBOM licence scan produced no usable evidence: %w", err)
	}
	return json.RawMessage(result), nil
}
