//go:build !unit_test

// The container half of the Go licence read: go mod edit over every go.mod, then
// go mod download from the Go module proxy, then the snapshot Trivy reads
// licences from. Everything that decides anything lives in licencegomod.go,
// untagged, where the unit suite reaches it.
package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
	"path"
)

// downloadGoModules downloads every module the go.mod files require and returns
// a GOPATH root holding each module's top-level files, and what happened, for
// the caller to report. The snapshot is nil when there was nothing to download.
//
// gomods are mount-relative paths from goLicenceDownloadNeeded. They reach the
// container as argv and as data files, never as script text.
//
// The module cache volume is mounted PRIVATE for the reason nugetPackagesVolume
// is: stage-2 at --parallelism > 1 can run two of these side by side, and the go
// command's cache lock is not something this file should have to trust across
// containers sharing one volume.
func downloadGoModules(ctx context.Context, src *dagger.Directory, gomods []string) (*dagger.Directory, goDownloadOutcome, error) {
	base := dag.Container().
		From(golangImage).
		WithEnvVariable("GOTOOLCHAIN", "local").
		WithEnvVariable("GOWORK", "off").
		WithEnvVariable("GOFLAGS", "").
		WithEnvVariable("GOPROXY", goModuleProxy).
		WithEnvVariable("GOMODCACHE", goModCachePath).
		WithMountedDirectory(goSrcMount, src).
		WithDirectory(goWorkDir, dag.Directory()).
		WithWorkdir(goWorkDir)

	args := []string{"sh", "-c", goModEditScript(), "sh"}
	for _, gm := range gomods {
		args = append(args, path.Join(goSrcMount, gm))
	}
	edit := base.WithExec(args)

	// The script always exits 0 and writes every status down, so an unreadable
	// file here means the exec itself did not complete.
	if _, err := edit.File(goEditDonePath).Contents(ctx); err != nil {
		return nil, goDownloadOutcome{}, fmt.Errorf("security license scan: go mod edit did not complete, "+
			"so which Go modules the tree requires is unknown and no Go licence was read: %w", err)
	}
	stream, err := edit.File(goEditOutPath).Contents(ctx)
	if err != nil {
		return nil, goDownloadOutcome{}, fmt.Errorf("security license scan: could not read go mod edit's "+
			"output, so which Go modules the tree requires is unknown: %w", err)
	}

	plan := planGoDownload(gomods, stream)
	if len(plan.Refs) == 0 {
		return nil, goDownloadOutcome{Plan: plan}, nil
	}

	dl := base.
		WithMountedCache(goModCachePath, dag.CacheVolume(goModCacheVolume), dagger.ContainerWithMountedCacheOpts{Sharing: dagger.CacheSharingModePrivate}).
		WithNewFile(goDownloadArgsPath, goDownloadArgs(plan.Refs)).
		WithNewFile(goDownloadRelsPath, goDownloadRels(plan.Refs)).
		WithExec([]string{"sh", "-c", goDownloadScript()})

	if _, err := dl.File(goDownloadDonePath).Contents(ctx); err != nil {
		return nil, goDownloadOutcome{Plan: plan}, fmt.Errorf("security license scan: the Go module "+
			"download did not complete, so no Go module licence was read: %w", err)
	}
	var run goDownloadRun
	for _, f := range []struct {
		path string
		dst  *string
	}{
		{goDownloadExitPath, &run.Exit},
		{goDownloadOutPath, &run.JSON},
		{goDownloadErrPath, &run.Stderr},
		{goCopiedPath, &run.Copied},
		{goCopyFailedPath, &run.CopyFailed},
	} {
		s, err := dl.File(f.path).Contents(ctx)
		if err != nil {
			return nil, goDownloadOutcome{Plan: plan}, fmt.Errorf("security license scan: could not read "+
				"%s from the Go module download, so what it did is unknown: %w", f.path, err)
		}
		*f.dst = s
	}
	return dl.Directory(goSnapshotPath), classifyGoDownload(plan, run), nil
}
