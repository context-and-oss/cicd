//go:build !unit_test

// The container half of the Roslyn security-analyzer leg: discovery, the
// build, and reading back what the build left. Every decision is in
// roslyn.go, untagged, where the unit suite reaches it.
package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
	"strings"
)

// runRoslyn builds every C#/VB project in the tree with the SDK's security
// analyzers switched on and returns the leg's result. A tree without a .NET
// project returns a result with Present false: the leg has no row.
//
// The tree is copied, never mounted: the build writes bin/ and obj/ into it,
// and nothing it writes leaves the container except the logs and the status
// files the script keeps.
func runRoslyn(ctx context.Context, src *dagger.Directory, feedUrl string, feedToken *dagger.Secret) roslynResult {
	contents := map[string]string{}
	for _, pattern := range roslynProjectGlobs {
		matches, err := src.Glob(ctx, pattern)
		if err != nil {
			return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — could not list the "+
				".NET project files (%s): %w", roslynToolName, pattern, err)}
		}
		for _, m := range matches {
			if roslynInBuildOutput(m) {
				continue
			}
			body, err := src.File(m).Contents(ctx)
			if err != nil {
				return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — could not read "+
					"the project file %s: %w", roslynToolName, m, err)}
			}
			contents[m] = body
		}
	}
	scope := classifyRoslynProjects(contents)
	if len(scope.Build) == 0 {
		return roslynScopeOnly(scope)
	}

	req, err := discoverDotnetBandRequest(ctx, src)
	if err != nil {
		return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — could not read which .NET "+
			"SDK band this tree asks for: %w", roslynToolName, err)}
	}
	band, note := dotnetResolveBand(req)
	base, ok := dotnetSDKBase(band)
	if !ok {
		return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — no pinned .NET SDK image "+
			"for band %s (cicd pins %s)", roslynToolName, band, dotnetBandsLabel())}
	}

	ctr := base.
		WithMountedCache(nugetPackagesPath, dag.CacheVolume(nugetPackagesVolume), dagger.ContainerWithMountedCacheOpts{Sharing: dagger.CacheSharingModePrivate}).
		WithDirectory(roslynMount, src).
		WithWorkdir(roslynMount).
		WithEnvVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1").
		WithEnvVariable("DOTNET_NOLOGO", "1").
		WithEnvVariable("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1").
		WithNewFile(roslynTargetsPath, roslynTargets).
		WithNewFile(roslynProjectsPath, roslynProjectsFile(scope.Build))

	if feedUrl != "" && feedToken != nil {
		ctr = ctr.
			WithNewFile("/root/.nuget/NuGet/NuGet.Config",
				nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, feedUrl), feedUrl)).
			WithSecretVariable("NUGET_AUTH_TOKEN", feedToken)
	}

	ctr = ctr.WithExec([]string{"sh", "-c", roslynBuildScript()})

	out := roslynOutcome{Band: band, BandNote: note}
	// The script always exits 0 and writes every status down, so an
	// unreadable status file means the exec itself did not complete.
	read := func(path string) (string, error) {
		s, err := ctr.File(path).Contents(ctx)
		if err != nil {
			return "", fmt.Errorf("%s: SAST did not run — the build container did not complete (%s "+
				"unreadable): %w", roslynToolName, path, err)
		}
		return s, nil
	}
	failed, err := read(roslynFailedPath)
	if err != nil {
		return roslynResult{Present: true, Err: err, Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
	}
	for _, line := range strings.Split(failed, "\n") {
		if p := roslynSidecarProject(line); p != "" {
			out.Failed = append(out.Failed, p)
		}
	}
	if out.Output, err = read(roslynOutPath); err != nil {
		return roslynResult{Present: true, Err: err, Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
	}
	if out.Stderr, err = read(roslynErrPath); err != nil {
		return roslynResult{Present: true, Err: err, Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
	}

	logs := ctr.Directory(roslynOutDir)
	entries, err := logs.Entries(ctx)
	if err != nil {
		return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — could not list the "+
			"analyzer logs: %w", roslynToolName, err), Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
	}
	for _, name := range entries {
		id, isSidecar := strings.CutSuffix(name, ".project")
		if !isSidecar {
			continue
		}
		sidecar, err := logs.File(name).Contents(ctx)
		if err != nil {
			return roslynResult{Present: true, Err: fmt.Errorf("%s: could not read the analyzer log index "+
				"%s: %w", roslynToolName, name, err), Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
		}
		sarif, err := logs.File(id + ".sarif").Contents(ctx)
		if err != nil {
			// The target ran and CoreCompile did not write a log: the compile
			// was skipped (up to date) or never started. Not a log, so the
			// project reads as not analysed unless another compile of it was.
			continue
		}
		out.Logs = append(out.Logs, roslynLog{Project: roslynSidecarProject(sidecar), SARIF: []byte(sarif)})
	}
	return analyseRoslyn(scope, out)
}
