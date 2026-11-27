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
	"sync"
)

// runRoslyn builds every C#/VB project in the tree with the SDK's security
// analyzers switched on and returns the leg's result. A tree without a .NET
// project returns a result with Present false: the leg has no row.
//
// The tree is copied, never mounted: the build writes bin/ and obj/ into it,
// and nothing it writes leaves the container except the logs and the status
// files the script keeps.
func runRoslyn(ctx context.Context, src *dagger.Directory, feedUrl string, feedToken *dagger.Secret) roslynResult {
	var paths []string
	for _, pattern := range roslynProjectGlobs {
		matches, err := src.Glob(ctx, pattern)
		if err != nil {
			return roslynResult{Present: true, Err: fmt.Errorf("%s: SAST did not run — could not list the "+
				".NET project files (%s): %w", roslynToolName, pattern, err)}
		}
		for _, m := range matches {
			if !roslynInBuildOutput(m) {
				paths = append(paths, m)
			}
		}
	}
	contents, err := readProjectFiles(ctx, src, paths)
	if err != nil {
		return roslynResult{Present: true, Err: err}
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
		WithNewFile(roslynTargetsPath, roslynTargets)

	if feedUrl != "" && feedToken != nil {
		ctr = ctr.
			WithNewFile("/root/.nuget/NuGet/NuGet.Config",
				nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, feedUrl), feedUrl)).
			WithSecretVariable("NUGET_AUTH_TOKEN", feedToken)
	}
	notRun := func(err error) roslynResult {
		return roslynResult{Present: true, Err: err, Examined: &Examined{Unit: roslynExamined, Total: scope.total()}}
	}

	// The combined build: every project the solution can name, in one
	// parallel MSBuild call.
	sln, unlisted := roslynSolution(scope.Build)
	final := ctr
	var fast roslynFastResult
	if roslynFastNeeded(scope.Build, unlisted) {
		fastCtr := ctr.
			WithNewFile(roslynSolutionPath, sln).
			WithExec([]string{"sh", "-c", roslynFastScript()})
		logs, started, built, err := readRoslynOutputs(ctx, fastCtr)
		if err != nil {
			// The per-project builds then start on a fresh container: one
			// that did not complete (a node killed for memory, say) is not
			// one to build on.
			fast.Err = err
		} else {
			final = fastCtr
			fast = roslynFastResult{Logs: logs, Started: started, Failed: roslynMarkerFailures(started, built)}
		}
	}

	// The per-project builds, for whatever the combined build did not
	// analyse or did not build cleanly.
	retry := roslynFallback(scope.Build, unlisted, fast)
	if len(retry) > 0 {
		final = final.
			WithNewFile(roslynProjectsPath, roslynProjectsFile(retry)).
			WithExec([]string{"sh", "-c", roslynFallbackScript()})
	}

	out := roslynOutcome{Band: band, BandNote: note, Fallback: retry, Unlisted: unlisted}
	if fast.Err != nil {
		out.FastFailed = fast.Err.Error()
	}
	// Both scripts always exit 0 and write every status down, so an
	// unreadable status file means the exec itself did not complete.
	read := func(path string) (string, error) {
		s, err := final.File(path).Contents(ctx)
		if err != nil {
			return "", fmt.Errorf("%s: SAST did not run — the build container did not complete (%s "+
				"unreadable): %w", roslynToolName, path, err)
		}
		return s, nil
	}
	failed, err := read(roslynFailedPath)
	if err != nil {
		return notRun(err)
	}
	if out.Output, err = read(roslynOutPath); err != nil {
		return notRun(err)
	}
	if out.Stderr, err = read(roslynErrPath); err != nil {
		return notRun(err)
	}
	logs, started, built, err := readRoslynOutputs(ctx, final)
	if err != nil {
		return notRun(fmt.Errorf("%s: SAST did not run — %w", roslynToolName, err))
	}
	out.Logs = logs

	var failedFile []string
	for _, line := range strings.Split(failed, "\n") {
		if p := roslynSidecarProject(line); p != "" {
			failedFile = append(failedFile, p)
		}
	}
	out.Failed = roslynFailures(fast, started, built, failedFile, retry)

	res := analyseRoslyn(scope, out)
	if w := roslynFeedWarning(feedUrl, feedToken != nil); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	return res
}

// readRoslynOutputs reads what the builds left in the log directory: every
// compiler log with the project its sidecar names, and the build markers
// (started: marker id → project; built: the ids that finished). An error means
// the container could not be read at all; it says what could not be read, and
// the caller says what that means (a non-run, or a combined build to retry).
func readRoslynOutputs(ctx context.Context, ctr *dagger.Container) (logs []roslynLog, started map[string]string, built map[string]bool, err error) {
	dir := ctr.Directory(roslynOutDir)
	entries, err := dir.Entries(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not list the analyzer logs: %w", err)
	}
	present := map[string]bool{}
	for _, name := range entries {
		present[name] = true
	}
	built = map[string]bool{}
	var sidecars, starts []string
	for _, name := range entries {
		switch {
		case strings.HasSuffix(name, ".project"):
			// A sidecar without its log: the target ran and CoreCompile did
			// not write one (skipped as up to date, or never started). Not a
			// log, so the project reads as not analysed unless another
			// compile of it was.
			if present[strings.TrimSuffix(name, ".project")+".sarif"] {
				sidecars = append(sidecars, name)
			}
		case strings.HasSuffix(name, ".started"):
			starts = append(starts, name)
		case strings.HasSuffix(name, ".built"):
			built[strings.TrimSuffix(name, ".built")] = true
		}
	}
	var names []string
	for _, s := range sidecars {
		names = append(names, s, strings.TrimSuffix(s, ".project")+".sarif")
	}
	names = append(names, starts...)
	bodies, err := readDirFiles(ctx, dir, names)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, s := range sidecars {
		logs = append(logs, roslynLog{
			Project: roslynSidecarProject(bodies[s]),
			SARIF:   []byte(bodies[strings.TrimSuffix(s, ".project")+".sarif"]),
		})
	}
	started = map[string]string{}
	for _, s := range starts {
		started[strings.TrimSuffix(s, ".started")] = roslynSidecarProject(bodies[s])
	}
	return logs, started, built, nil
}

// readDirFiles reads named files of one directory, a bounded number at a time
// (each is an engine round trip, and a large tree leaves hundreds). The first
// failure is the one reported, by name.
func readDirFiles(ctx context.Context, dir *dagger.Directory, names []string) (map[string]string, error) {
	bodies := make([]string, len(names))
	errs := make([]error, len(names))
	sem := make(chan struct{}, roslynReadConcurrency)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			bodies[i], errs[i] = dir.File(n).Contents(ctx)
		}()
	}
	wg.Wait()
	out := make(map[string]string, len(names))
	for i, n := range names {
		if errs[i] != nil {
			return nil, fmt.Errorf("could not read the analyzer output %s: %w", n, errs[i])
		}
		out[n] = bodies[i]
	}
	return out, nil
}

// roslynReadConcurrency bounds the project-file reads in flight. Each is an
// engine round trip; a .NET monorepo has hundreds of projects, and reading
// them one after another made the listing the slowest part of a small build.
const roslynReadConcurrency = 8

// readProjectFiles reads every project file, a bounded number at a time. The
// first failure is the one reported, by the path that failed, and every read
// still in flight is left to finish so no goroutine outlives the call.
func readProjectFiles(ctx context.Context, src *dagger.Directory, paths []string) (map[string]string, error) {
	bodies := make([]string, len(paths))
	errs := make([]error, len(paths))
	sem := make(chan struct{}, roslynReadConcurrency)
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			bodies[i], errs[i] = src.File(p).Contents(ctx)
		}()
	}
	wg.Wait()
	contents := make(map[string]string, len(paths))
	for i, p := range paths {
		if errs[i] != nil {
			return nil, fmt.Errorf("%s: SAST did not run — could not read the project file %s: %w",
				roslynToolName, p, errs[i])
		}
		contents[p] = bodies[i]
	}
	return contents, nil
}
