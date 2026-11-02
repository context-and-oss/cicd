//go:build !unit_test

// The container half of the lockfile-free NuGet fallback: the pinned SDK, the
// band probe, and the restore itself. Everything that decides anything lives in
// dotnetband.go and dotnetrestore.go, untagged, where the unit suite reaches it.
// src/quality/dotnetexec.go is the sibling, not a copy: it serves two legs
// that run the consumer's own lint and test commands, while this file builds
// one container for one restore.
package main

import (
	"context"
	"dagger/security/internal/dagger"
	"fmt"
)

// dotnetSDKBase returns the digest-pinned SDK container for one pinned band, and
// false for a band cicd pins no image for.
//
// Every band has its own literal From() on purpose, and this must stay a switch
// over constants rather than becoming a map or a slice index — the same rule,
// and the same reason, as src/quality/dotnetexec.go.
// scripts/check-runtime-image-pins.py discovers image selections by resolving
// each From() argument through package constants and local literals; an argument
// it cannot resolve is classified as an ADR-004 consumer-resolved toolchain and
// is never failed. So `From(dotnetSDKImages[band])` would not fail the pin gate,
// it would *pass* it, by looking like the one thing the gate deliberately
// exempts — while cicd's own tool image went unpinned. The tidier spelling is
// the one that silently switches the check off.
//
// There is no `default:` arm. Substituting some other band for one nobody pinned
// would attribute a dependency graph to an SDK nobody selected; the caller turns
// the false into a non-run instead.
func dotnetSDKBase(band string) (*dagger.Container, bool) {
	switch band {
	case dotnetSDK80Band:
		return dag.Container().From(dotnetSDK80Image), true
	case dotnetSDK100Band:
		return dag.Container().From(dotnetSDK100Image), true
	}
	return nil, false
}

// nugetPackagesPath and nugetPackagesVolume cache NuGet's global packages folder
// across runs, the way trivyCacheVolume caches the vulnerability database. It
// cannot change a verdict: version resolution is answered by the feed, the cache
// only supplies bytes for a version already chosen, and a cache too damaged to
// supply them fails the restore — which dotnetRestoreRunError reports as a
// non-run.
//
// The volume is mounted PRIVATE, never SHARED. NuGet's cross-process lock lives
// in the container's own /tmp/NuGetScratch, so two containers restoring into one
// shared volume do not exclude each other, and stage-2 at --parallelism > 1 runs
// the dependency and licence restores side by side. Measured on the quality
// copy of this mount: two concurrent cold restores of testdata/dotnet-app failed
// 3 runs in 4 with "Could not find file …/system.runtime.handles/4.0.1/<tmp>".
// PRIVATE hands a contended mount a volume of its own (a cold restore, never a
// corrupt one); LOCKED would hold the volume for the whole exec.
const (
	nugetPackagesPath   = "/root/.nuget/packages"
	nugetPackagesVolume = "cicd-nuget-packages"
)

// restoreDotnetGraph restores the NuGet graph for every project in the tree and
// returns the tree with the generated packages.lock.json files in it, the
// .nuspec snapshot the licence scan reads licences from, and what happened, for
// the caller to classify. The dependency scan ignores the snapshot; it is lazy,
// so a caller that never reads it never copies anything out of the engine.
//
// The source is *copied* into the container (WithDirectory) rather than mounted.
// The point of this container is its output — the tree it writes lockfiles into —
// and a copy makes that unambiguous rather than relying on how a mount is read
// back. The copy is also what keeps the fallback honest about scope: the restored
// tree is a scan input, never something handed back to the consumer.
//
// A restore container reaches the network and, when a private feed is configured,
// carries a credential. Both are already true of the quality module's .NET legs
// against the same feeds; the credential is a Dagger secret and is never
// interpolated into the NuGet.Config or a shell word.
func restoreDotnetGraph(
	ctx context.Context,
	src *dagger.Directory,
	feedUrl string,
	feedToken *dagger.Secret,
) (*dagger.Directory, *dagger.Directory, dotnetRestoreOutcome, error) {
	req, err := discoverDotnetBandRequest(ctx, src)
	if err != nil {
		return nil, nil, dotnetRestoreOutcome{}, fmt.Errorf("security dependency scan: could not read "+
			"which .NET SDK band this tree asks for, so no restore was attempted: %w", err)
	}
	band, note := dotnetResolveBand(req)

	base, ok := dotnetSDKBase(band)
	if !ok {
		// Unreachable unless dotnetSDKBands and dotnetSDKBase disagree. It is an
		// error rather than a fallback to another band for the reason above: a
		// graph is only evidence about the SDK that produced it.
		return nil, nil, dotnetRestoreOutcome{}, fmt.Errorf("security dependency scan: no pinned .NET "+
			"SDK image for band %s (cicd pins %s)", band, dotnetBandsLabel())
	}

	out := dotnetRestoreOutcome{Band: band, BandNote: note}

	ctr := base.
		WithMountedCache(nugetPackagesPath, dag.CacheVolume(nugetPackagesVolume), dagger.ContainerWithMountedCacheOpts{Sharing: dagger.CacheSharingModePrivate}).
		WithDirectory(dotnetRestoreMount, src).
		WithWorkdir(dotnetRestoreMount).
		WithEnvVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1").
		WithEnvVariable("DOTNET_NOLOGO", "1").
		WithEnvVariable("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")

	if feedUrl != "" && feedToken != nil {
		ctr = ctr.
			WithNewFile("/root/.nuget/NuGet/NuGet.Config",
				nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, feedUrl), feedUrl)).
			WithSecretVariable("NUGET_AUTH_TOKEN", feedToken)
	}

	ctr = ctr.WithExec([]string{"sh", "-c", dotnetRestoreScript(dotnetRestoreMount, nugetPackagesPath)})

	// The script always exits 0 and writes every status down, so an unreadable
	// file here means the exec itself did not complete — which is not a restore
	// result and must not be classified as one.
	findExit, err := ctr.File(dotnetRestoreFindPath).Contents(ctx)
	if err != nil {
		return nil, nil, out, fmt.Errorf("security dependency scan: the .NET dependency-graph restore "+
			"left no project-sweep exit status, so what it did is unknown: %w", err)
	}
	projects, err := ctr.File(dotnetRestoreProjectsPath).Contents(ctx)
	if err != nil {
		return nil, nil, out, fmt.Errorf("security dependency scan: could not read the .NET "+
			"dependency-graph restore's project list: %w", err)
	}
	failed, err := ctr.File(dotnetRestoreFailedPath).Contents(ctx)
	if err != nil {
		return nil, nil, out, fmt.Errorf("security dependency scan: could not read which projects the "+
			".NET dependency-graph restore failed for: %w", err)
	}
	stderr, err := ctr.File(dotnetRestoreErrPath).Contents(ctx)
	if err != nil {
		return nil, nil, out, fmt.Errorf("security dependency scan: could not read the .NET "+
			"dependency-graph restore's stderr: %w", err)
	}

	nuspecExit, err := ctr.File(dotnetRestoreNuspecPath).Contents(ctx)
	if err != nil {
		return nil, nil, out, fmt.Errorf("security dependency scan: could not read the .NET "+
			"dependency-graph restore's package-metadata snapshot status: %w", err)
	}

	out.FindExit = findExit
	out.NuspecExit = nuspecExit
	out.Projects = splitProbeLines(dotnetRestoreMount, projects)
	out.Failed = splitProbeLines(dotnetRestoreMount, failed)
	out.Stderr = stderr

	return ctr.Directory(dotnetRestoreMount), ctr.Directory(nuspecSnapshotPath), out, nil
}

// discoverDotnetBandRequest reads what the repository asks of the .NET SDK: a
// global.json sdk.version, else the highest literal TargetFramework across the
// project files and the Directory.Build.props that can set one for a whole tree.
//
// Runs in alpine, not the SDK image, for the same reason the dependency probe
// does: which SDK to use cannot be a question only an SDK can answer, and a probe
// sharing the suspect's container shares its failure modes.
//
// An error here is an error, not a fallback to the lowest band. This is the same
// tiny image that already answered the dependency probe, so a failure means the
// engine or the mount is broken, and a restore attributed to a band read from a
// tree cicd could not read is not evidence about anything.
func discoverDotnetBandRequest(ctx context.Context, src *dagger.Directory) (dotnetBandRequest, error) {
	script := `echo "` + dotnetProbeGlobalJSON + `"
if [ -f ` + dotnetRestoreMount + `/global.json ]; then cat ` + dotnetRestoreMount + `/global.json; fi
echo
echo "` + dotnetProbeTFM + `"
find ` + dotnetRestoreMount + ` -maxdepth 4 \( -name '*.csproj' -o -name '*.fsproj' -o -name '*.vbproj' -o -name 'Directory.Build.props' \) \
  -not -path '*/bin/*' -not -path '*/obj/*' -exec cat {} \;`

	out, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory(dotnetRestoreMount, src).
		WithExec([]string{"sh", "-c", script}).
		Stdout(ctx)
	if err != nil {
		return dotnetBandRequest{}, err
	}
	return parseDotnetBandRequest(out), nil
}

// nugetSourceNameForFeed reports the source key the consumer's own NuGet.config
// gives this feed, falling back to a generic name when no committed config names
// it.
//
// Matching the consumer's key matters: the credential block is keyed by source
// *name*, so inventing one declares a second source for the same URL — which
// breaks any packageSourceMapping pointing at the real one and leaves the
// restore unauthenticated against a feed it can see.
//
// Verbatim behaviour from src/quality/byotest.go, over the shared helpers in
// nugetfeed.go, so the two modules cannot disagree about which source a token
// belongs to.
func nugetSourceNameForFeed(ctx context.Context, src *dagger.Directory, feedURL string) string {
	for _, name := range nugetConfigNames {
		contents, err := src.File(name).Contents(ctx)
		if err != nil {
			continue
		}
		if key, ok := nugetSourceNameFromConfig(contents, feedURL); ok {
			return key
		}
	}
	return nugetDefaultSourceName
}
