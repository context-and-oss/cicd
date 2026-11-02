//go:build !unit_test

package main

import (
	"context"
	"crypto/sha256"
	"dagger/quality/internal/dagger"
	"fmt"
	"path"
	"strings"
)

// Prepare executes the consumer's dependency preparation and optional compile
// command once. Tests, lint and packaging branch from this immutable state.
// Feed credentials are secret variables, never baked into source or artifacts.
func (m *Quality) Prepare(
	ctx context.Context,
	src *dagger.Directory,
	cmd, toolchainImage, repoUrl string,
	// +optional
	npmFeedUrl string,
	// "registry" (default) or "npmrc"; see quality.Check.
	// +optional
	npmFeedRouting string,
	// +optional
	npmToken *dagger.Secret,
	// +optional
	nugetFeedUrl string,
	// +optional
	nugetToken *dagger.Secret,
) (*dagger.Container, error) {
	if strings.TrimSpace(cmd) == "" || strings.TrimSpace(toolchainImage) == "" {
		return nil, fmt.Errorf("prepare requires a command and an explicit toolchain-image")
	}
	if err := validateNpmFeedRouting(npmFeedRouting, npmFeedUrl); err != nil {
		return nil, err
	}
	if err := validateFeedCredentials(npmFeedUrl, npmToken != nil, nugetFeedUrl, nugetToken != nil); err != nil {
		return nil, err
	}
	ctr := commandBase(src, toolchainImage, repoUrl)
	ctr = commandFeeds(ctx, ctr, src, npmFeedUrl, npmFeedRouting, npmToken, nugetFeedUrl, nugetToken)
	ctr = ctr.WithExec([]string{"sh", "-c", cmd})
	synced, err := ctr.Sync(ctx)
	if err != nil {
		// Engine logs carry command output; do not copy credential-bearing errors
		// into durable evidence or manifests.
		return nil, fmt.Errorf("preparation failed; inspect the execution log")
	}
	return synced, nil
}

func commandBase(src *dagger.Directory, image, scope string) *dagger.Container {
	return commandCaches(dag.Container().From(image), scope).
		WithMountedDirectory("/src", src).WithWorkdir("/src")
}

// Cache only package bytes, never the working tree. Scope by repository and
// mount inside the command container; a runner's host cache is not this cache.
// Persistence between CI jobs requires a persistent engine/cache backend.
func commandCaches(ctr *dagger.Container, scope string) *dagger.Container {
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(scope)))
	return ctr.
		// PRIVATE, never SHARED: NuGet's cross-process lock lives in the
		// container's own /tmp/NuGetScratch, so containers restoring into one
		// shared volume do not exclude each other. Measured: two concurrent cold
		// restores of testdata/dotnet-app as test legs failed 3 runs in 4 with
		// "Could not find file …/system.runtime.handles/4.0.1/<tmp>". PRIVATE
		// hands a contended mount a volume of its own (a cold restore, never a
		// corrupt one); LOCKED would hold the volume for the whole exec and
		// serialise every .NET leg, test run included. The npm, pnpm, yarn and
		// corepack caches below are built for concurrent writers and stay
		// shared; that is their design, not a measurement made here.
		WithMountedCache("/root/.nuget/packages", dag.CacheVolume("cicd-nuget-"+key), dagger.ContainerWithMountedCacheOpts{Sharing: dagger.CacheSharingModePrivate}).
		WithMountedCache("/root/.npm", dag.CacheVolume("cicd-npm-"+key)).
		WithMountedCache("/root/.local/share/pnpm/store", dag.CacheVolume("cicd-pnpm-"+key)).
		// corepack's download of pnpm or yarn itself, and yarn berry's
		// package cache. Both are content the lockfile or packageManager
		// pins, so sharing them across runs of one scope changes no result.
		WithMountedCache("/root/.cache/node/corepack", dag.CacheVolume("cicd-corepack-"+key)).
		WithMountedCache("/root/.yarn/berry/cache", dag.CacheVolume("cicd-yarn-"+key))
}

func commandFeeds(ctx context.Context, ctr *dagger.Container, src *dagger.Directory, npmURL, npmRouting string, npmToken *dagger.Secret, nugetURL string, nugetToken *dagger.Secret) *dagger.Container {
	ctr = withNodeFeed(ctr, npmURL, npmRouting, npmToken)
	if nugetURL != "" && nugetToken != nil {
		ctr = ctr.WithNewFile("/root/.nuget/NuGet/NuGet.Config", nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, nugetURL), nugetURL)).WithSecretVariable("NUGET_AUTH_TOKEN", nugetToken)
	}
	return ctr
}

func formatRestoreArgs(prepared bool) []string {
	if prepared {
		return []string{"--no-restore"}
	}
	return nil
}

func clearPreparedCoverage(ctx context.Context, ctr *dagger.Container, report string) (*dagger.Container, error) {
	if !path.IsAbs(report) {
		report = path.Join("/src", report)
	}
	if !coveragePathIsGlob(report) {
		return ctr.WithExec([]string{"rm", "-f", "--", report}), nil
	}
	dir, name, err := splitCoverageGlob(report)
	if err != nil {
		return nil, err
	}
	// The directory may not exist until tests run. find still owns glob
	// matching, exactly as in harvesting; no pattern is expanded by a shell.
	return ctr.WithExec([]string{"sh", "-c", `if [ -d "$1" ]; then find "$1" -type f -name "$2" -exec rm -f -- {} +; fi`, "sh", dir, name}), nil
}
