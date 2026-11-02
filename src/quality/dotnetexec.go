//go:build !unit_test

// Shared .NET container setup and target discovery for the lint and test legs.
// src/security/dotnetexec.go is the sibling, not a copy: it builds the SDK
// container for one restore in the lockfile-free NuGet fallback, while this
// file serves two legs that run the consumer's own lint and test commands.
package main

import (
	"context"
	"dagger/quality/internal/dagger"
	"strconv"
	"strings"
)

// dotnetSrcMount, the mount every container here uses, is declared in
// dotnetreport.go so the untagged report parser can strip it.

// dotnetSDKBase returns the digest-pinned SDK container for one pinned band, and
// false for a band cicd pins no image for.
//
// Every band has its own literal From() on purpose, and this must stay a switch
// over constants rather than becoming a map or a slice index.
// scripts/check-runtime-image-pins.py discovers image selections by resolving
// each From() argument through package constants and local literals; an argument
// it cannot resolve is classified as an ADR-004 consumer-resolved toolchain and
// is never failed. So `From(dotnetSDKImages[band])` would not fail the pin gate
// — it would pass it, by looking like the one thing the gate deliberately
// exempts, while cicd's own tool image went unpinned. The tidier spelling is the
// one that silently switches the check off.
//
// There is also no `default:` arm. A default would substitute some other band
// for one nobody pinned, and a verdict attributed to an SDK nobody selected is
// the shape of false pass this module exists to prevent; the caller turns the
// false into a non-run instead (dotnetUnpinnedBandError).
func dotnetSDKBase(band string) (*dagger.Container, bool) {
	switch band {
	case dotnetSDK80Band:
		return dag.Container().From(dotnetSDK80Image), true
	case dotnetSDK100Band:
		return dag.Container().From(dotnetSDK100Image), true
	}
	return nil, false
}

// dotnetContainer builds the SDK container both .NET legs run in for the
// selected band, wiring the private NuGet feed when one is configured. The token
// is a Dagger secret and is never interpolated into the NuGet.Config or a shell
// word. ok is false when the band has no pinned image, and the caller must treat
// that as a non-run rather than falling back to another band.
//
// This used to declare the source and set NUGET_AUTH_TOKEN and stop there, with
// no <packageSourceCredentials> block. NuGet reads no such environment variable
// on its own, so every restore against a private feed went out anonymously: the
// feed answered 401 and both legs reported "restore operation failed" — a
// message that names neither the feed nor authentication, on a token that was
// present and correct the whole time. It also hard-coded the source name
// "internal", which shadows the consumer's own source and breaks any
// packageSourceMapping pointing at it. Both the naming and the credential body
// are now shared with the BYO test path (feeds.go, byotest.go), so the two
// cannot disagree about how a credential is handed to NuGet.
func dotnetContainer(
	ctx context.Context,
	src *dagger.Directory,
	band string,
	feedUrl string,
	feedToken *dagger.Secret,
	cacheScope string,
) (*dagger.Container, bool) {
	base, ok := dotnetSDKBase(band)
	if !ok {
		return nil, false
	}
	ctr := commandCaches(base, cacheScope).
		WithMountedDirectory(dotnetSrcMount, src).
		WithWorkdir(dotnetSrcMount)

	if feedUrl != "" && feedToken != nil {
		ctr = ctr.
			WithNewFile("/root/.nuget/NuGet/NuGet.Config",
				nugetCredentialedConfig(nugetSourceNameForFeed(ctx, src, feedUrl), feedUrl)).
			WithSecretVariable("NUGET_AUTH_TOKEN", feedToken)
	}
	return ctr, true
}

// discoverDotnetBandRequest reads what the repository asks of the .NET SDK: a
// global.json sdk.version, else the highest literal TargetFramework across the
// project files and the Directory.Build.props that can set one for a whole tree.
//
// Runs in alpine, not the SDK image, for the same reason the target sweep does —
// which SDK to use cannot be a question only an SDK can answer. Directory.Build.
// props is included because that is where a monorepo usually declares the band,
// and it was the single most likely place for cicd to be blind to it.
//
// An error here is an error, not a fallback. It is the same tiny image that just
// answered the target sweep, so a failure means the engine or the mount is
// broken, and every verdict downstream of it would be describing a tree cicd
// could not read.
func discoverDotnetBandRequest(ctx context.Context, src *dagger.Directory) (dotnetBandRequest, error) {
	out, err := readDotnetProbe(ctx, src)
	if err != nil {
		return dotnetBandRequest{}, err
	}
	return parseDotnetBandRequest(out), nil
}

// readDotnetProbe runs the probe both readers of it share. Two questions are
// answered from the same global.json — which SDK band to run (sdk.version) and
// which `dotnet test` command line the repository asks for (test.runner) — and
// asking them in one script means they can never be answered about two different
// files. The second call is the same image, mount and script, so Dagger serves it
// from cache rather than executing twice.
func readDotnetProbe(ctx context.Context, src *dagger.Directory) (string, error) {
	script := `echo "` + dotnetProbeGlobalJSON + `"
if [ -f ` + dotnetSrcMount + `/global.json ]; then cat ` + dotnetSrcMount + `/global.json; fi
echo
echo "` + dotnetProbeTFM + `"
find ` + dotnetSrcMount + ` -maxdepth ` + strconv.Itoa(markerSearchDepth) + ` \( -name '*.csproj' -o -name 'Directory.Build.props' \) \
  -not -path '*/bin/*' -not -path '*/obj/*' -exec cat {} \;`

	return dag.Container().
		From(alpineImage).
		WithMountedDirectory(dotnetSrcMount, src).
		WithExec([]string{"sh", "-c", script}).
		Stdout(ctx)
}

// discoverDotnetTestRunner reads which `dotnet test` command-line surface the
// repository asks for. Runs in alpine, like the band question and for the same
// reason: which invocation to use must not be a question only a working SDK can
// answer.
//
// Deliberately **not** the `IsTestingPlatformApplication` MSBuild property, which
// is what the original report proposed. Three measured reasons, all in
// specs/detect-the-dotnet-test-runner.md: the property describes what a project
// *is* while global.json's test.runner is what selects the CLI that parses the
// flags; `dotnet msbuild -getProperty` is refused outright on a solution target
// (MSB1063), which is one of the two shapes cicd hands to `dotnet test`; and on a
// cold NuGet cache the property reads empty for a genuine MTP project, because the
// targets defining it live inside a package that has not been restored yet — a
// detector that answers "VSTest" for an MTP project when a cache is cold is the
// same class of defect as the one being fixed.
func discoverDotnetTestRunner(ctx context.Context, src *dagger.Directory) (dotnetRunner, string, string, error) {
	out, err := readDotnetProbe(ctx, src)
	if err != nil {
		return "", "", "", err
	}
	runner, note, errMsg := dotnetRunnerFromGlobalJSON(dotnetProbeGlobalJSONSection(out))
	return runner, note, errMsg, nil
}

// discoverDotnetTargets sweeps the source tree once for solutions and projects,
// tagging each .csproj as a test project or not by looking for a test-runner
// reference in its text. Runs in the tiny alpine image, not the SDK image: it
// is a filesystem question, so it must not depend on the SDK being usable.
//
// The classification itself lives in dotnetreport.go so it is unit-tested.
//
// The depth comes from markerSearchDepth rather than a literal of its own, and
// sharing it with language detection is the correct coupling, not a convenience.
// If the two depths could differ, a .csproj sitting between them would make
// detection report that dotnet is present while this sweep reports no project to
// run — two statements about one tree that cannot both be acted on. It also ends
// a drift markers.go's own header warns about one field over: the depth was
// written out three times here, and dotnetLegScopeWarning now quotes it to a
// consumer, so a fourth copy would be a number in an evidence envelope that no
// search had to agree with.
func discoverDotnetTargets(ctx context.Context, src *dagger.Directory) (dotnetDiscovery, error) {
	script := `set -e
find ` + dotnetSrcMount + ` -maxdepth ` + strconv.Itoa(markerSearchDepth) + ` \( -name '*.sln' -o -name '*.slnx' \) \
  -not -path '*/bin/*' -not -path '*/obj/*' | while IFS= read -r f; do
  echo "SLN $f"
done
find ` + dotnetSrcMount + ` -maxdepth ` + strconv.Itoa(markerSearchDepth) + ` -name '*.csproj' \
  -not -path '*/bin/*' -not -path '*/obj/*' | while IFS= read -r f; do
  if grep -qiE "$MARKERS" "$f"; then
    echo "TEST $f"
  else
    echo "PROJ $f"
  fi
done`

	out, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory(dotnetSrcMount, src).
		// The marker alternation reaches grep through the environment, not by
		// being spliced into the script body — same rule the ADO templates are
		// held to, applied to cicd's own generated shell.
		WithEnvVariable("MARKERS", dotnetTestMarkerPattern()).
		WithExec([]string{"sh", "-c", script}).
		Stdout(ctx)
	if err != nil {
		return dotnetDiscovery{}, err
	}
	return parseDotnetDiscovery(dotnetSrcMount, strings.Split(out, "\n")), nil
}

// readDotnetSDKVersion reports the SDK the container will actually use. It asks
// `dotnet --version`, which honours a consumer's global.json — so when that
// pins a band the image does not carry, this fails too and falls back to what
// is installed. Either way the answer is observed, never assumed: reporting the
// compile-time pin would misattribute findings to an SDK that never ran.
func readDotnetSDKVersion(ctx context.Context, ctr *dagger.Container) string {
	out, err := ctr.WithExec([]string{"sh", "-c",
		`dotnet --version 2>/dev/null || dotnet --list-sdks 2>/dev/null | tail -1 | cut -d' ' -f1`,
	}).Stdout(ctx)
	if err != nil {
		return "unknown"
	}
	return dotnetSDKVersionOrUnknown(out)
}
