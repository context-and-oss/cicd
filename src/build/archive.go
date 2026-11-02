//go:build !unit_test

package main

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing/fstest"

	"dagger/build/internal/dagger"
)

// BuildArchive runs a consumer-owned build command in a resolved toolchain
// container and returns the built artifact directory (the "archive" shape —
// a vite dist/, a dotnet publish output, a Dataverse solution folder).
//
// The toolchain image follows the ADR-004 precedence: explicit param >
// version-file detection (.nvmrc, global.json) > pinned per-language default.
// The build command runs via `sh -c` with src mounted at /src and workdir /src.
//
// Unlike Build, no OCI labels are stamped — directories carry none. The
// commitSha/branch/repoUrl params are kept for signature symmetry with Build;
// provenance for archives rides in evidence envelopes downstream.
func (m *Build) BuildArchive(
	ctx context.Context,
	// Source directory to build.
	src *dagger.Directory,
	// Build command, run via `sh -c` in the toolchain container (always explicit, never auto-detected).
	buildCmd string,
	// Path of the build output directory, relative to the source root (e.g. "dist").
	outputPath string,
	// Toolchain container image override — the only digest-pinnable level (ADR-004).
	// +optional
	toolchainImage string,
	// Git commit SHA — kept for signature symmetry with Build.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Shared preparation/build state. Packaging runs in an immutable branch.
	// +optional
	prepared *dagger.Container,
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
) (*dagger.Directory, error) {
	if buildCmd == "" {
		return nil, fmt.Errorf("build-cmd must not be empty")
	}
	if outputPath == "" {
		return nil, fmt.Errorf("output-path must not be empty")
	}
	// The artifact must live under the mounted source tree — an absolute or
	// traversing path would silently return an unrelated container directory.
	cleaned := path.Clean(outputPath)
	if path.IsAbs(cleaned) || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned == ".git" || strings.HasPrefix(cleaned, ".git/") {
		return nil, fmt.Errorf("output-path must be a relative path inside the source tree, got %q", outputPath)
	}
	outputPath = cleaned

	image, err := resolveArchiveToolchain(ctx, src, toolchainImage)
	if err != nil {
		return nil, err
	}

	ctr := prepared
	if ctr == nil {
		ctr = dag.Quality().Prepare(src, ":", image, repoUrl, dagger.QualityPrepareOpts{
			NpmFeedURL: npmFeedUrl, NpmFeedRouting: npmFeedRouting, NpmToken: npmToken, NugetFeedURL: nugetFeedUrl, NugetToken: nugetToken,
		})
	}
	// A no-op build must never export an old checked-in or prepared output.
	ctr = ctr.WithWorkdir("/src").WithExec([]string{"rm", "-rf", "--", path.Join("/src", outputPath)}).
		WithExec(archiveBuildArgv(buildCmd, "/tmp/build-archive.out", "/tmp/build-archive.err", "/tmp/build-archive.exit"))

	exitRaw, err := ctr.File("/tmp/build-archive.exit").Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("run build command in %s: %w", image, err)
	}
	if exitCode := strings.TrimSpace(exitRaw); exitCode != "0" {
		// A stderr cicd could not read back is said so: "(no stderr output)"
		// would claim the build command was silent.
		stderr, rerr := ctr.File("/tmp/build-archive.err").Contents(ctx)
		stderr = strings.TrimSpace(stderr)
		switch {
		case rerr != nil:
			stderr = fmt.Sprintf("(stderr unreadable: %v)", rerr)
		case stderr == "":
			stderr = "(no stderr output)"
		}
		return nil, fmt.Errorf("build command exited with code %s: %s", exitCode, stderr)
	}

	outDir := ctr.Directory(path.Join("/src", outputPath))
	if _, err := outDir.Sync(ctx); err != nil {
		return nil, fmt.Errorf("build command succeeded but output path %q was not found under /src: %w", outputPath, err)
	}
	return outDir, nil
}

// resolveArchiveToolchain applies the ADR-004 precedence using the
// module-local ResolveToolchain copy: an explicit image short-circuits;
// otherwise the language is inferred from marker files in src and the
// root-level version files (.nvmrc, global.json) are consulted.
func resolveArchiveToolchain(ctx context.Context, src *dagger.Directory, explicitImage string) (string, error) {
	if explicitImage != "" {
		return explicitImage, nil
	}

	lang, err := inferToolchainLanguage(ctx, src)
	if err != nil {
		return "", fmt.Errorf("detect toolchain language: %w", err)
	}

	fsys, err := versionFileFS(ctx, src)
	if err != nil {
		return "", fmt.Errorf("read version files: %w", err)
	}

	image := ResolveToolchain(lang, "", fsys)
	if image == "" {
		// The list names every marker detection actually looks for
		// (markers.go). A message that omits one sends the consumer who has
		// exactly that file looking for something else.
		return "", fmt.Errorf("could not resolve a toolchain image: no language marker files (%s) detected — pass --toolchain-image explicitly",
			strings.Join(markerFileNames, ", "))
	}
	return image, nil
}

// inferToolchainLanguage probes src for language indicator files (same probe
// as the quality module's autoDetectLanguages) and returns the first detected
// language in canonical order. Returns "" when nothing is detected.
func inferToolchainLanguage(ctx context.Context, src *dagger.Directory) (string, error) {
	entries, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory("/src", src).
		WithExec([]string{"sh", "-c",
			`find /src ` + markerFindArgs() + ` 2>/dev/null || true`,
		}).
		Stdout(ctx)
	if err != nil {
		return "", err
	}

	// Classification lives in markers.go, fed from the same list that generates
	// the find above, so a marker cannot be searched for and then not
	// understood (or the reverse).
	seen := map[Language]bool{}
	for _, line := range strings.Split(entries, "\n") {
		if l := markerLanguage(line); l != "" {
			seen[Language(l)] = true
		}
	}

	for _, l := range []Language{Go, Node, Python, Dotnet} {
		if seen[l] {
			return string(l), nil
		}
	}
	return "", nil
}

// versionFileFS materialises the root-level toolchain version files (.nvmrc,
// global.json) from src into an in-memory fs.FS for ResolveToolchain. Absent
// files are simply omitted — resolution falls through to the pinned defaults.
func versionFileFS(ctx context.Context, src *dagger.Directory) (fstest.MapFS, error) {
	entries, err := src.Entries(ctx)
	if err != nil {
		return nil, err
	}

	fsys := fstest.MapFS{}
	for _, name := range entries {
		if name != ".nvmrc" && name != "global.json" {
			continue
		}
		contents, err := src.File(name).Contents(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		fsys[name] = &fstest.MapFile{Data: []byte(contents)}
	}
	return fsys, nil
}
