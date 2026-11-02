//go:build !unit_test

package main

import (
	"context"
	"dagger/commit/internal/dagger"
	"encoding/json"
	"fmt"
	"strings"
)

type appRunOptions struct {
	artifact, failOn, sastRulesets, commitSha, branch, repoUrl string
	buildCmd, outputPath, toolchainImage                       string
	npmFeedURL, npmFeedRouting, nugetFeedURL, licenseGate      string
	licenseAllow                                               []string
	npmToken, nugetToken                                       *dagger.Secret
	parallelism                                                int
	prepared                                                   *dagger.Container
	prepareLanguage, prepareTestLabel, runURL                  string
}

// appSourceView retains repository-relative paths and excludes all undeclared
// neighbours. Copying the directory view also retains symlinks as links rather
// than dereferencing each file from the unrestricted checkout.
func appSourceView(ctx context.Context, src *dagger.Directory, paths []string) (*dagger.Directory, error) {
	files, err := src.Glob(ctx, "**")
	if err != nil {
		return nil, fmt.Errorf("enumerate checkout: %w", err)
	}
	var patterns []string
	for _, p := range paths {
		found := false
		for _, f := range files {
			if f == p || strings.HasPrefix(f, p+"/") {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("source path %q is missing or empty", p)
		}
		patterns = append(patterns, p, p+"/**")
	}
	return dag.Directory().WithDirectory(".", src, dagger.DirectoryWithDirectoryOpts{Include: patterns}), nil
}

func runApp(ctx context.Context, src *dagger.Directory, c appConfig, o appRunOptions) (*dagger.Directory, error) {
	if o.failOn != "CRITICAL" && o.failOn != "HIGH" && o.failOn != "MEDIUM" && o.failOn != "LOW" && o.failOn != "NONE" {
		return nil, fmt.Errorf("invalid fail-on %q", o.failOn)
	}
	if o.artifact != "archive" && o.artifact != "none" {
		return nil, fmt.Errorf("application mode supports artifact archive or none; container and dependency assessments are deferred")
	}
	if o.artifact == "archive" && (strings.TrimSpace(o.buildCmd) == "" || !appRelativePath(o.outputPath)) {
		return nil, fmt.Errorf("archive requires build-cmd and a literal relative output-path")
	}
	scoped, err := appSourceView(ctx, src, c.Paths)
	if err != nil {
		return nil, err
	}
	type check struct {
		module, tool, concern string
		file                  *dagger.File
	}
	var checks []check
	for _, l := range c.Lint {
		var base *dagger.Container
		image := l.ToolchainImage
		if o.prepared != nil && l.Language == o.prepareLanguage {
			if image != "" && image != o.toolchainImage {
				return nil, fmt.Errorf("prepared lint must use the preparation toolchain-image")
			}
			base, image = o.prepared, o.toolchainImage
		}
		checks = append(checks, check{"quality", l.Label, "lint", dag.Quality().Collect(src, "lint", l.Label, l.Language, l.Cmd, l.ReportPath, l.Format, c.Paths, o.commitSha, o.branch, o.repoUrl,
			dagger.QualityCollectOpts{ToolchainImage: image, Prepared: base, FailOn: o.failOn, NpmFeedURL: o.npmFeedURL, NpmFeedRouting: o.npmFeedRouting, NpmToken: o.npmToken, NugetFeedURL: o.nugetFeedURL, NugetToken: o.nugetToken})})
	}
	tests, err := json.Marshal(c.Tests)
	if err != nil {
		return nil, err
	}
	preparedImage := ""
	if o.prepared != nil {
		preparedImage = o.toolchainImage
	}
	checks = append(checks,
		check{"quality", "tests", "tests", dag.Quality().Test(src, o.commitSha, o.branch, o.repoUrl,
			dagger.QualityTestOpts{TestLegs: string(tests), AppSource: scoped, Prepared: o.prepared, PreparedImage: preparedImage, PreparedLanguage: o.prepareLanguage, PreparedTestLabel: o.prepareTestLabel, NpmFeedURL: o.npmFeedURL, NpmFeedRouting: o.npmFeedRouting, NpmToken: o.npmToken, NugetFeedURL: o.nugetFeedURL, NugetToken: o.nugetToken, Parallelism: o.parallelism})},
		check{"security", "source-code", "sast", dag.Security().ScanSource(scoped, o.commitSha, o.branch, o.repoUrl,
			dagger.SecurityScanSourceOpts{CodeOnly: true, SastRulesets: o.sastRulesets, FailOn: o.failOn})},
		check{"security", "source-licenses", "licenses", dag.Security().ScanLicenses(scoped, o.commitSha, o.branch, o.repoUrl,
			dagger.SecurityScanLicensesOpts{SourceOnly: true, LicenseGate: o.licenseGate, LicenseAllow: o.licenseAllow, FailOn: o.failOn})},
		check{"risk", "validate", "iac", dag.Risk().Validate(scoped, o.commitSha, o.branch, o.repoUrl,
			dagger.RiskValidateOpts{FailOn: o.failOn, InfraScope: "tree"})})
	parts := make([]*dagger.File, len(checks))
	errs := RunBounded(ctx, len(checks), o.parallelism, func(i int) error {
		parts[i] = checks[i].file
		if _, err := parts[i].Contents(ctx); err != nil {
			parts[i] = dag.Evidence().Failure(checks[i].module, checks[i].tool, checks[i].concern, "Execution did not produce usable evidence; inspect the Dagger execution log.", o.commitSha, o.branch, o.repoUrl)
		}
		return nil
	})
	for i, err := range errs {
		if err != nil {
			parts[i] = dag.Evidence().Failure(checks[i].module, checks[i].tool, checks[i].concern, "Check cancelled before completion.", o.commitSha, o.branch, o.repoUrl)
		}
	}
	capture := func(module, tool, concern string, file *dagger.File) {
		if _, err := file.Contents(ctx); err != nil {
			file = dag.Evidence().Failure(module, tool, concern, "Execution did not produce usable evidence; inspect the execution log.", o.commitSha, o.branch, o.repoUrl)
		}
		parts = append(parts, file)
	}
	var payload *dagger.File

	switch o.artifact {
	case "archive":
		output := dag.Build().BuildArchive(src.WithoutDirectory(o.outputPath), o.buildCmd, o.outputPath, o.commitSha, o.branch, o.repoUrl, dagger.BuildBuildArchiveOpts{ToolchainImage: o.toolchainImage, Prepared: o.prepared, NpmFeedURL: o.npmFeedURL, NpmFeedRouting: o.npmFeedRouting, NpmToken: o.npmToken, NugetFeedURL: o.nugetFeedURL, NugetToken: o.nugetToken})
		if _, err := output.Sync(ctx); err != nil {
			capture("build", "archive", "", dag.Evidence().Failure("build", "archive", "", "Build failed; inspect the execution log.", o.commitSha, o.branch, o.repoUrl))
			break
		}
		payload = dag.Build().Bundle(output)
		capture("security", "archive", "secrets", dag.Security().ScanArchive(scoped, output, o.commitSha, o.branch, o.repoUrl, dagger.SecurityScanArchiveOpts{ArtifactOnly: true, FailOn: o.failOn}))
	case "none":
		capture("build", "artifact-attestation", "", dag.Build().NoArtifact(o.commitSha, o.branch, o.repoUrl, dagger.BuildNoArtifactOpts{SbomDisabled: true}))
	}
	// No renderer, notification, SARIF upload or Pages call.
	audit := dag.Evidence().Wrap(parts, o.commitSha, o.branch, o.repoUrl, dagger.EvidenceWrapOpts{AppID: c.ID, SourcePaths: c.Paths, OmitSbom: true})
	return retainArtifact(audit, payload, o.artifact, o.commitSha, o.branch, o.repoUrl, o.runURL, c.ID, o.toolchainImage, ""), nil
}
