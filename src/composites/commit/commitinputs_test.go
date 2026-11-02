package main

import (
	"strings"
	"testing"
)

func TestParseArtifactShape(t *testing.T) {
	for _, s := range []string{"container", "archive", "none"} {
		shape, err := parseArtifactShape(s)
		if err != nil || string(shape) != s {
			t.Errorf("parseArtifactShape(%q) = %q, %v", s, shape, err)
		}
	}
	for _, s := range []string{"", "Container", "image", "archive ", "container|archive"} {
		shape, err := parseArtifactShape(s)
		if err == nil || shape != "" {
			t.Errorf("parseArtifactShape(%q) = %q, %v; want refusal", s, shape, err)
			continue
		}
		// scripts/smoke/commit-shapes.sh greps for this phrase.
		if !strings.Contains(err.Error(), "invalid --artifact") || !strings.Contains(err.Error(), "want container|archive|none") {
			t.Errorf("refusal wording changed: %v", err)
		}
		if !strings.Contains(err.Error(), `"`+s+`"`) {
			t.Errorf("refusal must quote the value as given: %v", err)
		}
	}
}

func TestValidateCommitInputs(t *testing.T) {
	base := commitInputs{parallelism: 1, nodeProjectLimit: 4, artifact: "container"}
	with := func(f func(*commitInputs)) commitInputs { in := base; f(&in); return in }
	cases := []struct {
		name      string
		in        commitInputs
		wantShape artifactShape
		wantErr   string
	}{
		{"container defaults", base, artifactContainer, ""},
		{"none", with(func(i *commitInputs) { i.artifact = "none" }), artifactNone, ""},
		{"archive with both inputs", with(func(i *commitInputs) { i.artifact = "archive"; i.buildCmd = "make"; i.outputPath = "dist" }), artifactArchive, ""},
		{"archive without build-cmd", with(func(i *commitInputs) { i.artifact = "archive"; i.outputPath = "dist" }), "", "archive requires build-cmd and output-path"},
		{"archive without output-path", with(func(i *commitInputs) { i.artifact = "archive"; i.buildCmd = "make" }), "", "archive requires build-cmd and output-path"},
		{"parallelism zero", with(func(i *commitInputs) { i.parallelism = 0 }), "", "parallelism must be an integer from 1 to 4, got 0"},
		{"node project limit zero", with(func(i *commitInputs) { i.nodeProjectLimit = 0 }), "", "node-project-limit must be positive"},
		{"bad artifact", with(func(i *commitInputs) { i.artifact = "image" }), "", `invalid --artifact "image": want container|archive|none`},
		{"preparation without image", with(func(i *commitInputs) { i.prepareCmd = "npm ci"; i.prepareLanguage = "node"; i.testCmd = "npm test" }), "", "prepare-cmd requires an explicit toolchain-image and prepare-language node or dotnet"},
		{"prepared container", with(func(i *commitInputs) {
			i.prepareCmd = "npm ci"
			i.prepareLanguage = "node"
			i.toolchainImage = "node:22-alpine"
			i.testCmd = "npm test"
		}), artifactContainer, ""},
		// Order: every input wrong names parallelism, the first check Run ever ran.
		{"every input wrong names parallelism", commitInputs{parallelism: 9, nodeProjectLimit: 0, artifact: "x", prepareLanguage: "node"}, "", "parallelism must be an integer from 1 to 4, got 9"},
		// ...then the node limit before the artifact selector.
		{"node limit before artifact", commitInputs{parallelism: 1, nodeProjectLimit: 0, artifact: "x"}, "", "node-project-limit must be positive"},
		// ...then the selector before the archive inputs it would gate.
		{"selector before archive inputs", commitInputs{parallelism: 1, nodeProjectLimit: 4, artifact: "x", prepareLanguage: "node"}, "", `invalid --artifact "x": want container|archive|none`},
		// ...and preparation last, so a bad selector is never masked by it.
		{"preparation last", with(func(i *commitInputs) { i.prepareLanguage = "node" }), "", "prepare-language and prepare-test-label require prepare-cmd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shape, err := validateCommitInputs(tc.in)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("expected %q, got nil (shape %q)", tc.wantErr, shape)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
			if shape != tc.wantShape {
				t.Errorf("shape = %q, want %q", shape, tc.wantShape)
			}
		})
	}
}

func TestAppModeRefusal(t *testing.T) {
	repoDefaults := appModeInputs{tolerance: 1, coverageGate: "gate", licenseFull: true, nodeProjectLimit: 4}
	app := repoDefaults
	app.appID = "web"
	with := func(base appModeInputs, f func(*appModeInputs)) appModeInputs { in := base; f(&in); return in }
	const delivery = "app mode uses test-legs and produces evidence only; test-cmd, baselines and delivery inputs are not supported"
	const repoInputs = "app mode does not accept repository discovery, coverage-policy, licence-exclusion, metadata-only licence, live-secret-verification or notification inputs; use the application workflow contract"
	cases := []struct {
		name    string
		in      appModeInputs
		wantErr string
	}{
		{"repository mode, no app inputs", repoDefaults, ""},
		{"repository mode with everything a repo may set", with(repoDefaults, func(i *appModeInputs) {
			i.testCmd = "go test"
			i.hasBaseline = true
			i.hasTeamsWebhook = true
			i.includeCount = 2
			i.minCoverage = 80
			i.verifySecrets = true
		}), ""},
		{"source paths without app-id", with(repoDefaults, func(i *appModeInputs) { i.sourcePathCount = 1 }), "application inputs require app-id"},
		{"lint legs without app-id", with(repoDefaults, func(i *appModeInputs) { i.lintLegs = "[]" }), "application inputs require app-id"},
		{"app mode at defaults", app, ""},
		{"app mode with source paths and lint legs", with(app, func(i *appModeInputs) { i.sourcePathCount = 3; i.lintLegs = "[]" }), ""},
		{"app mode with test-cmd", with(app, func(i *appModeInputs) { i.testCmd = "npm test" }), delivery},
		{"app mode with baseline", with(app, func(i *appModeInputs) { i.hasBaseline = true }), delivery},
		{"app mode with teams webhook", with(app, func(i *appModeInputs) { i.hasTeamsWebhook = true }), delivery},
		{"app mode with include", with(app, func(i *appModeInputs) { i.includeCount = 1 }), repoInputs},
		{"app mode with min coverage", with(app, func(i *appModeInputs) { i.minCoverage = 0.5 }), repoInputs},
		{"app mode with coverage min lines", with(app, func(i *appModeInputs) { i.coverageMinLines = 10 }), repoInputs},
		{"app mode with coverage path", with(app, func(i *appModeInputs) { i.coveragePath = "cov.json" }), repoInputs},
		{"app mode with tolerance", with(app, func(i *appModeInputs) { i.tolerance = 0.5 }), repoInputs},
		{"app mode with coverage gate", with(app, func(i *appModeInputs) { i.coverageGate = "warn" }), repoInputs},
		{"app mode with licence exclude", with(app, func(i *appModeInputs) { i.licenseExclude = 1 }), repoInputs},
		{"app mode metadata-only licence", with(app, func(i *appModeInputs) { i.licenseFull = false }), repoInputs},
		{"app mode with verify secrets", with(app, func(i *appModeInputs) { i.verifySecrets = true }), repoInputs},
		{"app mode with node project limit", with(app, func(i *appModeInputs) { i.nodeProjectLimit = 2 }), repoInputs},
		// Delivery inputs are refused before discovery inputs, as Run always did.
		{"delivery refusal first", with(app, func(i *appModeInputs) { i.testCmd = "x"; i.includeCount = 1 }), delivery},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appModeRefusal(tc.in)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("expected %q, got nil", tc.wantErr)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestPreparedImageRef(t *testing.T) {
	if got := preparedImageRef(true, "node:22-alpine"); got != "node:22-alpine" {
		t.Errorf("prepared: %q", got)
	}
	if got := preparedImageRef(false, "node:22-alpine"); got != "" {
		t.Errorf("an image must not be named for a container that does not exist: %q", got)
	}
	if got := preparedImageRef(true, ""); got != "" {
		t.Errorf("no image, no ref: %q", got)
	}
}
