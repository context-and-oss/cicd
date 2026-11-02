// What Run refuses before it calls a module, and the one value it derives
// from its inputs for stage-2. The Dagger signature stays flat (Dagger takes
// no custom argument structs); these helpers take module-private structs.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session, and for as long as these
// rules lived beside the dag calls no test could reach them. Every message
// here is one a smoke script or a consumer's log greps for, so the wording
// is part of the contract: scripts/smoke/commit-shapes.sh asserts the
// invalid-artifact refusal.
package main

import "fmt"

// artifactShape is the --artifact selector after it has been accepted: the
// artifact tail switches on it, so a value that is not one of these three
// cannot reach the switch. The shape is never inferred (ADR-001, ADR-005).
type artifactShape string

const (
	artifactContainer artifactShape = "container"
	artifactArchive   artifactShape = "archive"
	artifactNone      artifactShape = "none"
)

// parseArtifactShape accepts exactly the three documented values. Case is
// not folded: "Container" is a typo until someone documents otherwise, and a
// refusal names the value as given so the log shows what was typed.
func parseArtifactShape(s string) (artifactShape, error) {
	switch artifactShape(s) {
	case artifactContainer, artifactArchive, artifactNone:
		return artifactShape(s), nil
	}
	return "", fmt.Errorf("invalid --artifact %q: want container|archive|none", s)
}

// commitInputs is the subset of Run's parameters the pre-flight refusals
// read. Secrets and Dagger objects stay out of it: the rules need to know
// only whether they were supplied, and the test must not need a session.
type commitInputs struct {
	parallelism      int
	nodeProjectLimit int
	artifact         string
	buildCmd         string
	outputPath       string
	prepareCmd       string
	prepareLanguage  string
	toolchainImage   string
	prepareTestLabel string
	testCmd          string
	testLegs         string
}

// validateCommitInputs runs the refusals in the order Run always applied
// them — parallelism, the node project limit, the artifact selector, the
// archive shape's two required inputs, then the preparation contract — and
// returns the accepted shape. A caller that sees an error has had nothing
// pulled or built yet.
func validateCommitInputs(in commitInputs) (artifactShape, error) {
	if err := ValidateParallelism(in.parallelism); err != nil {
		return "", err
	}
	if in.nodeProjectLimit < 1 {
		return "", fmt.Errorf("node-project-limit must be positive")
	}
	shape, err := parseArtifactShape(in.artifact)
	if err != nil {
		return "", err
	}
	if shape == artifactArchive && (in.buildCmd == "" || in.outputPath == "") {
		return "", fmt.Errorf("archive requires build-cmd and output-path")
	}
	if err := validatePreparation(in.prepareCmd, in.prepareLanguage, in.toolchainImage, in.prepareTestLabel, in.testCmd, in.testLegs); err != nil {
		return "", err
	}
	return shape, nil
}

// appModeInputs is what the application-mode rules read. Counts and
// presence flags stand in for the slices, files and secrets, because the
// rule asks only whether a repository-mode input was supplied at all.
type appModeInputs struct {
	appID            string
	sourcePathCount  int
	lintLegs         string
	testCmd          string
	hasBaseline      bool
	hasTeamsWebhook  bool
	includeCount     int
	minCoverage      float64
	coverageMinLines int
	coveragePath     string
	tolerance        float64
	coverageGate     string
	licenseExclude   int
	licenseFull      bool
	verifySecrets    bool
	nodeProjectLimit int
}

// appModeRefusal decides whether the application and repository contracts
// have been mixed. With an app-id, the run produces evidence only and takes
// its legs from the application contract, so a repository-discovery or
// delivery input is refused rather than silently ignored — an ignored
// --min-coverage is a coverage gate the caller believes is on. Without an
// app-id, the application-only inputs are refused for the mirror reason.
// The defaults compared against (tolerance 1, coverage-gate "gate",
// license-full true, node-project-limit 4) are the Dagger defaults on Run.
func appModeRefusal(in appModeInputs) error {
	if in.appID == "" {
		if in.sourcePathCount > 0 || in.lintLegs != "" {
			return fmt.Errorf("application inputs require app-id")
		}
		return nil
	}
	if in.testCmd != "" || in.hasBaseline || in.hasTeamsWebhook {
		return fmt.Errorf("app mode uses test-legs and produces evidence only; test-cmd, baselines and delivery inputs are not supported")
	}
	if in.includeCount > 0 || in.minCoverage != 0 || in.coverageMinLines != 0 || in.coveragePath != "" || in.tolerance != 1 || in.coverageGate != "gate" || in.licenseExclude > 0 || !in.licenseFull || in.verifySecrets || in.nodeProjectLimit != 4 {
		return fmt.Errorf("app mode does not accept repository discovery, coverage-policy, licence-exclusion, metadata-only licence, live-secret-verification or notification inputs; use the application workflow contract")
	}
	return nil
}

// preparedImageRef is the image stage-2 is told the prepared container was
// built from: the explicit toolchain image when a preparation ran, and empty
// otherwise, because naming an image for a container that does not exist
// would let stage-2 attest a toolchain nothing ran in.
func preparedImageRef(hasPrepared bool, toolchainImage string) string {
	if hasPrepared {
		return toolchainImage
	}
	return ""
}
