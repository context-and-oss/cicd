package main

import (
	"fmt"
	"strings"
)

// validateTestInputs is every refusal Test states before a container is built,
// in the order the entry function always had them: the leg document, the
// test-cmd/test-legs exclusivity, the coverage-path/legs exclusivity, the
// ratchet knobs, the npm feed routing and the feed credentials. A malformed input must not run half
// of what was asked and then report on it. It returns the declared legs so the
// caller parses the document once.
func validateTestInputs(
	testCmd, testLegs, coveragePath, coverageGate string,
	tolerance float64,
	parallelism int,
	npmFeedURL, npmFeedRouting string, hasNpmToken bool,
	nugetFeedURL string, hasNugetToken bool,
) ([]testLeg, error) {
	declared, err := parseTestLegs(testLegs)
	if err != nil {
		return nil, err
	}
	if err := exclusiveTestInput(testCmd, declared); err != nil {
		return nil, err
	}
	if err := legsExcludeCoveragePath(coveragePath, declared); err != nil {
		return nil, err
	}
	if coverageGate != "gate" && coverageGate != "warn" {
		return nil, fmt.Errorf("coverage-gate must be \"gate\" or \"warn\", got %q", coverageGate)
	}
	// A negative tolerance would raise the floor above the baseline and turn
	// the ratchet into a coverage-increase mandate — exactly what ADR-003 rejects.
	if tolerance < 0 {
		return nil, fmt.Errorf("tolerance must be >= 0, got %v", tolerance)
	}
	if err := ValidateParallelism(parallelism); err != nil {
		return nil, err
	}
	if err := validateNpmFeedRouting(npmFeedRouting, npmFeedURL); err != nil {
		return nil, err
	}
	if err := validateFeedCredentials(npmFeedURL, hasNpmToken, nugetFeedURL, hasNugetToken); err != nil {
		return nil, err
	}
	return declared, nil
}

// applyPreparedLeg binds the prepared container's metadata to the one leg that
// shares it, and refuses metadata that names no leg, disagrees with a leg's
// own image, or arrives without a container to describe.
//
// It returns the legs with the prepared leg's image pinned and the effective
// label: an empty label with a prepared container means the single test-cmd
// leg. declaredCount is how many legs the consumer declared; with none, and a
// prepared language, the legacy leg takes that language because the
// preparation already chose it.
func applyPreparedLeg(
	legs []testLeg,
	declaredCount int,
	hasPrepared bool,
	preparedTestLabel, preparedImage, preparedLanguage string,
) ([]testLeg, string, error) {
	out := append([]testLeg(nil), legs...)
	if !hasPrepared {
		if preparedTestLabel != "" || preparedImage != "" || preparedLanguage != "" {
			return nil, "", fmt.Errorf("prepared test metadata requires a prepared container")
		}
		return out, preparedTestLabel, nil
	}
	if preparedTestLabel == "" {
		preparedTestLabel = legacyLegLabel
	}
	if declaredCount == 0 && preparedLanguage != "" && len(out) > 0 {
		out[0].Language = preparedLanguage
	}
	matched := false
	for i := range out {
		if out[i].Label != preparedTestLabel {
			continue
		}
		if (preparedLanguage != "" && out[i].Language != preparedLanguage) || preparedImage == "" || (out[i].ToolchainImage != "" && out[i].ToolchainImage != preparedImage) {
			return nil, "", fmt.Errorf("prepared test leg must use the preparation toolchain image")
		}
		out[i].ToolchainImage = preparedImage
		matched = true
	}
	if !matched {
		return nil, "", fmt.Errorf("prepared-test-label %q does not name a test leg", preparedTestLabel)
	}
	return out, preparedTestLabel, nil
}

// singleContainerWarning is the line the single-command shape owes a polyglot
// repository: test-cmd resolves one container from the first detected
// language, and that order is an enum's order, not a judgement about this
// repository. A consumer reading "node:20-alpine" on a mostly-C# repo has no
// other way to find out why its backend tests never ran. Empty when legs were
// declared, an image was chosen deliberately, or there was only one candidate.
func singleContainerWarning(declaredCount int, toolchainImage string, detected []string, image string) string {
	if declaredCount > 0 || toolchainImage != "" || len(detected) <= 1 {
		return ""
	}
	return fmt.Sprintf(
		"byo-test: test-cmd runs in exactly one container and %s was chosen from the first detected language (%s) of %s — that order is fixed, not a judgement about this repository. Use test-legs for one command, image and coverage report per language, or toolchain-image / include to choose deliberately.",
		image, detected[0], strings.Join(detected, ", "))
}

// testPlanWarnings is what resolution alone can say, before any container is
// pulled, in the order the envelope always carried it: a version file cicd read
// and could not use (a property of resolution, and a line a leg whose command
// fails for an unrelated reason should still carry), a toolchain-image that
// reaches only one leg, and the single-container disclosure.
func testPlanWarnings(
	legs []testLeg,
	resolutions []ToolchainResolution,
	images []string,
	declaredCount int,
	toolchainImage, preparedTestLabel string,
	detected []string,
) []string {
	var warnings []string
	warnings = append(warnings, toolchainNoteWarnings(legs, resolutions)...)
	if declaredCount > 0 && toolchainImage != "" {
		warnings = append(warnings, toolchainImageLegScopeWarning(toolchainImage, preparedTestLabel))
	}
	first := ""
	if len(images) > 0 {
		first = images[0]
	}
	if w := singleContainerWarning(declaredCount, toolchainImage, detected, first); w != "" {
		warnings = append(warnings, w)
	}
	return warnings
}
