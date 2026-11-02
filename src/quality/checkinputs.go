package main

import "fmt"

// validateCheckInputs is every refusal Check makes before a container runs,
// in the order it makes them: a prepared container only pairs with a lint-only
// run for the language whose linter uses it, the Node project cap must be
// positive, the npm feed routing must be one cicd knows, and a feed credential
// never goes over a cleartext transport.
//
// The order is part of the contract. A consumer who gets both wrong is told
// about the prepared container first, so the messages a smoke script or a
// consumer's run log greps for do not move when a second check is added.
//
// Untagged: Check lives behind the Dagger build tag, so the one place these
// refusals were made could not be reached by a unit test.
func validateCheckInputs(
	hasPrepared, lintOnly bool,
	preparedLanguage string,
	nodeProjectLimit int,
	npmFeedURL, npmFeedRouting string, hasNpmToken bool,
	nugetFeedURL string, hasNugetToken bool,
) error {
	if hasPrepared && (!lintOnly || (preparedLanguage != "node" && preparedLanguage != "dotnet")) {
		return fmt.Errorf("prepared quality checks require lint-only and prepared-language node or dotnet")
	}
	if err := validateNodeProjectLimit(nodeProjectLimit); err != nil {
		return err
	}
	if err := validateNpmFeedRouting(npmFeedRouting, npmFeedURL); err != nil {
		return err
	}
	// Refuse a cleartext transport before any leg is built, rather than letting
	// four injection paths each ship a token over plain HTTP.
	return validateFeedCredentials(npmFeedURL, hasNpmToken, nugetFeedURL, hasNugetToken)
}
