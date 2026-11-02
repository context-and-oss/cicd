// The vitest coverage-provider decision, and how it is reported.
//
// Deliberately untagged (no //go:build !unit_test): the in-container script is
// a string built from the project's package manager and reading the sentinel
// it leaves behind is a switch over four cases, so vitestcoverage_test.go can drive both with
// `go test -tags unit_test ./...`. The script itself only ran under Dagger and
// was therefore covered by nothing — which is how a branch that silently drops
// coverage survived in it.
package main

import "strings"

// Where the script records what happened to the coverage provider, and the two
// words it writes there.
//
// The sentinel exists because the interesting outcome is invisible in the
// artifacts otherwise. When the provider cannot be installed the script runs
// `vitest run` with no --coverage, so no report is written — and "no report" is
// exactly what a passing suite in a repository with no coverage configured also
// produces. Without a sentinel the two are the same bytes.
const (
	covStatePath = "/tmp/coverage.state"

	covProviderOK      = "provider-ok"
	covProviderMissing = "provider-missing"
	covVitestMissing   = "vitest-missing"

	// A pnpm or yarn project that does not declare the provider: cicd adds
	// packages to an npm install only (see vitestScript).
	covProviderUndeclared = "provider-undeclared"

	// Where the script records what the dependency install exited with.
	nodeInstallExitPath = "/tmp/node-install.exit"

	// Where the script records the version of the vitest the project
	// installed, empty when it installed none. Written before anything else
	// can install a package, so a provider install that drags vitest in as a
	// peer cannot make a project without vitest look like one with it.
	vitestVersionPath = "/tmp/vitest.version"
)

// vitestScript is the script runVitestIn executes.
//
// The sentinel is written on every branch, before vitest runs. Writing it only
// in the else branch would be smaller and wrong: the reader could not then
// distinguish "the provider installed" from "the script died before it got
// there", and treating an absent file as success is the absent-check-reads-as-
// passing failure this whole change is about.
//
// vitest is never fetched. `npx vitest` with no vitest installed downloads the
// newest one off the registry and runs it against the tree, so a project whose
// install failed — or an npm workspace member whose vitest is declared at the
// root, which `npm install` in the member does not install (measured, npm 10) —
// was tested by a vitest nobody chose. `npx --no` refuses the fetch and still
// resolves the binary the way node does, up through a workspace root, which is
// why it is used instead of ./node_modules/.bin/vitest. The version is read
// before the provider install, through the same resolution: a project with no
// vitest takes the first branch, runs nothing, and vitestNonRun names it.
//
// The provider follows the project's vitest. @vitest/coverage-v8 peer-requires
// an exact vitest, so an unversioned install pulled the newest provider beside
// an older vitest; on a tree pinning vitest ^4, coverage-v8 5.x made npm
// 11.16.0 throw inside arborist (`Cannot read properties of null (reading
// 'children')`), and the 2>/dev/null that keeps the log readable also swallows
// that crash. The `if` still takes its else, which is why the outcome is
// recorded as a fact rather than inferred from the absence of an error.
//
// Only an npm project gets a provider cicd adds. `npm install --no-save`
// leaves package-lock.json alone; pnpm and yarn have no equivalent — `pnpm
// add` and `yarn add` rewrite package.json and the lockfile, and against a
// frozen install they fail outright. So a pnpm or yarn project that does not
// declare the provider runs without coverage, and the warning says why.
//
// Install, binary and module resolution all go through pm (nodeinstall.go).
func vitestScript(pm nodePM) string {
	// The install's exit is recorded, not swallowed: when it fails, vitest
	// below runs without the project's dependencies, and vitestNonRun names the
	// install as the reason no test result exists.
	provider := pm.node() + ` -e "require.resolve('@vitest/coverage-v8/package.json')" >/dev/null 2>&1`
	missing := covProviderUndeclared
	if pm.name == "npm" {
		// Prefer the repository's own pinned provider — `npm ls`
		// short-circuits the fetch when it resolves. Only a repo that pins no
		// provider reaches the fetch, and it fetches the provider matching the
		// vitest it has.
		provider = `npm ls @vitest/coverage-v8 >/dev/null 2>&1 || npm install --no-save "@vitest/coverage-v8@$(cat ` +
			vitestVersionPath + `)" --silent >/dev/null 2>&1`
		missing = covProviderMissing
	}
	vitest := pm.exec() + ` vitest run`
	return pm.installLine() + `; ` +
		pm.node() + ` -p "require('vitest/package.json').version" > ` + vitestVersionPath + ` 2>/dev/null || : > ` + vitestVersionPath + `; ` +
		// `false` keeps the exit non-zero, so a reader that missed the version
		// sentinel still cannot read a run that never started as a pass.
		`if [ ! -s ` + vitestVersionPath + ` ]; then ` +
		`echo ` + covVitestMissing + ` > ` + covStatePath + `; : > /tmp/vitest.out; false; ` +
		`elif ` + provider + `; then ` +
		`echo ` + covProviderOK + ` > ` + covStatePath + `; ` +
		vitest + ` --coverage --coverage.reporter=json-summary --coverage.reportsDirectory=/tmp/coverage > /tmp/vitest.out 2>&1; ` +
		// Fall back to a plain run so coverage availability never decides test
		// pass/fail. That silence was the defect: the run degraded and said so
		// to nobody.
		`else echo ` + missing + ` > ` + covStatePath + `; ` +
		vitest + ` > /tmp/vitest.out 2>&1; fi; ` +
		`echo $? > /tmp/vitest.exit`
}

// coverageProviderWarning states why a Node project reports no coverage, or ""
// when there is nothing to say.
//
// state is the sentinel's contents and stateErr whether it could be read at
// all; measured is whether a coverage report was parsed. The three states are
// kept apart on purpose — an unreadable sentinel is not a working one — so that
// every run reporting no coverage number carries a reason next to it.
//
// A run that measured coverage produces no warning even if the sentinel is
// unreadable: the number is the stronger evidence, and a warning beside a real
// figure would only teach readers to ignore the warnings.
//
// suitePassed is whether the leg produced a passing result. vitest writes no
// coverage report for a run that did not pass (coverage.reportOnFailure is off
// by default), so with the provider in place that, not the provider, is why
// there is no number — and saying "no parseable coverage-summary.json was
// produced" sent the reader after a provider that worked (measured on
// changesets). cicd does not turn reportOnFailure on: a figure from a suite
// that failed, or ran on part of its files, would read as the suite's coverage.
func coverageProviderWarning(state string, stateErr error, measured, suitePassed bool) string {
	if measured {
		return ""
	}
	if stateErr != nil {
		return "coverage not measured, and whether the @vitest/coverage-v8 " +
			"provider was available could not be determined (" + covStatePath +
			" is unreadable). Treat this run as having no coverage evidence, " +
			"not as coverage of zero."
	}
	switch strings.TrimSpace(state) {
	case covProviderMissing:
		return "coverage not measured: @vitest/coverage-v8 matching the " +
			"project's vitest could not be installed, so the suite ran without " +
			"--coverage. Test results are unaffected. Declare the provider in " +
			"the repository's devDependencies to make this deterministic."
	case covProviderUndeclared:
		return "coverage not measured: the project does not declare " +
			"@vitest/coverage-v8, and cicd adds packages only to an npm install " +
			"(pnpm and yarn would rewrite the lockfile), so the suite ran without " +
			"--coverage. Test results are unaffected. Declare the provider in " +
			"devDependencies at the version matching vitest."
	case covVitestMissing:
		return "coverage not measured: vitest is not installed, so no suite ran."
	case covProviderOK:
		if !suitePassed {
			return "coverage not measured: the suite did not pass, and vitest writes " +
				"no coverage report for a run that did not pass " +
				"(coverage.reportOnFailure is off by default), so this run has no " +
				"coverage evidence; the provider was available."
		}
		return "coverage not measured: the @vitest/coverage-v8 provider was " +
			"available and --coverage was passed, but no parseable " +
			"coverage-summary.json was produced."
	default:
		return "coverage not measured, and the coverage-provider sentinel " +
			"holds an unexpected value, so why is unknown. Treat this run as " +
			"having no coverage evidence, not as coverage of zero."
	}
}
