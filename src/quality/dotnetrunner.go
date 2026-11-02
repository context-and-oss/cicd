package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// dotnetRunner names which command-line surface `dotnet test` exposes for a
// repository. The two are mutually exclusive and they do not share a flag set,
// so cicd cannot have a house invocation: the wrong one is rejected outright.
//
// Measured on SDK 10.0.400 (see specs/detect-the-dotnet-test-runner.md):
//
//	MTP project, no opt-in, VSTest flags   exit 1, "Testing with VSTest target
//	                                       is no longer supported", no .trx
//	MTP project, opt-in, VSTest flags      exit 5, "Unknown option '--logger'"
//	VSTest project, opt-in, MTP flags      exit 1, "All projects must use that
//	                                       test runner"
//
// Every one of those is a non-run: no test executed and no .trx was written, so
// `gatedPassed` must fail them at every threshold, NONE included.
type dotnetRunner string

const (
	dotnetRunnerVSTest dotnetRunner = "VSTest"
	dotnetRunnerMTP    dotnetRunner = "Microsoft.Testing.Platform"
)

// dotnetCoberturaGlob is the one filename pattern the coverage harvest looks
// for, and it is deliberately shared by both runners rather than being chosen
// per runner.
//
// coverlet writes `coverage.cobertura.xml`; Microsoft.Testing.Extensions.
// CodeCoverage writes `<guid>.cobertura.xml`, one guid per test application.
// Harvesting the literal coverlet name — which is what this code did — finds
// zero files on an MTP run: measured, `find <results> -name
// 'coverage.cobertura.xml'` returned 0 hits over a pooled run that had written
// two reports.
//
// The guid is not an obstacle to be pinned away with `--coverage-output`: it is
// what keeps one test application's report from overwriting another's. Measured
// on a two-project solution: without `--coverage-output`, two distinct reports;
// with `--coverage-output coverage.cobertura.xml`, both write the same path in
// the pooled results directory and the surviving root document describes
// whichever application finished last. A well-formed cobertura document holding
// one project's numbers is worse than no document at all, because it reads as a
// successful measurement — so cicd never passes `--coverage-output`.
const dotnetCoberturaGlob = "*.cobertura.xml"

// dotnetRunnerFromGlobalJSON reads the runner opt-in out of a repository-root
// global.json.
//
// This — not the `IsTestingPlatformApplication` MSBuild property — is what
// selects the CLI surface, and it is the only mechanism that does. Measured:
// `dotnet.config`'s `[dotnet.test.runner]` section is not honoured by 10.0.400
// (the MTP flags still fail with MSB1001), and the property describes what a
// project *is*, not what the CLI will parse.
//
// Unlike dotnetBandFromGlobalJSON, malformed input is an error here rather than
// "no opinion". The band has a next answer to fall back on (the project files);
// the runner does not — falling back would mean guessing an invocation, which is
// the defect this function exists to remove. It is also what the SDK itself
// does: measured, a malformed global.json and an unsupported runner name both
// make *every* `dotnet` invocation throw
// (`InvalidOperationException: Test runner 'Banana' is not supported.`).
func dotnetRunnerFromGlobalJSON(raw string) (runner dotnetRunner, note, errMsg string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return dotnetRunnerVSTest, "runner VSTest (no global.json in the repository root, " +
			"so the SDK default applies)", ""
	}
	var doc struct {
		Test *struct {
			Runner *string `json:"runner"`
		} `json:"test"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return "", "", "global.json in the repository root is not valid JSON, so which " +
			"test runner this repository asks for cannot be read: " + err.Error() +
			" — no test was run, because the invocation `dotnet test` accepts depends " +
			"on that answer (the SDK fails every dotnet command on this file too)"
	}
	if doc.Test == nil || doc.Test.Runner == nil || strings.TrimSpace(*doc.Test.Runner) == "" {
		return dotnetRunnerVSTest, "runner VSTest (global.json sets no " +
			`"test": {"runner": …}, so the SDK default applies)`, ""
	}
	value := strings.TrimSpace(*doc.Test.Runner)
	// The SDK matches the value case-insensitively — measured: a lowercase
	// "microsoft.testing.platform" selects the MTP CLI and runs.
	switch strings.ToLower(value) {
	case strings.ToLower(string(dotnetRunnerMTP)):
		return dotnetRunnerMTP, `runner Microsoft.Testing.Platform (global.json "test": ` +
			`{"runner": …}), which is repository-wide: every test project must use it`, ""
	case strings.ToLower(string(dotnetRunnerVSTest)):
		return dotnetRunnerVSTest, `runner VSTest (global.json "test": {"runner": …})`, ""
	}
	return "", "", "global.json in the repository root sets " +
		`"test": {"runner": ` + strconv.Quote(value) + `}, which no .NET SDK supports — ` +
		`the accepted values are "VSTest" and "Microsoft.Testing.Platform". No test was ` +
		"run: cicd will not pick a runner the repository did not ask for, and the SDK " +
		"rejects this file as well"
}

// dotnetTestArgs builds the arguments that follow the target, as argv elements.
//
// Every element here reaches `dotnet test` through sh's "$@", so none of them is
// ever parsed as a shell word. That matters most for the VSTest collector name:
// written the obvious way — --collect:"XPlat Code Coverage" — sh strips the
// inner quotes and splits it into three arguments, the collector name becomes
// "XPlat", no coverage is collected, and `dotnet test` still exits 0. That was a
// real silent false pass in this repository. Passing argv removes the class
// rather than quoting around it.
//
// nil for an unknown runner, deliberately: there is no default invocation, and a
// caller that reaches this with an unresolved runner must fail rather than run
// something. The switch has no default arm for the same reason.
func dotnetTestArgs(runner dotnetRunner, results string) []string {
	switch runner {
	case dotnetRunnerVSTest:
		return []string{
			"--logger", "trx",
			"--results-directory", results,
			// One argv element. See above.
			"--collect:XPlat Code Coverage",
		}
	case dotnetRunnerMTP:
		return []string{
			// MTP accepts --results-directory as its own option and pools every
			// test application's reports into it, guid-named, without collision
			// — measured on a two-project solution: 2 trx and 2 distinct
			// cobertura at the pool root. Without it, reports land inside each
			// project's build tree (bin/<cfg>/<tfm>/TestResults/), i.e. in the
			// consumer's source, which is why it is passed.
			"--results-directory", results,
			"--report-trx",
			"--coverage",
			// Load-bearing, not decorative. --coverage alone exits 0 and writes
			// <guid>.coverage — the binary default format — so zero cobertura
			// documents are harvested from a run that succeeded and said
			// nothing. Measured. That is the VSTest silent-absence bug arriving
			// through a different door, and it is worse: VSTest at least printed
			// "Unable to find a datacollector". Never emit --coverage without
			// this pair.
			"--coverage-output-format", "cobertura",
		}
	}
	return nil
}

// dotnetVSTestTargetRefusal reports whether `dotnet test` refused to drive a
// Microsoft.Testing.Platform project through the VSTest target. Verbatim,
// measured on SDK 10.0.400 against an MSTest 4.0.2 project with no opt-in:
//
//	…/Microsoft.Testing.Platform.MSBuild.targets(263,5): error : Testing with
//	VSTest target is no longer supported by Microsoft.Testing.Platform on .NET
//	10 SDK and later. If you use dotnet test, you should opt-in to the new
//	dotnet test experience.
//	EXIT=1
//
// The string decides nothing on its own — exit 1 with no .trx is already
// classified as a non-run by dotnetTestRunError's structure. It only adds the
// remedy, which is the whole value of the message to whoever reads the evidence.
// A verdict may never depend on a tool's wording; an explanation may.
func dotnetVSTestTargetRefusal(out string) bool {
	return strings.Contains(strings.ToLower(out), "testing with vstest target is no longer supported")
}

// dotnetMTPRunnerMismatch reports whether the MTP runner refused the run because
// a project in the tree is still VSTest-shaped. Verbatim, SDK 10.0.400:
//
//	error : Project /src/tests/App.Tests.csproj uses VSTest. All projects must
//	use that test runner.
//	EXIT=1
//
// Like dotnetVSTestTargetRefusal, this decides nothing: exit 1 is already a
// non-run. It selects the remedy, and the remedy is worth selecting because the
// mismatch and a project MSBuild could not load share that exit status.
func dotnetMTPRunnerMismatch(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "uses vstest") ||
		strings.Contains(lower, "must use that test runner")
}

// dotnetMTPOptInRemedy names the file and the exact key, because a message that
// says "opt in" without them costs the reader a search through release notes.
const dotnetMTPOptInRemedy = ` — add "test": {"runner": "Microsoft.Testing.Platform"} to ` +
	`global.json in the repository root. The setting is repository-wide: every test ` +
	`project in the repository must then use that runner`

// dotnetBYOTestRemedy names the one remedy in this file that is not a change to
// the consumer's own repository.
//
// Every other remedy here — opt into MTP, reference the TrxReport extension, fix
// the filter — is something the consumer edits in their tree, which is the right
// shape when the project could have run here. Some cannot: a browser E2E suite
// needs installed browsers and often a live service, and neither exists in the
// SDK image, so no edit to that project makes cicd's solution-wide `dotnet test`
// pass. cicd cannot supply a runtime environment — it never publishes the
// artifact (ADR-001) — so for those trees the only fix is to stop asking cicd to
// run that project, and the evidence did not say so. Measured on a consumer
// whose reading of a correct red was to abandon cicd's test leg altogether and
// keep every test in their own workflow: the remedy existed, and no message
// named it.
//
// This is not the escape hatch --fail-on NONE is, and that distinction has to
// survive future edits to this string. A declared leg is still a witnessed run:
// the command is recorded in the evidence, its coverage is harvested, the
// ratchet still applies, and quality.Check records that it ran lint-only. What
// narrows is which projects are tested — a reduction that names itself. Compare
// --minimum-expected-tests 0, which silences the zero-test guard for the whole
// run and is refused outright in dotnetrunner_test.go. If this text ever reads
// as a way to make a red go away, it has become the thing it was written to
// replace.
//
// No backticks: notify renders every errors[] entry as a markdown code span.
const dotnetBYOTestRemedy = " — to run only some of the test projects, take over test " +
	`execution: pass --test-legs (a JSON array of legs, one with "language": "dotnet" and a ` +
	"cmd naming the projects that can run here) or --test-cmd for a single command. Either " +
	"switches this leg off and witnesses yours in its place, coverage and ratchet intact. " +
	"That is the remedy for a test project no container can satisfy, which no edit to the " +
	"project itself can make runnable here"

// dotnetMTPExitDiagnosis classifies an exit status the Microsoft.Testing.Platform
// CLI produced. decided=false means the status carries a real test result and the
// shared .trx checks own the verdict.
//
// The map, measured on SDK 10.0.400:
//
//	0  tests ran, all passed
//	1  a test project in the tree still uses VSTest while global.json opted the
//	   repository into MTP — nothing ran
//	2  tests ran, some failed (.trx and coverage were written)
//	5  the command line was rejected: "Unknown option '--report-trx'" when the
//	   project ships no MTP report/coverage extension, or an invalid
//	   --coverage-output-format value
//	8  the invocation was valid and matched zero tests
//
// Exit 2 was the sharpest reason this needed a runner parameter at all: the
// VSTest branch treats every status outside {0,1} as "did not run", so a real
// MTP test failure was reported as a leg that never executed — a wrong cause on
// a correctly red build, which sends the reader looking for a broken pipeline.
func dotnetMTPExitDiagnosis(code int, out string) (msg string, decided bool) {
	switch code {
	case 0, 2:
		return "", false
	case 1:
		// Exit 1 is MTP's "the run never started", and the runner mismatch is only
		// its most likely cause — a project file MSBuild cannot even load exits 1
		// here too (measured: MSB4025 on a malformed .csproj). Structure decides
		// the non-run; the wording only picks which explanation to offer, and it
		// must not assert a cause it did not see. Claiming the mismatch on every
		// exit 1 sends the reader to global.json for a broken XML comment.
		m := "dotnet test: did not run (exit 1): the Microsoft.Testing.Platform runner " +
			"the repository opted into never started the test run"
		if s := dotnetDiagnosticLine(out); s != "" {
			m += ": " + s
		}
		if dotnetMTPRunnerMismatch(out) {
			return m + " — at least one test project in the tree still uses VSTest, and the " +
				`opt-in is repository-wide: move every test project to the MTP runner, or ` +
				`remove the "test": {"runner": …} key from global.json`, true
		}
		return m, true
	case 5:
		m := "dotnet test: did not run (exit 5): the Microsoft.Testing.Platform runner " +
			"rejected cicd's command line, so no test executed"
		if s := dotnetDiagnosticLine(out); s != "" {
			m += ": " + s
		}
		return m + " — cicd asks for --report-trx and --coverage " +
			"--coverage-output-format cobertura, which a test project only accepts when it " +
			"references the Microsoft.Testing.Extensions.TrxReport and " +
			"Microsoft.Testing.Extensions.CodeCoverage extensions (MSTest 4 supplies both " +
			"transitively; a bare xunit.v3 project supplies neither)", true
	case 8:
		m := "dotnet test: did not run (exit 8): the invocation was valid and matched zero " +
			"tests"
		if s := dotnetDiagnosticLine(out); s != "" {
			m += ": " + s
		}
		return m + " — exit 8 is reported for the run as a whole, not per project, so a " +
			"single test project matching nothing (a --filter that empties it, or a test " +
			"project holding no tests) fails the run even when every other project " +
			"executed its tests" + dotnetBYOTestRemedy, true
	}
	m := "dotnet test: did not run (exit " + strconv.Itoa(code) + ")"
	if s := dotnetDiagnosticLine(out); s != "" {
		m += ": " + s
	}
	return m, true
}
