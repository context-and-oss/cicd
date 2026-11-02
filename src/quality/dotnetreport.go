// .NET target resolution, report parsing and run-status classification.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so dotnetreport_test.go can drive it with `go test -tags unit_test ./...`.
//
// Two independent false passes lived in the code this replaces, and both are
// the same shape as the ESLint one in eslintreport.go: a .NET tool that never
// examined any code reported exactly what a clean tree reports.
package main

import (
	"encoding/json"
	"encoding/xml"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// dotnetTargetLimit caps how many projects cicd will invoke a dotnet command on
// individually. Exceeding it is an error, not a silent truncation: a partial
// sweep that reports "no findings" is the false pass this file exists to stop.
// A repository this size should ship a solution file, which is one invocation.
const dotnetTargetLimit = 8

// dotnetVendorDirs are path segments whose .csproj/.sln files describe restored
// or generated output rather than source the team owns.
var dotnetVendorDirs = map[string]bool{
	"bin": true, "obj": true, ".git": true, "packages": true, "node_modules": true,
}

// dotnetTestMarkers are POSIX-ERE fragments matching the package references and
// properties that identify a project as one `dotnet test` can execute. A project
// without any of them is not a test project, and pointing `dotnet test` at it
// runs zero tests while exiting 0 — measured, and the origin of the second false
// pass.
//
// They are ERE rather than plain substrings because the discovery sweep greps
// project files in a container (see dotnetTestMarkerPattern) and Go matches the
// same pattern here. One list, two consumers, so the shell rule and the tested
// rule cannot drift. Note IsTestProject must be pinned to `true`: a project
// declaring it false is explicitly not a test project.
//
// The last two are the Microsoft.Testing.Platform generation, and they are here
// because every marker above them is VSTest vocabulary. An MTP test project
// references no adapter and no Microsoft.NET.Test.Sdk — the runner is compiled
// into the test application — so a current MSTest 4 or xunit.v3 project carried
// **none** of the original six. Measured: a project whose only reference was
// `<PackageReference Include="MSTest" Version="4.0.2" />` was reported as
// `none of the 1 projects found is a test project … so no test ran`, i.e. the
// runner detection this change adds could never have been reached from the two
// shapes that need it most. That failure is loud (errors[], passed=false) rather
// than a false pass, which is how it survived — but it is a false *red* on a
// legitimate repository, and the MTP invocation is unreachable without it.
//
// The MSTest meta-package is matched with its attribute so it cannot collide with
// another package's name (MSTest.Analyzers, MSTest.Sdk) — `MSTest\.TestAdapter`
// above still covers MSTest 3 — and the attribute is matched tolerantly, because
// XML allows either quote character and whitespace around the `=`.
var dotnetTestMarkers = []string{
	`Microsoft\.NET\.Test\.Sdk`,
	`IsTestProject>[[:space:]]*true`,
	`xunit\.runner\.visualstudio`,
	`NUnit3TestAdapter`,
	`MSTest\.TestAdapter`,
	`Microsoft\.Testing\.Platform`,
	`Include[[:space:]]*=[[:space:]]*["']MSTest["']`,
	`xunit\.v3`,
}

// dotnetTestMarkerPattern is the case-insensitive alternation of every marker,
// suitable for both `grep -iE` and Go's regexp package.
func dotnetTestMarkerPattern() string {
	return strings.Join(dotnetTestMarkers, "|")
}

// dotnetDiscovery is what a single filesystem sweep found, with every path made
// relative to the mount root.
type dotnetDiscovery struct {
	Solutions    []string // *.sln / *.slnx
	Projects     []string // every *.csproj
	TestProjects []string // the subset `dotnet test` can execute
}

// parseDotnetDiscovery turns the tagged output of the discovery sweep into
// relative, sorted, de-duplicated path lists. Each line is "<TAG> <abs path>"
// where TAG is SLN, TEST or PROJ; anything else is ignored, so tool noise on
// the same stream cannot invent a target.
func parseDotnetDiscovery(root string, lines []string) dotnetDiscovery {
	sln := map[string]bool{}
	proj := map[string]bool{}
	test := map[string]bool{}

	for _, raw := range lines {
		tag, rest, ok := strings.Cut(strings.TrimSpace(raw), " ")
		if !ok {
			continue
		}
		rel, ok := dotnetRelPath(root, strings.TrimSpace(rest))
		if !ok || hasDotnetVendorSegment(rel) {
			continue
		}
		switch tag {
		case "SLN":
			if ext := strings.ToLower(path.Ext(rel)); ext == ".sln" || ext == ".slnx" {
				sln[rel] = true
			}
		case "TEST":
			if strings.EqualFold(path.Ext(rel), ".csproj") {
				proj[rel] = true
				test[rel] = true
			}
		case "PROJ":
			if strings.EqualFold(path.Ext(rel), ".csproj") {
				proj[rel] = true
			}
		}
	}

	return dotnetDiscovery{
		Solutions:    sortedKeys(sln),
		Projects:     sortedKeys(proj),
		TestProjects: sortedKeys(test),
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dotnetRelPath expresses an absolute discovered path relative to the mount
// root. A path outside the root is dropped rather than guessed at.
func dotnetRelPath(root, p string) (string, bool) {
	root = strings.TrimSuffix(path.Clean(root), "/")
	p = path.Clean(p)
	switch {
	case p == root:
		return ".", true
	case strings.HasPrefix(p, root+"/"):
		return strings.TrimPrefix(p, root+"/"), true
	default:
		return "", false
	}
}

func hasDotnetVendorSegment(rel string) bool {
	if rel == "." {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if dotnetVendorDirs[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// dotnetShallowestSolution returns the single shallowest solution file, if the
// shallowest depth holds exactly one. Two solutions at the same depth are
// ambiguous, so this reports no solution and the caller falls back to
// per-project targeting — which always works — rather than failing the gate on
// a layout choice.
func dotnetShallowestSolution(solutions []string) (string, bool) {
	best, count, pick := -1, 0, ""
	for _, s := range solutions {
		d := dotnetPathDepth(s)
		if best == -1 || d < best {
			best, count, pick = d, 1, s
			continue
		}
		if d == best {
			count++
		}
	}
	if count != 1 {
		return "", false
	}
	return pick, true
}

func dotnetPathDepth(rel string) int {
	if rel == "." {
		return 0
	}
	return strings.Count(rel, "/")
}

// dotnetFormatTargets picks what `dotnet format` is pointed at. A solution
// restores once and covers every project the team declared; without one, every
// discovered project is checked individually so nested code is not skipped —
// `dotnet format` at a directory loads only the project in that directory, so
// the old bare invocation never looked at a nested test project's sources.
func dotnetFormatTargets(d dotnetDiscovery) (string, []string) {
	if s, ok := dotnetShallowestSolution(d.Solutions); ok {
		return "solution", []string{s}
	}
	if len(d.Projects) > 0 {
		return "project", d.Projects
	}
	return "", nil
}

// dotnetTestTargets picks what `dotnet test` is pointed at: the solution when
// there is an unambiguous one, otherwise only the projects a test runner can
// execute. Never a non-test project — that combination exits 0 having run
// nothing.
func dotnetTestTargets(d dotnetDiscovery) (string, []string) {
	if s, ok := dotnetShallowestSolution(d.Solutions); ok {
		return "solution", []string{s}
	}
	if len(d.TestProjects) > 0 {
		return "project", d.TestProjects
	}
	return "", nil
}

// dotnetTextualClassificationNote is appended wherever cicd reports that some
// project is not a test project.
//
// The classification is a grep of each .csproj and nothing else
// (discoverDotnetTargets), so a reference that reaches the project through
// MSBuild rather than through its own text is invisible to it. Measured with the
// real marker alternation against a tree whose test/Directory.Build.props injects
// Microsoft.NET.Test.Sdk and xunit.v3 into every project beneath it: both
// projects classified PROJ, while the props file two directories up matched two
// markers. That layout is not exotic — it is the standard way a repository stops
// repeating test dependencies in thirteen project files.
//
// Naming the remedy matters more than naming the cause, and the remedy is the
// one path that skips this classification entirely: with an unambiguous solution
// dotnetTestTargets returns it before it ever consults TestProjects, and
// `dotnet test <solution>` lets MSBuild resolve what a grep cannot see. Without
// it the message reads "add a test project" to someone who has thirteen.
//
// No backticks: notify renders each errors[] and warnings[] entry as a markdown
// code span.
const dotnetTextualClassificationNote = " Note that this classification greps each " +
	"project file on its own: a test SDK or IsTestProject arriving from a " +
	"Directory.Build.props is invisible to it, so a real test project can read as a " +
	"non-test project here. Committing a solution covering these projects avoids the " +
	"question — cicd runs the solution and MSBuild resolves the references a grep " +
	"cannot see."

// dotnetTestScopeWarning states which branch of dotnetTestTargets was taken and
// what it covers, for both branches.
//
// Naming the branch is half the point. dotnetTestTargets opens with
// dotnetShallowestSolution and returns early, so a repository with an
// unambiguous solution never reaches the per-project classification at all —
// which means the textual-marker hazard below is structurally unreachable there,
// and it also means a ratio can never be reported for it. If only the project
// branch said anything about scope, a solution repository would be silent in a
// way indistinguishable from a repository whose classification had been checked
// and found complete. So the solution branch says that the solution decides
// membership and that no per-project classification was applied, and it still
// carries the count of project files found, which is the one number cicd does
// know on that path.
//
// Why the denominator is the point. The warning used to read "ran 8 test
// project(s): <names>" and nothing else, so 8 of 8 and 8 of 13 rendered
// identically — a reader could see which projects ran but never how many did
// not. Combined with the textual classification above, a repository whose test
// dependencies live in a props file loses projects from the sweep with nothing
// anywhere saying a project was dropped. That is this module's founding doctrine
// reached through MSBuild evaluation instead of a crashed tool, and the numbers
// needed to close it were already in hand: dotnetDiscovery carries every .csproj
// it found alongside the subset it classified.
//
// A warning and never an error. A repository legitimately holds non-test
// projects — most of them do, and for most the ratio is unremarkable — so
// failing on it would be a permanent red with no remedy. The claim is only that
// the ratio stops being invisible.
func dotnetTestScopeWarning(kind string, d dotnetDiscovery, targets []string) string {
	switch {
	case kind == "solution" && len(targets) > 0:
		return "dotnet test: ran solution " + targets[0] + " — the solution decides which of " +
			"the " + strconv.Itoa(len(d.Projects)) + " .csproj found under the source root are " +
			"tested, so cicd applied no per-project test-marker classification and reports no " +
			"ratio for this run."
	case kind == "project" && len(d.Projects) > 0:
		msg := "dotnet test: ran " + strconv.Itoa(len(targets)) + " of " +
			strconv.Itoa(len(d.Projects)) + " .csproj found under the source root: " +
			strings.Join(targets, ", ")
		skipped := len(d.Projects) - len(targets)
		if skipped <= 0 {
			return msg
		}
		// Pluralised because this sentence is read by a consumer, not by a
		// test: "The other 1 carry" is the kind of wart that makes evidence
		// look machine-generated and unreviewed.
		tail := " carry no test marker in the project file itself."
		if skipped == 1 {
			tail = " carries no test marker in the project file itself."
		}
		return msg + ". The other " + strconv.Itoa(skipped) + tail +
			dotnetTextualClassificationNote
	default:
		return ""
	}
}

// dotnetTargetLimitError returns a non-empty message when a per-project sweep
// is too wide to run. It names the remedy that makes the fast path available.
func dotnetTargetLimitError(tool string, targets []string) string {
	if len(targets) <= dotnetTargetLimit {
		return ""
	}
	msg := tool + ": found " + strconv.Itoa(len(targets)) + " projects (limit " +
		strconv.Itoa(dotnetTargetLimit) + ") and no single solution file to restore once. " +
		"Commit a .sln covering them, or narrow what cicd is pointed at"
	// The BYO remedy is appended for the test leg only. It takes over test
	// execution, so offering it to `dotnet format` would name a remedy that
	// cannot fix the failure being reported — the same defect as claiming the
	// runner mismatch on every exit 1. A wrong remedy costs a reader more than
	// no remedy.
	if tool == "dotnet test" {
		msg += dotnetBYOTestRemedy
	}
	return msg + ". Refusing to check only some of them, because a partial sweep " +
		"reads as clean: " + strings.Join(targets, ", ")
}

// dotnetNoTargetError explains an empty target set for the leg that found none.
func dotnetNoTargetError(tool string, d dotnetDiscovery) string {
	switch tool {
	case "dotnet test":
		if len(d.Projects) == 0 {
			return "dotnet test: no .csproj found under the source root, so no test ran"
		}
		return "dotnet test: none of the " + strconv.Itoa(len(d.Projects)) +
			" projects found is a test project (no Microsoft.NET.Test.Sdk, IsTestProject or " +
			"test-adapter reference), so no test ran. Add a test project, or drop dotnet from --include." +
			dotnetTextualClassificationNote
	default:
		return tool + ": no .csproj or solution found under the source root, so nothing was checked"
	}
}

// dotnetTargetLabel prefixes a per-target message with the target that produced
// it, so a multi-project sweep's errors stay attributable.
func dotnetTargetLabel(target, msg string) string {
	if target == "" || target == "." {
		return msg
	}
	return target + ": " + msg
}

// dotnetFormatRunError classifies a `dotnet format --verify-no-changes`
// invocation from its exit status, stderr and report, returning "" when the run
// is trustworthy.
//
// The contract, measured against SDK 8.0.422 and 10.0.100:
//
//	0   formatting is clean          — report written, "[]"
//	2   formatting changes needed    — report written, one entry per change
//	1   the command failed           — NO report ("Restore operation failed")
//	145 no matching SDK (global.json) — NO report
//
// The code this replaces ended in `|| true && [ -f report ] || echo '[]' >
// report`, which mapped both failure rows onto row 0: zero findings, nothing in
// errors[], gate green. A .NET consumer whose global.json named an SDK the
// image did not carry, or whose private feed was unreachable, was never linted.
func dotnetFormatRunError(exitCode, stderr, report, band string) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "dotnet format: unreadable exit status " + strconv.Quote(code)
	case n == 0 || n == 2:
		// Ran. A trustworthy run always writes the report, "[]" when clean.
		if strings.TrimSpace(report) == "" {
			return "dotnet format: exited " + code + " but wrote no report"
		}
		return ""
	default:
		msg := "dotnet format: did not run (exit " + code + ")"
		if s := dotnetDiagnosticLine(stderr); s != "" {
			msg += ": " + s
		}
		return msg + dotnetSDKRemedy(stderr, band)
	}
}

// dotnetDiagnosticMarkers are the line prefixes/substrings that carry the cause
// of a .NET failure. MSBuild and the SDK print the cause first and then unwind a
// stack, so lastNonEmptyLine alone reports a `System.CommandLine` frame and
// hides "Restore operation failed" — measured on a project with a malformed
// csproj, which is exactly when a consumer needs the message to be useful.
var dotnetDiagnosticMarkers = []string{
	"unhandled exception",
	"restore operation failed",
	"error ",
	"error:",
	": error",
	"a compatible .net sdk was not found",
	"could not find data collector",
	// Microsoft.Testing.Platform rejects an option it does not know with
	// `Unknown option '--report-trx'`, then prints its entire help text and ends
	// with `error: 1`. Without this marker the diagnostic line was `error: 1` —
	// literally true and useless, while the line naming the rejected flag sat 200
	// lines above it. Measured on SDK 10.0.400 against a bare xunit.v3 3.1.0
	// project (which ships neither the trx nor the coverage extension).
	"unknown option",
}

// dotnetDiagnosticLine picks the most informative line of a tool's output: the
// first line carrying a diagnostic marker, else the last line that is not a
// stack frame, else — when frames are all the tool produced — the last frame.
// Never empty for non-empty input: an empty cause reads as cicd having nothing
// to say rather than as the tool having died.
//
// The line is scrubbed on the way out (scrubCredentials): this is the one place
// a line of `dotnet` output is quoted verbatim into an errors[] entry, by every
// caller in this module, and a NuGet restore error quotes the feed URL — userinfo
// included when the consumer's NuGet.Config carries one.
func dotnetDiagnosticLine(s string) string {
	line, _ := scrubCredentials(dotnetPickDiagnosticLine(s))
	return line
}

func dotnetPickDiagnosticLine(s string) string {
	var lastReal string
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "at ") {
			continue
		}
		lower := strings.ToLower(line)
		for _, m := range dotnetDiagnosticMarkers {
			if strings.Contains(lower, m) {
				return line
			}
		}
		lastReal = line
	}
	if lastReal != "" {
		return lastReal
	}
	return lastNonEmptyLine(s)
}

// dotnetSDKRemedy appends the fix for the non-run causes a consumer can act on
// without seeing cicd's internals. Both are band mismatches between the pinned
// SDK image and what the repository asks for, and they are opposite ends of the
// same axis, which is why they are answered together:
//
//   - global.json names an SDK the image does not carry (exit 145).
//   - the project targets a framework NEWER than the image's SDK can build
//     (NETSDK1045). This is the one a consumer is most likely to hit and least
//     able to diagnose: the SDK is present and working, `dotnet --version`
//     answers, and the failure looks like a project error rather than a
//     toolchain one.
//
// Without a remedy the second case reads as
// `dotnet format: did not run (exit 1): … error NETSDK1045: The current .NET SDK
// does not support targeting .NET 10.0.` — true, and silent about *whose* SDK
// that is. A consumer reasonably concludes their project is misconfigured and
// goes looking in their csproj, where there is nothing to find.
func dotnetSDKRemedy(out, band string) string {
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "compatible .net sdk was not found"):
		return " — global.json requests an SDK the image cicd ran (" +
			dotnetSDKLabelFor(band) + ") does not carry. cicd reads global.json's " +
			"sdk.version to choose among the bands it pins (" + dotnetBandsLabel() +
			"), so this means the requested band is not one of them, or its exact " +
			"patch level is not in the image: name a pinned band, add " +
			`"rollForward": "latestFeature" so any patch of it will do, or remove ` +
			"global.json to use the image default."
	case strings.Contains(lower, "netsdk1045"),
		strings.Contains(lower, "does not support targeting"):
		return " — " + dotnetTargetBandRemedy(dotnetRequestedTargetFramework(out), band)
	default:
		return ""
	}
}

// dotnetSDKLabelFor names the SDK image the Check legs ran a target in.
func dotnetSDKLabelFor(band string) string {
	return "mcr.microsoft.com/dotnet/sdk:" + band
}

// dotnetTargetBandRemedy explains a target framework above the band cicd ran.
// tfm is the framework ("10.0", "Core 3.1") when it is known and "" when it is
// not — the message gets vaguer, never wrong.
//
// This used to rule global.json out flatly, and it was right to: with one pinned
// band, naming another SDK there swapped a legible NETSDK1045 for exit 145. Now
// that global.json's sdk.version *selects* among the pinned bands
// (dotnetResolveBand), it is the lever for exactly the case that reaches this
// message with a band cicd does pin — a TargetFramework cicd could not read,
// because it lives behind an MSBuild condition or a property. It is still not a
// way to reach a band cicd does not pin, and the message says which is which.
func dotnetTargetBandRemedy(tfm, band string) string {
	var msg string
	if tfm != "" {
		msg = "the project targets .NET " + tfm + ", which is newer than the SDK " +
			"cicd ran it in (" + dotnetSDKLabelFor(band) + ")"
	} else {
		msg = "the project's target framework is newer than the SDK cicd ran it " +
			"in (" + dotnetSDKLabelFor(band) + ")"
	}
	return msg + ". cicd pins the bands " + dotnetBandsLabel() + " and picks one " +
		"from global.json's sdk.version, else from the highest literal " +
		"TargetFramework it can read. So if the framework is declared somewhere " +
		"cicd cannot read it — behind an MSBuild condition, in a property, in an " +
		"imported .props — set sdk.version in global.json to a pinned band and " +
		"that band will be used. A band not in that list needs the pin raised in " +
		"src/quality/images.go; failing that, run the test leg through " +
		"quality.Test with --toolchain-image (ADR-004 resolves that one at run " +
		"time), or drop dotnet from --include so cicd stops reporting a leg it " +
		"cannot run."
}

// dotnetUnpinnedBandError is the refusal for a band with no pinned image. It is
// unreachable while dotnetResolveBand and dotnetSDKBase agree — resolution only
// ever returns a member of dotnetSDKBands — and exists because the alternative
// to a loud refusal is a default arm quietly substituting some other band, which
// would attribute a verdict to an SDK nobody selected.
func dotnetUnpinnedBandError(tool, band string) string {
	return tool + ": cicd pins no SDK image for band " + strconv.Quote(band) +
		" (pinned: " + dotnetBandsLabel() + "), so nothing was checked. This is a " +
		"cicd defect, not a repository one: add the band to src/quality/images.go, " +
		"dotnetSDKBands and dotnetSDKBase, or drop dotnet from --include."
}

// dotnetProbeGlobalJSONSection returns the global.json section of the probe, or
// "" when the probe carries none. Two questions are answered from that one file —
// which SDK band to run and which `dotnet test` runner the repository asks for —
// and they read the same bytes, so the cut is written once.
func dotnetProbeGlobalJSONSection(raw string) string {
	_, rest, ok := strings.Cut(raw, dotnetProbeGlobalJSON)
	if !ok {
		return ""
	}
	if section, _, ok := strings.Cut(rest, dotnetProbeTFM); ok {
		return section
	}
	return rest
}

// dotnetTFMAboveBand reports the highest literal target framework in a csproj
// that the band cicd ran cannot build, or "" when there is none.
//
// This exists because `dotnet format` does NOT relay NETSDK1045: measured on a
// net10.0 project under the 8.0 image, the test leg's output carried the SDK's
// full explanation while the format leg's said only "Unhandled exception:
// System.Exception: Restore operation failed." — the same root cause, with the
// one useful sentence missing. Reading the project file is deterministic and
// does not depend on a tool's wording.
//
// It only ever ENRICHES a failure that already happened. It never decides one:
// a project file can set its framework through Directory.Build.props or an
// MSBuild property this cannot see, so a "" here means "no hint to add", not
// "the bands agree". Band selection now reads the same elements to choose the
// SDK, which makes this hint rarer — it fires when the selected band still could
// not build the target, i.e. when the request was unreadable or above every
// pinned band.
func dotnetTFMAboveBand(csproj, band string) string {
	highest := dotnetHighestTFM(csproj)
	if highest == "" {
		return ""
	}
	if cmp, ok := dotnetBandCompare(highest, band); !ok || cmp <= 0 {
		return ""
	}
	return highest
}

// dotnetTargetFrameworkPattern matches the framework version out of NETSDK1045,
// whose wording is "The current .NET SDK does not support targeting .NET 10.0."
// — and "…targeting .NET Core 3.1." on the older bands. Anchored on the SDK's
// own sentence rather than scanning for any version-shaped token, so an
// unrelated version elsewhere in the build log cannot be reported as the target.
var dotnetTargetFrameworkPattern = regexp.MustCompile(
	`(?i)does not support targeting \.NET (Core )?(\d+\.\d+)`)

// dotnetRequestedTargetFramework returns the framework the SDK said it could not
// target, e.g. "10.0" or "Core 3.1". Returns "" when the SDK phrased it some
// other way — a missing version makes the message vaguer, never wrong.
func dotnetRequestedTargetFramework(out string) string {
	m := dotnetTargetFrameworkPattern.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1] + m[2])
}

// trxSummary is the executed-test accounting from one .trx result file.
type trxSummary struct {
	Total    int
	Executed int
	Failed   int
}

// parseTrxCounters reads ResultSummary/Counters out of a .trx document. ok is
// false when the payload is not a TRX at all, which must never be read as
// "zero tests failed".
func parseTrxCounters(raw string) (trxSummary, bool) {
	if strings.TrimSpace(raw) == "" {
		return trxSummary{}, false
	}
	var doc struct {
		XMLName       xml.Name `xml:"TestRun"`
		ResultSummary struct {
			Counters struct {
				Total    int `xml:"total,attr"`
				Executed int `xml:"executed,attr"`
				Failed   int `xml:"failed,attr"`
			} `xml:"Counters"`
		} `xml:"ResultSummary"`
	}
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		return trxSummary{}, false
	}
	c := doc.ResultSummary.Counters
	return trxSummary{Total: c.Total, Executed: c.Executed, Failed: c.Failed}, true
}

// sumTrx accumulates the per-target summaries of a multi-project sweep.
func sumTrx(all []trxSummary) trxSummary {
	var out trxSummary
	for _, s := range all {
		out.Total += s.Total
		out.Executed += s.Executed
		out.Failed += s.Failed
	}
	return out
}

// splitTrxDocuments splits a concatenation of .trx files into the individual XML
// documents it contains. A solution with several test projects writes one .trx
// each, and reading only the first would under-count the run.
func splitTrxDocuments(raw string) []string {
	const end = "</TestRun>"
	var docs []string
	rest := raw
	for {
		i := strings.Index(rest, end)
		if i < 0 {
			return docs
		}
		docs = append(docs, rest[:i+len(end)])
		rest = rest[i+len(end):]
	}
}

// parseTrxAll returns the summed counters across a concatenation of .trx files
// and how many documents were understood. A caller must use the count, not the
// summed totals, to decide whether results were readable at all: an unparseable
// payload sums to zero, which is exactly what a passing run of zero tests looks
// like.
func parseTrxAll(raw string) (trxSummary, int) {
	var sums []trxSummary
	for _, d := range splitTrxDocuments(raw) {
		if s, ok := parseTrxCounters(d); ok {
			sums = append(sums, s)
		}
	}
	return sumTrx(sums), len(sums)
}

// dotnetCoverage is one coverage reading.
type dotnetCoverage struct {
	Percent float64
	Lines   int
}

// coberturaSeparator delimits the cobertura documents a run produced. coverlet
// writes the same report twice — once as the collector attachment, once as the
// final artifact — and a solution with several test projects writes one set per
// project, so the documents must be enumerated rather than sampled.
const coberturaSeparator = "===CICD-COBERTURA==="

// parseCoberturaSet parses every cobertura document in a marker-separated
// concatenation, dropping the ones reporting the same measurement. Reading only
// the first document (`find -print -quit`) happens to be right for a single test
// project and silently under-reports a solution with several.
//
// The identity is coverageIdentity, not the raw bytes — see there for why. In
// short: the pairs this drops are byte-identical only because MTP publishes the
// trx attachment as a file copy, and the timestamp attribute those documents
// carry demonstrably varies within one run, so a release that serialised the
// attachment instead of copying it would put every project's numbers in twice
// with Duplicates reading 0 and the percentage staying plausible.
func parseCoberturaSet(raw string) []dotnetCoverage {
	seen := map[string]bool{}
	var out []dotnetCoverage
	for _, doc := range strings.Split(raw, coberturaSeparator) {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		key := coverageIdentity(doc)
		if seen[key] {
			continue
		}
		seen[key] = true
		if pct, lines, ok := parseCobertura(doc); ok && pct >= 0 {
			out = append(out, dotnetCoverage{Percent: pct, Lines: lines})
		}
	}
	return out
}

// dotnetCoverageUnavailable reports whether the VSTest collector told us it
// could not collect coverage. It says so and exits 0 — measured:
//
//	Data collection : Unable to find a datacollector with friendly name 'XPlat Code Coverage'.
//	Data collection : Could not find data collector 'XPlat Code Coverage'
//	EXIT=0
//
// The collector ships in coverlet.collector, which Microsoft.NET.Test.Sdk does
// not pull in, so a test project without it yields no coverage at all while the
// run looks entirely healthy.
//
// Both strings are VSTest vocabulary, so this detector is **dead on the MTP
// path** — neither can ever appear there. That is why it takes a runner, and why
// the MTP half of dotnetCoverageOutcome is structural instead of a log match: MTP
// has its own silent-absence state (see dotnetTestArgs on
// --coverage-output-format) and no string to match on. A log matcher sitting on a
// shared path that covers one runner is a guard a reader assumes covers both.
func dotnetCoverageUnavailable(runner dotnetRunner, out string) bool {
	if runner != dotnetRunnerVSTest {
		return false
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "unable to find a datacollector") ||
		strings.Contains(lower, "could not find data collector")
}

// dotnetCoverageOutcome classifies what the coverage harvest found: docs is how
// many cobertura documents were harvested from the results directory, outside how
// many were found under the projects' own build trees instead, and usable how
// many of the harvested ones carried a coverage figure worth reporting.
//
// Four distinguishable states, because they are four different facts:
//
//   - Reports were harvested and parsed. Nothing to say.
//   - Reports were harvested and none carried a coverable line count. An empty
//     cobertura document — `<packages />`, no lines-valid, measured at 178 bytes,
//     exit 0 — is what a test project that instruments nothing writes. It is not
//     a measurement, and above all it is not the 100% its line-rate="1" claims;
//     see parseCobertura.
//   - Nothing was harvested but reports exist in the build trees. That is cicd
//     harvesting the wrong location, and saying so is the only way "a report cicd
//     failed to find" is distinguishable from "no report was produced".
//   - Nothing was harvested anywhere. On the MTP path that is an **error**: MTP
//     writes a cobertura document whenever it accepts --coverage, and rejects the
//     flag loudly (exit 5) when it cannot, so an absence means coverage was
//     requested and something swallowed the result.
//
// The VSTest path keeps its warning: there the collector is a package a consumer
// may legitimately not have installed, and the run says so in its own output.
func dotnetCoverageOutcome(runner dotnetRunner, out string, docs, outside, usable int) (errMsg, warnMsg string) {
	if usable > 0 {
		return "", ""
	}
	if docs > 0 {
		return "", "dotnet test: " + strconv.Itoa(docs) + " cobertura report(s) were produced " +
			"but none carried a coverable line count, so no coverage was measured — an empty " +
			"report is what a test project that instruments no code writes, and it is not a " +
			"100% measurement"
	}
	if outside > 0 {
		return "dotnet test: coverage was requested and no cobertura report reached the " +
			"results directory, while " + strconv.Itoa(outside) + " were written under the " +
			"projects' own build trees — the run measured coverage and cicd harvested the " +
			"wrong location, so this is a cicd defect, not a consumer one", ""
	}
	if runner == dotnetRunnerMTP {
		return "dotnet test: coverage was requested (--coverage --coverage-output-format " +
			"cobertura), the Microsoft.Testing.Platform runner accepted the flags, and no " +
			"cobertura report was written anywhere — a run that could not measure coverage " +
			"must not report none. Check that the test project resolves " +
			"Microsoft.Testing.Extensions.CodeCoverage", ""
	}
	if dotnetCoverageUnavailable(runner, out) {
		return "", "dotnet test: coverage was requested but the 'XPlat Code Coverage' collector " +
			"is not installed, so no coverage was measured — add the coverlet.collector package " +
			"to the test project"
	}
	return "", "dotnet test: no cobertura coverage report was produced, so no coverage was measured"
}

// mergeDotnetCoverage combines per-target coverage into one figure, weighting by
// coverable lines when every target reported them. Without weights an 8-line
// project with 100% and a 4000-line project with 10% would average to 55%, which
// would let the ratchet read a collapse as an improvement.
func mergeDotnetCoverage(cov []dotnetCoverage) (*float64, *int) {
	if len(cov) == 0 {
		return nil, nil
	}
	totalLines := 0
	weighted := 0.0
	for _, c := range cov {
		if c.Lines <= 0 {
			continue
		}
		totalLines += c.Lines
		weighted += c.Percent * float64(c.Lines)
	}
	if totalLines > 0 {
		pct := weighted / float64(totalLines)
		return &pct, &totalLines
	}
	sum := 0.0
	for _, c := range cov {
		sum += c.Percent
	}
	pct := sum / float64(len(cov))
	return &pct, nil
}

// dotnetTestRunError classifies whether `dotnet test` actually executed tests.
// It says nothing about whether they passed — the caller reports a non-zero
// exit separately, because "tests failed" and "tests never ran" are different
// facts and only the second one can masquerade as success.
//
// The contract, measured against SDK 8.0.422 and 10.0.100:
//
//	0 + .trx with total>0   tests ran and passed
//	1 + .trx with total>0   tests ran, some failed
//	0 + NO .trx             nothing ran at all
//
// That last row is what `dotnet test` does at a directory whose only project in
// that directory is not a test project: MSBuild resolves the one project beside
// it, does not recurse, finds no test to execute and exits 0. Measured on this
// repository's own dotnet-app fixture — which ships a working xUnit project in
// tests/ that had therefore never executed in CI.
//
// The contract above is VSTest's. Microsoft.Testing.Platform has its own, and
// they disagree on the codes in both directions — MTP's exit 2 is "tests failed"
// where VSTest's 2 is nothing at all, and MTP's 8 is "matched zero tests" where
// VSTest has no equivalent status. So the runner is a parameter: reading one
// runner's exit through the other's table reports the wrong cause, and on exit 2
// it reported a genuine test failure as a leg that never executed.
func dotnetTestRunError(runner dotnetRunner, exitCode string, trxFiles int, sum trxSummary, out, band string) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	if err != nil {
		return "dotnet test: unreadable exit status " + strconv.Quote(code)
	}
	// The SDK's own refusal, relayed with the remedy. Structure has already
	// decided this is a non-run (exit 1 with no .trx); the string only explains
	// it, which is the one thing a tool's wording may be trusted for.
	if runner == dotnetRunnerVSTest && dotnetVSTestTargetRefusal(out) {
		return "dotnet test: did not run (exit " + code + "): the test project(s) are " +
			"Microsoft.Testing.Platform applications, which the .NET 10 SDK refuses to drive " +
			"through the VSTest target" + dotnetMTPOptInRemedy
	}
	if runner == dotnetRunnerMTP {
		if msg, decided := dotnetMTPExitDiagnosis(n, out); decided {
			return msg
		}
	}
	switch {
	case runner != dotnetRunnerMTP && n != 0 && n != 1:
		msg := "dotnet test: did not run (exit " + code + ")"
		if s := dotnetDiagnosticLine(out); s != "" {
			msg += ": " + s
		}
		return msg + dotnetSDKRemedy(out, band)
	case trxFiles == 0:
		msg := "dotnet test: exited " + code + " but wrote no .trx result file, so no test executed"
		if s := dotnetDiagnosticLine(out); s != "" {
			msg += ": " + s
		}
		// A target framework above the pinned SDK lands HERE, not in the
		// did-not-run branch above: the build fails, so `dotnet test` exits 1,
		// which is also its "tests ran and some failed" code. The remedy is
		// appended for the same reason it is there — and it stays empty for the
		// unrelated no-test-project case this branch also catches.
		return msg + dotnetSDKRemedy(out, band)
	case sum.Total == 0:
		return "dotnet test: exited " + code + " but the .trx reports 0 tests"
	default:
		return ""
	}
}

// dotnetSkippedWarning reports an all-skipped run. Skipping is a deliberate,
// reviewable choice in the consumer's source, so it does not fail the gate —
// but it must not be invisible either.
func dotnetSkippedWarning(sum trxSummary) string {
	if sum.Total > 0 && sum.Executed == 0 {
		return "dotnet test: all " + strconv.Itoa(sum.Total) + " tests were skipped; none executed"
	}
	return ""
}

// ---- dotnet format report → SARIF ----

// dotnetSrcMount is where the consumer's tree is mounted in every .NET
// container this module runs (dotnetexec.go). It lives in this untagged file
// because the report parser below has to strip it, and the parser is proven by
// the unit suite, where dotnetexec.go is not compiled.
const dotnetSrcMount = "/src"

// dotnetFormatChange is one entry of `dotnet format --report`. Measured against
// SDK 10.0.400: FileName is the
// BARE file name — `Controller.cs` — and FilePath is the absolute path
// inside the container. Two same-named files in different folders share a
// FileName and differ only in FilePath. DocumentId holds two workspace GUIDs
// that are not stable across runs and name nothing a reader can open; they are
// deliberately not carried into evidence.
type dotnetFormatChange struct {
	DocumentId struct {
		ProjectId struct{ Id string } `json:"ProjectId"`
		Id        string              `json:"Id"`
	} `json:"DocumentId"`
	FileName    string `json:"FileName"`
	FilePath    string `json:"FilePath"`
	FileChanges []struct {
		LineNumber        int    `json:"LineNumber"`
		CharNumber        int    `json:"CharNumber"`
		DiagnosticId      string `json:"DiagnosticId"`
		FormatDescription string `json:"FormatDescription"`
	} `json:"FileChanges"`
}

// dotnetFormatURIFallback says why a finding fell back to its bare file name.
// The zero value means it did not: the uri is the path relative to the mounted
// source root.
type dotnetFormatURIFallback int

const (
	dotnetFormatURIFromPath        dotnetFormatURIFallback = iota
	dotnetFormatURINoPath                                  // the entry carried no FilePath
	dotnetFormatURIPathOutsideRoot                         // FilePath was not under the mount
)

// dotnetFormatURI decides what `artifactLocation.uri` says about one report
// entry, and why.
//
// The uri is FilePath with the container mount stripped — `/src/Api/Foo.cs`
// becomes `Api/Foo.cs` — because the mount is an implementation detail no
// consumer can navigate to, and because the aggregator's dedupe keys on the
// whole finding, path included: with only the bare name, two same-named files
// in different folders holding the same violation on the same line were one
// finding, and the second vanished from the combined table.
//
// Two shapes fall back to FileName and are reported to the caller so it can
// warn: an entry with no FilePath, and a FilePath not under the mount — which
// is also where a Windows-style `C:\...` lands. Neither has been observed (the
// report is written inside cicd's own Linux container), and the fallback exists
// so that an absolute container path can never reach evidence, not because
// either is expected. Backslashes are not rewritten: dotnet on a Unix host
// writes forward slashes (measured), and a backslash is a legal byte in a Linux
// file name, so rewriting it would edit a real location.
func dotnetFormatURI(c dotnetFormatChange, root string) (string, dotnetFormatURIFallback) {
	if c.FilePath == "" {
		return c.FileName, dotnetFormatURINoPath
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	rel := strings.TrimPrefix(c.FilePath, prefix)
	if rel == c.FilePath || rel == "" {
		return c.FileName, dotnetFormatURIPathOutsideRoot
	}
	return rel, dotnetFormatURIFromPath
}

// dotnetFormatFallbackWarning names how many findings carry only a file name,
// and why. Empty when every finding has its path. A warning and not an error:
// the findings are real and counted, only their location is coarser than it
// should be — and that is exactly what the reader must be told, because
// same-named files in different folders can then collapse into one row
// downstream.
func dotnetFormatFallbackWarning(total, noPath, outsideRoot int) string {
	n := noPath + outsideRoot
	if n == 0 {
		return ""
	}
	var reasons []string
	if noPath > 0 {
		reasons = append(reasons, strconv.Itoa(noPath)+" had no FilePath in the report")
	}
	if outsideRoot > 0 {
		reasons = append(reasons, strconv.Itoa(outsideRoot)+" had a path outside "+dotnetSrcMount)
	}
	return "dotnet format: " + strconv.Itoa(n) + " of " + strconv.Itoa(total) +
		" findings carry only a file name, not a path (" + strings.Join(reasons, "; ") +
		"); same-named files in different folders may collapse into one finding"
}

// parseDotnetFormatReport converts dotnet format's --report JSON into SARIF plus
// severity counts, and any warnings about findings whose location had to be
// coarsened to a bare file name. A nil SARIF means the payload was not a format
// report at all; callers must treat that as an error, never as "no findings".
//
// root is the container path the source tree was mounted at (dotnetSrcMount);
// a parameter so the unit suite proves the stripping without Dagger.
//
// version is the SDK that actually ran, not a compile-time constant: the
// version cicd claims in evidence has to be the one that produced the report,
// or the envelope misattributes findings to an SDK that was never involved.
func parseDotnetFormatReport(data []byte, version, root string) (json.RawMessage, map[Severity]int, []string) {
	var changes []dotnetFormatChange
	if err := json.Unmarshal(data, &changes); err != nil {
		return nil, nil, nil
	}

	counts := map[Severity]int{}
	var results []map[string]any
	total, noPath, outsideRoot := 0, 0, 0

	for _, c := range changes {
		uri, why := dotnetFormatURI(c, root)
		for _, fc := range c.FileChanges {
			total++
			switch why {
			case dotnetFormatURINoPath:
				noPath++
			case dotnetFormatURIPathOutsideRoot:
				outsideRoot++
			}
			counts[SeverityMedium]++
			physical := map[string]any{
				"artifactLocation": map[string]any{"uri": uri},
			}
			// SARIF 2.1.0 §3.30.5/§3.30.6: startLine and startColumn are
			// 1-based and must be positive, so a value the tool did not give
			// is left out rather than written as 0 (invalid) or 1 (a guess).
			// CharNumber is 1-based: the console line `(5,19)` matched
			// CharNumber 19 on the same measured run.
			region := map[string]any{}
			if fc.LineNumber > 0 {
				region["startLine"] = fc.LineNumber
			}
			if fc.CharNumber > 0 {
				region["startColumn"] = fc.CharNumber
			}
			if len(region) > 0 {
				physical["region"] = region
			}
			results = append(results, map[string]any{
				"ruleId":  fc.DiagnosticId,
				"level":   "warning",
				"message": map[string]any{"text": strings.TrimSpace(fc.FormatDescription)},
				"locations": []map[string]any{{
					"physicalLocation": physical,
				}},
			})
		}
	}

	var warnings []string
	if w := dotnetFormatFallbackWarning(total, noPath, outsideRoot); w != "" {
		warnings = append(warnings, w)
	}

	if version == "" {
		version = "unknown"
	}
	sarif := singleRunSARIF("dotnet-format", version, results)
	raw, _ := json.Marshal(sarif)
	return json.RawMessage(raw), counts, warnings
}

// dotnetSDKVersionOrUnknown normalises the SDK version read out of the running
// container. An empty read becomes "unknown" rather than the pinned constant,
// so evidence never claims a version cicd did not observe.
func dotnetSDKVersionOrUnknown(raw string) string {
	v := strings.TrimSpace(lastNonEmptyLine(raw))
	if v == "" {
		return "unknown"
	}
	return v
}

// dotnetTestExitFailure is the message for a non-zero exit, and it exists
// because on the one shape it has to describe, the message was a dead end.
//
// One consumer's run: about a hundred tests, all passed, a .trx
// parsed, coverage measured — and exit 1. dotnetTestRunError has a
// dotnetDiagnosticLine on every branch, but this run reaches none of them: the
// structure is healthy, so it returns "" through its default arm, and all the
// leg reported was
//
//	dotnet test failed (exit 1)
//
// with no cause. The cause was not missing. `dotnet test`'s own output had
// already been read out of the container and was sitting in `out`, and it was
// dropped on the floor because no branch that fires here looks at it. So an
// evidence pipeline built to refuse silent signals shipped a verdict with the
// explanation still in a variable.
//
// runErr is what dotnetTestRunError decided, and the diagnostic is appended
// only when that is empty. On every other branch the diagnostic is already in
// the message, and repeating it would read as two findings where there is one.
//
// hasRun distinguishes "the tests reported no failure" from "there is nothing
// to reconcile": a suite with genuine failures exiting non-zero needs no
// explaining, and pinning cicd's guesswork to it would bury the real result.
// The unexplained shape is exactly the one where the accounting and the exit
// code disagree.
//
// kept is the bounded output record dotnetCaptureOutput built for this run, or
// nil when dotnetKeepOutput said there was nothing to keep. When it holds
// diagnostics, the message lists them (bounded, see dotnetDiagnosticsSummary)
// instead of the single line dotnetDiagnosticLine would pick — "the
// diagnostics", not "a diagnostic" — and either way ends by saying where the
// tail is. The single line stays as the fallback for output matching no
// signature, because a message that names nothing when the log said something
// is the shape this function was written to remove.
func dotnetTestExitFailure(code, runErr, out string, sum trxSummary, hasRun bool, kept *dotnetTestOutput) string {
	msg := "dotnet test failed (exit " + code + ")"
	if runErr != "" {
		return msg
	}
	if hasRun && sum.Failed > 0 {
		return msg
	}
	if summary := dotnetDiagnosticsSummary(kept); summary != "" {
		return msg + ": " + dotnetKeepReasonUnexplained + " — " + summary + dotnetOutputKeptNote(kept)
	}
	line := dotnetDiagnosticLine(out)
	if line == "" {
		// Never silently equivalent to the old string: a non-zero exit with no
		// accounting failure and no output at all is its own strange fact, and
		// saying so beats implying cicd simply had nothing to add.
		return msg + ": every test reported passing and the runner printed nothing, " +
			"so the cause is not in `dotnet test`'s output" + dotnetOutputKeptNote(kept)
	}
	return msg + ": " + dotnetKeepReasonUnexplained + " — last diagnostic: " + line + dotnetOutputKeptNote(kept)
}
