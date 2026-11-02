//go:build unit_test

package main

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// dotnetTestMarkerRE compiles the marker alternation the container `grep -iE`
// runs, so the cases below prove the pattern in Go's regexp as well as in
// grep's. It lives here because nothing outside this test classifies a project
// in Go: the sweep is the shell grep in dotnetexec.go.
var dotnetTestMarkerRE = regexp.MustCompile(`(?i)` + dotnetTestMarkerPattern())

// dotnetIsTestProject is the test oracle for that pattern.
func dotnetIsTestProject(contents string) bool {
	return dotnetTestMarkerRE.MatchString(contents)
}

// trxDoc wraps counters in the real TRX envelope, namespace included, so the
// parser is proven against the shape MSBuild actually writes rather than a
// namespace-free simplification Go would match more easily.
func trxDoc(total, executed, failed string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<TestRun id="8c84fa94-04c1-424b-9868-57a2d4851a1d" name="@runner 2026-08-03"
         xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Results />
  <ResultSummary outcome="Completed">
    <Counters total="` + total + `" executed="` + executed + `" passed="1" failed="` + failed + `"
              error="0" timeout="0" aborted="0" inconclusive="0" notExecuted="0" />
  </ResultSummary>
</TestRun>`
}

func TestParseDotnetDiscovery(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  dotnetDiscovery
	}{
		{
			name: "root project and nested test project",
			lines: []string{
				"PROJ /src/dotnet-app.csproj",
				"TEST /src/tests/dotnet-app.Tests.csproj",
			},
			want: dotnetDiscovery{
				Projects:     []string{"dotnet-app.csproj", "tests/dotnet-app.Tests.csproj"},
				TestProjects: []string{"tests/dotnet-app.Tests.csproj"},
			},
		},
		{
			name:  "solution recorded separately from projects",
			lines: []string{"SLN /src/App.sln", "PROJ /src/App/App.csproj"},
			want: dotnetDiscovery{
				Solutions: []string{"App.sln"},
				Projects:  []string{"App/App.csproj"},
			},
		},
		{
			name:  "slnx accepted",
			lines: []string{"SLN /src/App.slnx"},
			want:  dotnetDiscovery{Solutions: []string{"App.slnx"}},
		},
		{
			name: "restored output is not a target",
			lines: []string{
				"PROJ /src/App/App.csproj",
				"PROJ /src/App/obj/Debug/net8.0/generated.csproj",
				"PROJ /src/App/bin/Release/leftover.csproj",
				"SLN /src/packages/vendored.sln",
			},
			want: dotnetDiscovery{Projects: []string{"App/App.csproj"}},
		},
		{
			name:  "path outside the mount is dropped",
			lines: []string{"PROJ /elsewhere/App.csproj", "PROJ /src/App.csproj"},
			want:  dotnetDiscovery{Projects: []string{"App.csproj"}},
		},
		{
			name:  "a TEST tag counts as a project too",
			lines: []string{"TEST /src/T.csproj"},
			want: dotnetDiscovery{
				Projects:     []string{"T.csproj"},
				TestProjects: []string{"T.csproj"},
			},
		},
		{
			name:  "duplicates collapse",
			lines: []string{"PROJ /src/A.csproj", "PROJ /src/./A.csproj", "PROJ /src/A.csproj"},
			want:  dotnetDiscovery{Projects: []string{"A.csproj"}},
		},
		{
			name: "unrecognised lines and noise are ignored",
			lines: []string{
				"", "   ",
				"grep: /src/weird: Permission denied",
				"PROJ",
				"PROJ /src/notes.txt",
				"SLN /src/App.csproj",
				"PROJ /src/A.csproj",
			},
			want: dotnetDiscovery{Projects: []string{"A.csproj"}},
		},
		{
			name:  "nothing found",
			lines: []string{""},
			want:  dotnetDiscovery{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDotnetDiscovery("/src", tc.lines)
			assertPaths(t, "solutions", got.Solutions, tc.want.Solutions)
			assertPaths(t, "projects", got.Projects, tc.want.Projects)
			assertPaths(t, "test projects", got.TestProjects, tc.want.TestProjects)
		})
	}
}

func assertPaths(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

func TestParseDotnetDiscoveryTrailingSlashRoot(t *testing.T) {
	got := parseDotnetDiscovery("/src/", []string{"PROJ /src/A.csproj"})
	assertPaths(t, "projects", got.Projects, []string{"A.csproj"})
}

func TestDotnetIsTestProject(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		want     bool
	}{
		{"test sdk reference", `<PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />`, true},
		{"xunit visualstudio runner", `<PackageReference Include="xunit.runner.visualstudio" />`, true},
		{"nunit adapter", `<PackageReference Include="NUnit3TestAdapter" />`, true},
		{"mstest adapter", `<PackageReference Include="MSTest.TestAdapter" />`, true},
		{"microsoft testing platform", `<PackageReference Include="Microsoft.Testing.Platform" />`, true},
		// The two MTP shapes. Neither carries an adapter or Microsoft.NET.Test.Sdk,
		// so before these markers existed a real MSTest 4 / xunit.v3 test project was
		// reported as "not a test project" and no test ran — measured, and the reason
		// the runner detection beside this was unreachable from the shapes needing it.
		{"mstest 4 meta-package", `<PackageReference Include="MSTest" Version="4.0.2" />`, true},
		{"mstest 4 meta-package single-quoted", `<PackageReference Include='MSTest' />`, true},
		{"mstest 4 meta-package spaced attribute", `<PackageReference Include = "MSTest" />`, true},
		{"xunit v3", `<PackageReference Include="xunit.v3" Version="3.1.0" />`, true},
		// …and the collision the attribute match exists to avoid: analyzers cannot run
		// a test, so a project carrying only them would be handed to `dotnet test` for
		// nothing. A bare `MSTest` marker would have matched this string.
		//
		// Deliberately not asserted either way: `<Project Sdk="MSTest.Sdk/4.0.2">`, the
		// MSBuild-SDK spelling of an MSTest project. It matches no marker today, so
		// such a repository gets the loud "not a test project" non-run rather than a
		// false pass — a false red on a legitimate shape, and it is left open here
		// because nothing in this change measured a real MSTest.Sdk run. Pinning an
		// expectation for it would turn an unmeasured case into a ruled-out one.
		{"mstest analyzers alone is not runnable", `<PackageReference Include="MSTest.Analyzers" />`, false},
		{"IsTestProject true", `<IsTestProject>true</IsTestProject>`, true},
		{"IsTestProject true with whitespace", "<IsTestProject>\n  true</IsTestProject>", true},
		{"lowercase spelling still matches", `<packagereference include="microsoft.net.test.sdk" />`, true},
		// The reason the marker is pinned to `true`: a project that explicitly
		// opts out must not be handed to `dotnet test`, which would run zero
		// tests there and — before this change — report success.
		{"IsTestProject false is not a test project", `<IsTestProject>false</IsTestProject>`, false},
		{"plain app project", `<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>`, false},
		{"xunit assertion library alone is not runnable", `<PackageReference Include="xunit.assert" />`, false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dotnetIsTestProject(tc.contents); got != tc.want {
				t.Fatalf("dotnetIsTestProject(%q) = %v, want %v", tc.contents, got, tc.want)
			}
		})
	}
}

// The container greps with the same alternation this matches, so the pattern
// must stay usable as a POSIX ERE: no Go-only constructs.
func TestDotnetTestMarkerPatternIsPortableERE(t *testing.T) {
	p := dotnetTestMarkerPattern()
	for _, bad := range []string{`\d`, `\w`, `\s`, `(?i)`, `(?:`, `\b`} {
		if strings.Contains(p, bad) {
			t.Fatalf("marker pattern contains non-POSIX construct %q: %s", bad, p)
		}
	}
	if !strings.Contains(p, "|") {
		t.Fatalf("marker pattern is not an alternation: %s", p)
	}
}

func TestDotnetShallowestSolution(t *testing.T) {
	cases := []struct {
		name      string
		solutions []string
		want      string
		wantOK    bool
	}{
		{"none", nil, "", false},
		{"single at root", []string{"App.sln"}, "App.sln", true},
		{"single nested", []string{"src/App.sln"}, "src/App.sln", true},
		{"root beats nested", []string{"src/Inner.sln", "App.sln"}, "App.sln", true},
		{"two at root is ambiguous", []string{"A.sln", "B.sln"}, "", false},
		{"two at the same nested depth is ambiguous", []string{"a/A.sln", "b/B.sln"}, "", false},
		{"deeper sibling does not create ambiguity", []string{"a/A.sln", "a/b/B.sln"}, "a/A.sln", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := dotnetShallowestSolution(tc.solutions)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("= (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestDotnetFormatTargets(t *testing.T) {
	cases := []struct {
		name     string
		d        dotnetDiscovery
		wantKind string
		want     []string
	}{
		{
			name:     "solution wins",
			d:        dotnetDiscovery{Solutions: []string{"App.sln"}, Projects: []string{"a/A.csproj", "b/B.csproj"}},
			wantKind: "solution",
			want:     []string{"App.sln"},
		},
		{
			// Format checks every project, not just the test ones: unformatted
			// application code is the point of the leg.
			name:     "every project without a solution",
			d:        dotnetDiscovery{Projects: []string{"A.csproj", "t/T.csproj"}, TestProjects: []string{"t/T.csproj"}},
			wantKind: "project",
			want:     []string{"A.csproj", "t/T.csproj"},
		},
		{
			name:     "ambiguous solutions fall back to projects",
			d:        dotnetDiscovery{Solutions: []string{"A.sln", "B.sln"}, Projects: []string{"A.csproj"}},
			wantKind: "project",
			want:     []string{"A.csproj"},
		},
		{name: "nothing", d: dotnetDiscovery{}, wantKind: "", want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, got := dotnetFormatTargets(tc.d)
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
			assertPaths(t, "targets", got, tc.want)
		})
	}
}

func TestDotnetTestTargets(t *testing.T) {
	cases := []struct {
		name     string
		d        dotnetDiscovery
		wantKind string
		want     []string
	}{
		{
			name:     "solution wins",
			d:        dotnetDiscovery{Solutions: []string{"App.sln"}, TestProjects: []string{"t/T.csproj"}},
			wantKind: "solution",
			want:     []string{"App.sln"},
		},
		{
			// The false pass in one line: the app project is present and must
			// not be a target, because dotnet test would exit 0 having run none.
			name: "only test projects, never the app project",
			d: dotnetDiscovery{
				Projects:     []string{"A.csproj", "t/T.csproj"},
				TestProjects: []string{"t/T.csproj"},
			},
			wantKind: "project",
			want:     []string{"t/T.csproj"},
		},
		{
			name:     "projects but none testable",
			d:        dotnetDiscovery{Projects: []string{"A.csproj"}},
			wantKind: "",
			want:     nil,
		},
		{name: "nothing", d: dotnetDiscovery{}, wantKind: "", want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, got := dotnetTestTargets(tc.d)
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
			assertPaths(t, "targets", got, tc.want)
		})
	}
}

func TestDotnetTargetLimitError(t *testing.T) {
	within := make([]string, dotnetTargetLimit)
	for i := range within {
		within[i] = "p.csproj"
	}
	if msg := dotnetTargetLimitError("dotnet format", within); msg != "" {
		t.Fatalf("at the limit should be allowed, got %q", msg)
	}

	over := append(within, "one/more.csproj")
	msg := dotnetTargetLimitError("dotnet format", over)
	if msg == "" {
		t.Fatal("over the limit must be an error, not a silent truncation")
	}
	for _, want := range []string{"dotnet format", "9", "one/more.csproj", ".sln"} {
		if !strings.Contains(msg, want) {
			t.Errorf("limit error missing %q: %s", want, msg)
		}
	}

	// The BYO remedy takes over test execution, so it belongs to the test leg
	// only. Offered to dotnet format it names a remedy that cannot fix the
	// failure being reported.
	if strings.Contains(msg, "--test-legs") {
		t.Errorf("dotnet format must not be offered a test-execution remedy: %s", msg)
	}
	testMsg := dotnetTargetLimitError("dotnet test", over)
	if !strings.Contains(testMsg, "--test-legs") {
		t.Errorf("the test leg must name the remedy that narrows what is tested: %s", testMsg)
	}
}

func TestDotnetNoTargetError(t *testing.T) {
	noProjects := dotnetNoTargetError("dotnet test", dotnetDiscovery{})
	if !strings.Contains(noProjects, "no .csproj") {
		t.Errorf("want a no-project message, got %q", noProjects)
	}

	noTests := dotnetNoTargetError("dotnet test", dotnetDiscovery{Projects: []string{"A.csproj", "B.csproj"}})
	for _, want := range []string{"2 projects", "Microsoft.NET.Test.Sdk", "no test ran"} {
		if !strings.Contains(noTests, want) {
			t.Errorf("no-test-project message missing %q: %s", want, noTests)
		}
	}

	fmtMsg := dotnetNoTargetError("dotnet format", dotnetDiscovery{})
	if !strings.HasPrefix(fmtMsg, "dotnet format:") {
		t.Errorf("format message should name its own tool: %s", fmtMsg)
	}
}

func TestDotnetFormatRunError(t *testing.T) {
	cases := []struct {
		name     string
		exit     string
		stderr   string
		report   string
		wantOK   bool // "" expected
		contains []string
	}{
		{name: "clean run writes an empty array", exit: "0", report: "[]", wantOK: true},
		{name: "findings", exit: "2", report: `[{"FileName":"A.cs"}]`, wantOK: true},
		{name: "trailing newline in exit status", exit: "0\n", report: "[]", wantOK: true},
		{
			// The exact false pass: the old command fabricated "[]" here.
			name:     "exit zero with no report is a non-run",
			exit:     "0",
			report:   "",
			contains: []string{"exited 0", "wrote no report"},
		},
		{
			name:     "exit two with no report is a non-run",
			exit:     "2",
			report:   "   \n",
			contains: []string{"wrote no report"},
		},
		{
			name:   "restore failure",
			exit:   "1",
			stderr: "MSBUILD : error MSB1011\nRestore operation failed",
			report: "",
			// The first diagnostic line wins: MSB1011 is the actionable code,
			// "Restore operation failed" is the generic summary printed after it.
			contains: []string{"did not run (exit 1)", "MSB1011"},
		},
		{
			name:     "global.json names an absent SDK",
			exit:     "145",
			stderr:   "A compatible .NET SDK was not found.\nRequested SDK version: 10.0.100",
			report:   "",
			contains: []string{"did not run (exit 145)", "global.json requests an SDK", "mcr.microsoft.com/dotnet/sdk:"},
		},
		{
			// The .NET 10 consumer on cicd's .NET 8 pin. The SDK is present and
			// working, so this reads as a project error unless the message says
			// whose SDK is too old.
			name:   "target framework above the pinned SDK",
			exit:   "1",
			stderr: netsdk1045,
			report: "",
			contains: []string{
				"did not run (exit 1)",
				"NETSDK1045",
				"targets .NET 10.0",
				"mcr.microsoft.com/dotnet/sdk:",
				"--toolchain-image",
			},
		},
		{
			name:     "unreadable exit status",
			exit:     "segfault",
			report:   "[]",
			contains: []string{"unreadable exit status"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dotnetFormatRunError(tc.exit, tc.stderr, tc.report, dotnetSDK80Band)
			if tc.wantOK {
				if got != "" {
					t.Fatalf("want a trustworthy run, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("want an error, got none — this is the false pass")
			}
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("error missing %q: %s", want, got)
				}
			}
		})
	}
}

func TestDotnetTestRunError(t *testing.T) {
	ran := trxSummary{Total: 3, Executed: 3, Failed: 0}
	failed := trxSummary{Total: 3, Executed: 3, Failed: 1}

	cases := []struct {
		name string
		// runner is the CLI surface the exit status came from. The zero value
		// means VSTest, which is what an absent global.json resolves to, so the
		// pre-MTP rows below read exactly as they did before the runner became a
		// parameter — the point being that the VSTest table is unchanged.
		runner   dotnetRunner
		exit     string
		trxFiles int
		sum      trxSummary
		out      string
		wantOK   bool
		contains []string
	}{
		{name: "passing run", exit: "0", trxFiles: 1, sum: ran, wantOK: true},
		{
			// Exit 1 means tests ran and some failed. That is a real result, not
			// a non-run, and the caller reports the failure separately.
			name: "failing tests still counts as having run", exit: "1", trxFiles: 1, sum: failed, wantOK: true,
		},
		{name: "several projects", exit: "0", trxFiles: 3, sum: trxSummary{Total: 9, Executed: 9}, wantOK: true},
		{
			// The measured false pass, reproduced: exit 0, no .trx, no tests.
			name:     "exit zero having run nothing",
			exit:     "0",
			trxFiles: 0,
			out:      "Determining projects to restore...\nRestored /src/dotnet-app.csproj",
			contains: []string{"exited 0", "no .trx", "no test executed"},
		},
		{
			name:     "trx accounting for zero tests",
			exit:     "0",
			trxFiles: 1,
			sum:      trxSummary{},
			contains: []string{"0 tests"},
		},
		{
			name:     "sdk missing",
			exit:     "145",
			out:      "A compatible .NET SDK was not found.\nRequested SDK version: 10.0.100",
			contains: []string{"did not run (exit 145)", "global.json requests an SDK"},
		},
		{
			name:     "build failure exit 2",
			exit:     "2",
			out:      "error CS1002: ; expected",
			contains: []string{"did not run (exit 2)", "CS1002"},
		},
		{name: "unreadable exit status", exit: "", trxFiles: 1, sum: ran, contains: []string{"unreadable exit status"}},
		{
			// The MTP project that this whole change exists for: no opt-in, so
			// cicd drove it through the VSTest target and the SDK refused. Exit 1
			// with no .trx is already a non-run structurally; the remedy names
			// the file and the key so the reader is not sent to release notes.
			name:     "vstest target refused for an mtp project",
			exit:     "1",
			trxFiles: 0,
			out: "/usr/share/dotnet/sdk/10.0.400/Microsoft.Testing.Platform.MSBuild.targets(263,5): " +
				"error : Testing with VSTest target is no longer supported by " +
				"Microsoft.Testing.Platform on .NET 10 SDK and later.",
			contains: []string{"did not run (exit 1)", "refuses to drive", "VSTest target",
				`"test": {"runner": "Microsoft.Testing.Platform"}`, "global.json"},
		},
		{
			// The sharpest reason the runner had to become a parameter. MTP's
			// exit 2 is "tests ran and some failed"; VSTest's 2 is a non-run. Read
			// through the wrong table this reported a genuine test failure as a leg
			// that never executed — a wrong cause on a correctly red build.
			name:     "mtp exit 2 is a real test failure",
			runner:   dotnetRunnerMTP,
			exit:     "2",
			trxFiles: 1,
			sum:      failed,
			wantOK:   true,
		},
		{
			name:     "mtp exit 2 with a trx accounting for zero tests",
			runner:   dotnetRunnerMTP,
			exit:     "2",
			trxFiles: 1,
			sum:      trxSummary{},
			contains: []string{"0 tests"},
		},
		{
			name:     "mtp refuses a vstest project in the tree",
			runner:   dotnetRunnerMTP,
			exit:     "1",
			trxFiles: 0,
			out:      "error : Project uses VSTest. All projects must use that test runner.",
			contains: []string{"did not run (exit 1)", "never started the test run", "still uses VSTest"},
		},
		{
			name:     "mtp rejected the command line",
			runner:   dotnetRunnerMTP,
			exit:     "5",
			trxFiles: 0,
			out:      "Unknown option '--report-trx'",
			contains: []string{"did not run (exit 5)", "--report-trx",
				"Microsoft.Testing.Extensions.CodeCoverage"},
		},
		{
			name:     "mtp matched zero tests",
			runner:   dotnetRunnerMTP,
			exit:     "8",
			trxFiles: 1,
			sum:      trxSummary{},
			contains: []string{"did not run (exit 8)", "matched zero", "run as a whole, not per project"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := tc.runner
			if runner == "" {
				runner = dotnetRunnerVSTest
			}
			got := dotnetTestRunError(runner, tc.exit, tc.trxFiles, tc.sum, tc.out, dotnetSDK80Band)
			if tc.wantOK {
				if got != "" {
					t.Fatalf("want a trustworthy run, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("want an error, got none — this is the false pass")
			}
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("error missing %q: %s", want, got)
				}
			}
		})
	}
}

func TestDotnetSkippedWarning(t *testing.T) {
	if w := dotnetSkippedWarning(trxSummary{Total: 4, Executed: 4}); w != "" {
		t.Errorf("an executed run needs no warning, got %q", w)
	}
	if w := dotnetSkippedWarning(trxSummary{}); w != "" {
		t.Errorf("zero tests is an error elsewhere, not a warning, got %q", w)
	}
	w := dotnetSkippedWarning(trxSummary{Total: 4, Executed: 0})
	if !strings.Contains(w, "4") || !strings.Contains(w, "skipped") {
		t.Errorf("all-skipped must be visible: %q", w)
	}
}

func TestParseTrxCounters(t *testing.T) {
	sum, ok := parseTrxCounters(trxDoc("7", "6", "2"))
	if !ok {
		t.Fatal("a real TRX with its namespace must parse")
	}
	if sum.Total != 7 || sum.Executed != 6 || sum.Failed != 2 {
		t.Fatalf("counters = %+v", sum)
	}

	for _, bad := range []string{"", "   ", "Passed! - Failed: 0", "<html><body>nope</body></html>", "{}"} {
		if _, ok := parseTrxCounters(bad); ok {
			t.Errorf("payload %q must not parse as a TRX", bad)
		}
	}
}

func TestParseTrxCountersMissingSummary(t *testing.T) {
	// Well-formed TestRun with no ResultSummary: it parses, but reports zero
	// tests — which dotnetTestRunError then rejects rather than reading as pass.
	sum, ok := parseTrxCounters(`<?xml version="1.0"?><TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results /></TestRun>`)
	if !ok {
		t.Fatal("a TestRun document should parse")
	}
	if sum.Total != 0 {
		t.Fatalf("want zero tests, got %+v", sum)
	}
	if msg := dotnetTestRunError(dotnetRunnerVSTest, "0", 1, sum, "", dotnetSDK80Band); msg == "" {
		t.Fatal("zero tests must still be an error")
	}
}

func TestParseTrxAll(t *testing.T) {
	one := trxDoc("2", "2", "0")
	two := trxDoc("3", "3", "1")

	sum, parsed := parseTrxAll(one + "\n" + two)
	if parsed != 2 {
		t.Fatalf("parsed = %d, want 2", parsed)
	}
	if sum.Total != 5 || sum.Executed != 5 || sum.Failed != 1 {
		t.Fatalf("summed counters = %+v", sum)
	}

	if _, parsed := parseTrxAll(one); parsed != 1 {
		t.Fatalf("single document parsed = %d, want 1", parsed)
	}

	// An unparseable payload must report zero documents, so the caller cannot
	// mistake its zero totals for a clean run.
	if sum, parsed := parseTrxAll("Passed! - Failed: 0, Passed: 1"); parsed != 0 || sum.Total != 0 {
		t.Fatalf("garbage parsed = %d, sum = %+v", parsed, sum)
	}
	if _, parsed := parseTrxAll(""); parsed != 0 {
		t.Fatal("empty payload must parse nothing")
	}
}

func TestSplitTrxDocuments(t *testing.T) {
	docs := splitTrxDocuments(trxDoc("1", "1", "0") + trxDoc("1", "1", "0"))
	if len(docs) != 2 {
		t.Fatalf("len = %d, want 2", len(docs))
	}
	for i, d := range docs {
		if !strings.HasSuffix(strings.TrimSpace(d), "</TestRun>") {
			t.Errorf("document %d is not a complete TestRun", i)
		}
	}
	if got := splitTrxDocuments("no closing tag here"); got != nil {
		t.Errorf("want nil for a truncated payload, got %v", got)
	}
}

func TestMergeDotnetCoverage(t *testing.T) {
	if pct, lines := mergeDotnetCoverage(nil); pct != nil || lines != nil {
		t.Fatal("no coverage must stay absent, not become zero")
	}

	pct, lines := mergeDotnetCoverage([]dotnetCoverage{{Percent: 75, Lines: 40}})
	if pct == nil || *pct != 75 || lines == nil || *lines != 40 {
		t.Fatalf("single = (%v, %v)", pct, lines)
	}

	// The false pass a plain mean would produce: a tiny fully-covered project
	// beside a large bare one averages to 55%, which reads as healthy.
	pct, lines = mergeDotnetCoverage([]dotnetCoverage{
		{Percent: 100, Lines: 8},
		{Percent: 10, Lines: 4000},
	})
	if pct == nil || *pct > 11 {
		t.Fatalf("weighted coverage = %v, want ~10.2", pct)
	}
	if lines == nil || *lines != 4008 {
		t.Fatalf("total lines = %v, want 4008", lines)
	}

	// No line counts anywhere: fall back to the mean rather than inventing one.
	pct, lines = mergeDotnetCoverage([]dotnetCoverage{{Percent: 80}, {Percent: 60}})
	if pct == nil || *pct != 70 {
		t.Fatalf("mean = %v, want 70", pct)
	}
	if lines != nil {
		t.Fatalf("line total must stay absent when unknown, got %v", *lines)
	}
}

func TestDotnetTargetLabel(t *testing.T) {
	if got := dotnetTargetLabel("", "boom"); got != "boom" {
		t.Errorf("= %q", got)
	}
	if got := dotnetTargetLabel(".", "boom"); got != "boom" {
		t.Errorf("= %q", got)
	}
	if got := dotnetTargetLabel("tests/T.csproj", "boom"); got != "tests/T.csproj: boom" {
		t.Errorf("= %q", got)
	}
}

// dotnetFormatSARIFDoc is the slice of a SARIF document these tests read back.
type dotnetFormatSARIFDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			Level     string                `json:"level"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region *struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeDotnetFormatSARIF(t *testing.T, sarif json.RawMessage) dotnetFormatSARIFDoc {
	t.Helper()
	var doc dotnetFormatSARIFDoc
	if err := json.Unmarshal(sarif, &doc); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	return doc
}

func TestParseDotnetFormatReport(t *testing.T) {
	// The measured shape (SDK 10.0.400): FileName is the bare name, FilePath
	// is absolute inside the container.
	report := `[{"FileName":"MathHelper.cs","FilePath":"/src/MathHelper.cs","FileChanges":[
	  {"LineNumber":7,"CharNumber":1,"DiagnosticId":"WHITESPACE","FormatDescription":"  Fix whitespace  "},
	  {"LineNumber":9,"CharNumber":3,"DiagnosticId":"IDE0055","FormatDescription":"Fix formatting"}]}]`

	sarif, counts, warnings := parseDotnetFormatReport([]byte(report), "10.0.100", dotnetSrcMount)
	if sarif == nil {
		t.Fatal("a valid report must produce SARIF")
	}
	if counts[SeverityMedium] != 2 {
		t.Fatalf("counts = %v, want 2 medium", counts)
	}
	if len(warnings) != 0 {
		t.Errorf("every entry had its path; warnings = %q", warnings)
	}

	doc := decodeDotnetFormatSARIF(t, sarif)
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2", len(doc.Runs[0].Results))
	}
	// The SDK that ran, not the compile-time pin: reporting the constant
	// misattributes findings to a version that was never involved.
	if got := doc.Runs[0].Tool.Driver.Version; got != "10.0.100" {
		t.Errorf("driver version = %q, want the observed SDK 10.0.100", got)
	}
	if got := doc.Runs[0].Results[0].Message.Text; got != "Fix whitespace" {
		t.Errorf("description not trimmed: %q", got)
	}
	loc := doc.Runs[0].Results[1].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "MathHelper.cs" {
		t.Errorf("uri = %q, want the mount stripped", loc.ArtifactLocation.URI)
	}
	if loc.Region == nil || loc.Region.StartLine != 9 || loc.Region.StartColumn != 3 {
		t.Errorf("region = %+v, want startLine 9, startColumn 3", loc.Region)
	}

	// An unknown version stays labelled unknown rather than borrowing the pin.
	sarif, _, _ = parseDotnetFormatReport([]byte("[]"), "", dotnetSrcMount)
	if !strings.Contains(string(sarif), `"version":"unknown"`) {
		t.Errorf("empty version should render as unknown: %s", sarif)
	}

	// Not a format report at all — must be nil so the caller errors.
	for _, bad := range []string{"", "not json", `{"runs":[]}`} {
		if got, _, _ := parseDotnetFormatReport([]byte(bad), "8.0", dotnetSrcMount); got != nil {
			t.Errorf("payload %q must not parse as a format report", bad)
		}
	}
}

// dotnetFormatRealReport is the verbatim `dotnet format --report` output of SDK
// 10.0.400 over a project holding Controllers/OrderController.cs and
// Api/Controllers/OrderController.cs with identical contents (a trailing
// space on line 3, spacing violations on line 5). The only edit is the
// absolute prefix of the host directory the probe ran in, replaced by the
// container mount so the fixture reads as the report cicd sees. Every one of
// the ten changes is byte-identical to its twin apart from FilePath — which is
// the collapse this fixture exists to reproduce.
const dotnetFormatRealReport = `[
  {
    "DocumentId": {
      "ProjectId": { "Id": "91cc3009-0784-4f68-ba8a-79991d37f45b" },
      "Id": "518e3869-49a6-4ba4-9ff5-f2128ee7d509"
    },
    "FileName": "OrderController.cs",
    "FilePath": "/src/Api/Controllers/OrderController.cs",
    "FileChanges": [
      { "LineNumber": 3, "CharNumber": 33, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Replace 4 characters with '\\n'." },
      { "LineNumber": 5, "CharNumber": 3, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Insert '\\s\\s'." },
      { "LineNumber": 5, "CharNumber": 19, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." },
      { "LineNumber": 5, "CharNumber": 21, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." },
      { "LineNumber": 5, "CharNumber": 34, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." }
    ]
  },
  {
    "DocumentId": {
      "ProjectId": { "Id": "91cc3009-0784-4f68-ba8a-79991d37f45b" },
      "Id": "f069beab-83e2-40b2-b477-b25e1944fd42"
    },
    "FileName": "OrderController.cs",
    "FilePath": "/src/Controllers/OrderController.cs",
    "FileChanges": [
      { "LineNumber": 3, "CharNumber": 33, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Replace 4 characters with '\\n'." },
      { "LineNumber": 5, "CharNumber": 3, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Insert '\\s\\s'." },
      { "LineNumber": 5, "CharNumber": 19, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." },
      { "LineNumber": 5, "CharNumber": 21, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." },
      { "LineNumber": 5, "CharNumber": 34, "DiagnosticId": "WHITESPACE", "FormatDescription": "Fix whitespace formatting. Delete 1 characters." }
    ]
  }
]`

// TestDotnetFormatFindingsKeepTheirFolder is the regression guard for the
// combined-table collapse: with FileName as the uri, all ten results below were
// five distinct findings, and the evidence aggregator — which keys its dedupe on
// the whole finding, path included — dropped the other five.
func TestDotnetFormatFindingsKeepTheirFolder(t *testing.T) {
	sarif, counts, warnings := parseDotnetFormatReport([]byte(dotnetFormatRealReport), "10.0.400", dotnetSrcMount)
	if sarif == nil {
		t.Fatal("the real report must parse")
	}
	if counts[SeverityMedium] != 10 {
		t.Fatalf("counts = %v, want 10 medium", counts)
	}
	if len(warnings) != 0 {
		t.Errorf("every entry carried FilePath; warnings = %q", warnings)
	}

	doc := decodeDotnetFormatSARIF(t, sarif)
	results := doc.Runs[0].Results
	if len(results) != 10 {
		t.Fatalf("results = %d, want 10", len(results))
	}

	uris := map[string]int{}
	for _, r := range results {
		if len(r.Locations) != 1 {
			t.Fatalf("locations = %d, want 1: %+v", len(r.Locations), r)
		}
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		uris[uri]++
		if !strings.Contains(uri, "/") {
			t.Errorf("uri %q carries no folder — this is the bare FileName", uri)
		}
		if strings.HasPrefix(uri, "/") || strings.Contains(uri, dotnetSrcMount+"/") {
			t.Errorf("uri %q leaks the container mount into evidence", uri)
		}
	}
	want := map[string]int{
		"Api/Controllers/OrderController.cs": 5,
		"Controllers/OrderController.cs":     5,
	}
	if len(uris) != len(want) {
		t.Fatalf("distinct uris = %v, want %v", uris, want)
	}
	for uri, n := range want {
		if uris[uri] != n {
			t.Errorf("uri %q appears %d times, want %d", uri, uris[uri], n)
		}
	}

	// A change that differs from its twin only by folder must be a distinct
	// identity under the aggregator's key (tool, rule, severity, message, path,
	// line) — assert the pair, not just the uri set, so the test fails if some
	// other field were made to carry the folder instead.
	type key struct {
		rule, msg, uri string
		line           int
	}
	seen := map[key]int{}
	bare := map[key]int{}
	for _, r := range results {
		loc := r.Locations[0].PhysicalLocation
		k := key{r.RuleID, r.Message.Text, loc.ArtifactLocation.URI, loc.Region.StartLine}
		seen[k]++
		k.uri = "OrderController.cs" // what the uri used to be
		bare[k]++
	}
	// Per file: (Replace…, line 3), (Insert…, line 5) and three
	// (Delete 1 characters, line 5) that differ only by column — which the
	// aggregator legitimately merges, since the column is not part of its
	// key. So 3 identities per folder, 6 across both; with the bare file
	// name as the uri the two folders are indistinguishable and it is 3.
	if len(seen) != 6 || len(bare) != 3 {
		t.Errorf("distinct identities: with folder %d (want 6), bare name %d (want 3)", len(seen), len(bare))
	}

	// CharNumber reaches evidence as startColumn; the console line `(5,19)`
	// matched CharNumber 19 on the measured run, so both are 1-based.
	region := results[2].Locations[0].PhysicalLocation.Region
	if region == nil || region.StartLine != 5 || region.StartColumn != 19 {
		t.Errorf("region = %+v, want startLine 5, startColumn 19", region)
	}
}

func TestDotnetFormatURI(t *testing.T) {
	entry := func(name, path string) dotnetFormatChange {
		var c dotnetFormatChange
		c.FileName = name
		c.FilePath = path
		return c
	}
	cases := []struct {
		name    string
		c       dotnetFormatChange
		root    string
		wantURI string
		wantWhy dotnetFormatURIFallback
	}{
		{"under the mount", entry("A.cs", "/src/Api/A.cs"), "/src", "Api/A.cs", dotnetFormatURIFromPath},
		{"at the mount root", entry("A.cs", "/src/A.cs"), "/src", "A.cs", dotnetFormatURIFromPath},
		{"root with trailing slash", entry("A.cs", "/src/Api/A.cs"), "/src/", "Api/A.cs", dotnetFormatURIFromPath},
		{"no FilePath at all", entry("A.cs", ""), "/src", "A.cs", dotnetFormatURINoPath},
		{"outside the mount", entry("A.cs", "/tmp/gen/A.cs"), "/src", "A.cs", dotnetFormatURIPathOutsideRoot},
		// A prefix match is not a directory match: /srcfoo is not under /src.
		{"sibling of the mount", entry("A.cs", "/srcfoo/A.cs"), "/src", "A.cs", dotnetFormatURIPathOutsideRoot},
		{"the mount itself", entry("A.cs", "/src/"), "/src", "A.cs", dotnetFormatURIPathOutsideRoot},
		// A Windows-style path is not rewritten into a Unix one: it is not under
		// the mount, so it falls back and is counted. dotnet in cicd's Linux
		// container writes forward slashes (measured), so this shape is a
		// guard, not an expectation.
		{"windows-style path", entry("A.cs", `C:\src\Api\A.cs`), "/src", "A.cs", dotnetFormatURIPathOutsideRoot},
		// A backslash inside a Linux path is a legal file-name byte and stays.
		{"backslash in a linux name", entry(`Odd\A.cs`, `/src/Api/Odd\A.cs`), "/src", `Api/Odd\A.cs`, dotnetFormatURIFromPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri, why := dotnetFormatURI(tc.c, tc.root)
			if uri != tc.wantURI || why != tc.wantWhy {
				t.Errorf("= (%q, %d), want (%q, %d)", uri, why, tc.wantURI, tc.wantWhy)
			}
			if strings.HasPrefix(uri, "/") {
				t.Errorf("uri %q is absolute — an absolute container path must never reach evidence", uri)
			}
		})
	}
}

// TestDotnetFormatFallbackIsCounted: a report that names no paths is worth a
// line in warnings[], because the reader must know the table can collapse.
func TestDotnetFormatFallbackIsCounted(t *testing.T) {
	report := `[
	  {"FileName":"A.cs","FileChanges":[
	    {"LineNumber":1,"CharNumber":1,"DiagnosticId":"WHITESPACE","FormatDescription":"x"},
	    {"LineNumber":2,"CharNumber":1,"DiagnosticId":"WHITESPACE","FormatDescription":"x"}]},
	  {"FileName":"B.cs","FilePath":"C:\\src\\B.cs","FileChanges":[
	    {"LineNumber":1,"CharNumber":1,"DiagnosticId":"WHITESPACE","FormatDescription":"x"}]},
	  {"FileName":"C.cs","FilePath":"/src/Lib/C.cs","FileChanges":[
	    {"LineNumber":1,"CharNumber":1,"DiagnosticId":"WHITESPACE","FormatDescription":"x"}]}]`

	sarif, counts, warnings := parseDotnetFormatReport([]byte(report), "10.0.400", dotnetSrcMount)
	if sarif == nil {
		t.Fatal("report must parse")
	}
	if counts[SeverityMedium] != 4 {
		t.Fatalf("counts = %v, want 4 — a coarsened location is still a finding", counts)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %q, want exactly one", warnings)
	}
	for _, want := range []string{
		"3 of 4 findings carry only a file name",
		"2 had no FilePath in the report",
		"1 had a path outside /src",
		"same-named files in different folders may collapse",
	} {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("warning %q lacks %q", warnings[0], want)
		}
	}

	doc := decodeDotnetFormatSARIF(t, sarif)
	var uris []string
	for _, r := range doc.Runs[0].Results {
		uris = append(uris, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if want := []string{"A.cs", "A.cs", "B.cs", "Lib/C.cs"}; !slices.Equal(uris, want) {
		t.Errorf("uris = %q, want %q", uris, want)
	}

	// The warning has one owner and is silent when nothing fell back.
	if got := dotnetFormatFallbackWarning(10, 0, 0); got != "" {
		t.Errorf("no fallback must produce no warning, got %q", got)
	}
	if got := dotnetFormatFallbackWarning(10, 0, 2); !strings.Contains(got, "2 of 10") || strings.Contains(got, "no FilePath") {
		t.Errorf("outside-root-only warning = %q", got)
	}
}

// TestDotnetFormatRegionIsNeverGuessed: SARIF region values are 1-based and
// positive, so a value the tool did not give is omitted — never 0 (invalid)
// and never 1 (a location the tool did not report).
func TestDotnetFormatRegionIsNeverGuessed(t *testing.T) {
	report := `[{"FileName":"A.cs","FilePath":"/src/A.cs","FileChanges":[
	  {"LineNumber":0,"CharNumber":0,"DiagnosticId":"ENDOFLINE","FormatDescription":"x"},
	  {"LineNumber":4,"CharNumber":0,"DiagnosticId":"ENDOFLINE","FormatDescription":"x"}]}]`
	sarif, _, _ := parseDotnetFormatReport([]byte(report), "10.0.400", dotnetSrcMount)
	doc := decodeDotnetFormatSARIF(t, sarif)
	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if r := results[0].Locations[0].PhysicalLocation.Region; r != nil {
		t.Errorf("no line and no column must emit no region, got %+v", r)
	}
	r := results[1].Locations[0].PhysicalLocation.Region
	if r == nil || r.StartLine != 4 {
		t.Fatalf("region = %+v, want startLine 4", r)
	}
	if strings.Contains(string(sarif), `"startColumn"`) {
		t.Errorf("a zero CharNumber must not be written as a column: %s", sarif)
	}
}

func TestDotnetSDKVersionOrUnknown(t *testing.T) {
	cases := map[string]string{
		"8.0.422\n":                            "8.0.422",
		"  10.0.100  ":                         "10.0.100",
		"":                                     "unknown",
		"\n\n":                                 "unknown",
		"Welcome to .NET!\nbanner\n10.0.100\n": "10.0.100",
	}
	for in, want := range cases {
		if got := dotnetSDKVersionOrUnknown(in); got != want {
			t.Errorf("dotnetSDKVersionOrUnknown(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDotnetDiagnosticLine(t *testing.T) {
	// The real shape of a dotnet format failure: the cause first, then frames.
	// lastNonEmptyLine would return the frame and bury the cause.
	formatFailure := `Unhandled exception: System.Exception: Restore operation failed.
   at Microsoft.CodeAnalysis.Tools.CodeFormatter.OpenMSBuildWorkspaceAsync(String path)
   at System.CommandLine.Invocation.InvocationPipeline.InvokeAsync(ParseResult parseResult)`
	if got := dotnetDiagnosticLine(formatFailure); !strings.Contains(got, "Restore operation failed") {
		t.Errorf("want the cause, got %q", got)
	}

	msbuild := "Determining projects to restore...\n" +
		"/src/tests/T.csproj(13,48): error MSB4025: The project file could not be loaded.\n" +
		"Build FAILED."
	if got := dotnetDiagnosticLine(msbuild); !strings.Contains(got, "MSB4025") {
		t.Errorf("want the MSBuild error, got %q", got)
	}

	// Microsoft.Testing.Platform's option rejection, in the real order: the
	// rejected flag, then its whole help text, then `error: 1`. Both lines carry a
	// marker, so the *first* one has to win: a trailing `error: 1` must not
	// hide the earlier line naming the rejected flag.
	mtpOption := "  Standard output: Unknown option '--report-trx'\n" +
		"  Unknown option '--coverage'\n" +
		"      --xunit-info\n          Show xUnit.net headers and information\n" +
		"Test run summary: Zero tests ran\n  error: 1"
	if got := dotnetDiagnosticLine(mtpOption); !strings.Contains(got, "--report-trx") {
		t.Errorf("want the rejected option, got %q", got)
	}

	sdk := "A compatible .NET SDK was not found.\nRequested SDK version: 10.0.100"
	if got := dotnetDiagnosticLine(sdk); !strings.Contains(got, "compatible .NET SDK") {
		t.Errorf("want the SDK error, got %q", got)
	}

	// Nothing diagnostic: fall back rather than returning empty.
	if got := dotnetDiagnosticLine("first\nsecond\n\n"); got != "second" {
		t.Errorf("fallback = %q, want %q", got, "second")
	}
	if got := dotnetDiagnosticLine(""); got != "" {
		t.Errorf("empty input = %q", got)
	}
	// Frames are skipped in favour of any real line, even a trailing one.
	if got := dotnetDiagnosticLine("   at Some.Frame(String s)\nBuild FAILED."); got != "Build FAILED." {
		t.Errorf("frame preferred over a real line: %q", got)
	}
	// When frames are all there is, report them — unhelpful beats empty, and an
	// empty cause reads as "cicd had nothing to say" rather than "the SDK died".
	if got := dotnetDiagnosticLine("   at Some.Frame(String s)"); got == "" {
		t.Error("frames-only output must still yield a cause")
	}
}

func TestParseCoberturaSet(t *testing.T) {
	doc := func(rate string, valid int) string {
		return `<?xml version="1.0"?><coverage line-rate="` + rate + `" lines-valid="` +
			itoaTest(valid) + `" branch-rate="0"></coverage>`
	}

	// coverlet writes the same report twice per run (attachment + artifact),
	// byte-identical — measured. Counting it twice would double the line total.
	one := doc("0.3333", 3)
	got := parseCoberturaSet(coberturaSeparator + "\n" + one + "\n" + coberturaSeparator + "\n" + one)
	if len(got) != 1 {
		t.Fatalf("identical duplicates must collapse, got %d readings: %+v", len(got), got)
	}
	if got[0].Lines != 3 {
		t.Fatalf("lines = %d, want 3", got[0].Lines)
	}

	// Two genuinely different projects both count.
	got = parseCoberturaSet(coberturaSeparator + "\n" + doc("1", 8) + "\n" + coberturaSeparator + "\n" + doc("0.1", 4000))
	if len(got) != 2 {
		t.Fatalf("want 2 readings, got %d", len(got))
	}
	pct, lines := mergeDotnetCoverage(got)
	if pct == nil || *pct > 11 || lines == nil || *lines != 4008 {
		t.Fatalf("merged = (%v, %v), want ~10.2%% over 4008 lines", pct, lines)
	}

	for _, bad := range []string{"", coberturaSeparator, coberturaSeparator + "\nnot xml at all"} {
		if got := parseCoberturaSet(bad); len(got) != 0 {
			t.Errorf("payload %q must yield no coverage, got %+v", bad, got)
		}
	}
}

// The dedup was written for coverlet's attachment-plus-artifact pair, where it
// was a tidiness measure — one project, one report either way. Under
// Microsoft.Testing.Platform it became load-bearing: the harvest globs
// '*.cobertura.xml' with no depth limit (it has to, because the per-project
// layout is nested), and MTP writes every test application's report a second
// time into the .trx attachment directory. This independently generated fixture
// creates five distinct reports and an interleaved copy of each. Counting both
// copies would double every line total, so coverage depends on this collapse.
func TestParseCoberturaSetPooledDuplicates(t *testing.T) {
	const projects = 5
	var b strings.Builder
	// Interleaved the way the harvest emits them — root documents first, then the
	// attachment copies — so the dedup is not accidentally passing because
	// duplicates happen to be adjacent.
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < projects; i++ {
			b.WriteString(coberturaSeparator + "\n" +
				`<?xml version="1.0"?><coverage line-rate="0.5" lines-valid="` +
				itoaTest(10+i) + `" branch-rate="0"></coverage>` + "\n")
		}
	}

	got := parseCoberturaSet(b.String())
	if len(got) != projects {
		t.Fatalf("10 generated files over %d projects must yield %d readings, got %d",
			projects, projects, len(got))
	}
	// 10+11+12+13+14 = 60. Twice that would be the silent doubling.
	_, lines := mergeDotnetCoverage(got)
	if lines == nil || *lines != 60 {
		t.Fatalf("merged lines = %v, want 60 (120 means every report was counted twice)", lines)
	}
}

// The empty-report shape an MTP test application can write when it instruments
// nothing: exit 0, line-rate="1" and no lines-valid at all. It must not reach
// the coverage figure, because line-rate="1" reads as 100%.
func TestParseCoberturaSetDropsEmptyDocument(t *testing.T) {
	empty := `<?xml version="1.0" encoding="utf-8"?><coverage line-rate="1" branch-rate="1" ` +
		`complexity="1" version="1.9" timestamp="0"><packages /></coverage>`

	if got := parseCoberturaSet(coberturaSeparator + "\n" + empty); len(got) != 0 {
		t.Fatalf("an empty report is not a measurement, got %+v", got)
	}

	real := `<?xml version="1.0"?><coverage line-rate="0.4" lines-valid="100"></coverage>`
	got := parseCoberturaSet(coberturaSeparator + "\n" + empty + "\n" +
		coberturaSeparator + "\n" + real)
	if len(got) != 1 || got[0].Lines != 100 {
		t.Fatalf("the real report must survive alone, got %+v", got)
	}
	pct, lines := mergeDotnetCoverage(got)
	if pct == nil || *pct != 40 || lines == nil || *lines != 100 {
		t.Fatalf("merged = (%v, %v), want 40%% over 100 lines", pct, lines)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// collectorMissing is dotnet test's verbatim wording when the XPlat collector is
// not installed. It still exits 0, which is why the wording is all there was.
const collectorMissing = "Data collection : Unable to find a datacollector with friendly name 'XPlat Code Coverage'.\n" +
	"Data collection : Could not find data collector 'XPlat Code Coverage'"

func TestDotnetCoverageOutcome(t *testing.T) {
	healthy := "Passed!  - Failed: 0, Passed: 1"

	cases := []struct {
		name         string
		runner       dotnetRunner
		out          string
		docs         int
		outside      int
		usable       int
		wantErr      []string
		wantWarn     []string
		wantNeither  bool
		forbidInWarn []string
	}{
		{
			name: "measured coverage says nothing", runner: dotnetRunnerMTP,
			out: healthy, docs: 2, usable: 2, wantNeither: true,
		},
		{
			// A generated empty document: <packages />, line-rate="1", no
			// lines-valid. parseCobertura now refuses it, so docs>0 and usable==0.
			// It is a warning, not an error — the run measured what it was asked
			// to, the consumer instrumented nothing — but it must never be
			// reported as the 100% its line-rate claims.
			name: "reports exist and measure nothing", runner: dotnetRunnerMTP,
			out: healthy, docs: 2, usable: 0,
			wantWarn: []string{"2 cobertura report(s)", "none carried a coverable line count",
				"not a 100% measurement"},
		},
		{
			// cicd's own defect, and it says so: reports exist, just not where the
			// harvest looked. Without this state, "we looked in the wrong place"
			// and "no coverage was produced" are the same evidence.
			name: "reports landed outside the results directory", runner: dotnetRunnerMTP,
			out: healthy, docs: 0, outside: 3,
			wantErr: []string{"no cobertura report reached the results directory",
				"3 were written under the projects' own build trees", "cicd defect"},
		},
		{
			// The structural absence detector. Nothing in the log distinguishes
			// this from a healthy run — measured, `--coverage` without
			// `--coverage-output-format cobertura` exits 0 and writes a binary
			// .coverage file — so the verdict comes from the file count, not a
			// string.
			name: "mtp accepted the flags and wrote nothing", runner: dotnetRunnerMTP,
			out: healthy, docs: 0, outside: 0,
			wantErr: []string{"coverage was requested", "--coverage-output-format",
				"must not report none", "Microsoft.Testing.Extensions.CodeCoverage"},
		},
		{
			name: "vstest collector missing", runner: dotnetRunnerVSTest,
			out: collectorMissing, docs: 0,
			wantWarn: []string{"coverlet.collector"},
		},
		{
			name: "vstest absence with no explanation", runner: dotnetRunnerVSTest,
			out: healthy, docs: 0,
			wantWarn: []string{"no cobertura coverage report"},
			// The coverlet remedy is wrong under MTP, and it is also wrong here:
			// nothing said the collector was missing.
			forbidInWarn: []string{"coverlet.collector"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errMsg, warnMsg := dotnetCoverageOutcome(tc.runner, tc.out, tc.docs, tc.outside, tc.usable)
			if tc.wantNeither {
				if errMsg != "" || warnMsg != "" {
					t.Fatalf("want silence, got err=%q warn=%q", errMsg, warnMsg)
				}
				return
			}
			if len(tc.wantErr) > 0 {
				if errMsg == "" {
					t.Fatal("want an error, got none — this is the false pass")
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(errMsg, want) {
						t.Errorf("error missing %q: %s", want, errMsg)
					}
				}
				if warnMsg != "" {
					t.Errorf("an error state must not also warn: %q", warnMsg)
				}
			}
			if len(tc.wantWarn) > 0 {
				if warnMsg == "" {
					t.Fatal("want a warning, got none")
				}
				for _, want := range tc.wantWarn {
					if !strings.Contains(warnMsg, want) {
						t.Errorf("warning missing %q: %s", want, warnMsg)
					}
				}
				for _, bad := range tc.forbidInWarn {
					if strings.Contains(warnMsg, bad) {
						t.Errorf("warning must not contain %q: %s", bad, warnMsg)
					}
				}
				if errMsg != "" {
					t.Errorf("a warning state must not also error: %q", errMsg)
				}
			}
		})
	}
}

// The collector-missing wording is VSTest's, and the remedy it carries
// (coverlet.collector) is meaningless under MTP — a coverage extension is what
// that runner needs. So the matcher is gated on the runner, not on the log alone.
func TestDotnetCoverageUnavailableIsVSTestOnly(t *testing.T) {
	if !dotnetCoverageUnavailable(dotnetRunnerVSTest, collectorMissing) {
		t.Error("the collector-missing message must be recognised on the VSTest path")
	}
	if dotnetCoverageUnavailable(dotnetRunnerVSTest, "Passed!  - Failed: 0, Passed: 1") {
		t.Error("a healthy run must not look like a missing collector")
	}
	if dotnetCoverageUnavailable(dotnetRunnerMTP, collectorMissing) {
		t.Error("VSTest's collector wording must not produce VSTest's remedy under MTP")
	}
}

// netsdk1045 is the SDK's verbatim wording when a project targets a framework
// the installed SDK cannot build — the failure a .NET 10 repository hits on
// cicd's .NET 8 pin. Kept as one constant so the format leg, the test leg and
// the parser are all driven by the same real text.
const netsdk1045 = "/src/App/App.csproj : error NETSDK1045: The current .NET SDK does not " +
	"support targeting .NET 10.0.  Either target .NET 8.0 or lower, or use a version of the " +
	".NET SDK that supports .NET 10.0. [/src/App/App.csproj]\n" +
	"Restore operation failed"

func TestDotnetRequestedTargetFramework(t *testing.T) {
	cases := map[string]string{
		netsdk1045: "10.0",
		"error NETSDK1045: The current .NET SDK does not support targeting .NET Core 3.1.": "Core 3.1",
		// Phrased some other way: vaguer message, never a wrong version.
		"error NETSDK1045: something new the SDK started saying": "",
		"":                                "",
		"Restore operation failed":        "",
		"Passed!  - Failed: 0, Passed: 1": "",
		// Adversarial: a version elsewhere in the log must not be picked up as
		// the target, which is why the pattern is anchored on the SDK sentence.
		"Determining projects to restore...\nMicrosoft (R) Build Engine 17.9.0": "",
	}
	for out, want := range cases {
		if got := dotnetRequestedTargetFramework(out); got != want {
			t.Errorf("dotnetRequestedTargetFramework(%.40q) = %q, want %q", out, got, want)
		}
	}
}

func TestDotnetSDKRemedy(t *testing.T) {
	// A band mismatch upward: the project is newer than the SDK that ran.
	band := dotnetSDKRemedy(netsdk1045, dotnetSDK80Band)
	for _, want := range []string{
		"targets .NET 10.0",
		"newer than",
		"mcr.microsoft.com/dotnet/sdk:" + dotnetSDK80Band,
		"--toolchain-image",
		"--include",
		"src/quality/images.go",
	} {
		if !strings.Contains(band, want) {
			t.Errorf("band remedy missing %q: %s", want, band)
		}
	}
	// It must name the bands on offer, because "raise the pin" is only the
	// remedy for a band cicd does not already pin.
	if !strings.Contains(band, dotnetBandsLabel()) {
		t.Errorf("band remedy must name the pinned bands: %s", band)
	}
	// global.json is now the lever for an unreadable TargetFramework — it
	// selects among the pinned bands. It must be offered as that and not as a
	// way to reach a band cicd has no image for.
	if !strings.Contains(band, "sdk.version") {
		t.Errorf("band remedy must point at global.json sdk.version: %s", band)
	}
	if strings.Contains(band, "global.json cannot fix this") {
		t.Errorf("the pre-band-selection wording survived: %s", band)
	}

	// A band mismatch downward: global.json asks for an SDK that is not there.
	absent := dotnetSDKRemedy("A compatible .NET SDK was not found.\nRequested SDK version: 10.0.100",
		dotnetSDK80Band)
	if !strings.Contains(absent, "global.json requests an SDK") {
		t.Errorf("absent-SDK remedy regressed: %s", absent)
	}
	// The two causes are opposite ends of one axis and must not blur: the
	// absent-SDK case must not claim the project targets anything.
	if strings.Contains(absent, "targets .NET") {
		t.Errorf("absent-SDK remedy must not describe a target framework: %s", absent)
	}

	// Everything else stays silent — a remedy for a cause cicd has not
	// identified is worse than none.
	for _, quiet := range []string{
		"",
		"Restore operation failed",
		"MSBUILD : error MSB1011: more than one project",
		"Passed!  - Failed: 0, Passed: 1",
	} {
		if got := dotnetSDKRemedy(quiet, dotnetSDK80Band); got != "" {
			t.Errorf("dotnetSDKRemedy(%q) = %q, want empty", quiet, got)
		}
	}
}

// The band failure reaches the TEST leg through a different branch than the
// format leg: the build fails, so `dotnet test` exits 1 — which is also its
// "tests ran, some failed" code — and lands in the wrote-no-.trx branch.
func TestDotnetTestRunError_targetBandCarriesTheRemedy(t *testing.T) {
	msg := dotnetTestRunError(dotnetRunnerVSTest, "1", 0, trxSummary{}, netsdk1045, dotnetSDK80Band)
	if msg == "" {
		t.Fatal("a build that never produced a .trx must not read as a test result")
	}
	for _, want := range []string{"no .trx", "NETSDK1045", "targets .NET 10.0", "--toolchain-image"} {
		if !strings.Contains(msg, want) {
			t.Errorf("test-leg message missing %q: %s", want, msg)
		}
	}

	// The same branch catches "the root project is not a test project", which is
	// unrelated to any band — that message must stay free of SDK advice.
	plain := dotnetTestRunError(dotnetRunnerVSTest, "0", 0, trxSummary{}, "Determining projects to restore...\nRestore complete", dotnetSDK80Band)
	if strings.Contains(plain, "toolchain-image") || strings.Contains(plain, "global.json") {
		t.Errorf("a no-test-project run must not be blamed on the SDK band: %s", plain)
	}
}

// dotnetTFMAboveBand exists because `dotnet format` withholds NETSDK1045; it
// must therefore be right from the project file alone, and — because it only
// enriches an already-failed run — must stay silent whenever it is unsure.
func TestDotnetTFMAboveBand(t *testing.T) {
	// The band these expectations are written against.
	const band = "8.0"
	if dotnetSDK80Band != band {
		t.Skipf("the oldest pinned band moved to %s — revisit these cases", dotnetSDK80Band)
	}

	cases := []struct {
		name   string
		csproj string
		want   string
	}{
		{
			name:   "above the pin",
			csproj: "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
			want:   "10.0",
		},
		{
			name:   "at the pin is not above it",
			csproj: "<TargetFramework>net8.0</TargetFramework>",
			want:   "",
		},
		{
			name:   "below the pin",
			csproj: "<TargetFramework>net6.0</TargetFramework>",
			want:   "",
		},
		{
			name:   "multi-target reports the highest offender",
			csproj: "<TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>",
			want:   "10.0",
		},
		{
			name:   "multi-target entirely at or below the pin",
			csproj: "<TargetFrameworks>net6.0;net8.0</TargetFrameworks>",
			want:   "",
		},
		{
			// Two-digit minors must compare numerically, not lexically: "8.10"
			// is above "8.0" but sorts below it as text.
			name:   "minor version compares numerically",
			csproj: "<TargetFramework>net8.10</TargetFramework>",
			want:   "8.10",
		},
		{
			// A version elsewhere in the file is not the target framework. This
			// is why the element is isolated first.
			name: "a package version is not a target framework",
			csproj: `<TargetFramework>net8.0</TargetFramework>
				<PackageReference Include="Some.Net10.0.Shim" Version="10.0.1" />`,
			want: "",
		},
		{
			// MSBuild has to evaluate this; guessing would be inventing a cause.
			name:   "an msbuild property is unknowable",
			csproj: "<TargetFramework>$(DefaultTargetFramework)</TargetFramework>",
			want:   "",
		},
		{
			name:   "netstandard is not a net band",
			csproj: "<TargetFramework>netstandard2.0</TargetFramework>",
			want:   "",
		},
		{
			name:   "framework-era target is not a net band",
			csproj: "<TargetFramework>net48</TargetFramework>",
			want:   "",
		},
		{
			name:   "attribute-cased element still matches",
			csproj: "<targetframework>NET10.0</targetframework>",
			want:   "10.0",
		},
		{
			name:   "no target framework at all",
			csproj: "<Project><ItemGroup /></Project>",
			want:   "",
		},
		{
			// A solution file, which the format leg may target instead: nothing
			// to read, so nothing to say.
			name:   "a solution file yields no hint",
			csproj: "Microsoft Visual Studio Solution File, Format Version 12.00",
			want:   "",
		},
		{name: "empty", csproj: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dotnetTFMAboveBand(tc.csproj, band); got != tc.want {
				t.Fatalf("dotnetTFMAboveBand = %q, want %q", got, tc.want)
			}
		})
	}

	// The band is a parameter now, so the same project reads differently under a
	// different SDK — which is the whole point of pinning more than one.
	const net10 = "<TargetFramework>net10.0</TargetFramework>"
	if got := dotnetTFMAboveBand(net10, dotnetSDK100Band); got != "" {
		t.Errorf("net10.0 under the 10.0 band must yield no hint, got %q", got)
	}
	// A band that is not a band must not be read as agreement.
	if got := dotnetTFMAboveBand(net10, "not-a-band"); got != "" {
		t.Errorf("an unparseable band must yield no hint, got %q", got)
	}
}

func TestDotnetTargetBandRemedy_vagueWithoutAVersion(t *testing.T) {
	named := dotnetTargetBandRemedy("10.0", dotnetSDK80Band)
	if !strings.Contains(named, "targets .NET 10.0") {
		t.Errorf("a known band must be named: %s", named)
	}
	anon := dotnetTargetBandRemedy("", dotnetSDK80Band)
	if strings.Contains(anon, ".NET  ") || strings.Contains(anon, "targets .NET,") {
		t.Errorf("an unknown band must not leave a hole: %s", anon)
	}
	for _, want := range []string{
		"newer than the SDK",
		dotnetSDKLabelFor(dotnetSDK80Band),
		dotnetBandsLabel(),
		"--toolchain-image",
	} {
		if !strings.Contains(anon, want) {
			t.Errorf("vague remedy missing %q: %s", want, anon)
		}
	}
}

// The band map is only honest if the three places that must agree do: a constant
// pair per band in images.go, the ordered list, and (unreachable from a unit
// test) the From() switch in dotnetexec.go. This covers the two it can see, and
// the third fails loud rather than silently substituting a band —
// dotnetUnpinnedBandError.
func TestDotnetSDKBandsArePinnedAndOrdered(t *testing.T) {
	if len(dotnetSDKBands) < 2 {
		t.Fatal("a single band is the defect a consumer reported: a consumer above " +
			"it cannot be linted or tested at all")
	}

	images := map[string]string{
		dotnetSDK80Band:  dotnetSDK80Image,
		dotnetSDK100Band: dotnetSDK100Image,
	}
	if len(images) != len(dotnetSDKBands) {
		t.Fatalf("dotnetSDKBands has %d bands but %d image constants are known here — "+
			"a band with no image reaches dotnetSDKBase and refuses to run",
			len(dotnetSDKBands), len(images))
	}

	for i, band := range dotnetSDKBands {
		if _, _, ok := dotnetBand(band); !ok {
			t.Errorf("band %q is not <major>.<minor>, so it can never be compared", band)
		}
		image, ok := images[band]
		if !ok {
			t.Fatalf("band %q has no pinned image constant", band)
		}
		if want := "mcr.microsoft.com/dotnet/sdk:" + band + "@sha256:"; !strings.HasPrefix(image, want) {
			t.Errorf("band %q image %q must be %q plus a digest — a mutable tag is "+
				"repointable under us (CWE-494)", band, image, want)
		}
		if i > 0 {
			cmp, ok := dotnetBandCompare(dotnetSDKBands[i-1], band)
			if !ok || cmp >= 0 {
				t.Errorf("dotnetSDKBands must ascend: %q is not below %q",
					dotnetSDKBands[i-1], band)
			}
		}
	}
}

func TestDotnetBandCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign
		ok   bool
	}{
		{"8.0", "8.0", 0, true},
		{"8.0", "10.0", -1, true},
		{"10.0", "8.0", 1, true},
		// Two-digit minors compare numerically, not lexically.
		{"8.10", "8.9", 1, true},
		{"8.9", "8.10", -1, true},
		{"", "8.0", 0, false},
		{"8.0", "", 0, false},
		{"net8.0", "8.0", 0, false},
		{"8", "8.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := dotnetBandCompare(tc.a, tc.b)
		if ok != tc.ok {
			t.Errorf("dotnetBandCompare(%q, %q) ok = %v, want %v", tc.a, tc.b, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if sign(got) != tc.want {
			t.Errorf("dotnetBandCompare(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestDotnetHighestTFM(t *testing.T) {
	cases := map[string]string{
		"<TargetFramework>net10.0</TargetFramework>":          "10.0",
		"<TargetFrameworks>net8.0;net10.0</TargetFrameworks>": "10.0",
		"<TargetFramework>net8.0</TargetFramework>":           "8.0",
		// Highest across a concatenation of several project files, which is how
		// the probe hands them over.
		"<TargetFramework>net8.0</TargetFramework><TargetFramework>net10.0</TargetFramework>": "10.0",
		// Nothing readable is "" — never a guessed default.
		"<TargetFramework>$(Band)</TargetFramework>":                   "",
		"<TargetFramework>netstandard2.0</TargetFramework>":            "",
		"<TargetFramework>net48</TargetFramework>":                     "",
		`<PackageReference Include="Net10.0.Shim" Version="10.0.1" />`: "",
		"": "",
	}
	for in, want := range cases {
		if got := dotnetHighestTFM(in); got != want {
			t.Errorf("dotnetHighestTFM(%.60q) = %q, want %q", in, got, want)
		}
	}
}

// Band resolution is the fix for the single-band defect, and the case that must not regress
// is the last one: a band cicd cannot serve resolves to a run that can fail,
// never to a refusal built on a string cicd only half understands, and never to
// a quiet substitution that would attribute the verdict to an SDK nobody chose.
func TestDotnetResolveBand(t *testing.T) {
	lowest, highest := dotnetSDKBands[0], dotnetSDKBands[len(dotnetSDKBands)-1]

	cases := []struct {
		name     string
		req      dotnetBandRequest
		want     string
		wantNote []string
	}{
		{
			name:     "nothing readable keeps the oldest pinned band, as before",
			req:      dotnetBandRequest{},
			want:     lowest,
			wantNote: []string{"SDK band " + lowest, "no global.json"},
		},
		{
			name:     "an exact pinned band is used",
			req:      dotnetBandRequest{Band: highest, Source: "TargetFramework"},
			want:     highest,
			wantNote: []string{"SDK band " + highest, "TargetFramework"},
		},
		{
			name:     "global.json is honoured, which is what keeps exit 145 off the table",
			req:      dotnetBandRequest{Band: lowest, Source: "global.json"},
			want:     lowest,
			wantNote: []string{"global.json"},
		},
		{
			name:     "below every pinned band runs the oldest, which can build it",
			req:      dotnetBandRequest{Band: "6.0", Source: "TargetFramework"},
			want:     lowest,
			wantNote: []string{"pins no image for", "6.0"},
		},
		{
			name:     "between bands runs the nearest above",
			req:      dotnetBandRequest{Band: "9.0", Source: "TargetFramework"},
			want:     highest,
			wantNote: []string{"pins no image for", "9.0"},
		},
		{
			name:     "above every pinned band runs the newest and says so, loudly",
			req:      dotnetBandRequest{Band: "99.0", Source: "TargetFramework"},
			want:     highest,
			wantNote: []string{"above every band cicd pins", "non-run", "--fail-on"},
		},
		{
			name:     "a request that is not a band is no request",
			req:      dotnetBandRequest{Band: "latest", Source: "global.json"},
			want:     lowest,
			wantNote: []string{"SDK band " + lowest},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note := dotnetResolveBand(tc.req)
			if got != tc.want {
				t.Fatalf("band = %q, want %q (note: %s)", got, tc.want, note)
			}
			// Whatever is returned must be servable, or the run refuses.
			if !slices.Contains(dotnetSDKBands, got) {
				t.Fatalf("resolved band %q is not pinned", got)
			}
			// Never silent: an SDK choice a consumer cannot see is an
			// unexplained verdict.
			if strings.TrimSpace(note) == "" {
				t.Fatal("resolution must always record which band it chose and why")
			}
			for _, want := range tc.wantNote {
				if !strings.Contains(note, want) {
					t.Errorf("note missing %q: %s", want, note)
				}
			}
		})
	}
}

func TestParseDotnetBandRequest(t *testing.T) {
	probe := func(globalJSON, projects string) string {
		return dotnetProbeGlobalJSON + "\n" + globalJSON + "\n" +
			dotnetProbeTFM + "\n" + projects
	}

	cases := []struct {
		name       string
		raw        string
		wantBand   string
		wantSource string
	}{
		{
			name:       "global.json outranks the project files",
			raw:        probe(`{"sdk":{"version":"8.0.404"}}`, "<TargetFramework>net10.0</TargetFramework>"),
			wantBand:   "8.0",
			wantSource: "global.json",
		},
		{
			name:       "no global.json falls to the highest TargetFramework",
			raw:        probe("", "<TargetFrameworks>net8.0;net10.0</TargetFrameworks>"),
			wantBand:   "10.0",
			wantSource: "TargetFramework",
		},
		{
			name: "Directory.Build.props content arrives on the same section",
			raw: probe("", "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>"+
				"</PropertyGroup></Project>"),
			wantBand:   "10.0",
			wantSource: "TargetFramework",
		},
		{
			// Malformed global.json is not an error and not a guess: the project
			// files answer instead.
			name:       "malformed global.json falls through",
			raw:        probe("{not json", "<TargetFramework>net10.0</TargetFramework>"),
			wantBand:   "10.0",
			wantSource: "TargetFramework",
		},
		{
			name:       "global.json with no sdk.version falls through",
			raw:        probe(`{"msbuild-sdks":{"X":"1.0"}}`, "<TargetFramework>net10.0</TargetFramework>"),
			wantBand:   "10.0",
			wantSource: "TargetFramework",
		},
		{
			name:       "nothing readable is no request at all",
			raw:        probe("", "<Project><ItemGroup /></Project>"),
			wantBand:   "",
			wantSource: "",
		},
		{
			// A probe whose markers are absent means cicd did not get the answer
			// it asked for. That must read as "no request", never as a band
			// scraped out of whatever text arrived.
			name:       "a probe with no markers yields nothing",
			raw:        "<TargetFramework>net10.0</TargetFramework>",
			wantBand:   "",
			wantSource: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDotnetBandRequest(tc.raw)
			if got.Band != tc.wantBand || got.Source != tc.wantSource {
				t.Fatalf("parseDotnetBandRequest = %+v, want band %q source %q",
					got, tc.wantBand, tc.wantSource)
			}
		})
	}
}

func TestDotnetUnpinnedBandError(t *testing.T) {
	msg := dotnetUnpinnedBandError("dotnet format", "11.0")
	for _, want := range []string{"dotnet format", "11.0", dotnetBandsLabel(), "nothing was checked"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q: %s", want, msg)
		}
	}
}

func TestDotnetTestScopeWarning(t *testing.T) {
	// Both branches report scope, and that is the point rather than a symmetry
	// preference. dotnetTestTargets returns a solution before it consults
	// TestProjects, so a repository with an unambiguous solution never reaches
	// the textual classification — and if only the project branch said anything
	// about scope, the solution branch's silence would be indistinguishable from a
	// classification that was checked and found complete.
	sol := dotnetTestScopeWarning("solution",
		dotnetDiscovery{Solutions: []string{"App.slnx"}, Projects: make([]string, 53)},
		[]string{"App.slnx"})
	for _, want := range []string{"ran solution App.slnx", "53 .csproj", "no per-project", "no ratio"} {
		if !strings.Contains(sol, want) {
			t.Errorf("solution warning missing %q: %s", want, sol)
		}
	}
	// It must not claim a classification it did not perform, and must not imply
	// cicd enumerated what the solution contains.
	if strings.Contains(sol, " of 53") {
		t.Errorf("the solution branch has no ratio to report, so it must not read like one: %s", sol)
	}

	// 2 of 2: nothing was skipped, so there is no skipped clause and no caveat
	// about a classification that excluded nothing.
	all := dotnetTestScopeWarning("project",
		dotnetDiscovery{Projects: []string{"a.csproj", "b.csproj"}, TestProjects: []string{"a.csproj", "b.csproj"}},
		[]string{"a.csproj", "b.csproj"})
	if !strings.Contains(all, "ran 2 of 2 .csproj") {
		t.Errorf("the ratio is the whole point of this warning: %s", all)
	}
	if strings.Contains(all, "The other") || strings.Contains(all, "Directory.Build.props") {
		t.Errorf("nothing was skipped, so nothing should be excused: %s", all)
	}

	// Synthetic 1-of-3 classification: report what was skipped and why the
	// classification may be incomplete. If a project relies only on an
	// IsTestProject marker, moving it into Directory.Build.props can make
	// the project invisible to a text-only per-project classifier.
	partial := dotnetTestScopeWarning("project",
		dotnetDiscovery{
			Projects:     []string{"a.csproj", "b.csproj", "c.csproj"},
			TestProjects: []string{"a.csproj"},
		},
		[]string{"a.csproj"})
	for _, want := range []string{
		"ran 1 of 3 .csproj", "a.csproj", "The other 2",
		"Directory.Build.props", "Committing a solution",
	} {
		if !strings.Contains(partial, want) {
			t.Errorf("partial-sweep warning missing %q: %s", want, partial)
		}
	}

	// No scope claim where there is no scope to claim: a run with no discovered
	// projects must not emit "ran 0 of 0", which is the vacuous truth that let an
	// empty language set report a pass.
	if got := dotnetTestScopeWarning("project", dotnetDiscovery{}, nil); got != "" {
		t.Errorf("no projects discovered means no ratio to state, got %q", got)
	}
	if got := dotnetTestScopeWarning("", dotnetDiscovery{Projects: []string{"a.csproj"}}, nil); got != "" {
		t.Errorf("no target kind means no run to describe, got %q", got)
	}
	if got := dotnetTestScopeWarning("solution", dotnetDiscovery{}, nil); got != "" {
		t.Errorf("a solution branch with no target names nothing, got %q", got)
	}

	// notify renders every warnings[] entry as a markdown code span.
	for _, w := range []string{sol, all, partial} {
		if strings.Contains(w, "`") {
			t.Errorf("warning carries a backtick, which notify renders as a code span: %s", w)
		}
	}
}

func TestDotnetNoTargetErrorNamesTheClassificationLimit(t *testing.T) {
	// "Add a test project" is actively misleading to the repository most likely to
	// hit this: one whose test dependencies arrive from a Directory.Build.props,
	// where the test projects already exist and the grep cannot see them. The
	// remedy that works there is committing a solution, because that path skips
	// classification entirely rather than making the grep less blind.
	msg := dotnetNoTargetError("dotnet test", dotnetDiscovery{Projects: []string{"a.csproj", "b.csproj"}})
	for _, want := range []string{"Directory.Build.props", "Committing a solution", "greps each"} {
		if !strings.Contains(msg, want) {
			t.Errorf("no-target error missing %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "`") {
		t.Errorf("error carries a backtick: %s", msg)
	}

	// The no-projects case has no classification to caveat — there was nothing to
	// grep — and a caveat there would send a reader after a props file that
	// explains nothing.
	none := dotnetNoTargetError("dotnet test", dotnetDiscovery{})
	if strings.Contains(none, "Directory.Build.props") {
		t.Errorf("no .csproj at all is not a classification failure: %s", none)
	}
}

// TestSayWhyTheRunnerExitedNonZero pins the shape that had no explanation: a
// green suite and a red exit code, where dotnetTestRunError's default arm
// returns "" and the runner's own output was being discarded.
func TestSayWhyTheRunnerExitedNonZero(t *testing.T) {
	// Invented accounting keeps the green-suite/non-zero-exit contradiction.
	green := trxSummary{Total: 72, Executed: 72, Failed: 0}
	noTests := "Starting test execution, please wait...\n" +
		"No test is available in /src/Widget.Tools/bin/Debug/net10.0/Widget.Tools.dll. " +
		"Make sure that test discoverer & executors are registered.\n"

	for _, tc := range []struct {
		name    string
		code    string
		runErr  string
		out     string
		sum     trxSummary
		hasRun  bool
		want    []string
		notWant []string
	}{
		{
			name:   "synthetic regression: 72 passed, exit 1, cause was in output",
			code:   "1",
			out:    noTests,
			sum:    green,
			hasRun: true,
			want:   []string{"exit 1", "every test reported passing", "No test is available"},
		},
		{
			name:    "a suite that genuinely failed explains itself",
			code:    "1",
			out:     noTests,
			sum:     trxSummary{Total: 72, Executed: 72, Failed: 3},
			hasRun:  true,
			want:    []string{"dotnet test failed (exit 1)"},
			notWant: []string{"every test reported passing", "No test is available"},
		},
		{
			name:    "a classified non-run is not explained twice",
			code:    "1",
			runErr:  "dotnet test: exited 1 but wrote no .trx result file, so no test executed: Build FAILED.",
			out:     "Build FAILED.\n",
			hasRun:  false,
			want:    []string{"dotnet test failed (exit 1)"},
			notWant: []string{"every test reported passing", "Build FAILED"},
		},
		{
			name:   "no accounting at all is still unexplained, not excused",
			code:   "1",
			out:    noTests,
			hasRun: false,
			want:   []string{"every test reported passing", "No test is available"},
		},
		{
			name:   "a non-zero exit that printed nothing says so",
			code:   "1",
			out:    "",
			sum:    green,
			hasRun: true,
			want:   []string{"exit 1", "printed nothing"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dotnetTestExitFailure(tc.code, tc.runErr, tc.out, tc.sum, tc.hasRun, nil)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q\ngot: %s", w, got)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("unexpectedly contains %q\ngot: %s", w, got)
				}
			}
		})
	}
}

// The message must never be empty, whatever it was handed: an empty error is a
// leg that failed and said nothing.
func TestTheExitFailureMessageIsNeverEmpty(t *testing.T) {
	if got := dotnetTestExitFailure("", "", "", trxSummary{}, false, nil); !strings.Contains(got, "dotnet test failed") {
		t.Errorf("dotnetTestExitFailure on empty input = %q", got)
	}
}
