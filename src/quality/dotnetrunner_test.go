//go:build unit_test

package main

// dotnetrunner_test.go pins the two halves of "detect the runner, do not assume
// one": which CLI surface a repository asked for, and the exact argv cicd hands
// to it. Both are pure functions in dotnetrunner.go for that reason — the leg
// that used to hold this logic is behind //go:build !unit_test, which is how a
// VSTest-only invocation survived the arrival of a second runner.

import (
	"slices"
	"strings"
	"testing"
)

func TestDotnetRunnerFromGlobalJSON(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want dotnetRunner
		// noteContains is checked when a runner resolved: the note lands in
		// warnings[], so the evidence says which invocation produced the verdict
		// and where that answer came from.
		noteContains []string
		// errContains is checked when nothing resolved. An unresolvable runner is
		// a non-run, never a default.
		errContains []string
	}{
		{
			name: "no global.json at all",
			raw:  "",
			want: dotnetRunnerVSTest,
			noteContains: []string{"VSTest", "no global.json in the repository root",
				"SDK default"},
		},
		{
			name:         "whitespace only",
			raw:          "   \n\t ",
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest", "no global.json"},
		},
		{
			// The overwhelmingly common global.json: an SDK pin and nothing else.
			// It must resolve to VSTest with a note, because a band pin says
			// nothing about the runner.
			name:         "global.json pinning only the sdk",
			raw:          `{"sdk": {"version": "10.0.400", "rollForward": "latestFeature"}}`,
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest", "sets no", `"runner"`},
		},
		{
			name:         "test section without a runner key",
			raw:          `{"test": {"other": true}}`,
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest", "sets no"},
		},
		{
			name:         "blank runner value",
			raw:          `{"test": {"runner": "   "}}`,
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest", "sets no"},
		},
		{
			name: "the mtp opt-in",
			raw:  `{"sdk": {"version": "10.0.400"}, "test": {"runner": "Microsoft.Testing.Platform"}}`,
			want: dotnetRunnerMTP,
			// "repository-wide" is in the note because the setting is: one
			// VSTest-shaped project anywhere in the tree fails the whole run
			// (exit 1), and a reader of the evidence has to know that before
			// hunting the wrong project.
			noteContains: []string{"Microsoft.Testing.Platform", "repository-wide"},
		},
		{
			// Measured: the SDK matches the value case-insensitively, so a
			// lowercase spelling really does select the MTP CLI and run. A
			// case-sensitive match here would drive an MTP repository through
			// VSTest flags — the exact defect being fixed, reintroduced by
			// cicd itself.
			name:         "lowercase opt-in still selects mtp",
			raw:          `{"test": {"runner": "microsoft.testing.platform"}}`,
			want:         dotnetRunnerMTP,
			noteContains: []string{"Microsoft.Testing.Platform"},
		},
		{
			name:         "explicit vstest",
			raw:          `{"test": {"runner": "VSTest"}}`,
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest", `"runner"`},
		},
		{
			name:         "explicit vstest lowercase",
			raw:          `{"test": {"runner": "vstest"}}`,
			want:         dotnetRunnerVSTest,
			noteContains: []string{"VSTest"},
		},
		{
			// Not a fallback to VSTest. Measured: an unsupported runner name makes
			// the SDK throw on *every* dotnet command, so guessing an invocation
			// here would report a cause that has nothing to do with the failure.
			name: "unsupported runner name",
			raw:  `{"test": {"runner": "Banana"}}`,
			errContains: []string{`"Banana"`, "no .NET SDK supports",
				`"VSTest"`, `"Microsoft.Testing.Platform"`, "No test was"},
		},
		{
			name:        "malformed json",
			raw:         `{"test": {"runner": "VSTest",}`,
			errContains: []string{"not valid JSON", "no test was run"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, note, errMsg := dotnetRunnerFromGlobalJSON(tc.raw)

			if len(tc.errContains) > 0 {
				if errMsg == "" {
					t.Fatalf("want a refusal, got runner %q with note %q", runner, note)
				}
				if runner != "" {
					t.Errorf("a refusal must resolve no runner, got %q", runner)
				}
				for _, want := range tc.errContains {
					if !strings.Contains(errMsg, want) {
						t.Errorf("refusal missing %q: %s", want, errMsg)
					}
				}
				return
			}

			if errMsg != "" {
				t.Fatalf("unexpected refusal: %s", errMsg)
			}
			if runner != tc.want {
				t.Fatalf("runner = %q, want %q", runner, tc.want)
			}
			// A resolved runner always says which one and why, because
			// "cicd chose an invocation" is a fact the evidence has to carry.
			if note == "" {
				t.Fatal("a resolved runner must be named in the evidence")
			}
			for _, want := range tc.noteContains {
				if !strings.Contains(note, want) {
					t.Errorf("note missing %q: %s", want, note)
				}
			}
		})
	}
}

// The lowercase error message is deliberately checked case-insensitively above in
// one row only; this keeps the refusal wording honest about what did not happen.
func TestDotnetRunnerRefusalSaysNothingRan(t *testing.T) {
	for _, raw := range []string{`{"test": {"runner": "Banana"}}`, `{`} {
		_, _, errMsg := dotnetRunnerFromGlobalJSON(raw)
		if errMsg == "" {
			t.Fatalf("%q must be refused", raw)
		}
		if !strings.Contains(strings.ToLower(errMsg), "no test was run") {
			t.Errorf("a refusal must state that nothing ran: %s", errMsg)
		}
	}
}

// The band and the runner are two questions about the same file, and the probe
// answers both in one pass so they cannot end up describing two different
// global.json files. This pins the shared cut.
func TestDotnetProbeGlobalJSONSection(t *testing.T) {
	probe := dotnetProbeGlobalJSON + "\n" +
		`{"sdk": {"version": "10.0.400"}, "test": {"runner": "Microsoft.Testing.Platform"}}` + "\n" +
		dotnetProbeTFM + "\n" +
		`<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>`

	section := dotnetProbeGlobalJSONSection(probe)
	runner, _, errMsg := dotnetRunnerFromGlobalJSON(section)
	if errMsg != "" {
		t.Fatalf("the probe section must parse as global.json: %s", errMsg)
	}
	if runner != dotnetRunnerMTP {
		t.Fatalf("runner = %q, want the opt-in from the probe", runner)
	}
	// Same bytes, same file: the band read agrees.
	if req := parseDotnetBandRequest(probe); req.Source != "global.json" || req.Band != dotnetSDK100Band {
		t.Fatalf("band request = %+v, want the global.json band", req)
	}

	// A repository with no global.json: the probe still carries both markers, the
	// section is empty, and the runner resolves to the SDK default with a note.
	empty := dotnetProbeGlobalJSON + "\n\n" + dotnetProbeTFM + "\n<Project />"
	if got := strings.TrimSpace(dotnetProbeGlobalJSONSection(empty)); got != "" {
		t.Fatalf("section = %q, want empty", got)
	}
	if runner, note, errMsg := dotnetRunnerFromGlobalJSON(dotnetProbeGlobalJSONSection(empty)); errMsg != "" ||
		runner != dotnetRunnerVSTest || note == "" {
		t.Fatalf("absent global.json = (%q, %q, %q), want VSTest with a note", runner, note, errMsg)
	}

	// Probe output cicd could not recognise at all yields no section rather than
	// a half-read one — which dotnetRunnerFromGlobalJSON then treats as "no
	// global.json", the same answer parseDotnetBandRequest gives it.
	if got := dotnetProbeGlobalJSONSection("total garbage"); got != "" {
		t.Fatalf("an unrecognised probe must yield no section, got %q", got)
	}
}

func TestDotnetTestArgs(t *testing.T) {
	const results = "/tmp/test-results"

	vstest := dotnetTestArgs(dotnetRunnerVSTest, results)
	// One argv element, spaces included. Spliced into a shell body the obvious
	// way — --collect:"XPlat Code Coverage" — sh strips the inner quotes and
	// word-splits it into three arguments, the collector name becomes "XPlat", no
	// coverage is collected and dotnet test still exits 0. That was a real silent
	// false pass here, so it is pinned as an element rather than as a substring of
	// a joined string.
	if !slices.Contains(vstest, "--collect:XPlat Code Coverage") {
		t.Fatalf("VSTest args must carry the collector name as ONE element: %q", vstest)
	}
	for _, fragment := range []string{"XPlat", "Code", "Coverage", `--collect:"XPlat`} {
		if slices.Contains(vstest, fragment) {
			t.Errorf("collector name was split: %q appears as its own element in %q",
				fragment, vstest)
		}
	}
	assertFlagValue(t, vstest, "--results-directory", results)
	assertFlagValue(t, vstest, "--logger", "trx")

	mtp := dotnetTestArgs(dotnetRunnerMTP, results)
	assertFlagValue(t, mtp, "--results-directory", results)
	if !slices.Contains(mtp, "--report-trx") {
		t.Errorf("MTP args must ask for a trx report: %q", mtp)
	}
	// --coverage alone exits 0 and writes <guid>.coverage, the binary default
	// format, so zero cobertura documents are harvested from a run that succeeded
	// and said nothing. The pair is the whole point.
	if slices.Contains(mtp, "--coverage") {
		assertFlagValue(t, mtp, "--coverage-output-format", "cobertura")
	} else {
		t.Errorf("MTP args must request coverage: %q", mtp)
	}
	// The guid in <guid>.cobertura.xml is what keeps one test application's
	// report from overwriting another's in the pooled results directory. Pinning
	// the name destroys exactly that.
	if slices.Contains(mtp, "--coverage-output") {
		t.Errorf("--coverage-output collapses every project's report onto one path: %q", mtp)
	}
	// VSTest vocabulary must not leak onto the MTP command line — measured, MTP
	// rejects it with exit 5 and nothing runs.
	for _, vstestOnly := range []string{"--logger", "--collect:XPlat Code Coverage"} {
		if slices.Contains(mtp, vstestOnly) {
			t.Errorf("MTP args must not carry VSTest's %q: %q", vstestOnly, mtp)
		}
	}
	// --minimum-expected-tests 0 is the obvious way to make exit 8 go away, and
	// it is a false pass: the option is global to the run, so it switches off the
	// zero-test guard for every test application, which is the one guard that
	// makes "matched no tests" distinguishable from "all tests passed".
	if slices.Contains(mtp, "--minimum-expected-tests") {
		t.Errorf("the zero-test guard must not be silenced: %q", mtp)
	}

	// No default invocation. A caller reaching this with an unresolved runner has
	// to fail, not run something.
	if got := dotnetTestArgs("", results); got != nil {
		t.Errorf("an unknown runner must yield no invocation, got %q", got)
	}
	if got := dotnetTestArgs("Banana", results); got != nil {
		t.Errorf("an unknown runner must yield no invocation, got %q", got)
	}
}

// assertFlagValue pins a flag and the element that follows it, which is the only
// thing that proves the value is a separate argv element rather than part of the
// flag string.
func assertFlagValue(t *testing.T, args []string, flag, value string) {
	t.Helper()
	i := slices.Index(args, flag)
	if i < 0 {
		t.Fatalf("args are missing %q: %q", flag, args)
	}
	if i+1 >= len(args) || args[i+1] != value {
		t.Fatalf("%q must be followed by %q: %q", flag, value, args)
	}
}

func TestDotnetCoberturaGlobIsNotCoverletsLiteralName(t *testing.T) {
	// The harvest used to glob coverlet's literal filename, which finds zero
	// files on an MTP run — measured, over a pooled run that had written two
	// reports. One glob covers both runners; a per-runner glob would be a second
	// place for the same mistake to live.
	if dotnetCoberturaGlob == "coverage.cobertura.xml" {
		t.Fatal("the glob must not be coverlet's literal filename")
	}
	if !strings.HasPrefix(dotnetCoberturaGlob, "*") ||
		!strings.HasSuffix(dotnetCoberturaGlob, ".cobertura.xml") {
		t.Fatalf("glob %q must match both coverage.cobertura.xml and <guid>.cobertura.xml",
			dotnetCoberturaGlob)
	}
}

func TestDotnetVSTestTargetRefusal(t *testing.T) {
	// Verbatim, SDK 10.0.400, MSTest 4.0.2 project with no opt-in.
	const refusal = "/usr/share/dotnet/sdk/10.0.400/Microsoft.Testing.Platform.MSBuild.targets(263,5): " +
		"error : Testing with VSTest target is no longer supported by Microsoft.Testing.Platform " +
		"on .NET 10 SDK and later. If you use dotnet test, you should opt-in to the new dotnet " +
		"test experience."
	if !dotnetVSTestTargetRefusal(refusal) {
		t.Error("the SDK's refusal must be recognised so the remedy can be attached")
	}
	if !dotnetVSTestTargetRefusal(strings.ToUpper(refusal)) {
		t.Error("matching must not depend on the SDK's casing")
	}
	if dotnetVSTestTargetRefusal("Passed!  - Failed: 0, Passed: 3") {
		t.Error("a healthy run must not match the refusal")
	}
	// The remedy has to name the file and the exact key. "Opt in to the new
	// experience" — which is all the SDK says — costs the reader a search through
	// release notes.
	for _, want := range []string{"global.json", `"test"`, `"runner"`,
		"Microsoft.Testing.Platform", "repository-wide"} {
		if !strings.Contains(dotnetMTPOptInRemedy, want) {
			t.Errorf("the remedy must name %q: %s", want, dotnetMTPOptInRemedy)
		}
	}
}

func TestDotnetMTPExitDiagnosis(t *testing.T) {
	// The whole point of a second table: MTP's codes are not VSTest's, and read
	// through the wrong one they name the wrong cause.
	for _, code := range []int{0, 2} {
		msg, decided := dotnetMTPExitDiagnosis(code, "Passed!")
		if decided || msg != "" {
			t.Errorf("exit %d carries a real test result, so the .trx checks own the "+
				"verdict; got %q", code, msg)
		}
	}

	cases := []struct {
		code     int
		out      string
		contains []string
	}{
		{
			code: 1,
			out:  "error : Project uses VSTest. All projects must use that test runner.",
			contains: []string{"did not run (exit 1)", "never started the test run",
				"still uses VSTest", "repository-wide"},
		},
		{
			// Exit 1 without the mismatch wording: still a non-run, but the
			// remedy is withheld rather than asserted. Measured cause here was a
			// project file MSBuild could not load (MSB4025) — pointing that reader
			// at global.json would be a wrong cause on a correctly red build.
			code:     1,
			out:      "/src/tests/App.Tests.csproj(18,45): error MSB4025: The project file could not be loaded.",
			contains: []string{"did not run (exit 1)", "MSB4025"},
		},
		{
			code:     5,
			out:      "Unknown option '--report-trx'",
			contains: []string{"did not run (exit 5)", "rejected cicd's command line", "--report-trx"},
		},
		{
			code: 8,
			out:  "Zero tests ran",
			// --test-legs is named here and nowhere else in the exit map. Exit 1
			// and exit 5 have remedies the consumer can reach inside their own
			// tree, and a second remedy beside a reachable one dilutes it; exit 8
			// is the status a project that cannot run in any container produces
			// once someone tries to filter it away.
			contains: []string{"did not run (exit 8)", "matched zero tests", "not per project",
				"--test-legs", "coverage and ratchet intact"},
		},
		{
			// An unknown status is still a non-run, never a pass.
			code:     137,
			out:      "Killed",
			contains: []string{"did not run (exit 137)"},
		},
	}

	seen := map[string]int{}
	for _, tc := range cases {
		msg, decided := dotnetMTPExitDiagnosis(tc.code, tc.out)
		if !decided {
			t.Fatalf("exit %d must be decided as a non-run", tc.code)
		}
		for _, want := range tc.contains {
			if !strings.Contains(msg, want) {
				t.Errorf("exit %d message missing %q: %s", tc.code, want, msg)
			}
		}
		// 1, 5 and 8 have three different causes and three different remedies.
		// One shared "did not run" string would send the reader to the wrong
		// place three times out of four.
		if prev, dup := seen[msg]; dup {
			t.Errorf("exit %d and exit %d produce the same diagnosis: %s", prev, tc.code, msg)
		}
		seen[msg] = tc.code
	}

	// The remedy switches cicd's own test leg off, which is one edit away from
	// being the escape hatch --fail-on NONE is. Two properties keep it honest and
	// neither is visible from reading the const alone.
	//
	// It stays off the statuses whose remedy the consumer can reach in their own
	// tree: exit 1 (move the projects, or drop the global.json key) and exit 5
	// (reference the missing MTP extensions). Offering "run fewer projects"
	// beside either is offering a way to delete the failing project from the run
	// instead of fixing it.
	for _, code := range []int{1, 5} {
		for _, out := range []string{"uses VSTest. All projects must use that test runner.",
			"Unknown option '--report-trx'", "error MSB4025"} {
			if msg, _ := dotnetMTPExitDiagnosis(code, out); strings.Contains(msg, "--test-legs") {
				t.Errorf("exit %d has a remedy inside the consumer's tree; the BYO remedy "+
					"must not dilute it: %s", code, msg)
			}
		}
	}

	// And it must never name a way to make a red go away without running the
	// tests. A declared leg is witnessed — command recorded, coverage harvested,
	// ratchet applied — so the text says so; these are the strings that would
	// appear if someone rewrote it into a suppression hint.
	msg8, _ := dotnetMTPExitDiagnosis(8, "Zero tests ran")
	for _, forbidden := range []string{"--fail-on", "minimum-expected-tests", "ignore", "skip"} {
		if strings.Contains(msg8, forbidden) {
			t.Errorf("the BYO remedy must not read as suppression, found %q: %s", forbidden, msg8)
		}
	}
}
