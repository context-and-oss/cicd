//go:build unit_test

package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The measured shape: a measured consumer run on cicd v3.6.0. Every test
// passed, exit 1, and the one line cicd quoted. Reconstructed around that line
// with the summary blocks VSTest prints, so the fixture has a tail worth keeping
// and the exception is NOT the last line — the summaries come after it, which is
// why lastNonEmptyLine alone would have hidden it.
const lockedPackageLine = "Unhandled exception: The process cannot access the file " +
	"'/root/.nuget/packages/example.devtool/1.0.0/example.devtool.1.0.0.nupkg' because it is being used by another process."

func lockedPackageOutput() string {
	var b strings.Builder
	b.WriteString("  Determining projects to restore...\n")
	for i := 0; i < 20; i++ {
		b.WriteString("  Restored /src/Project" + strconv.Itoa(i) + "/Project" + strconv.Itoa(i) + ".csproj (in 1.2 sec).\n")
	}
	b.WriteString(lockedPackageLine + "\n")
	b.WriteString("   at System.IO.FileStream.ValidateFileHandle(SafeFileHandle fileHandle)\n")
	b.WriteString("   at System.IO.FileStream..ctor(String path, FileMode mode)\n")
	for i := 0; i < 5; i++ {
		b.WriteString("Test run for /src/Tests" + strconv.Itoa(i) + "/bin/Debug/net10.0/Tests" + strconv.Itoa(i) + ".dll (.NETCoreApp,Version=v10.0)\n")
		b.WriteString("Starting test execution, please wait...\n")
		b.WriteString("Results File: /tmp/test-results/_runner_" + strconv.Itoa(i) + ".trx\n")
		b.WriteString("Passed!  - Failed:     0, Passed:    22, Skipped:     0, Total:    22, Duration: 4 s\n")
	}
	return b.String()
}

func TestTheOutputIsKeptExactlyWhenTheExitIsUnexplained(t *testing.T) {
	green := trxSummary{Total: 100, Executed: 100, Failed: 0}
	for _, tc := range []struct {
		name   string
		code   string
		runErr string
		sum    trxSummary
		hasRun bool
		want   bool
	}{
		{name: "the regression: exit 1, every test passed", code: "1", sum: green, hasRun: true, want: true},
		{name: "a failing suite explains itself through tests.failed", code: "1", sum: trxSummary{Total: 100, Executed: 100, Failed: 3}, hasRun: true, want: false},
		{name: "a green run keeps nothing", code: "0", sum: green, hasRun: true, want: false},
		{name: "a classified non-run keeps its output whatever the exit", code: "0", runErr: "dotnet test: exited 0 but wrote no .trx result file, so no test executed", want: true},
		{name: "an unreadable exit is a non-run", code: "", runErr: "dotnet test: unreadable exit status \"\"", want: true},
		{name: "MTP exit 5 (command line rejected) is a non-run", code: "5", runErr: "dotnet test: did not run (exit 5): …", want: true},
		{name: "MTP exit 2 with failures is a failing suite", code: "2", sum: trxSummary{Total: 4, Executed: 4, Failed: 1}, hasRun: true, want: false},
		{name: "an unparsed .trx is not an accounting of zero failures", code: "1", sum: trxSummary{}, hasRun: false, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dotnetKeepOutput(tc.code, tc.runErr, tc.sum, tc.hasRun); got != tc.want {
				t.Errorf("dotnetKeepOutput = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheToolRestoreRaceIsNamedAndItsTailIsKept(t *testing.T) {
	out := lockedPackageOutput()
	green := trxSummary{Total: 100, Executed: 100, Failed: 0}

	kept := dotnetCaptureOutput("Consumer.slnx", dotnetRunnerVSTest, "1\n", dotnetKeepReasonUnexplained, out)
	wantLines := len(strings.Split(strings.TrimSuffix(out, "\n"), "\n"))
	if kept.OutputLines != wantLines {
		t.Errorf("OutputLines = %d, want %d", kept.OutputLines, wantLines)
	}
	if kept.OutputBytes != len(out) {
		t.Errorf("OutputBytes = %d, want %d", kept.OutputBytes, len(out))
	}
	if kept.ExitCode != "1" {
		t.Errorf("ExitCode = %q, want trimmed \"1\"", kept.ExitCode)
	}
	// Under the line cap: the whole output is the tail, starting at line 1.
	if len(kept.Tail) != wantLines || kept.TailFromLine != 1 {
		t.Errorf("tail = %d lines from %d, want all %d from 1", len(kept.Tail), kept.TailFromLine, wantLines)
	}
	if last := kept.Tail[len(kept.Tail)-1]; !strings.HasPrefix(last, "Passed!") {
		t.Errorf("last tail line = %q, want the last summary line", last)
	}
	if kept.Redacted {
		t.Error("nothing here is a credential, but Redacted is true")
	}
	if kept.TruncatedLines != 0 {
		t.Errorf("TruncatedLines = %d on short lines", kept.TruncatedLines)
	}
	// The diagnostics: the exception, and only the exception — restore lines and
	// summaries match no signature, and the frames are not diagnostics.
	if kept.DiagnosticsMatched != 1 || len(kept.Diagnostics) != 1 || kept.Diagnostics[0] != lockedPackageLine {
		t.Errorf("diagnostics = %d matched, %v", kept.DiagnosticsMatched, kept.Diagnostics)
	}

	// The errors[] entry names it, and says where the rest is.
	msg := dotnetTestExitFailure("1", "", out, green, true, &kept)
	for _, want := range []string{
		"dotnet test failed (exit 1)",
		dotnetKeepReasonUnexplained,
		"1 diagnostic line(s) in the output: [1] " + lockedPackageLine,
		"the last " + strconv.Itoa(wantLines) + " of " + strconv.Itoa(wantLines) + " output lines are kept in this envelope's genericReport",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q\ngot: %s", want, msg)
		}
	}
	if strings.Contains(msg, "last diagnostic:") {
		t.Errorf("the single-line fallback fired although diagnostics matched:\n%s", msg)
	}
	// And the same reason travels in the record, so the two can be matched.
	if kept.Reason != dotnetKeepReasonUnexplained {
		t.Errorf("Reason = %q", kept.Reason)
	}
}

// Without a signature match the message keeps its one line, so a shape nobody
// has listed yet still names something — and still says where the tail is.
func TestNoSignatureFallsBackToTheSingleLine(t *testing.T) {
	out := "Starting test execution, please wait...\nSomething odd happened.\nPassed! - Failed: 0, Passed: 3, Skipped: 0, Total: 3\n"
	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerVSTest, "1", dotnetKeepReasonUnexplained, out)
	if kept.DiagnosticsMatched != 0 || len(kept.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", kept.Diagnostics)
	}
	msg := dotnetTestExitFailure("1", "", out, trxSummary{Total: 3, Executed: 3}, true, &kept)
	if !strings.Contains(msg, "last diagnostic: Passed!") {
		t.Errorf("fallback line missing:\n%s", msg)
	}
	if !strings.Contains(msg, "the last 3 of 3 output lines are kept") {
		t.Errorf("pointer missing:\n%s", msg)
	}
}

// A failing suite keeps no tail, and the message must not point at one: the
// pointer sentence exists only when the record does.
func TestAFailingSuiteGetsNoTailAndNoPointer(t *testing.T) {
	msg := dotnetTestExitFailure("1", "", lockedPackageOutput(), trxSummary{Total: 100, Executed: 100, Failed: 3}, true, nil)
	if msg != "dotnet test failed (exit 1)" {
		t.Errorf("got %q", msg)
	}
	if note := dotnetOutputKeptNote(nil); note != "" {
		t.Errorf("a nil record produced a pointer: %q", note)
	}
}

func TestTheTailIsBoundedByLinesAndSaysWhatFractionItIs(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 500; i++ {
		b.WriteString("line " + strconv.Itoa(i) + "\n")
	}
	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerMTP, "8", "x", b.String())
	if kept.OutputLines != 500 {
		t.Errorf("OutputLines = %d", kept.OutputLines)
	}
	if len(kept.Tail) != dotnetOutputTailLines {
		t.Errorf("len(Tail) = %d, want %d", len(kept.Tail), dotnetOutputTailLines)
	}
	if kept.TailFromLine != 301 {
		t.Errorf("TailFromLine = %d, want 301", kept.TailFromLine)
	}
	if kept.Tail[0] != "line 301" || kept.Tail[len(kept.Tail)-1] != "line 500" {
		t.Errorf("tail spans %q..%q", kept.Tail[0], kept.Tail[len(kept.Tail)-1])
	}
	// The invariant a reader relies on to know what they are not seeing.
	if kept.OutputLines-kept.TailFromLine+1 != len(kept.Tail) {
		t.Errorf("OutputLines-TailFromLine+1 = %d, len(Tail) = %d", kept.OutputLines-kept.TailFromLine+1, len(kept.Tail))
	}
	if note := dotnetOutputKeptNote(&kept); !strings.Contains(note, "the last 200 of 500 output lines") {
		t.Errorf("note = %q", note)
	}
}

// Long lines exist — a serialised object, a base64 blob — so lines are capped
// too, and the byte cap bounds the whole. 200 lines of 10 KiB is 2 MB of input;
// what is stored must be under 64 KiB plus the cut markers.
func TestTheTailIsBoundedByBytesAndMarksEveryCut(t *testing.T) {
	long := strings.Repeat("x", 10<<10)
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString(long + "\n")
	}
	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerVSTest, "1", "x", b.String())

	total := 0
	for _, l := range kept.Tail {
		total += len(l)
		if !strings.Contains(l, " …[") || !strings.HasSuffix(l, " more bytes]") {
			t.Fatalf("a cut line carries no marker: %q…", l[:40])
		}
		if len(l) > dotnetOutputLineBytes+40 {
			t.Errorf("line of %d bytes exceeds the cap of %d by more than its marker", len(l), dotnetOutputLineBytes)
		}
	}
	if total > dotnetOutputTailBytes {
		t.Errorf("tail holds %d bytes, cap is %d", total, dotnetOutputTailBytes)
	}
	if kept.TruncatedLines != len(kept.Tail) {
		t.Errorf("TruncatedLines = %d, want every one of the %d kept lines", kept.TruncatedLines, len(kept.Tail))
	}
	if len(kept.Tail) >= dotnetOutputTailLines {
		t.Errorf("byte cap did not drop any of the %d lines", len(kept.Tail))
	}
	if kept.OutputLines != 300 || kept.OutputLines-kept.TailFromLine+1 != len(kept.Tail) {
		t.Errorf("counts disagree: OutputLines %d, TailFromLine %d, len(Tail) %d", kept.OutputLines, kept.TailFromLine, len(kept.Tail))
	}
	if kept.OutputBytes != 300*(10<<10+1) {
		t.Errorf("OutputBytes = %d", kept.OutputBytes)
	}
}

func TestLineTruncationStaysOnARuneBoundary(t *testing.T) {
	// 'é' is two bytes; a cap that falls between them must back up.
	s := strings.Repeat("é", 10)
	got, cut := truncateLineBytes(s, 5)
	if !cut {
		t.Fatal("not cut")
	}
	if !strings.HasPrefix(got, "éé …[") {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(got, "[16 more bytes]") {
		t.Errorf("removed count wrong: %q", got)
	}
	if got, cut := truncateLineBytes("short", 100); cut || got != "short" {
		t.Errorf("short line changed: %q %v", got, cut)
	}
}

func TestDiagnosticsAreDedupedAndCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("/src/T.csproj(1,1): error MSB4025: The project file could not be loaded.\n")
	}
	kept := dotnetCaptureOutput("T.csproj", dotnetRunnerVSTest, "1", "x", b.String())
	if kept.DiagnosticsMatched != 1 || len(kept.Diagnostics) != 1 {
		t.Errorf("50 identical lines → %d matched, %d listed", kept.DiagnosticsMatched, len(kept.Diagnostics))
	}

	b.Reset()
	for i := 0; i < 30; i++ {
		b.WriteString("/src/T.csproj(1,1): error CS" + strconv.Itoa(1000+i) + ": distinct.\n")
	}
	kept = dotnetCaptureOutput("T.csproj", dotnetRunnerVSTest, "1", "x", b.String())
	if kept.DiagnosticsMatched != 30 {
		t.Errorf("DiagnosticsMatched = %d, want 30", kept.DiagnosticsMatched)
	}
	if len(kept.Diagnostics) != dotnetOutputDiagnostics {
		t.Errorf("len(Diagnostics) = %d, want the cap %d", len(kept.Diagnostics), dotnetOutputDiagnostics)
	}
	if !strings.Contains(kept.Diagnostics[0], "CS1000") || !strings.Contains(kept.Diagnostics[19], "CS1019") {
		t.Errorf("order of first appearance lost: %q .. %q", kept.Diagnostics[0], kept.Diagnostics[19])
	}
	// The message quotes three, and its arithmetic distinguishes the 17 the field
	// holds from the 10 that matched past the field's cap.
	msg := dotnetDiagnosticsSummary(&kept)
	for _, want := range []string{"30 diagnostic line(s)", "[1] ", "[3] ", "+17 more in genericReport", "10 more matched beyond its cap of 20"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %s", want, msg)
		}
	}
	if strings.Contains(msg, "[4] ") {
		t.Errorf("more than %d quoted: %s", dotnetErrorDiagnosticLines, msg)
	}
}

// Every signature matches the line it was written for. The list is what turns
// "a diagnostic" into "the diagnostics", so a signature that matches nothing
// is a silent gap.
func TestEveryFailureSignatureMatchesItsOwnShape(t *testing.T) {
	samples := []string{
		lockedPackageLine,
		"/src/T.csproj(13,48): error MSB4025: The project file could not be loaded.",
		"error NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json.",
		"/src/App/Program.cs(3,5): error CS0103: The name 'x' does not exist in the current context",
		"error NETSDK1045: The current .NET SDK does not support targeting .NET 10.0.",
		"The active test run was aborted. Reason: Test host process crashed",
		"Data collector 'XPlat Code Coverage' message: [coverlet]Unable to instrument module",
		"No test is available in /src/Widget.Tools/bin/Debug/net10.0/Widget.Tools.dll.",
		"  Standard output: Unknown option '--report-trx'",
	}
	for _, s := range samples {
		if !dotnetMatchesFailureSignature(s) {
			t.Errorf("no signature matches %q", s)
		}
	}
	// And the routine lines a green run prints match none of them.
	for _, s := range []string{
		"Restored /src/App/App.csproj (in 1.2 sec).",
		"Passed!  - Failed:     0, Passed:   100, Skipped:     0, Total:   100, Duration: 4 s",
		"Build succeeded.",
		"    0 Warning(s)",
		"    0 Error(s)",
		"Attachments:",
		"  /tmp/test-results/abc/coverage.cobertura.xml",
	} {
		if dotnetMatchesFailureSignature(s) {
			t.Errorf("routine line matched a failure signature: %q", s)
		}
	}
}

// A credential echoed by the runner must reach neither the record nor the
// message. The proof is on the serialised JSON — what the envelope would carry —
// not on a struct field, because a field that was missed is exactly the leak.
func TestACredentialInTheOutputNeverReachesTheEnvelope(t *testing.T) {
	const pat = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop"
	// Split so the source carries no literal a secrets scanner reads as a
	// GitHub token; the value the test feeds the runner output is whole.
	const ghp = "ghp" + "_SYNTHETIC0token0must0never0appear0in0evidence"
	out := "  Determining projects to restore...\n" +
		"error NU1301: Unable to load the service index for source https://build:" + pat + "@pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json.\n" +
		"  Authorization: Bearer " + ghp + "\n" +
		"Build FAILED.\n"

	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerVSTest, "1", "the run was classified as a non-run", out)
	raw, err := json.Marshal([]dotnetTestOutput{kept})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{pat, ghp, "SYNTHETIC"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the serialised record leaks %q:\n%s", secret, raw)
		}
	}
	if !kept.Redacted {
		t.Error("Redacted must say the text was edited")
	}
	if !strings.Contains(string(raw), "pkgs.dev.azure.com/org/_packaging/feed") {
		t.Error("the feed host, which is not a secret, was lost with the credential")
	}

	// The single-line path is the older door, and it closes the same way.
	line := dotnetDiagnosticLine(out)
	if strings.Contains(line, pat) {
		t.Errorf("dotnetDiagnosticLine leaked the PAT: %q", line)
	}
	msg := dotnetTestExitFailure("1", "", out, trxSummary{Total: 1, Executed: 1}, true, &kept)
	for _, secret := range []string{pat, ghp} {
		if strings.Contains(msg, secret) {
			t.Fatalf("the errors[] entry leaks %q: %s", secret, msg)
		}
	}
	// And the exact record shape a reader will look for, keyed by the runner.
	var back []struct {
		Target, Runner, ExitCode, Reason string
		Tail, Diagnostics                []string
		OutputLines, TailFromLine        int
		Redacted                         bool
	}
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 1 {
		t.Fatalf("record did not round-trip: %v", err)
	}
	if back[0].Runner != "VSTest" || back[0].Target != "App.csproj" || back[0].OutputLines != 4 || back[0].TailFromLine != 1 {
		t.Errorf("record fields: %+v", back[0])
	}
}

func TestEmptyOutputIsRecordedAsEmptyNotOmitted(t *testing.T) {
	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerVSTest, "1", "x", "")
	if kept.OutputLines != 0 || kept.TailFromLine != 0 || len(kept.Tail) != 0 {
		t.Errorf("empty output → %+v", kept)
	}
	raw, _ := json.Marshal(kept)
	// Arrays, not null: a reader iterating the tail must not have to null-check.
	if !strings.Contains(string(raw), `"tail":[]`) || !strings.Contains(string(raw), `"diagnostics":[]`) {
		t.Errorf("empty arrays serialised as null: %s", raw)
	}
	if note := dotnetOutputKeptNote(&kept); !strings.Contains(note, "printed nothing") {
		t.Errorf("note on empty output = %q", note)
	}
}

func TestCRLFOutputCountsLinesNotCarriageReturns(t *testing.T) {
	kept := dotnetCaptureOutput("App.csproj", dotnetRunnerVSTest, "1", "x", "a\r\nb\r\nc\r\n")
	if kept.OutputLines != 3 || kept.Tail[2] != "c" {
		t.Errorf("CRLF: %d lines, tail %q", kept.OutputLines, kept.Tail)
	}
}

func TestTheCheckEnvelopeWrapsLegPayloadsUnderTheirOwnFormat(t *testing.T) {
	got, format, err := qualityDiagnosticsReport(map[string]json.RawMessage{})
	if err != nil || got != nil || format != "" {
		t.Errorf("empty → (%s, %q, %v), want nothing", got, format, err)
	}
	got, format, err = qualityDiagnosticsReport(map[string]json.RawMessage{
		dotnetTestOutputFormat: json.RawMessage(`[{"target":"A.slnx"}]`),
		"ignored/1.0":          json.RawMessage(`null`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if format != qualityDiagnosticsFormat {
		t.Errorf("format = %q", format)
	}
	if string(got) != `{"dotnet-test-output/1.0":[{"target":"A.slnx"}]}` {
		t.Errorf("payload = %s", got)
	}
	if _, _, err := qualityDiagnosticsReport(map[string]json.RawMessage{"x": json.RawMessage(`{not json`)}); err == nil {
		t.Error("an unwritable payload must be an error, not a silent drop")
	}
}
