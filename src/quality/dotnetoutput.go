// What survives of `dotnet test`'s output when its exit status is not explained
// by a failing test. Untagged so `go test -tags unit_test` reaches it.
package main

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The bounds on what is kept, per target. They are stated once here; the
// doctrine quotes the 200-line figure, so change both.
const (
	// dotnetOutputTailLines is how many trailing lines of the output are kept.
	// The cause of a non-test exit sits near the end on the shapes measured so
	// far — a tool-restore race printed its exception after the last test summary,
	// MSBuild prints its error summary last — and 200 is about four times the
	// length of a VSTest per-project summary block, so a solution of a dozen
	// projects still shows the tail of its last several projects.
	dotnetOutputTailLines = 200
	// dotnetOutputLineBytes caps one kept line. A stack frame is ~200 bytes and
	// an MSBuild diagnostic with a full path ~500; 2 KiB keeps either whole and
	// stops a single pathological line (a serialised object, a base64 blob) from
	// spending the whole byte budget by itself.
	dotnetOutputLineBytes = 2 << 10
	// dotnetOutputTailBytes caps the whole tail of one target. 64 KiB is 0.12%
	// of the 50-odd MB quality part the consumer already ships, and roughly a third
	// of what 200 lines would come to if every one of them were cut at the line
	// cap — so the byte cap, not the line cap, is what bounds the worst case.
	dotnetOutputTailBytes = 64 << 10
	// dotnetOutputDiagnostics caps the deduplicated diagnostic lines listed
	// beside the tail. Twenty is more than any measured failure printed distinct
	// causes for, and few enough to read.
	dotnetOutputDiagnostics = 20
	// dotnetErrorDiagnosticLines and dotnetErrorDiagnosticBytes bound how much of
	// the diagnostics list the errors[] entry itself quotes. notify renders every
	// entry as one markdown code span in a PR comment, so the entry stays a
	// summary and the field holds the full lines.
	dotnetErrorDiagnosticLines = 3
	dotnetErrorDiagnosticBytes = 300
)

// dotnetTestOutputFormat names the payload shape of a []dotnetTestOutput, as the
// per-language envelope's genericFormat. quality.Check nests it under that name
// in its own genericReport; see qualityDiagnosticsReport.
const dotnetTestOutputFormat = "dotnet-test-output/1.0"

// dotnetTestOutput is the bounded record of one target's `dotnet test` output,
// kept only when the exit status needs it as evidence.
//
// This exists because the alternative was a claim. One consumer's run: every one of
// about a hundred tests passed, exit 1, and the whole of what reached the audit bundle was one
// line cicd picked out of the log: "Unhandled exception: The process cannot
// access the file '…/example.devtool.1.0.0.nupkg' because it is being used by another
// process." Plausible — a `dotnet tool restore` race across some twenty projects — but the
// MSBuild Exec that races is ContinueOnError="true", so that line may not be
// what flipped the exit code, and nothing in the bundle could say: the output
// had been read out of the container into a variable and dropped. The Dagger
// step log did not have it either, because the redirect happens inside the
// container. An error that names one line of a long log is a claim; the lines
// around it are the evidence.
type dotnetTestOutput struct {
	// Target is the solution or project the run was invoked on.
	Target string `json:"target"`
	// Runner is the `dotnet test` CLI that produced the output.
	Runner string `json:"runner"`
	// ExitCode is the status as read, untrimmed of meaning — "1", "5", "8".
	ExitCode string `json:"exitCode"`
	// Reason says why this output was kept, in the same words the errors[]
	// entry uses, so the two can be matched by eye.
	Reason string `json:"reason"`
	// OutputLines and OutputBytes measure the whole output the tool wrote, so a
	// reader of Tail knows what fraction of it they are seeing.
	OutputLines int `json:"outputLines"`
	OutputBytes int `json:"outputBytes"`
	// TailFromLine is the 1-based line number of Tail[0] within the output; 0
	// when the output was empty. OutputLines-TailFromLine+1 == len(Tail).
	TailFromLine int `json:"tailFromLine"`
	// Tail is the kept trailing lines, oldest first, each cut to
	// dotnetOutputLineBytes and the whole bounded by dotnetOutputTailBytes.
	Tail []string `json:"tail"`
	// TruncatedLines is how many entries of Tail were cut at the line cap.
	TruncatedLines int `json:"truncatedLines"`
	// DiagnosticsMatched counts the distinct lines anywhere in the output that
	// matched a known non-test failure signature; Diagnostics holds the first
	// dotnetOutputDiagnostics of them. Equal means nothing was left out.
	DiagnosticsMatched int      `json:"diagnosticsMatched"`
	Diagnostics        []string `json:"diagnostics"`
	// Redacted is true when scrubCredentials changed at least one kept line, so
	// a reader knows `***` is cicd's edit and not the tool's text.
	Redacted bool `json:"redacted"`
}

// dotnetFailureSignatures are the shapes of a line that explains a non-test
// exit. Unlike dotnetDiagnosticMarkers, which pick ONE line for a one-line
// message and therefore include the broad `error ` so nothing is missed, these
// are tight enough to list: every match is shown, so a signature matching
// routine chatter would crowd out the cause within dotnetOutputDiagnostics.
//
// The locked-package line is the one measured cause (the consumer, cicd v3.6.0). The MSBuild,
// NuGet, compiler and SDK code families are the shapes a broken restore or build
// prints. The VSTest host lines are the platform's own words for a crashed or
// aborted run. `Unknown option` is Microsoft.Testing.Platform's rejection of a
// flag, measured on SDK 10.0.400, and matters here because MTP follows it with
// its entire help text — 200 lines that would be the whole tail on their own.
var dotnetFailureSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)unhandled exception`),
	regexp.MustCompile(`(?i)\berror (MSB|NU|CS|NETSDK)\d+`),
	regexp.MustCompile(`(?i)the active test run was aborted`),
	regexp.MustCompile(`(?i)test host process crashed`),
	regexp.MustCompile(`(?i)data collector`),
	regexp.MustCompile(`(?i)no test is available`),
	regexp.MustCompile(`(?i)unknown option`),
}

// dotnetKeepOutput decides whether a run's output is evidence. It is, whenever
// the exit status is a fact the envelope's other fields cannot verify:
//
//   - a classified non-run (runErr != ""), whatever the exit status — the
//     "exited 0 but wrote no .trx" shape included, because the reason nothing
//     ran is in the output and nowhere else;
//   - a non-zero exit with no failing test to explain it. A failing suite keeps
//     nothing: tests.failed > 0 in the same envelope verifies that claim by
//     itself, and the output of a suite with failures is dominated by the
//     failures' own stack traces, which explain the suite and not the exit.
//
// It does NOT change what dotnetTestRunError or dotnetTestExitFailure decide;
// it only reads their result. hasRun is the same parsed>0 the caller hands to
// dotnetTestExitFailure — an unparsed .trx sums to Failed 0, which must not be
// read as "no test failed".
func dotnetKeepOutput(exitCode, runErr string, sum trxSummary, hasRun bool) bool {
	if runErr != "" {
		return true
	}
	if strings.TrimSpace(exitCode) == "0" {
		return false
	}
	return !hasRun || sum.Failed == 0
}

// dotnetKeepReasonUnexplained is the wording shared by the errors[] entry and
// the Reason field for the shape this file exists for.
const dotnetKeepReasonUnexplained = "every test reported passing, so the exit status came from " +
	"something other than a failing test"

// dotnetCaptureOutput builds the bounded record. Scrubbing happens once, over
// the whole output, before any line is kept or matched — so the tail, the
// diagnostics and the Redacted flag all describe the same edited text and no
// path exists where a line reaches the record unscrubbed.
//
// OutputLines and OutputBytes are measured on the text as the tool wrote it,
// before scrubbing, because they describe the tool's output and not cicd's copy.
func dotnetCaptureOutput(target string, runner dotnetRunner, exitCode, reason, out string) dotnetTestOutput {
	rec := dotnetTestOutput{
		Target:      target,
		Runner:      string(runner),
		ExitCode:    strings.TrimSpace(exitCode),
		Reason:      reason,
		OutputBytes: len(out),
		Tail:        []string{},
		Diagnostics: []string{},
	}
	scrubbed, redacted := scrubCredentials(out)
	rec.Redacted = redacted

	lines := splitOutputLines(scrubbed)
	rec.OutputLines = len(lines)
	if len(lines) == 0 {
		return rec
	}

	// Diagnostics: every distinct matching line, in order of first appearance.
	seen := map[string]bool{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || seen[line] || !dotnetMatchesFailureSignature(line) {
			continue
		}
		seen[line] = true
		rec.DiagnosticsMatched++
		if len(rec.Diagnostics) < dotnetOutputDiagnostics {
			cut, _ := truncateLineBytes(line, dotnetOutputLineBytes)
			rec.Diagnostics = append(rec.Diagnostics, cut)
		}
	}

	// Tail: the last N lines, each cut at the line cap, then the oldest dropped
	// until the whole fits the byte cap. The byte cap is applied after the line
	// cut so that it bounds what is actually stored.
	from := len(lines) - dotnetOutputTailLines
	if from < 0 {
		from = 0
	}
	total := 0
	tail := make([]string, 0, len(lines)-from)
	for _, raw := range lines[from:] {
		cut, _ := truncateLineBytes(raw, dotnetOutputLineBytes)
		tail = append(tail, cut)
		total += len(cut)
	}
	for len(tail) > 1 && total > dotnetOutputTailBytes {
		total -= len(tail[0])
		tail = tail[1:]
		from++
	}
	// Counted over what is stored, not over what was considered: a line the
	// byte cap dropped is not an entry of Tail, and the field says "entries of Tail".
	for i, cut := range tail {
		if cut != lines[from+i] {
			rec.TruncatedLines++
		}
	}
	rec.Tail = tail
	rec.TailFromLine = from + 1
	return rec
}

// dotnetMatchesFailureSignature reports whether one line carries a known
// non-test failure signature.
func dotnetMatchesFailureSignature(line string) bool {
	for _, re := range dotnetFailureSignatures {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// splitOutputLines splits tool output into lines without the phantom empty
// line a trailing newline would produce, and tolerates CRLF, which `dotnet`
// emits on some hosts.
func splitOutputLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// truncateLineBytes cuts s to at most max bytes on a rune boundary and marks the
// cut with how much was removed, so a reader never mistakes a cut line for the
// line the tool printed. The marker is counted inside max only loosely — a cut
// line is a few bytes over — which is fine for a cap whose purpose is bounding
// pathological input, not hitting a byte exactly.
func truncateLineBytes(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + " …[" + strconv.Itoa(len(s)-cut) + " more bytes]", true
}

// dotnetOutputKeptNote is the sentence an errors[] entry ends with when the
// output that explains it was kept, so a reader of the message knows where to
// look. Empty when nothing was kept, so a message never points at an absence.
func dotnetOutputKeptNote(kept *dotnetTestOutput) string {
	if kept == nil {
		return ""
	}
	if kept.OutputLines == 0 {
		return " — the runner printed nothing, and the empty output is recorded in this envelope's genericReport"
	}
	return " — the last " + strconv.Itoa(len(kept.Tail)) + " of " + strconv.Itoa(kept.OutputLines) +
		" output lines are kept in this envelope's genericReport"
}

// dotnetDiagnosticsSummary renders the diagnostics list for an errors[] entry:
// up to dotnetErrorDiagnosticLines of them, each cut to
// dotnetErrorDiagnosticBytes, with the count of what the field holds beyond that.
// Empty when the record has no diagnostics, so the caller can fall back to the
// single dotnetDiagnosticLine.
func dotnetDiagnosticsSummary(kept *dotnetTestOutput) string {
	if kept == nil || len(kept.Diagnostics) == 0 {
		return ""
	}
	n := len(kept.Diagnostics)
	if n > dotnetErrorDiagnosticLines {
		n = dotnetErrorDiagnosticLines
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(kept.DiagnosticsMatched))
	b.WriteString(" diagnostic line(s) in the output:")
	for i := 0; i < n; i++ {
		cut, _ := truncateLineBytes(kept.Diagnostics[i], dotnetErrorDiagnosticBytes)
		b.WriteString(" [" + strconv.Itoa(i+1) + "] " + cut)
	}
	// Two different "more": lines the field holds past what is quoted here, and
	// lines that matched past the field's own cap. Folding them into one number
	// would point the reader at a field holding fewer lines than promised.
	inField := len(kept.Diagnostics) - n
	beyondCap := kept.DiagnosticsMatched - len(kept.Diagnostics)
	switch {
	case inField > 0 && beyondCap > 0:
		b.WriteString(" (+" + strconv.Itoa(inField) + " more in genericReport, and " +
			strconv.Itoa(beyondCap) + " more matched beyond its cap of " +
			strconv.Itoa(dotnetOutputDiagnostics) + ")")
	case inField > 0:
		b.WriteString(" (+" + strconv.Itoa(inField) + " more in genericReport)")
	case beyondCap > 0:
		b.WriteString(" (" + strconv.Itoa(beyondCap) + " more matched beyond genericReport's cap of " +
			strconv.Itoa(dotnetOutputDiagnostics) + ")")
	}
	return b.String()
}
