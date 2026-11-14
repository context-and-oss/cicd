package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// realSemgrepInvocations is the invocations array semgrep/semgrep:1.161.0 wrote,
// verbatim, over a fixture of two C# files its parser rejects (a deliberate
// syntax error and a C# 12 primary constructor), one pathological C# file run
// with --timeout 1, one clean C# file and one Python file. Captured, not
// recalled — the shape the brief for this change remembered had a `locations`
// array, and the real one does not.
const realSemgrepInvocations = `[{"executionSuccessful":true,"toolExecutionNotifications":[` +
	`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line Broken.cs:3:\n ` + "`public class Bar`" + ` was unexpected"}},` +
	`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line Primary.cs:3:\n ` + "`(int x)`" + ` was unexpected"}},` +
	`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running work.cs-nested-sum on Slow.cs:\n "}},` +
	`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running work.cs-string-concat on Slow.cs:\n "}}]}]`

func sarifWithInvocations(invocations string) json.RawMessage {
	return json.RawMessage(`{"version":"2.1.0","runs":[{"invocations":` + invocations +
		`,"results":[],"tool":{"driver":{"name":"Semgrep OSS","rules":[]}}}]}`)
}

func sarifWithNotifications(notes ...string) json.RawMessage {
	return sarifWithInvocations(`[{"executionSuccessful":true,"toolExecutionNotifications":[` +
		strings.Join(notes, ",") + `]}]`)
}

func syntaxNote(file string, line int, detail string) string {
	return `{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line ` +
		file + `:` + strconv.Itoa(line) + `:\n ` + detail + `"}}`
}

// TestSemgrepNotificationsRealCapture drives the parser over the verbatim
// capture. This is the test that matters: a hand-built fixture can agree with
// the code and both be wrong about semgrep.
func TestSemgrepNotificationsRealCapture(t *testing.T) {
	n := parseSemgrepNotifications(sarifWithInvocations(realSemgrepInvocations))

	if n.ParseFailures != 2 {
		t.Errorf("ParseFailures = %d, want 2", n.ParseFailures)
	}
	if got := strings.Join(n.UnparsedFiles, ","); got != "Broken.cs,Primary.cs" {
		t.Errorf("UnparsedFiles = %q, want Broken.cs,Primary.cs (from message.text — there is no locations array)", got)
	}
	if n.UnattributedParseFailures != 0 {
		t.Errorf("UnattributedParseFailures = %d, want 0", n.UnattributedParseFailures)
	}
	// The construct semgrep quoted is source text and is withheld; the file
	// and line still say where to look (semgrepredact.go).
	if want := "Broken.cs:3 [source withheld] was unexpected"; n.FirstParserMessage != want {
		t.Errorf("FirstParserMessage = %q, want %q", n.FirstParserMessage, want)
	}
	if n.Timeouts != 2 {
		t.Errorf("Timeouts = %d, want 2 (rule, file) pairs", n.Timeouts)
	}
	if got := strings.Join(n.TimedOutFiles, ","); got != "Slow.cs" {
		t.Errorf("TimedOutFiles = %q, want Slow.cs — two rules, one file, one distinct file", got)
	}
	if got := strings.Join(n.TimedOutRules, ","); got != "work.cs-nested-sum,work.cs-string-concat" {
		t.Errorf("TimedOutRules = %q", got)
	}
	if len(n.ErrorLevel) != 0 || len(n.Unclassified) != 0 {
		t.Errorf("every real notification must classify: errorLevel=%v unclassified=%v", n.ErrorLevel, n.Unclassified)
	}

	warnings := semgrepNotificationWarnings(sarifWithInvocations(realSemgrepInvocations))
	if len(warnings) != 1 {
		t.Fatalf("want exactly one warning, got %d: %v", len(warnings), warnings)
	}
	w := warnings[0]
	if strings.Contains(w, "public class Bar") || strings.Contains(w, "(int x)") {
		t.Errorf("the warning quotes the source the parser rejected:\n%s", w)
	}
	for _, want := range []string{
		"opengrep: PARTIAL SCAN — ",
		"2 file(s) could not be fully parsed",
		"C#: 2",
		"Broken.cs, Primary.cs",
		"2 rule timeout(s) hit 1 file(s)",
		"Slow.cs",
		"rules: work.cs-nested-sum, work.cs-string-concat",
		"floor, not a verdict",
		"not a clean one",
		"First parser message: Broken.cs:3 [source withheld] was unexpected.",
		"Opengrep " + opengrepVersion + " skips the region",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warning lacks %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "\n") {
		t.Errorf("warning must be one line — notify renders each entry as one list item:\n%q", w)
	}
	if strings.Contains(w, "received zero findings") || strings.Contains(w, "0 findings") {
		t.Errorf("semgrep parses partially (Primary.cs still yielded a finding); the warning must not claim zero:\n%s", w)
	}
}

// TestAnUnmeasuredConvergenceNoticeStillReadsAsPartial pins the fail-safe
// that replaced the fixpoint branch. Opengrep 2.0.0 emits no taint-convergence
// notice at all, so cicd has no descriptor for one; an engine that starts
// emitting one must land in the unclassified bucket and still read as a
// partial scan, never as nothing said.
func TestAnUnmeasuredConvergenceNoticeStillReadsAsPartial(t *testing.T) {
	raw := sarifWithNotifications(
		`{"descriptor":{"id":"Fixpoint timeout"},"level":"warning","message":{"text":"raw diagnostic text must not be quoted"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"pages/panel.html"}}}]}`,
	)
	warnings := semgrepNotificationWarnings(raw)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "PARTIAL SCAN") ||
		!strings.Contains(warnings[0], "could not classify (id(s): Fixpoint timeout)") {
		t.Fatalf("want one partial warning naming the unclassified id, got %v", warnings)
	}
	if strings.Contains(warnings[0], "raw diagnostic") {
		t.Fatal("diagnostic source was copied into the warning")
	}
}

// TestSemgrepNotificationsCleanRunSaysNothing pins the negative control. A
// disclosure on every clean run is noise, and the three clean shapes semgrep
// can produce must all be silent.
func TestSemgrepNotificationsCleanRunSaysNothing(t *testing.T) {
	cases := map[string]json.RawMessage{
		"empty notifications array": sarifWithNotifications(),
		"no invocations key":        json.RawMessage(`{"version":"2.1.0","runs":[{"results":[],"tool":{"driver":{"name":"Semgrep OSS"}}}]}`),
		"invocation without notifications": sarifWithInvocations(
			`[{"executionSuccessful":true}]`),
		"no runs":         json.RawMessage(`{"version":"2.1.0","runs":[]}`),
		"empty document":  json.RawMessage(``),
		"not JSON at all": json.RawMessage(`this is not sarif`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if w := semgrepNotificationWarnings(raw); len(w) != 0 {
				t.Errorf("want no warning, got %v", w)
			}
		})
	}
}

// TestSemgrepNotificationsMalformedAreCountedNotDropped. A notification with
// no descriptor, no message and no location is still semgrep saying something
// went wrong; it must neither panic nor vanish.
func TestSemgrepNotificationsMalformedAreCountedNotDropped(t *testing.T) {
	raw := sarifWithNotifications(
		`{}`,
		`{"level":"warning"}`,
		`{"descriptor":{},"message":{}}`,
		`{"descriptor":{"id":"Syntax error"}}`,
		`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"something new"}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"a shape nobody has seen"}}`,
		`{"descriptor":{"id":"Rule error"},"level":"error","message":{"text":"rule x failed to compile"}}`,
		`{"descriptor":{"id":"Odd"},"level":"note","message":{"text":"hm"}}`,
	)
	n := parseSemgrepNotifications(raw)

	if n.ParseFailures != 2 || n.UnattributedParseFailures != 2 || len(n.UnparsedFiles) != 0 {
		t.Errorf("syntax errors naming no file: ParseFailures=%d Unattributed=%d files=%v, want 2/2/none",
			n.ParseFailures, n.UnattributedParseFailures, n.UnparsedFiles)
	}
	if n.Timeouts != 1 || n.UnattributedTimeouts != 1 || len(n.TimedOutFiles) != 0 || len(n.TimedOutRules) != 0 {
		t.Errorf("timeout naming nothing: Timeouts=%d Unattributed=%d files=%v rules=%v, want 1/1/none/none",
			n.Timeouts, n.UnattributedTimeouts, n.TimedOutFiles, n.TimedOutRules)
	}
	if got := strings.Join(n.ErrorLevel, ","); got != "Rule error" {
		t.Errorf("ErrorLevel = %q, want Rule error", got)
	}
	if got := strings.Join(n.Unclassified, ","); got != "unnamed,unnamed,unnamed,Odd" {
		t.Errorf("Unclassified = %q, want the three descriptor-less ones and Odd", got)
	}

	w := semgrepNotificationWarnings(raw)
	if len(w) != 1 {
		t.Fatalf("want one warning, got %v", w)
	}
	for _, want := range []string{
		"0 file(s) could not be fully parsed across 2 syntax error(s), 2 of which named no file cicd could read",
		"1 rule timeout(s) hit 0 file(s), 1 naming no file",
		"1 error-level notification(s) opengrep raised (id(s): Rule error)",
		"4 notification(s) cicd could not classify (id(s): unnamed, Odd)",
	} {
		if !strings.Contains(w[0], want) {
			t.Errorf("warning lacks %q:\n%s", want, w[0])
		}
	}
	if strings.Contains(w[0], "First parser message") {
		t.Errorf("no parser message was readable, so none may be quoted:\n%s", w[0])
	}
}

// TestSemgrepNotificationsLocationFallback keeps the shape the brief recalled
// working: a later semgrep that attaches a SARIF location and drops the
// path from the message still gets its file named.
func TestSemgrepNotificationsLocationFallback(t *testing.T) {
	loc := `"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/Foo.cs"}}}]`
	raw := sarifWithNotifications(
		`{"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"parser gave up"},`+loc+`}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"slow"},`+loc+`}`,
	)
	n := parseSemgrepNotifications(raw)
	if got := strings.Join(n.UnparsedFiles, ","); got != "src/Foo.cs" {
		t.Errorf("UnparsedFiles = %q, want src/Foo.cs from the location", got)
	}
	if got := strings.Join(n.TimedOutFiles, ","); got != "src/Foo.cs" {
		t.Errorf("TimedOutFiles = %q, want src/Foo.cs from the location", got)
	}
	if n.UnattributedParseFailures != 0 || n.UnattributedTimeouts != 0 {
		t.Errorf("a located notification is attributed")
	}
	if want := "src/Foo.cs parser gave up"; n.FirstParserMessage != want {
		t.Errorf("FirstParserMessage = %q, want %q", n.FirstParserMessage, want)
	}
}

// TestSemgrepNotificationsDistinctFilesAndTheCap. Three syntax errors in one
// file are one unparsed file; seven files render as five names and a count.
func TestSemgrepNotificationsDistinctFilesAndTheCap(t *testing.T) {
	n := parseSemgrepNotifications(sarifWithNotifications(
		syntaxNote("A.cs", 1, "x"), syntaxNote("A.cs", 2, "y"), syntaxNote("A.cs", 3, "z"),
	))
	if n.ParseFailures != 3 || len(n.UnparsedFiles) != 1 {
		t.Errorf("ParseFailures=%d files=%v, want 3 notifications over 1 file", n.ParseFailures, n.UnparsedFiles)
	}
	w := semgrepPartialScanWarning(n)
	if !strings.Contains(w, "1 file(s) could not be fully parsed (C#: 1 — A.cs) across 3 syntax error(s)") {
		t.Errorf("both numbers must be stated:\n%s", w)
	}

	var notes []string
	for _, f := range []string{"a/One.cs", "a/Two.cs", "b/Three.cs", "b/Four.cs", "c/Five.cs", "c/Six.cs", "d/Seven.cs"} {
		notes = append(notes, syntaxNote(f, 1, "x"))
	}
	w = semgrepNotificationWarnings(sarifWithNotifications(notes...))[0]
	if !strings.Contains(w, "7 file(s) could not be fully parsed (C#: 7 — a/One.cs, a/Two.cs, b/Three.cs, b/Four.cs, c/Five.cs, and 2 more)") {
		t.Errorf("want five names then a count:\n%s", w)
	}
	if strings.Contains(w, "Six.cs") || strings.Contains(w, "Seven.cs") {
		t.Errorf("names past the cap must not be spelled out:\n%s", w)
	}
}

// TestSemgrepNotificationsLanguageSplit. The split says which parser failed;
// the C#-specific remedy is stated only when C# is among the files.
func TestSemgrepNotificationsLanguageSplit(t *testing.T) {
	w := semgrepNotificationWarnings(sarifWithNotifications(
		syntaxNote("web/app.ts", 1, "x"), syntaxNote("api/A.cs", 1, "y"), syntaxNote("api/B.cs", 1, "z"),
		syntaxNote("Dockerfile", 1, "q"), syntaxNote("odd.zig", 1, "r"), syntaxNote("README", 1, "s"),
	))[0]
	// Most files first, then byte order — deterministic, so two envelopes over
	// the same tree render the same line.
	if !strings.Contains(w, "(C#: 2, .zig: 1, Dockerfile: 1, TypeScript: 1, no extension: 1 — ") {
		t.Errorf("language split wrong or unordered:\n%s", w)
	}

	w = semgrepNotificationWarnings(sarifWithNotifications(syntaxNote("web/app.ts", 1, "x")))[0]
	if strings.Contains(w, "C#") {
		t.Errorf("no C# file, so no C# in the split:\n%s", w)
	}
	if !strings.Contains(w, "Opengrep "+opengrepVersion+" skips the region its parser rejects") {
		t.Errorf("the generic parse-failure clause must still be there:\n%s", w)
	}
	// Measured: an unbalanced brace widens the skipped span to the whole file
	// and the file yields no findings. A clause naming only the local case
	// would promise the rest of the file was read when it may not have been.
	if !strings.Contains(w, "the whole file") {
		t.Errorf("the parse-failure clause must name the whole-file case:\n%s", w)
	}
	// The old hint promised a remedy nobody measured; a later OSS release was
	// measured and rejected the same files. It must not come back.
	if strings.Contains(w, "Pro engine") || strings.Contains(w, "may accept the construct") {
		t.Errorf("the warning promises an unmeasured remedy:\n%s", w)
	}
}

// TestTheParseWarningDoesNotDescribeSemgrepsGaps. The C# clause written for
// Semgrep OSS named constructs the pinned Opengrep parses; printing it would
// send a reader hunting a gap the engine that ran does not have, and the
// "no newer release" line would deny the remedy that was in fact taken.
func TestTheParseWarningDoesNotDescribeSemgrepsGaps(t *testing.T) {
	w := semgrepNotificationWarnings(sarifWithNotifications(syntaxNote("api/A.cs", 1, "y")))[0]
	for _, stale := range []string{"Semgrep OSS", "primary constructors", "record declarations", "no newer"} {
		if strings.Contains(w, stale) {
			t.Errorf("the warning still carries the Semgrep-era claim %q:\n%s", stale, w)
		}
	}
	if !strings.Contains(w, "Opengrep "+opengrepVersion) {
		t.Errorf("the warning must name the engine that ran:\n%s", w)
	}
}

// TestSemgrepNoticesPartialFiles. Examined.Partial counts distinct NAMED files
// across every partial-read kind — a file that failed to parse and also timed
// out is one partly-read file, not two — and never counts an unnamed notice.
func TestSemgrepNoticesPartialFiles(t *testing.T) {
	n := parseSemgrepNotifications(sarifWithNotifications(
		syntaxNote("api/A.cs", 1, "x"),
		syntaxNote("api/A.cs", 9, "x"),
		syntaxNote("api/B.cs", 1, "y"),
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.one on api/A.cs:\n "}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.one on api/C.cs:\n "}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.two"}}`,
	))
	if got := n.partialFiles(); got != 3 {
		t.Errorf("partialFiles = %d, want 3 (A, B, C — A once despite three notices)", got)
	}
	if got := (semgrepNotices{}).partialFiles(); got != 0 {
		t.Errorf("no notices must be partial 0, got %d", got)
	}
}

// TestSemgrepNotificationsTimeoutOnlyIsStillAWarning. Timeouts without any
// parse failure are the other half of the disclosure and must not need one.
func TestSemgrepNotificationsTimeoutOnlyIsStillAWarning(t *testing.T) {
	w := semgrepNotificationWarnings(sarifWithNotifications(
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.one on X.cs:\n "}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.one on Y.cs:\n "}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.two on X.cs:\n "}}`,
	))
	if len(w) != 1 {
		t.Fatalf("want one warning, got %v", w)
	}
	if !strings.Contains(w[0], "opengrep: PARTIAL SCAN — 3 rule timeout(s) hit 2 file(s) (X.cs, Y.cs; rules: r.one, r.two).") {
		t.Errorf("timeout-only wording:\n%s", w[0])
	}
	if strings.Contains(w[0], "could not be fully parsed") || strings.Contains(w[0], "skips the region") {
		t.Errorf("no parse failure, so no parse-failure clauses:\n%s", w[0])
	}
	if !strings.Contains(w[0], "floor, not a verdict") {
		t.Errorf("a timeout still makes the finding count a floor:\n%s", w[0])
	}
}

// TestSemgrepNotificationsPathWithColonSurvives. The path regex is greedy so
// the LAST ":<line>:" on the first line is the location.
func TestSemgrepNotificationsPathWithColonSurvives(t *testing.T) {
	n := parseSemgrepNotifications(sarifWithNotifications(syntaxNote("odd:dir/File.cs", 12, "x")))
	if got := strings.Join(n.UnparsedFiles, ","); got != "odd:dir/File.cs" {
		t.Errorf("UnparsedFiles = %q", got)
	}
	if n.FirstParserMessage != "odd:dir/File.cs:12 x" {
		t.Errorf("FirstParserMessage = %q", n.FirstParserMessage)
	}
}

// TestSemgrepNoticesPartialFilesOneSpellingPerFile. The engine may name one
// file "./a.go" in a timeout and "/src/a.go" or a file URI in a syntax
// notice; read raw, it would be two partly-read files.
func TestSemgrepNoticesPartialFilesOneSpellingPerFile(t *testing.T) {
	n := parseSemgrepNotifications(sarifWithNotifications(
		syntaxNote("/src/api/A.cs", 1, "x"),
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.one on ./api/A.cs:\n "}}`,
		`{"descriptor":{"id":"Timeout"},"level":"warning","message":{"text":"Timeout when running r.two on api/A.cs:\n "}}`,
	))
	if got := n.partialFiles(); got != 1 {
		t.Errorf("partialFiles = %d, want 1 (one file, three spellings): unparsed=%v timed=%v",
			got, n.UnparsedFiles, n.TimedOutFiles)
	}
	for in, want := range map[string]string{
		"./a.go": "a.go", "/src/a.go": "a.go", "file:///src/a.go": "a.go", " a.go ": "a.go",
		"a//b/../c.go": "a/c.go", "": "", "/src/": "", ".": "",
	} {
		if got := semgrepNoticePath(in); got != want {
			t.Errorf("semgrepNoticePath(%q) = %q, want %q", in, got, want)
		}
	}
}
