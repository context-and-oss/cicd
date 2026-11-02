//go:build unit_test

package main

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// zapRealRejectBlock reconstructs the daemon's diagnostic shape with
// invented timestamps, node counts and plugin durations. zapspec is a fixture-
// local service alias, not a consumer endpoint. zapRunScript's grep is
//
//	grep -E -A 30 '(WARN|ERROR).*/JSON/(openapi|soap|graphql)/action/import' zap.log
//
// Its context includes routine INFO entries after the exception. Keeping that
// noise tests that zapMeaningfulLines excludes unrelated scan activity, rather
// than merely accepting a fixture cut at the end of the exception.
const zapRealRejectBlock = `2000-01-02 03:04:05,100 [ZAP-IO-Server-1-1] WARN  API - Bad request to API endpoint [/JSON/openapi/action/importUrl/] from [0:0:0:0:0:0:0:1]:
org.zaproxy.zap.extension.api.ApiException: BAD_EXTERNAL_DATA (The OpenAPI definition was invalid.)
	at org.zaproxy.zap.extension.openapi.OpenApiAPI.handleApiAction(OpenApiAPI.java:159)
	at org.zaproxy.zap.extension.api.API.handleApiRequest(API.java:538)
	at org.zaproxy.addon.network.internal.server.http.handlers.ZapApiHandler.handleApiRequest(ZapApiHandler.java:111)
	at org.zaproxy.addon.network.internal.server.http.handlers.ZapApiHandler.handleRequest(ZapApiHandler.java:85)
	at org.zaproxy.addon.network.internal.server.http.handlers.ZapApiHandler.handleMessage(ZapApiHandler.java:70)
	at org.zaproxy.addon.network.internal.server.http.MainServerHandler.notifyMessageHandlers(MainServerHandler.java:151)
	at org.zaproxy.addon.network.internal.server.http.MainServerHandler.processMessage(MainServerHandler.java:131)
	at org.zaproxy.addon.network.internal.server.http.LocalServerHandler.processMessage(LocalServerHandler.java:67)
	at org.zaproxy.addon.network.internal.server.http.MainServerHandler.process(MainServerHandler.java:94)
	at org.zaproxy.addon.network.internal.server.http.MainServerHandler.lambda$channelRead0$0(MainServerHandler.java:82)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
	at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)
	at java.base/java.lang.Thread.run(Thread.java:840)
Caused by: org.zaproxy.zap.extension.openapi.OpenApiExceptions$InvalidDefinitionException: The OpenAPI definition was invalid.
	at org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter.<init>(SwaggerConverter.java:170)
	at org.zaproxy.zap.extension.openapi.ExtensionOpenApi.importOpenApiDefinition(ExtensionOpenApi.java:441)
	at org.zaproxy.zap.extension.openapi.ExtensionOpenApi.importOpenApiDefinitionV2(ExtensionOpenApi.java:269)
	at org.zaproxy.zap.extension.openapi.OpenApiAPI.handleApiAction(OpenApiAPI.java:134)
	... 13 more
2000-01-02 03:04:05,110 [ZAP-IO-Server-1-1] INFO  Scanner - scanner with ID 0 started
2000-01-02 03:04:05,120 [ZAP-Scanner-0] INFO  HostProcess - Scanning 4 node(s) from http://zapspec:8000
2000-01-02 03:04:05,120 [ZAP-Scanner-0] INFO  HostProcess - start host http://zapspec:8000 | RemoteFileIncludeScanRule strength MEDIUM threshold MEDIUM
2000-01-02 03:04:05,140 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin http://zapspec:8000 | RemoteFileIncludeScanRule in 0.02s with 0 message(s) sent and 0 alert(s) raised.
2000-01-02 03:04:05,140 [ZAP-Scanner-0] INFO  HostProcess - start host http://zapspec:8000 | ExternalRedirectScanRule strength MEDIUM threshold MEDIUM
2000-01-02 03:04:05,149 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin http://zapspec:8000 | ExternalRedirectScanRule in 0.009s with 0 message(s) sent and 0 alert(s) raised.
2000-01-02 03:04:05,149 [ZAP-Scanner-0] INFO  HostProcess - start host http://zapspec:8000 | ServerSideIncludeScanRule strength MEDIUM threshold MEDIUM
2000-01-02 03:04:05,156 [ZAP-Scanner-0] INFO  HostProcess - completed host/plugin http://zapspec:8000 | ServerSideIncludeScanRule in 0.007s with 0 message(s) sent and 0 alert(s) raised.
2000-01-02 03:04:05,156 [ZAP-Scanner-0] INFO  HostProcess - start host http://zapspec:8000 | SqlInjectionScanRule strength MEDIUM threshold MEDIUM`

// zapRealLevels places the parser's reason before the generic rejection
// in a synthetic WARN/ERROR stream. The public parser limit is diagnostic text,
// not a payload measurement; the reason must survive outside the rejection block.
const zapRealLevels = `2000-01-02 03:03:50,100 [ZAP-cfu] ERROR ExtensionCallHome - Read timed out
2000-01-02 03:04:04,800 [ZAP-IO-Server-1-1] WARN  DeserializationUtils - The incoming YAML document exceeds the limit: 3145728 code points.; Max code points: 3145728
2000-01-02 03:04:04,900 [ZAP-IO-Server-1-1] ERROR DeserializationUtils - Error parsing content
2000-01-02 03:04:05,000 [ZAP-IO-Server-1-1] WARN  OpenAPIV3Parser - Exception while parsing:
2000-01-02 03:04:05,100 [ZAP-IO-Server-1-1] WARN  API - Bad request to API endpoint [/JSON/openapi/action/importUrl/] from [0:0:0:0:0:0:0:1]:`

func TestRejectedKeepsTheEntryAndDropsTheScanAroundIt(t *testing.T) {
	got := zapMeaningfulLines(zapRealRejectBlock)
	want := []string{
		"2000-01-02 03:04:05,100 [ZAP-IO-Server-1-1] WARN  API - Bad request to API endpoint [/JSON/openapi/action/importUrl/] from [0:0:0:0:0:0:0:1]:",
		"org.zaproxy.zap.extension.api.ApiException: BAD_EXTERNAL_DATA (The OpenAPI definition was invalid.)",
		"Caused by: org.zaproxy.zap.extension.openapi.OpenApiExceptions$InvalidDefinitionException: The OpenAPI definition was invalid.",
	}
	if len(got) != len(want) {
		t.Fatalf("kept %d lines, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// Unrelated INFO entries in the context get their own exclusion assertion,
// rather than only being covered by a length check.
func TestRejectedCarriesNothingFromAnotherLogEntry(t *testing.T) {
	for _, line := range zapMeaningfulLines(zapRealRejectBlock) {
		for _, banned := range []string{"HostProcess", "Scanner - scanner with ID", "INFO "} {
			if strings.Contains(line, banned) {
				t.Errorf("kept a line from another entry (%q): %q", banned, line)
			}
		}
	}
}

// A second rejection in one block must survive whole. Stopping at the next log
// entry header would be the obvious implementation and would drop it.
func TestRejectedKeepsASecondRejection(t *testing.T) {
	block := zapRealRejectBlock + "\n--\n" +
		"2000-01-02 03:06:00,200 [ZAP-IO-Server-1-1] WARN  API - Bad request to API endpoint [/JSON/soap/action/importUrl/] from [0:0:0:0:0:0:0:1]:\n" +
		"org.zaproxy.zap.extension.api.ApiException: BAD_EXTERNAL_DATA (The SOAP definition was invalid.)\n" +
		"\tat org.zaproxy.zap.extension.soap.SoapAPI.handleApiAction(SoapAPI.java:99)\n" +
		"2000-01-02 03:06:00,210 [ZAP-Scanner-0] INFO  HostProcess - start host http://target:8000 | SqlInjectionScanRule\n"
	got := zapMeaningfulLines(block)
	if len(got) != 5 {
		t.Fatalf("kept %d lines, want 5:\n%s", len(got), strings.Join(got, "\n"))
	}
	if !strings.Contains(got[3], "/JSON/soap/action/importUrl/") {
		t.Errorf("second rejection header missing: %q", got[3])
	}
	if got[4] != "org.zaproxy.zap.extension.api.ApiException: BAD_EXTERNAL_DATA (The SOAP definition was invalid.)" {
		t.Errorf("second rejection body: %q", got[4])
	}
}

// The cause is in a different entry from the rejection, which is the whole
// argument for carrying DaemonLevels at all. The fixture proves it: the
// sentence naming the limit appears in zapRealLevels and nowhere in the block.
func TestTheReasonIsNotInTheRejectionEntry(t *testing.T) {
	const reason = "The incoming YAML document exceeds the limit: 3145728 code points."
	if strings.Contains(strings.Join(zapMeaningfulLines(zapRealRejectBlock), "\n"), reason) {
		t.Fatal("the fixture no longer demonstrates the split; re-check the design of DaemonLevels")
	}
	r := zapImportBuildReport(zapImportProbe{Status: 0, Block: zapRealRejectBlock, Levels: zapRealLevels})
	if r == nil {
		t.Fatal("no report for a rejection")
	}
	if !strings.Contains(strings.Join(r.DaemonLevels, "\n"), reason) {
		t.Errorf("daemonLevels does not carry the reason:\n%s", strings.Join(r.DaemonLevels, "\n"))
	}
}

func TestBuildReportOnTheSyntheticRun(t *testing.T) {
	r := zapImportBuildReport(zapImportProbe{Status: 0, Block: zapRealRejectBlock, Levels: zapRealLevels})
	if r == nil {
		t.Fatal("no report for a rejection")
	}
	if len(r.Rejected) != 3 {
		t.Errorf("rejected lines = %d, want 3", len(r.Rejected))
	}
	if len(r.DaemonLevels) != 5 {
		t.Errorf("daemonLevels = %d, want 5", len(r.DaemonLevels))
	}
	if r.DaemonLevelsTruncated {
		t.Error("five lines reported as truncated")
	}
}

// Status 1 is grep finding nothing, which is the only good news this file has.
// It must produce no report, no error and no warning — the disclosure rule
// TestWebDisclosureIsSilentWhenThereIsNothingToDisclose holds one level up.
func TestNoRejectionIsSilent(t *testing.T) {
	p := zapImportProbe{Status: 1, Levels: zapRealLevels}
	if r := zapImportBuildReport(p); r != nil {
		t.Errorf("report built with no rejection: %+v", r)
	}
	if msg := zapImportError(zapImportBuildReport(p)); msg != "" {
		t.Errorf("error on a clean import: %q", msg)
	}
	if msg := zapImportProbeWarning(p); msg != "" {
		t.Errorf("warning on a clean import: %q", msg)
	}
}

func TestRejectionIsAnError(t *testing.T) {
	msg := zapImportError(zapImportBuildReport(zapImportProbe{Status: 0, Block: zapRealRejectBlock}))
	if msg == "" {
		t.Fatal("a refused document produced no errors[] entry")
	}
	// The verdict has to carry the reason ZAP gave, or a reader is handed
	// the same "it reached nothing" this file exists to explain.
	if !strings.Contains(msg, "BAD_EXTERNAL_DATA") {
		t.Errorf("the message does not quote ZAP's reason: %q", msg)
	}
	// And it has to say why the packaged scan exited 0, or the first
	// response is to distrust the gate rather than the document.
	if !strings.Contains(msg, "exited 0") {
		t.Errorf("the message does not explain the green exit: %q", msg)
	}
}

func TestProbeFailureWarnsAndNamesWhy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{
		{"grep error", 2, "exit status 2"},
		{"no log", zapImportRejectStatusNoLog, "the log was not at " + zapDaemonLogPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := zapImportProbe{Status: tc.status}
			msg := zapImportProbeWarning(p)
			if msg == "" {
				t.Fatalf("status %d produced no warning", tc.status)
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("warning does not say %q: %s", tc.want, msg)
			}
			if r := zapImportBuildReport(p); r != nil {
				t.Errorf("an unasked question produced a report: %+v", r)
			}
			if msg := zapImportError(zapImportBuildReport(p)); msg != "" {
				t.Errorf("an unasked question produced an error: %q", msg)
			}
		})
	}
}

// zapImportRejectStatusNoLog is spelled twice because zapRunScript is a Go
// constant and strconv.Itoa cannot appear in one. This is the test that keeps
// the two spellings together; check_include_language_set exists because a pair
// like it was allowed to drift.
func TestNoLogStatusIsSpelledOnce(t *testing.T) {
	if got := strconv.Itoa(zapImportRejectStatusNoLog); got != zapImportRejectStatusNoLogText {
		t.Fatalf("the shell writes %s and Go reads %s", zapImportRejectStatusNoLogText, got)
	}
	if !strings.Contains(zapRunScript, "echo "+zapImportRejectStatusNoLogText+" >") {
		t.Error("zapRunScript no longer writes the no-log status this file reads")
	}
}

// The status range has to stay three answers wide. 0 and 1 are grep's; 2 and up
// are cicd failing to ask, and the no-log status has to land in that third
// group rather than passing for one of grep's answers.
func TestTheNoLogStatusCannotBeMistakenForGrep(t *testing.T) {
	p := zapImportProbe{Status: zapImportRejectStatusNoLog}
	if zapImportRejected(p) {
		t.Error("a missing log read as a rejection")
	}
	if !zapImportProbeFailed(p) {
		t.Error("a missing log read as an answered question")
	}
}

func TestDaemonLevelsAreCappedAndSaySo(t *testing.T) {
	var b strings.Builder
	for i := 0; i < zapDaemonLevelsMaxLines+5; i++ {
		b.WriteString("2000-01-02 03:05:30,700 [ZAP-Import-OpenAPI-1] WARN  ExtensionOpenApi - attribute " + strconv.Itoa(i) + "\n")
	}
	r := zapImportBuildReport(zapImportProbe{Status: 0, Block: zapRealRejectBlock, Levels: b.String()})
	if len(r.DaemonLevels) != zapDaemonLevelsMaxLines {
		t.Errorf("kept %d levels, want the cap %d", len(r.DaemonLevels), zapDaemonLevelsMaxLines)
	}
	if !r.DaemonLevelsTruncated {
		t.Error("the cap dropped lines and the report does not say so")
	}
}

// The count is over what is stored, not over what was considered: a bounded
// tail must not claim its capacity as the number of lines it actually kept.
func TestTruncationFlagIsFalseWhenNothingWasDropped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < zapDaemonLevelsMaxLines; i++ {
		b.WriteString("2000-01-02 03:05:30,700 WARN  ExtensionOpenApi - attribute " + strconv.Itoa(i) + "\n")
	}
	r := zapImportBuildReport(zapImportProbe{Status: 0, Block: zapRealRejectBlock, Levels: b.String()})
	if r.DaemonLevelsTruncated {
		t.Error("exactly the cap reported as truncated")
	}
}

func TestLongLineIsCutAtARuneBoundary(t *testing.T) {
	// A path a consumer could legitimately have. The multi-byte rune is
	// placed so that a byte-count cut lands inside it.
	line := strings.Repeat("a", zapLineMaxBytes-1) + "ø" + strings.Repeat("b", 100)
	got := truncateZAPLine(line)
	if !strings.HasSuffix(got, " … [truncated]") {
		t.Fatalf("not marked as truncated: %q", got[len(got)-20:])
	}
	if !utf8.ValidString(got) {
		t.Error("the cut split a rune")
	}
	if len(got) > zapLineMaxBytes+len(" … [truncated]") {
		t.Errorf("kept %d bytes, cap is %d", len(got), zapLineMaxBytes)
	}
}

func TestShortLineIsUntouched(t *testing.T) {
	const line = "2000-01-02 03:04:05,100 WARN  API - Bad request"
	if got := truncateZAPLine(line); got != line {
		t.Errorf("rewrote a short line: %q", got)
	}
}

// The pattern matches ZAP's API path and never the parser's wording, so that it
// cannot rot with whichever library upstream bundles this month. These are the
// three formats zap-api-scan.py accepts for -f.
func TestTheAPIPathPatternCoversEveryImportFormat(t *testing.T) {
	for _, format := range []string{"openapi", "soap", "graphql"} {
		line := "2000-01-02 03:04:05,100 [ZAP-IO-Server-1-1] WARN  API - Bad request to API endpoint [/JSON/" +
			format + "/action/importUrl/] from [0:0:0:0:0:0:0:1]:"
		if !zapImportAPIPath.MatchString(line) {
			t.Errorf("%s import rejection would not be matched", format)
		}
	}
	if zapImportAPIPath.MatchString("2000-01-02 03:04:05,100 WARN  API - Bad request to API endpoint [/JSON/core/view/urls/]") {
		t.Error("an unrelated API call matched the import pattern")
	}
}
