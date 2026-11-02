package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// zapNativeReport is shaped like a real ZAP 2.17.0 `-J` report: a site holding
// alerts, each alert holding the instances it fired on, and every numeric field
// serialised as a string — which is where the discarded strconv.Atoi error and
// the missing default arm both used to live.
const zapNativeReport = `{
  "@programName": "ZAP",
  "@version": "2.17.0",
  "@generated": "Thu, 10 Sep 2026 09:00:00",
  "site": [
    {
      "@name": "http://app-under-test:8080",
      "@host": "app-under-test",
      "@port": "8080",
      "@ssl": "false",
      "alerts": [
        {
          "pluginid": "40012",
          "alertRef": "40012",
          "alert": "Cross Site Scripting (Reflected)",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "3",
          "confidence": "2",
          "count": "2",
          "instances": [
            {"uri": "http://app-under-test:8080/greet", "method": "GET", "param": "name", "evidence": "<script>alert(1)</script>"},
            {"uri": "http://app-under-test:8080/greet?name=x", "method": "GET", "param": "name", "evidence": "<script>alert(1)</script>"}
          ]
        },
        {
          "pluginid": "10038",
          "alertRef": "10038-1",
          "alert": "CSP",
          "name": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "2",
          "confidence": "3",
          "count": "1",
          "instances": [
            {"uri": "http://app-under-test:8080/", "method": "GET", "param": "", "evidence": ""}
          ]
        },
        {
          "pluginid": "10021",
          "alertRef": "10021",
          "alert": "X-Content-Type-Options Header Missing",
          "name": "X-Content-Type-Options Header Missing",
          "riskcode": "1",
          "confidence": "2",
          "count": "1",
          "instances": [
            {"uri": "http://app-under-test:8080/", "method": "GET", "param": "x-content-type-options", "evidence": ""}
          ]
        },
        {
          "pluginid": "10049",
          "alertRef": "10049",
          "alert": "Storable and Cacheable Content",
          "name": "Storable and Cacheable Content",
          "riskcode": "0",
          "confidence": "2",
          "count": "1",
          "instances": [
            {"uri": "http://app-under-test:8080/api/items", "method": "GET", "param": "", "evidence": ""}
          ]
        }
      ]
    }
  ]
}`

func TestCompactZAPReportDropsUnboundedCaptures(t *testing.T) {
	raw := json.RawMessage(`{"site":[{"@name":"http://app/","alerts":[{` +
		`"pluginid":"10021","name":"Header missing","riskcode":"1","count":"1",` +
		`"requestHeader":"secret request","responseBody":"very large response",` +
		`"instances":[{"uri":"http://app/a","method":"GET","param":"header",` +
		`"evidence":"captured response bytes"}]}]}]}`)

	got := compactZAPReport(raw)
	if len(got) == 0 {
		t.Fatal("compactZAPReport returned no report")
	}
	text := string(got)
	for _, dropped := range []string{"secret request", "very large response", "captured response bytes", "requestHeader", "responseBody", "evidence"} {
		if strings.Contains(text, dropped) {
			t.Errorf("compact report retained %q: %s", dropped, text)
		}
	}
	for _, kept := range []string{"10021", "Header missing", "http://app/a", "GET", "header"} {
		if !strings.Contains(text, kept) {
			t.Errorf("compact report dropped %q: %s", kept, text)
		}
	}
}

func TestCompactZAPReportRejectsUnreadableInput(t *testing.T) {
	if got := compactZAPReport(json.RawMessage(`not json`)); got != nil {
		t.Fatalf("compactZAPReport returned %s, want nil", got)
	}
}

func TestParseZAPReportCountsEveryInstance(t *testing.T) {
	got, err := parseZAPReport(json.RawMessage(zapNativeReport))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}

	// 3=High, 2=Medium, 1=Low, 0=Informational-as-Low. The two XSS instances
	// are two HIGHs, not one: a rule firing on two URLs is two things to fix.
	want := map[Severity]int{SeverityHigh: 2, SeverityMedium: 1, SeverityLow: 2}
	for sev, n := range want {
		if got.BySeverity[sev] != n {
			t.Errorf("severity %s: got %d, want %d", sev, got.BySeverity[sev], n)
		}
	}
	if len(got.BySeverity) != len(want) {
		t.Errorf("bySeverity has %d buckets, want %d: %v", len(got.BySeverity), len(want), got.BySeverity)
	}

	// The counts and the rows must agree. A count over an empty table is the
	// defect this parser exists to close; a count that disagrees with the table
	// is the same defect wearing a number.
	total := 0
	for _, n := range got.BySeverity {
		total += n
	}
	if len(got.Findings) != total {
		t.Errorf("got %d findings for a severity total of %d", len(got.Findings), total)
	}
}

func TestParseZAPReportGivesEveryFindingItsURL(t *testing.T) {
	got, err := parseZAPReport(json.RawMessage(zapNativeReport))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}

	for _, f := range got.Findings {
		if f.Tool != "zap" {
			t.Errorf("finding %q: tool = %q, want zap", f.Message, f.Tool)
		}
		if f.Rule == "" {
			t.Errorf("finding %q has no rule id", f.Message)
		}
		if f.ArtifactPath == "" {
			t.Errorf("finding %q has no URL; a finding's location is part of its identity", f.Message)
		}
	}

	// The two XSS rows differ only by URL. If ArtifactPath were dropped they
	// would be byte-identical structs and dedupeFindings downstream would keep
	// one — the give-a-finding-its-line failure, restated for a URL.
	var xss []Finding
	for _, f := range got.Findings {
		if f.Rule == "40012" {
			xss = append(xss, f)
		}
	}
	if len(xss) != 2 {
		t.Fatalf("got %d XSS rows, want 2", len(xss))
	}
	if xss[0] == xss[1] {
		t.Error("the two XSS findings are identical structs, so the dedupe will collapse them to one row")
	}
}

func TestParseZAPReportCountsDistinctAlertedURLs(t *testing.T) {
	got, err := parseZAPReport(json.RawMessage(zapNativeReport))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}
	// /greet, /greet?name=x, / and /api/items — four distinct URIs across five
	// instances, because / carries two alerts.
	if got.URLsWithAlerts != 4 {
		t.Errorf("URLsWithAlerts = %d, want 4", got.URLsWithAlerts)
	}
}

func TestParseZAPReportReportsFiredRules(t *testing.T) {
	got, err := parseZAPReport(json.RawMessage(zapNativeReport))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}
	want := []string{"10021", "10038", "10049", "40012"}
	if len(got.FiredRuleIDs) != len(want) {
		t.Fatalf("FiredRuleIDs = %v, want %v", got.FiredRuleIDs, want)
	}
	for i := range want {
		if got.FiredRuleIDs[i] != want[i] {
			t.Errorf("FiredRuleIDs[%d] = %q, want %q", i, got.FiredRuleIDs[i], want[i])
		}
	}
}

// TestZAPSeverityHasNoSilentDefault is the regression guard for the missing
// default arm. The old switch listed "3", "2", "1" and "0" and dropped
// everything else on the floor, so a risk code ZAP added in a later release
// would have reduced the findings count without a word.
func TestZAPSeverityHasNoSilentDefault(t *testing.T) {
	for _, tc := range []struct {
		code  string
		want  Severity
		known bool
	}{
		{"3", SeverityHigh, true},
		{"2", SeverityMedium, true},
		{"1", SeverityLow, true},
		{"0", SeverityLow, true},
		{" 2 ", SeverityMedium, true},
		{"4", SeverityMedium, false},
		{"", SeverityMedium, false},
		{"high", SeverityMedium, false},
	} {
		got, known := zapSeverity(tc.code)
		if got != tc.want || known != tc.known {
			t.Errorf("zapSeverity(%q) = (%s, %v), want (%s, %v)", tc.code, got, known, tc.want, tc.known)
		}
	}
}

func TestParseZAPReportNamesUnknownRiskCodes(t *testing.T) {
	const report = `{"site":[{"@name":"http://x","alerts":[
      {"pluginid":"99999","name":"Future Rule","riskcode":"4","count":"1",
       "instances":[{"uri":"http://x/","method":"GET"}]}]}]}`
	got, err := parseZAPReport(json.RawMessage(report))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}
	if len(got.UnknownRiskCodes) != 1 || got.UnknownRiskCodes[0] != "4" {
		t.Errorf("UnknownRiskCodes = %v, want [4]", got.UnknownRiskCodes)
	}
	if got.BySeverity[SeverityMedium] != 1 {
		t.Errorf("an unknown risk code must still be counted; bySeverity = %v", got.BySeverity)
	}
	if len(got.Findings) != 1 {
		t.Errorf("an unknown risk code must still produce a row; got %d", len(got.Findings))
	}
}

// TestZAPAlertCountNeverRoundsToZero pins the other half of the discarded
// strconv.Atoi: an alert in the report happened at least once, so an
// unreadable count must not delete it.
func TestZAPAlertCountNeverRoundsToZero(t *testing.T) {
	for _, tc := range []struct {
		count string
		want  int
	}{
		{"3", 3},
		{"1", 1},
		{"", 1},
		{"0", 1},
		{"-4", 1},
		{"lots", 1},
	} {
		if got := zapAlertCount(zapAlert{Count: tc.count}); got != tc.want {
			t.Errorf("zapAlertCount(%q) = %d, want %d", tc.count, got, tc.want)
		}
	}
}

// TestParseZAPReportCountsAnAlertWithNoInstances covers the shape that has no
// location at all. It must still be reported — an alert with nowhere to point
// is a finding whose location is unknown, not a finding that did not happen.
func TestParseZAPReportCountsAnAlertWithNoInstances(t *testing.T) {
	const report = `{"site":[{"@name":"http://x","alerts":[
      {"pluginid":"10035","name":"HSTS Header Not Set","riskcode":"1","count":"3"}]}]}`
	got, err := parseZAPReport(json.RawMessage(report))
	if err != nil {
		t.Fatalf("parseZAPReport: %v", err)
	}
	if got.BySeverity[SeverityLow] != 3 {
		t.Errorf("bySeverity = %v, want 3 LOW from the alert's own count", got.BySeverity)
	}
	if len(got.Findings) != 3 {
		t.Errorf("got %d findings, want 3", len(got.Findings))
	}
	if got.URLsWithAlerts != 0 {
		t.Errorf("URLsWithAlerts = %d, want 0: the alert named no URL", got.URLsWithAlerts)
	}
}

// TestZAPRunErrorSeparatesResultsFromNonRuns is the regression guard for the
// `|| true` that used to end the ZAP command. Exit 3 is ZAP's "any other
// failure" and used to arrive as 0.
func TestZAPRunErrorSeparatesResultsFromNonRuns(t *testing.T) {
	const ok = `{"site":[{"@name":"http://x","alerts":[]}]}`

	for _, tc := range []struct {
		name    string
		exit    string
		stdout  string
		stderr  string
		report  string
		wantErr string // "" means the run is trustworthy
	}{
		{name: "clean", exit: "0", report: ok},
		{name: "fail rule tripped", exit: "1", report: ok},
		{name: "warn rule tripped", exit: "2", report: ok},
		{name: "any other failure", exit: "3", report: ok, wantErr: "did not run (exit 3)"},
		{name: "interpreter died", exit: "127", report: ok, wantErr: "did not run (exit 127)"},
		{name: "unreadable status", exit: "  ", report: ok, wantErr: "unreadable exit status"},
		{name: "no report", exit: "0", report: "   ", wantErr: "wrote no report"},
		{name: "report is not json", exit: "0", report: "Traceback (most recent call last):", wantErr: "not valid JSON"},
		{name: "report has no site", exit: "0", report: `{"@version":"2.17.0"}`, wantErr: "describes no site"},
		{name: "report site is null", exit: "0", report: `{"site":null}`, wantErr: "describes no site"},
		{
			name: "stderr is quoted in the message", exit: "3", report: ok,
			stderr:  "progress noise\nFailed to access the target",
			wantErr: "Failed to access the target",
		},
		{
			name: "stdout is quoted in the message", exit: "3", report: ok,
			stdout:  "usage: zap-api-scan.py\nInvalid option autooff",
			wantErr: "Invalid option autooff",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := zapRunError(tc.exit, tc.stdout, tc.stderr, tc.report)
			switch {
			case tc.wantErr == "" && got != "":
				t.Errorf("got error %q, want the run to be trustworthy", got)
			case tc.wantErr != "" && !strings.Contains(got, tc.wantErr):
				t.Errorf("got %q, want it to contain %q", got, tc.wantErr)
			}
		})
	}
}

// TestZAPFailureDetailReportsTheStreamThatExplainsIt is the regression guard
// for a diagnosis that was captured and thrown away. runZAP wrote stdout to
// /tmp/zap.out and read only /tmp/zap.err, and the packaged scan scripts put
// their own failures on stdout while the Java daemon logs at INFO on stderr —
// so an OOM-killed zap-full-scan.py reported a scan rule starting normally.
//
// The first case constructs synthetic streams with invented port, thread and
// elapsed-time values in the upstream log shape. Requiring both to survive is
// the point — reporting stdout alone would trade one dropped stream for another,
// and the INFO line identifies the rule running beside the connection failure.
func TestZAPFailureDetailReportsTheStreamThatExplainsIt(t *testing.T) {
	const oomStdout = "ERROR HTTPConnectionPool(host='localhost', port=32109): Max retries exceeded (Caused by ProxyError('Unable to connect to proxy', ConnectionResetError(104, 'Connection reset by peer')))"
	const oomStderr = "24005 [Thread-37] INFO  org.zaproxy.zap.extension.domxss.DomXssScanRule - Reaper thread starting"

	for _, tc := range []struct {
		name    string
		stdout  string
		stderr  string
		want    []string
		notWant []string
	}{
		{
			name:   "synthetic OOM keeps both streams",
			stdout: "24002 progress\n" + oomStdout, stderr: "18000 earlier\n" + oomStderr,
			want: []string{"Connection reset by peer", "DomXssScanRule"},
		},
		{
			name:   "stderr alone is still reported",
			stderr: "Failed to access the target",
			want:   []string{"Failed to access the target"},
		},
		{
			name:   "stdout alone is still reported",
			stdout: "Invalid option autooff",
			want:   []string{"Invalid option autooff"},
		},
		{
			name:   "an identical tail is not said twice",
			stdout: "same line", stderr: "same line",
			want:    []string{"same line"},
			notWant: []string{"last log line"},
		},
		{name: "silence stays silent", notWant: []string{"last log line"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := zapFailureDetail(tc.stdout, tc.stderr)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("zapFailureDetail = %q, want it to contain %q", got, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("zapFailureDetail = %q, want it not to contain %q", got, w)
				}
			}
			if len(tc.want) == 0 && got != "" {
				t.Errorf("zapFailureDetail = %q, want \"\" when neither stream said anything", got)
			}
		})
	}
}

func TestParseZAPReportRejectsGarbage(t *testing.T) {
	if _, err := parseZAPReport(json.RawMessage("not json")); err == nil {
		t.Error("a report that is not JSON must be an error, not an empty result")
	}
}

// TestZapLogKeepsWhatTheLastLineThrewAway.
//
// A closing INFO line can hide the cause. This synthetic log tests that the
// tail reaches back past that line, while zapFailureDetail keeps its bounded
// one-line summary for an errors[] entry.
func TestZapLogKeepsWhatTheLastLineThrewAway(t *testing.T) {
	stderr := "java.lang.OutOfMemoryError: Java heap space\n" +
		"45007 [ZAP-daemon] INFO  org.zaproxy.zap.DaemonBootstrap - ZAP 2.17.0 terminated.\n"
	stdout := "ERROR [Errno 5] Failed to connect to ZAP after 600 seconds\n"

	if got := zapFailureDetail(stdout, stderr); !strings.Contains(got, "terminated") {
		t.Fatalf("fixture no longer reproduces the one-line summary: %q", got)
	} else if strings.Contains(got, "OutOfMemoryError") {
		t.Fatalf("fixture no longer exercises the loss — the cause survived the summary: %q", got)
	}

	log := zapLogFor(false, false, stdout, stderr)
	if log == nil {
		t.Fatal("a non-run kept no log at all")
	}
	if !strings.Contains(log.Stderr, "OutOfMemoryError") {
		t.Errorf("the line that says why was dropped: %q", log.Stderr)
	}
	if !strings.Contains(log.Stdout, "Failed to connect to ZAP") {
		t.Errorf("the packaged script's own report was dropped: %q", log.Stdout)
	}
	if log.StdoutTruncated || log.StderrTruncated {
		t.Error("a short log was marked truncated")
	}
}

// TestZapLogIsNotCarriedByACleanCompletedScan. The bytes travel in every
// consumer's evidence bundle, so a run with nothing to explain explains
// nothing.
func TestZapLogIsNotCarriedByACleanCompletedScan(t *testing.T) {
	if got := zapLogFor(true, false, "lots", "and lots"); got != nil {
		t.Errorf("a clean completed scan carried its log: %+v", got)
	}
	// A non-run that said nothing on either stream has no tail to keep, and an
	// empty object in the envelope would read as a log that was captured.
	if got := zapLogFor(false, false, "", "  \n\t\n"); got != nil {
		t.Errorf("two silent streams produced a log object: %+v", got)
	}
}

// TestZapLogSurvivesAScanThatFinishedAndReachedNothing.
//
// A completed scan can still report a reach error. Discarding its streams
// would drop the import context beside the count cicd already parsed.
//
// This synthetic fixture uses invented counts and timestamps in the protocol
// shape: the importer logs to stderr, the packaged script's PASS list to
// stdout. Both are kept, because which one carries the cause is upstream's
// choice and not cicd's to predict.
func TestZapLogSurvivesAScanThatFinishedAndReachedNothing(t *testing.T) {
	stderr := "2031-02-03 04:05:06,010 Using override, new target: http://app:8080\n" +
		"2031-02-03 04:05:06,020 Errors in the OpenAPI definition, skipping 23 operations\n" +
		"2031-02-03 04:05:06,030 Number of Imported URLs: 6\n"
	stdout := "Total of 31 URLs\nPASS: Directory Browsing [0]\n"

	log := zapLogFor(true, true, stdout, stderr)
	if log == nil {
		t.Fatal("a completed scan that errored kept no log, so nothing says why it reached nothing")
	}
	if !strings.Contains(log.Stderr, "skipping 23 operations") {
		t.Errorf("the importer's own complaint was dropped: %q", log.Stderr)
	}
	if !strings.Contains(log.Stderr, "Number of Imported URLs: 6") {
		t.Errorf("the line cicd had already parsed was not kept beside its context: %q", log.Stderr)
	}
	if !strings.Contains(log.Stdout, "Total of 31 URLs") {
		t.Errorf("stdout was dropped: %q", log.Stdout)
	}
}

// TestTailBytesCutsAtALineBoundary. A tail that opens mid-token reads as
// corrupt output rather than as truncation.
func TestTailBytesCutsAtALineBoundary(t *testing.T) {
	s := "first line that will be dropped\nsecond\nthird\n"

	got, truncated := tailBytes(s, 20)
	if !truncated {
		t.Fatal("a cut tail was not reported as truncated")
	}
	if strings.HasPrefix(got, "e that will") || !strings.HasPrefix(got, "second") {
		t.Errorf("the tail did not resume at a line boundary: %q", got)
	}

	whole, truncated := tailBytes(s, len(s))
	if truncated || whole != s {
		t.Errorf("a log inside the budget was altered: %q truncated=%v", whole, truncated)
	}

	// One very long line is still the line that matters: returning nothing
	// because no newline was found would drop the only evidence there was.
	long := strings.Repeat("x", 100)
	got, truncated = tailBytes(long, 10)
	if !truncated || got != strings.Repeat("x", 10) {
		t.Errorf("a newline-free log was not tailed: %q truncated=%v", got, truncated)
	}
}

// TestAlertsAreTalliedPerRuleTheSameWayFindingsAre.
//
// The tally exists to answer one question the report cannot be asked directly —
// is this rule sitting on the packaged scan's per-rule cap — and it is only
// trustworthy if it counts what the finding list counts. So an alert with
// instances contributes one per instance, and an alert with none contributes
// its own stated count, exactly as the Findings loop does. Two alertRefs of the
// same plugin are one rule, because the cap is enforced per rule.
func TestAlertsAreTalliedPerRuleTheSameWayFindingsAre(t *testing.T) {
	raw := []byte(`{"site":[{"@name":"http://app/","alerts":[
		{"pluginid":"10015","alertRef":"10015-1","name":"Cache","riskcode":"1","count":"2",
		 "instances":[{"uri":"http://app/a"},{"uri":"http://app/b"}]},
		{"pluginid":"10015","alertRef":"10015-2","name":"Cache other","riskcode":"1","count":"1",
		 "instances":[{"uri":"http://app/c"}]},
		{"pluginid":"90004","name":"No instances","riskcode":"2","count":"4"}
	]}]}`)
	got, err := parseZAPReport(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := got.AlertsByRule["10015"]; n != 3 {
		t.Errorf("10015 tallied %d, want 3 — two alertRefs of one plugin are one capped rule", n)
	}
	if n := got.AlertsByRule["90004"]; n != 4 {
		t.Errorf("90004 tallied %d, want 4 — an instance-less alert still happened, count times", n)
	}
	total := 0
	for _, n := range got.AlertsByRule {
		total += n
	}
	if total != len(got.Findings) {
		t.Errorf("tally sums to %d over %d findings; the two must never disagree", total, len(got.Findings))
	}
}

// TestAnEmptyReportTalliesNothingRatherThanAnEmptyMap. Absent and empty read
// the same downstream, so the zero value is chosen for the one that cannot be
// mistaken for a measurement.
func TestAnEmptyReportTalliesNothingRatherThanAnEmptyMap(t *testing.T) {
	got, err := parseZAPReport([]byte(`{"site":[{"@name":"http://app/","alerts":[]}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.AlertsByRule != nil {
		t.Errorf("alerts by rule = %v, want nil", got.AlertsByRule)
	}
}
