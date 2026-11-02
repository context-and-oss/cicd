// ZAP report parsing and invocation classification: how to tell a scan that ran
// from one that died, and how to turn a ZAP JSON report into findings, severity
// counts and a scope signal.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so zapreport_test.go can drive it with `go test -tags unit_test ./...`. The
// previous implementation lived entirely in web.go behind the Dagger build tag,
// which is how a severity switch with no default arm and a discarded
// strconv.Atoi error survived — there was no build in which the question could
// be asked.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// zapRunError classifies a ZAP invocation from its exit status, both of its
// output streams and the report it left behind, returning "" when the scan is
// trustworthy and an error string otherwise. Which stream explains a failure
// depends on which layer failed; see zapFailureDetail.
//
// ZAP's packaged scans document four exit codes: 0 = no rule at FAIL or WARN
// (with -I, also no rule at WARN), 1 = at least one FAIL, 2 = at least one WARN,
// 3 = **any other failure**. The first three are results; the fourth is not, and
// neither is anything outside the set — a Python traceback in zap-baseline.py
// exits 1 from the interpreter only by accident, and usually exits something
// else entirely.
//
// The implementation this replaces ended the command in `|| true`, which
// collapsed 3 into 0. It had not yet produced a false pass only because a ZAP
// that died before writing /tmp/report.json made the subsequent File().Contents()
// call error — so the safety came from a missing file, not from the
// classification, and a partial report written before the crash read as clean.
func zapRunError(exitCode, stdout, stderr, report string) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "zap: unreadable exit status " + strconv.Quote(code)
	case n < 0 || n > 2:
		msg := "zap: did not run (exit " + code + ")"
		if d := zapFailureDetail(stdout, stderr); d != "" {
			msg += ": " + d
		}
		return msg
	}

	if strings.TrimSpace(report) == "" {
		return "zap: exited " + code + " but wrote no report"
	}
	var probe struct {
		Site json.RawMessage `json:"site"`
	}
	if err := json.Unmarshal([]byte(report), &probe); err != nil {
		return "zap: report is not valid JSON: " + err.Error()
	}
	// A completed packaged scan always writes a site array, even when it holds
	// no alerts. A report without one came from something other than a finished
	// scan, and counting its zero alerts as a clean target is the exact failure
	// this function exists to prevent. `"site": []` is the same report: a scan
	// that reached its target lists that target, alerts or none, so an empty
	// array names no site at all. It used to pass because only the raw bytes
	// were checked for absence.
	var sites []json.RawMessage
	if len(probe.Site) > 0 {
		if err := json.Unmarshal(probe.Site, &sites); err != nil {
			return "zap: report's site is not an array: " + err.Error()
		}
	}
	if len(sites) == 0 {
		msg := "zap: exited " + code + " but its report describes no site, so nothing was scanned"
		if d := zapFailureDetail(stdout, stderr); d != "" {
			msg += ": " + d
		}
		return msg
	}
	return ""
}

// zapInstance is one occurrence of an alert: a URL, and how it was reached.
type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Evidence string `json:"evidence,omitempty"`
}

type zapAlert struct {
	PluginID  string        `json:"pluginid"`
	AlertRef  string        `json:"alertRef"`
	Name      string        `json:"name"`
	Alert     string        `json:"alert"`
	RiskCode  string        `json:"riskcode"`
	Count     string        `json:"count"`
	Instances []zapInstance `json:"instances"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Alerts []zapAlert `json:"alerts"`
}

type zapReport struct {
	Site []zapSite `json:"site"`
}

// compactZAPReport keeps the alert topology that makes the native report
// useful while dropping fields outside zapReport's deliberately small schema.
// In particular, ZAP's full JSON can carry request and response bodies for
// every instance. Returning those bytes inside evidence made a 150-finding
// scan too large for Dagger to materialise, even though the normalized finding
// rows and counts were small.
func compactZAPReport(raw json.RawMessage) json.RawMessage {
	var report zapReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil
	}
	for i := range report.Site {
		for j := range report.Site[i].Alerts {
			for k := range report.Site[i].Alerts[j].Instances {
				report.Site[i].Alerts[j].Instances[k].Evidence = ""
			}
		}
	}
	data, err := json.Marshal(report)
	if err != nil {
		return nil
	}
	return data
}

// zapParsed is everything one ZAP report yields: the rows a reviewer acts on,
// the counts the gate reads, the scope signal, and the rule ids that fired.
type zapParsed struct {
	Findings   []Finding
	BySeverity map[Severity]int
	// URLsWithAlerts is the number of distinct instance URIs in the report.
	//
	// It is deliberately not called urlsCrawled: ZAP's JSON report enumerates
	// only URLs that produced an alert, never the ones it visited and found
	// nothing on, so this is a floor on coverage and never a measure of it. A
	// number that overstated its own scope would be worse than no number — the
	// scope signal exists because a scan of one page and a scan of four hundred
	// used to produce byte-identical evidence.
	URLsWithAlerts int
	// FiredRuleIDs is every plugin id that produced an alert, sorted. The
	// suppression disclosure needs it to answer "did this rule fire at all",
	// which is how a suppression that matched nothing gets named as such.
	FiredRuleIDs []string
	// AlertsByRule is how many alerts each rule id raised, counted the same
	// way Findings are produced so the two can never disagree.
	//
	// It exists for one question the report cannot be asked directly: the
	// packaged scans cap each passive rule at zapPassiveAlertCapPerRule alerts
	// and record the cap nowhere, so a rule that stopped reporting and a rule
	// that ran out of things to report are the same entry. A rule sitting
	// exactly on the cap is where that question arises; see rulesAtAlertCap.
	AlertsByRule map[string]int
	// UnknownRiskCodes lists risk codes the report carried that ZAP does not
	// document, sorted. They are counted as MEDIUM rather than dropped: a
	// severity switch that silently ignores what it does not recognise reports
	// fewer findings than the tool found, which is the founding doctrine one
	// field over.
	UnknownRiskCodes []string
}

// parseZAPReport turns a ZAP JSON report into findings, counts and scope.
func parseZAPReport(raw json.RawMessage) (zapParsed, error) {
	var report zapReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return zapParsed{}, fmt.Errorf("parse ZAP report: %w", err)
	}

	out := zapParsed{BySeverity: map[Severity]int{}, AlertsByRule: map[string]int{}}
	uris := map[string]bool{}
	rules := map[string]bool{}
	unknown := map[string]bool{}

	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			sev, known := zapSeverity(alert.RiskCode)
			if !known {
				unknown[strings.TrimSpace(alert.RiskCode)] = true
			}
			if id := zapRuleID(alert); id != "" {
				rules[id] = true
			}

			// One row per instance, because a finding's location is part of its
			// identity: one alert firing on twelve URLs is twelve things to fix,
			// and collapsing them to a single row under a count of twelve is the
			// defect give-a-finding-its-line fixed for secrets.
			if len(alert.Instances) == 0 {
				// An alert with no instances still happened. Report it once,
				// with no location, rather than not at all.
				out.BySeverity[sev] += zapAlertCount(alert)
				out.AlertsByRule[zapRuleID(alert)] += zapAlertCount(alert)
				for i := 0; i < zapAlertCount(alert); i++ {
					out.Findings = append(out.Findings, Finding{
						Severity: sev,
						Tool:     "zap",
						Rule:     zapRuleID(alert),
						Message:  zapAlertName(alert),
					})
				}
				continue
			}
			out.AlertsByRule[zapRuleID(alert)] += len(alert.Instances)
			for _, inst := range alert.Instances {
				if inst.URI != "" {
					uris[inst.URI] = true
				}
				out.BySeverity[sev]++
				out.Findings = append(out.Findings, Finding{
					Severity:     sev,
					Tool:         "zap",
					Rule:         zapRuleID(alert),
					Message:      zapFindingMessage(alert, inst),
					ArtifactPath: inst.URI,
				})
			}
		}
	}

	out.URLsWithAlerts = len(uris)
	out.FiredRuleIDs = sortedKeys(rules)
	out.UnknownRiskCodes = sortedKeys(unknown)
	if len(out.BySeverity) == 0 {
		out.BySeverity = nil
	}
	if len(out.AlertsByRule) == 0 {
		out.AlertsByRule = nil
	}
	return out, nil
}

// zapSeverity maps a ZAP risk code onto the module Severity enum, and says
// whether it recognised the code.
//
// ZAP risk codes: 3=High, 2=Medium, 1=Low, 0=Informational. **There is no
// Critical tier** — High is ZAP's maximum, which is why a DAST scan run with
// --fail-on CRITICAL can never fail over findings and why the envelope says so
// out loud rather than passing quietly.
//
// Informational maps to LOW rather than being discarded, and the default arm
// maps to MEDIUM — the same fallback severityFromSARIFLevel uses for a level it
// does not know, and for the same reason: an unrecognised classification means
// "unclassified", not "harmless".
func zapSeverity(riskCode string) (Severity, bool) {
	switch strings.TrimSpace(riskCode) {
	case "3":
		return SeverityHigh, true
	case "2":
		return SeverityMedium, true
	case "1", "0":
		return SeverityLow, true
	default:
		return SeverityMedium, false
	}
}

// zapAlertCount reads an alert's own instance count, which ZAP serialises as a
// string. An unreadable or absent value means one occurrence, never zero: an
// alert that is in the report happened at least once, and rounding it to zero
// would delete a finding the tool reported.
func zapAlertCount(a zapAlert) int {
	n, err := strconv.Atoi(strings.TrimSpace(a.Count))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// zapRuleID prefers the plugin id, which is what a suppression config names.
// alertRef ("10038-1") identifies a variant of the same plugin and is the
// fallback so a rule is never anonymous.
func zapRuleID(a zapAlert) string {
	if id := strings.TrimSpace(a.PluginID); id != "" {
		return id
	}
	return strings.TrimSpace(a.AlertRef)
}

func zapAlertName(a zapAlert) string {
	if n := strings.TrimSpace(a.Name); n != "" {
		return n
	}
	if n := strings.TrimSpace(a.Alert); n != "" {
		return n
	}
	return "unnamed ZAP alert"
}

// zapFindingMessage names the alert and how this instance was reached. The
// method and parameter are what separates two instances on the same URL, so
// they belong in the row rather than only in the raw report.
func zapFindingMessage(a zapAlert, inst zapInstance) string {
	msg := zapAlertName(a)
	var parts []string
	if m := strings.TrimSpace(inst.Method); m != "" {
		parts = append(parts, m)
	}
	if p := strings.TrimSpace(inst.Param); p != "" {
		parts = append(parts, "param "+p)
	}
	if len(parts) > 0 {
		msg += " (" + strings.Join(parts, ", ") + ")"
	}
	return msg
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// zapFailureDetail names why a ZAP invocation failed, from both of its output
// streams, because the two carry different voices and cicd used to read only
// the quieter one.
//
// stdout is the packaged scan script's own report — a usage error, or the
// "ERROR HTTPConnectionPool … Connection reset by peer" it prints when the ZAP
// daemon it was driving is gone. stderr is the Java daemon's log, which runs
// at INFO and is still emitting scan-rule progress at the moment of death.
//
// Reading stderr alone therefore produced a message that named a scan rule
// starting normally and said nothing about the failure. Measured, on an
// OOM-killed zap-full-scan.py against testdata/vuln-app:
//
//	stdout: ERROR HTTPConnectionPool(host='localhost', port=36482): … Connection reset by peer
//	stderr: 58111 [Thread-214] INFO  …DomXssScanRule - Reaper thread starting
//
// The container's own exit state said OOMKilled=true; neither stream says so,
// which is why both are reported and neither is interpreted. DomXssScanRule
// launches headless Firefox inside the scanner container, so a memory-starved
// runner kills the JVM mid-scan — that is a property of the machine, not a
// classification cicd can make from these bytes, and guessing at it here would
// be a diagnosis invented rather than observed.
//
// The stderr tail is appended only when it differs, so a scan that failed on
// one stream does not report the same line twice.
func zapFailureDetail(stdout, stderr string) string {
	out := lastNonEmptyLine(stdout)
	errl := lastNonEmptyLine(stderr)
	switch {
	case out == "" && errl == "":
		return ""
	case out == "":
		return errl
	case errl == "" || errl == out:
		return out
	}
	return out + " [last log line: " + errl + "]"
}

// zapLogTailBytes bounds each stream kept by zapLogFor.
//
// 16 KiB is roughly the last two hundred lines of the daemon's INFO log, which
// on every startup failure measured so far reaches back past the JVM's own
// complaint to what it was doing before it died. Bounded rather than whole
// because these bytes travel in every consumer's evidence bundle, and an
// unbounded log is how an envelope becomes something nobody opens.
const zapLogTailBytes = 16 << 10

// zapLogTail is the tail of ZAP's two output streams, kept in the evidence when
// an invocation did not complete.
//
// zapFailureDetail reduces each stream to its last non-empty line. That is the
// right length for an errors[] entry and the wrong length for a diagnosis: on
// every startup failure seen so far the last line is
//
//	NNNNN [ZAP-daemon] INFO org.zaproxy.zap.DaemonBootstrap - ZAP 2.17.0 terminated.
//
// which is the consequence. The lines that say why are above it, and cicd read
// both streams, built the one-line summary from them, and dropped the rest —
// so a run that failed could be reported but never explained. Three failures
// across two repositories produced three identical last lines and no cause.
//
// Kept when the invocation did not complete, and when it completed while
// putting something in errors[] anyway. Never on a clean completed scan: the
// bytes travel in every consumer's evidence bundle, and a log on every run is
// a log nobody opens.
//
// The second case is the one this comment used to rule out. It claimed a
// completed scan's log is "tens of thousands of INFO lines about rules that
// behaved", which is true of a daemon that dumped its bootstrap log and false
// of a packaged api-scan's summary streams. A completed invocation can still
// carry an import failure, so completion alone must not discard its context.
//
// The motivating run parsed a small imported-URL count out of stderr and
// recorded an errors[] entry saying the declared endpoints were not reached,
// then discarded the very stream that could explain the failed import. Keep
// bounded tails when an error is already present, without retaining the
// consumer's measured counts or payload characteristics.
type zapLogTail struct {
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdoutTruncated,omitempty"`
	StderrTruncated bool   `json:"stderrTruncated,omitempty"`
}

// zapLogFor returns the log tail to record for an invocation, and nil when the
// scan completed clean or when neither stream said anything.
//
// errored is whether this invocation put anything in the envelope's errors[].
// The alternative was a measure of how much of the document was imported, and
// every such measure is a ratio needing a threshold nobody can defend. An
// error is a verdict cicd has already reached, for reasons it has already
// stated, and reading it costs no new number.
func zapLogFor(completed, errored bool, stdout, stderr string) *zapLogTail {
	if completed && !errored {
		return nil
	}
	so, soTrunc := tailBytes(stdout, zapLogTailBytes)
	se, seTrunc := tailBytes(stderr, zapLogTailBytes)
	if strings.TrimSpace(so) == "" && strings.TrimSpace(se) == "" {
		return nil
	}
	return &zapLogTail{Stdout: so, Stderr: se, StdoutTruncated: soTrunc, StderrTruncated: seTrunc}
}

// tailBytes returns the last n bytes of s and whether anything was dropped.
//
// The cut advances to the next line boundary, so the first line kept is a whole
// line. A tail that opens mid-token reads as corrupt output rather than as
// truncation, and a reader who cannot tell those apart is back where this file
// started. A tail holding no newline at all is returned as-is: one very long
// line is still the line that matters.
func tailBytes(s string, n int) (string, bool) {
	if n <= 0 || len(s) <= n {
		return s, false
	}
	cut := s[len(s)-n:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i+1 < len(cut) {
		cut = cut[i+1:]
	}
	return cut, true
}
