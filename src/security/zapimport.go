// Why ZAP refused an API document, in the one place that says so.
//
// A consumer's DAST leg reported every rule PASS against an API document
// declaring ~400 operations, and cicd's own reconciliation was the only thing
// that noticed: apiReachError said ZAP had requested none of the declared
// paths. It said nothing about why, and why was not recoverable from anything
// cicd kept. Both streams cicd captures were silent — the packaged scan logs
// the import's answer at logging.debug, which no normal run enables — so the
// evidence supported exactly one conclusion, "the scan reached nothing", and a
// reader had no way to tell an unroutable target from a document ZAP had
// thrown out before the scan began.
//
// Measured against the pinned image on that document (~800 KB, ~350
// paths, ~600 definitions): ZAP answered the import call HTTP 400, and its own
// log, and only its own log, carried
//
//	WARN  API - Bad request to API endpoint [/JSON/openapi/action/importUrl/] from [...]:
//	org.zaproxy.zap.extension.api.ApiException: BAD_EXTERNAL_DATA (The OpenAPI definition was invalid.)
//
// The packaged scan then carried on, because its own guard against an empty
// import — `if len(urls) == 0: raise NoUrlsException()` — was satisfied by the
// two URLs the -O host override had already put in the site tree. Two is not
// zero, so nothing raised, and a total import failure exited 0 with a report
// full of PASS.
//
// Deliberately untagged (no //go:build !unit_test).
package main

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// zapDaemonLogPath is where ZAP writes its own log inside the pinned
	// image.
	//
	// Measured, not assumed: the packaged scan and a bare `zap.sh -daemon`
	// both write /home/zap/.ZAP/zap.log. The scan's -dir is
	// /home/zap/.ZAP_D and holds its policies and scripts, which is the
	// plausible wrong answer.
	zapDaemonLogPath = "/home/zap/.ZAP/zap.log"
	// zapImportRejectPath is where zapRunScript leaves the rejection block.
	zapImportRejectPath = "/tmp/zap-import-reject.log"
	// zapImportRejectStatusPath holds the grep's exit status, so that "no
	// rejection" and "cicd could not look" stay different answers.
	zapImportRejectStatusPath = "/tmp/zap-import-reject.rc"
	// zapDaemonLevelsPath is where zapRunScript leaves every WARN and ERROR
	// header from ZAP's log.
	zapDaemonLevelsPath = "/tmp/zap-daemon-levels.log"
)

// zapImportRejectStatusNoLog is the status zapRunScript writes when ZAP's log
// is not where cicd expected it. It is outside grep's range (0 match, 1 no
// match, 2 error) on purpose, so the three real answers stay three.
//
// Spelled twice because zapRunScript is a Go constant and a function call
// cannot appear in one. TestNoLogStatusIsSpelledOnce holds the two spellings
// together; a pair that can drift is how the accepted-language set and its
// shell case statement drifted, which is why check_include_language_set exists.
const (
	zapImportRejectStatusNoLog     = 127
	zapImportRejectStatusNoLogText = "127"
)

// zapDaemonLevelsMaxLines bounds how many WARN/ERROR headers ride along.
//
// Measured in the pinned image: a scan of the same document that imported
// cleanly logged 27 of them, 25 from the importer naming attributes it had to
// guess at and 2 from the active scanner, and the count grows with the scan.
// 60 is headroom over that, and the lines are carried only on a run this file
// has already called an error — the rule the review settled, that an error is a
// verdict already reached and reading its context costs no new number.
const zapDaemonLevelsMaxLines = 60

// zapLineMaxBytes bounds one carried line. Counted over what is stored.
const zapLineMaxBytes = 2048

// zapImportAPIPathPattern matches the ZAP API endpoints that import an API
// description, one per format zap-api-scan.py accepts for -f.
//
// Matching ZAP's own API path and not the parser's complaint is deliberate.
// The path is the surface cicd already calls, so it cannot drift without
// breaking the call itself; the wording of a rejection belongs to whichever
// library upstream bundles this month. This file classifies *that* an import
// was refused. The reason is quoted verbatim and never parsed.
const zapImportAPIPathPattern = `/JSON/(openapi|soap|graphql)/action/import`

// zapImportProbe is what zapRunScript found out about the import.
type zapImportProbe struct {
	// Status is the grep's exit status: 0 a rejection was logged, 1 none
	// was, 2 or more the question could not be asked.
	Status int
	// Block is the rejection's log entry and the lines that explain it.
	Block string
	// Levels is every WARN/ERROR header line from ZAP's log.
	Levels string
}

// zapImportReport is what rides in the envelope, and only on a rejection.
type zapImportReport struct {
	// Rejected is the log entry ZAP wrote when it refused the document,
	// reduced to the lines that carry meaning: the header, the exception,
	// and each Caused by. Stack frames are dropped — they name ZAP's
	// internals, not the document's problem.
	Rejected []string `json:"rejected"`
	// DaemonLevels is every WARN/ERROR header ZAP logged. The sentence that
	// actually explains the rejection is regularly in a *different* entry
	// from the rejection itself: on the measured run the API entry said
	// only "The OpenAPI definition was invalid", while the parser had
	// already logged, four entries earlier, that the document exceeded its
	// input limit. Carrying one without the other names the symptom and
	// discards the cause.
	DaemonLevels []string `json:"daemonLevels,omitempty"`
	// DaemonLevelsTruncated is whether the cap dropped any of them.
	DaemonLevelsTruncated bool `json:"daemonLevelsTruncated,omitempty"`
}

// zapImportRejected is whether ZAP refused the document.
func zapImportRejected(p zapImportProbe) bool { return p.Status == 0 }

// zapImportProbeFailed is whether cicd could not ask the question.
//
// Separate from "no rejection" because they are opposite facts wearing the
// same face: an unfiltered log and an unreadable one both yield no match.
func zapImportProbeFailed(p zapImportProbe) bool { return p.Status > 1 }

// zapImportBuildReport reduces the probe to what the envelope carries, and
// returns nil when the document was not refused.
func zapImportBuildReport(p zapImportProbe) *zapImportReport {
	if !zapImportRejected(p) {
		return nil
	}
	r := &zapImportReport{Rejected: zapMeaningfulLines(p.Block)}
	lines := splitNonEmpty(p.Levels)
	if len(lines) > zapDaemonLevelsMaxLines {
		lines = lines[:zapDaemonLevelsMaxLines]
		r.DaemonLevelsTruncated = true
	}
	for _, l := range lines {
		r.DaemonLevels = append(r.DaemonLevels, truncateZAPLine(l))
	}
	return r
}

// zapLogEntryHeader matches the start of a ZAP log entry. Everything after one,
// up to the next, is that entry's continuation — a stack trace, usually.
//
// Anchored on the timestamp ZAP's own layout writes, which is the only part of
// a log line cicd can rely on: the level, the thread name and the logger all
// vary per entry, and a continuation line can begin with anything at all.
var zapLogEntryHeader = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} `)

// zapImportAPIPath matches the API endpoint whose rejection this file reports.
var zapImportAPIPath = regexp.MustCompile(zapImportAPIPathPattern)

// zapMeaningfulLines keeps a logged rejection's header, exception type and
// causes, and drops everything that is neither.
//
// Three things go, each for its own reason. A stack frame names a class inside
// ZAP and can only mislead a reader looking for something in their own
// document, while the Caused by chain is where the reason lives. grep's --
// group separators are the tool's punctuation, not content. And **an entry that
// is not itself a rejection goes too**, which is the one that had to be
// measured: zapRunScript asks grep for 30 lines of trailing context because a
// Java stack trace has no knowable length, and on the measured run the
// exception ended after 20 — so ten INFO entries about active scan rules
// behaving normally followed it into the block. A reader handed those would be
// reading the scan's routine progress under a heading that says the document
// was refused.
//
// So a header line survives only if it is one of the lines grep matched, and a
// continuation line survives only if the header above it did. That also keeps a
// *second* rejection whole, which stopping at the next header would not.
func zapMeaningfulLines(block string) []string {
	var out []string
	keeping := false
	for _, l := range strings.Split(block, "\n") {
		t := strings.TrimSpace(l)
		if zapLogEntryHeader.MatchString(t) {
			keeping = zapImportAPIPath.MatchString(t)
			if !keeping {
				continue
			}
		}
		if !keeping {
			continue
		}
		if t == "" || t == "--" || strings.HasPrefix(t, "at ") || strings.HasPrefix(t, "... ") {
			continue
		}
		out = append(out, truncateZAPLine(t))
	}
	return out
}

// splitNonEmpty splits on newlines and drops blank lines.
func splitNonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// truncateZAPLine bounds one line, counting over what is kept.
//
// The cut is walked back to a rune boundary. A log line carries a consumer's
// own path names, which are not all ASCII, and half a rune in the envelope is a
// replacement character in every reader downstream — the field would still say
// what happened, and the one word a reader was looking for would be broken.
func truncateZAPLine(s string) string {
	if len(s) <= zapLineMaxBytes {
		return s
	}
	cut := zapLineMaxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + " … [truncated]"
}

// zapImportError is the verdict: the document was handed to ZAP, ZAP would not
// take it, and so nothing this scan says describes the API the document names.
//
// An error and not a warning. The scan did run, which is the usual reason this
// repository warns instead — but it ran over a site tree the document never
// entered, and a run whose entire input was discarded has produced no result
// to grade. The remedy is the consumer's too, not upstream's: the document is
// theirs, and cicd hands back the reason it was given.
func zapImportError(r *zapImportReport) string {
	if r == nil {
		return ""
	}
	msg := "dast: API DOCUMENT REFUSED — ZAP rejected the API document it was given, " +
		"so no endpoint the document declares entered this scan and these findings " +
		"describe only what the target served without it. " +
		"The packaged scan does not fail on this: its guard is an empty site tree, " +
		"and --hostname had already seeded the tree, so the scan ran and exited 0"
	if reason := strings.Join(r.Rejected, " | "); reason != "" {
		msg += ". ZAP's log: " + reason
	}
	return msg
}

// zapImportProbeWarning fires when cicd could not read ZAP's log.
//
// A warning, not an error: the scan itself is unaffected, and the rest of the
// envelope stands on its own. But it is said out loud, because a silent probe
// and a clean import are the same silence, and this file exists because those
// two were once indistinguishable.
func zapImportProbeWarning(p zapImportProbe) string {
	if !zapImportProbeFailed(p) {
		return ""
	}
	why := "exit status " + strconv.Itoa(p.Status)
	if p.Status == zapImportRejectStatusNoLog {
		why = "the log was not at " + zapDaemonLogPath
	}
	return "dast: IMPORT LOG UNREAD — cicd could not search ZAP's own log for a " +
		"rejected API document (" + why + "), so a document ZAP refused would not " +
		"appear in this envelope. Everything else here is unaffected"
}
