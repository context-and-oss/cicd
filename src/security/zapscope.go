// How much of the target ZAP actually reached, read from the packaged scan's
// own output — and the per-rule alert cap that makes a finding list a floor.
//
// The envelope used to carry two numbers that look like scope and are not.
// urlsWithAlerts counts the URLs that produced an alert, so it is bounded by
// the findings rather than by the scan; endpointsFromSpec counts what the API
// document declared, which is what cicd asked for and never what ZAP did. A
// run of a consumer's API published both — under twenty alerted URLs beside a
// ~400-operation document — and neither said that ZAP had requested a handful
// of swagger URLs and none of the API. The number that settles it was printed
// by the scan on both runs and thrown away: cicd captured stdout and stderr
// and read them only on the failure path.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// which is the condition under which a parser can be tested against a captured
// log at all. web.go, where the streams are read, cannot be.
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// zapExaminedUnit names what the count in Examined counts.
//
// "URLs requested" and not "endpoints" or "URLs scanned": the number is the
// size of ZAP's sites tree when the scan ended, and that tree is built from
// messages that went through the proxy. So it is what ZAP asked the target
// for, which is neither the set of endpoints that exist nor a statement that
// each was scanned by every rule.
const zapExaminedUnit = "URLs requested"

// zapPassiveAlertCapPerRule is how many alerts the packaged scans let each
// passive scan rule raise before it stops raising them.
//
// Measured in the pinned image (zap_common.py, zaproxy 2.17.0):
//
//	def zap_tune(zap):
//	    logging.debug('Tune')
//	    logging.debug('Disable all tags')
//	    zap.pscan.disable_all_tags()
//	    logging.debug('Set max pscan alerts')
//	    zap.pscan.set_max_alerts_per_rule(10)
//
// and zap_tune is called unconditionally by all three packaged scans
// (zap-api-scan.py:407, zap-baseline.py:557, zap-full-scan.py:333). There is
// no flag that disables it and cicd passes none, so every ScanWeb run is
// capped. It is recorded in the payload rather than left as a constant here
// because a pin bump can move it, and an envelope whose reader has to know
// which image produced it is an envelope that cannot be read later.
const zapPassiveAlertCapPerRule = 10

// zapScope is what the packaged scan said about its own reach, at the two
// moments it says anything.
//
// Both are pointers, and the distinction is the point: absent means the scan
// printed no such line, which is a different fact from a line saying zero. A
// zero that came from a missing line is cicd inventing a measurement.
type zapScope struct {
	// Imported is the size of ZAP's sites tree immediately after the API
	// document was imported — zap-api-scan.py's "Number of Imported URLs: N".
	//
	// It is not the number of operations the document declared and not the
	// number the import added: the line logs len(zap.core.urls()) over the
	// whole tree, which already holds the target seed. Only api mode prints
	// it, and only for the openapi and soap formats; the graphql branch logs a
	// request count instead and is left absent rather than approximated.
	Imported *int
	// Requested is the size of that tree when the scan ended — the packaged
	// scans' "Total of N URLs", printed by all three.
	Requested *int
}

var (
	// zapImportedURLsPattern matches the import line. The log carries a
	// timestamp prefix (logging.basicConfig with '%(asctime)s %(message)s'),
	// so the pattern is deliberately unanchored at the left.
	zapImportedURLsPattern = regexp.MustCompile(`Number of Imported URLs:\s*(\d+)`)
	// zapTotalURLsPattern matches the end-of-scan line, which is a bare
	// print() and so carries no prefix at all. Anchored both ends, because an
	// unanchored "Total of (\d+) URLs" would also match the same words inside
	// a longer sentence a future release might log.
	zapTotalURLsPattern = regexp.MustCompile(`(?m)^[ \t]*Total of[ \t]+(\d+)[ \t]+URLs[ \t]*\r?$`)
)

// zapNoURLsNotice is what the packaged scans log instead of the total when the
// sites tree is empty:
//
//	num_urls = len(zap.core.urls())
//	if num_urls == 0:
//	    logging.warning('No URLs found - is the target URL accessible? ...')
//	else:
//	    if detailed_output:
//	        print('Total of ' + str(num_urls) + ' URLs')
//
// So zero is the one value the total line cannot carry, and reading only that
// line would make the most important measurement the one that is always
// absent — exactly the shape where an absent count gets read as "no claim"
// about a scan that reached nothing.
const zapNoURLsNotice = "No URLs found - is the target URL accessible?"

// parseZAPScope reads the scope counts out of an invocation's two streams.
//
// Both streams are searched for both patterns rather than each pattern being
// bound to the stream it was measured on. Which file a line lands in is a
// property of the packaged scan's logging configuration — the total is a
// print() to stdout, the import line is logging.info to stderr — and that is
// not a fact about the scan worth encoding twice. The two patterns share no
// vocabulary, so searching both cannot confuse them.
//
// What it cannot see is stated rather than guessed at. `-s` sets
// detailed_output False and suppresses the total line; cicd passes no `-s`,
// but a consumer rule config cannot add one either, so the only way the line
// goes missing is a change in the pinned image — which is why an unreadable
// scope is disclosed as unreadable instead of defaulting to anything.
func parseZAPScope(stdout, stderr string) zapScope {
	both := stdout + "\n" + stderr

	var out zapScope
	if n, ok := lastCapturedInt(zapImportedURLsPattern, both); ok {
		out.Imported = &n
	}
	if n, ok := lastCapturedInt(zapTotalURLsPattern, both); ok {
		out.Requested = &n
	} else if strings.Contains(both, zapNoURLsNotice) {
		zero := 0
		out.Requested = &zero
	}
	return out
}

// lastCapturedInt returns the integer in the last match of re, if any.
//
// The last and not the first: zap-api-scan.py logs the import line once per
// import branch it takes, and a future release logging a second one after a
// retry would make the first a stale reading of a tree that has since grown.
// The final statement is the one that describes the scan that ran.
func lastCapturedInt(re *regexp.Regexp, s string) (int, bool) {
	m := re.FindAllStringSubmatch(s, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(m[len(m)-1][1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// zapExamined states how much this scan looked at, in the one field that
// survives aggregation into combined-evidence.json's sources[] and reaches the
// tool table in the PR comment. Nil when the scan did not say, so the cell
// reads "not stated" rather than a zero nobody measured.
//
// Total is deliberately left unset even in api mode, where endpointsFromSpec
// is sitting right there. Examined.Total is "how many units existed in scope",
// in the SAME unit as Count, and an operation is not a URL: ~400 operations
// across roughly 230 paths would render as "N of 400 URLs requested", which is
// a ratio between two different things and reads as a coverage percentage. The
// pair is stated side by side in the API SCAN disclosure instead, where the
// sentence can say they are not comparable.
func zapExamined(requested *int) *Examined {
	if requested == nil {
		return nil
	}
	return &Examined{Unit: zapExaminedUnit, Count: *requested}
}

// rulesAtAlertCap names every rule that raised exactly as many alerts as the
// packaged scan allows one rule to raise.
//
// A rule at the cap stopped reporting rather than ran out of things to report,
// so its share of the finding list is a floor and the URLs it would have named
// next are absent from evidence that otherwise reads as complete. Equality and
// not >=, because the cap is enforced by ZAP and a count above it would mean
// the cap is not what this build thinks it is — reporting that as "at the cap"
// would hide the more interesting fact.
//
// It names rules and never claims they were truncated. The cap applies to
// passive scan rules, ZAP's JSON report carries no field saying which rules
// are passive, and a rule can legitimately find exactly ten of something. So
// the list is the set of rules where the question arises; the disclosure says
// the rest.
func rulesAtAlertCap(alertsByRule map[string]int, limit int) []string {
	if limit <= 0 || len(alertsByRule) == 0 {
		return nil
	}
	at := map[string]bool{}
	for rule, n := range alertsByRule {
		if n == limit {
			at[rule] = true
		}
	}
	return sortedKeys(at)
}
