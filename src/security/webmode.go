// Scan-mode policy for the DAST leg: which packaged ZAP scan a mode selects,
// which arguments it gets, and how an API document is turned into a denominator.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The three scan modes.
//
// This is a string and not the bool it replaces for two reasons. A bool cannot
// carry three values; and a bool is the one parameter type Dagger's generated
// Go client cannot transmit as false — it drops any optional argument holding
// its zero value, which make-the-intent-gate-opt-in measured the hard way — so
// a two-valued knob that must be settable in both directions cannot be one.
const (
	webModeBaseline = "baseline"
	webModeAPI      = "api"
	webModeFull     = "full"
)

// The API document formats zap-api-scan.py accepts for -f.
var webAPIFormats = []string{"openapi", "soap", "graphql"}

// zapProxyPort is the port ZAP's own proxy listens on inside the scan
// container, pinned with -P rather than drawn.
//
// Read the correction first, because this constant was introduced on a
// diagnosis that turned out to be wrong. The BindException it was written to
// stop —
//
//	WARN  ExtensionNetwork - Failed to start the main proxy: java.net.BindException Address already in use
//	ERROR CommandLine      - Terminating ZAP, unable to start the main proxy.
//
// — came back *with* -P 8090 demonstrably on the command line, and the reason is
// in zapaddons.go: the packaged scan was hot-upgrading the `network` add-on,
// which owns the main proxy, inside the running daemon. ZAP collided with its
// own outgoing listener. No third party was involved, and no choice of port
// could have prevented it. `-silent` is what fixes that, not this.
//
// The claim in specs/stop-losing-the-port-race.md that 8090 is "not a default
// anything else here reaches for" was wrong twice over, and the second half is
// worth keeping in view: the pinned image reserves 8090 in three places for
// ZAP-under-Webswing (/zap/webswing/admin/jetty.properties,
// /zap/webswing/webswing.config, and /zap/zap-webswing.sh, which starts ZAP
// itself with `-host 0.0.0.0 -port 8090`). None of them runs here — Webswing is
// reachable only through `zap-webswing.sh run`, which cicd never invokes — so
// the port stays, but it stays as a port nothing on cicd's path uses, not as a
// port nothing in the image knows about.
//
// What -P still buys, unmeasured but real: left unset, zap_common.py picks the
// port like this —
//
//	def get_free_port():
//	    while True:
//	        port = randint(32768, 61000)
//	        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
//	        if not (sock.connect_ex(('127.0.0.1', port)) == 0):
//	            return port
//
// It draws a random number, asks whether anything answers on it *at that
// instant*, and returns it. Nothing is ever bound, so nothing is reserved — and
// 32768-61000 is the kernel's own ephemeral range in this image, the pool every
// outbound connection and every bind-to-zero service draws from, including the
// OAST add-on's callback service ("Started callback service on 0.0.0.0:35627").
// A port below 32768 cannot be drawn by that loop and is never handed out as an
// ephemeral port, so the gap between probe and bind stops being a gap. That race
// has never been observed here; it is closed on principle, and this comment no
// longer claims it was ever the one that bit.
//
// All three packaged scans declare P: in their getopt string — unlike --autooff,
// this one is universal.
const zapProxyPort = 8090

// zapScript returns the packaged scan a mode selects.
//
// No default arm that guesses: an unrecognised mode is an error before any
// container starts, because the alternative is a scan that silently ran a
// weaker analysis than the one that was asked for, and a baseline report is
// indistinguishable from a full one that found nothing.
func zapScript(mode string) (string, error) {
	switch strings.TrimSpace(mode) {
	case webModeBaseline:
		return "zap-baseline.py", nil
	case webModeAPI:
		return "zap-api-scan.py", nil
	case webModeFull:
		return "zap-full-scan.py", nil
	default:
		return "", fmt.Errorf("zap: unknown --mode %s: expected one of %s",
			strconv.Quote(mode), strings.Join([]string{webModeBaseline, webModeAPI, webModeFull}, ", "))
	}
}

// validateAPIFormat rejects a -f value zap-api-scan.py would not accept. ZAP
// exits non-zero on an unknown format, which zapRunError would classify as a
// non-run — correct, but a long way round to a typo.
func validateAPIFormat(format string) error {
	f := strings.TrimSpace(format)
	for _, ok := range webAPIFormats {
		if f == ok {
			return nil
		}
	}
	return fmt.Errorf("zap: unknown --api-format %s: expected one of %s",
		strconv.Quote(format), strings.Join(webAPIFormats, ", "))
}

// zapOptions is everything the invocation needs that is not the image itself.
type zapOptions struct {
	Mode string
	// TargetURL is the base URL of the running application, already resolved
	// from whichever of the three sources was supplied.
	TargetURL string
	// APITarget is what -t receives in api mode: either the container path of a
	// mounted spec file, or a URL the target serves the document on.
	APITarget string
	APIFormat string
	// RuleConfigPath is the container path of a mounted ZAP rule config (-c),
	// empty when the consumer supplied none.
	RuleConfigPath string
	// MaxDurationMinutes is the budget for ZAP to start up and for its passive
	// scan to finish (-T). It does not cap the whole scan: the packaged scans
	// document -T as "max time in minutes to wait for ZAP to start and the
	// passive scan to run", and the active scan is not on that clock. Zero
	// passes no -T, which is not "no budget" — see
	// zapStartAndPassiveBudgetSeconds.
	MaxDurationMinutes int
	// ReportPath is where the JSON report is written (-J).
	ReportPath string
	// HookPath is the container path of the custom Python hook module that
	// dumps ZAP's site tree (--hook), empty when no dump is wanted.
	HookPath string
}

// zapArgs builds the argument list for the packaged scan, after the script name.
//
// Every value is returned as a separate element and passed to the container as
// a positional argument, never spliced into the shell script — the same rule
// semgrepConfigFlags follows, and for the same reason: a target URL is a
// consumer value, and a consumer value that becomes shell text is a way to run
// something other than a scan.
func zapArgs(opts zapOptions) ([]string, error) {
	if strings.TrimSpace(opts.ReportPath) == "" {
		return nil, errors.New("zap: no report path")
	}

	var target string
	switch strings.TrimSpace(opts.Mode) {
	case webModeAPI:
		if err := validateAPIFormat(opts.APIFormat); err != nil {
			return nil, err
		}
		if strings.TrimSpace(opts.APITarget) == "" {
			return nil, errors.New("zap: --mode api needs an API document: pass --api-spec (a file) or --api-spec-path (a path the target serves it on)")
		}
		// In api mode -t is the *document*, not the application, which is the
		// one place ZAP's packaged scans change the meaning of their own
		// primary argument. The application is named separately with -O, so a
		// spec whose servers[] block points at localhost still gets scanned
		// where the app actually runs.
		target = opts.APITarget
	default:
		if strings.TrimSpace(opts.TargetURL) == "" {
			return nil, errors.New("zap: no target URL")
		}
		target = opts.TargetURL
	}

	args := []string{"-t", target, "-J", opts.ReportPath}
	// A port chosen rather than drawn. Not the fix for the BindException this
	// leg actually hit — see zapProxyPort for the correction — but it closes a
	// real race in get_free_port() that nothing else here closes.
	args = append(args, "-P", strconv.Itoa(zapProxyPort))
	if strings.TrimSpace(opts.Mode) == webModeAPI {
		args = append(args, "-f", strings.TrimSpace(opts.APIFormat))
		if u := strings.TrimSpace(opts.TargetURL); u != "" {
			args = append(args, "-O", u)
		}
	}
	if p := strings.TrimSpace(opts.RuleConfigPath); p != "" {
		args = append(args, "-c", p)
	}
	// --hook loads a Python module that reads ZAP's site tree out before the
	// daemon stops; see zapurls.go for what it does and why it cannot fail the
	// scan. All three packaged scans accept it — measured on the pinned image,
	// each declares "hook=" in its getopt long list and each triggers
	// zap_tuned, zap_pre_shutdown and pre_exit.
	//
	// One interaction, in baseline only: zap-baseline.py answers --hook by
	// marking the Automation Framework unsupported for this run
	// (add_af_unsupported at line 350). That is the same thing --autooff is
	// passed for, so the two agree rather than conflict, and a baseline run
	// with both was measured ending exit 0 with a complete dump. If --autooff
	// is ever dropped, this flag will still be turning the framework off.
	if p := strings.TrimSpace(opts.HookPath); p != "" {
		args = append(args, "--hook", p)
	}
	if opts.MaxDurationMinutes > 0 {
		args = append(args, "-T", strconv.Itoa(opts.MaxDurationMinutes))
	}
	// -I: do not fail the process over WARN-level rules. The gate is cicd's,
	// applied to severity counts through gatedPassed, so ZAP's own pass/fail
	// opinion must not pre-empt --fail-on. It still exits 1 on a FAIL rule,
	// which zapRunError treats as a result and not a non-run. All three
	// packaged scans accept it.
	args = append(args, "-I")
	// --autooff is baseline's alone, and passing it to either of the others is
	// a non-run rather than a slower scan: zap-api-scan.py exits 3 with
	// "Invalid option autooff" before it opens a socket. Measured on the pinned
	// image — only zap-baseline.py has the automation framework at all (17
	// references against 0 in the other two), so only it declares --autooff in
	// its getopt long list, and only it has anything to opt out of.
	//
	// Why baseline needs it: the framework writes zap.yaml into /zap/wrk, which
	// is a tmpfs mounted for the -J check and not writable by the image's
	// non-root user, so with the framework on ZAP dies with a PermissionError
	// before scanning anything.
	if strings.TrimSpace(opts.Mode) == webModeBaseline {
		args = append(args, "--autooff")
	}
	// -z "-silent": the single most consequential flag on this line.
	//
	// Without it every packaged scan starts ZAP with -addonupdate and
	// -addoninstall pscanrulesBeta, which downloads dozens of add-ons from the
	// marketplace before the scan begins — 73 on the measured run — including a
	// replacement for the add-on that owns the main proxy, whose reload races
	// the socket the daemon is still holding. It also makes the image digest
	// nearly meaningless: the rules that run are whatever the marketplace serves
	// that day, not what the pin names.
	//
	// The six passive rules -silent costs are put back from a pinned artifact
	// instead, verified by digest in zapRunScript, so the rule set is the same
	// one and now the pin decides it. zapaddons.go carries the measurements.
	//
	// Last, so that nothing after it can be mistaken for part of the -z value:
	// add_zap_options runs shlex.split over this single argument and appends the
	// results, and the packaged scans test for the literal string "-silent" in
	// it, which is why this travels through -z and not as a flag of its own.
	args = append(args, "-z", zapSilentOption)
	return args, nil
}

// countOpenAPIOperations returns the number of operations an OpenAPI document
// declares — the real denominator for an api-mode scan, and the only scope
// number in this module that is not a floor.
//
// A document it cannot read yields (0, error). The caller warns rather than
// failing the scan: an unreadable spec that ZAP nonetheless accepted is a gap
// in cicd's accounting, not in the scan.
func countOpenAPIOperations(raw []byte) (int, error) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("parse OpenAPI document: %w", err)
	}
	if doc.Paths == nil {
		return 0, errors.New("parse OpenAPI document: no paths object")
	}
	methods := map[string]bool{
		"get": true, "put": true, "post": true, "delete": true,
		"options": true, "head": true, "patch": true, "trace": true,
	}
	n := 0
	for _, item := range doc.Paths {
		for key := range item {
			if methods[strings.ToLower(key)] {
				n++
			}
		}
	}
	return n, nil
}

// openAPIPaths lists the paths a document declares, sorted. Used only for the
// evidence, so a reader can see which surface the denominator counted.
func openAPIPaths(raw []byte) []string {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// zapStartAndPassiveBudgetSeconds is the -T the packaged scan will run under,
// in seconds, given the minutes cicd passes it.
//
// Zero minutes means cicd passes no -T at all, and the value that then applies
// is not unlimited: zap_common.wait_for_zap_start falls back to 600 seconds,
// and zap_api_scan passes the same zero on to the passive-scan wait. Measured
// in the pinned image, zaproxy 2.17.0:
//
//	def wait_for_zap_start(zap, timeout_in_secs = 600):
//	    if not timeout_in_secs:
//	        # if ZAP doesn't start in 10 mins then its probably not going to start
//	        timeout_in_secs = 600
//
// A consumer who names no duration is therefore running against a ten-minute
// clock chosen by ZAP, which is exactly the number cicd's own dast smoke spent
// waiting for a daemon that had already logged its own termination. The number
// is reported rather than changed: lowering it would shorten the passive scan
// too, and a passive scan that runs out of budget reports partial coverage as
// complete. See startAndPassiveBudgetWarning.
func zapStartAndPassiveBudgetSeconds(maxDurationMinutes int) int {
	if maxDurationMinutes > 0 {
		return maxDurationMinutes * 60
	}
	return zapDefaultStartAndPassiveBudgetSeconds
}

// zapDefaultStartAndPassiveBudgetSeconds is what ZAP applies when given no -T.
const zapDefaultStartAndPassiveBudgetSeconds = 600
