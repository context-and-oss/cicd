// The dast/1.0 evidence payload, and the disclosures a running-app scan owes
// its reader.
//
// A DAST scan against an application started in a non-production profile is an
// application-layer regression detector, not a security attestation of the
// deployed system. That sentence is the whole reason this file exists: without
// it, a green envelope is read as the second thing, and the difference is
// invisible from every field in the schema.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// dastReportFormat is the genericFormat this module stamps.
//
// It replaces "zap-json". The payload is now a document cicd owns, with ZAP's
// alert report nested under zapReport, because the scope, readiness and
// suppression facts have nowhere else to live: putting them on the envelope
// would mean widening schema.go and its fourteen verbatim copies for one leg's
// metadata. Request and response captures are deliberately omitted from that
// nested report; they are unbounded, duplicate the normalized findings, and
// can prevent the evidence artifact itself from being exported.
const dastReportFormat = "dast/1.0"

// readinessResult is what the probe found, recorded whether or not it
// succeeded.
//
// It is a fact in the evidence and not merely a precondition, because the
// failure it guards against is silent: an application that never came up
// produces a ZAP report with no alerts, which is byte-for-byte the shape of a
// clean scan. A reader must be able to tell those apart without rerunning
// anything.
type readinessResult struct {
	URL           string `json:"url"`
	Status        int    `json:"status,omitempty"`
	Attempts      int    `json:"attempts"`
	WaitedSeconds int    `json:"waitedSeconds"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
}

// dastPayload is the genericReport document for a running-app scan.
type dastPayload struct {
	Mode      string `json:"mode"`
	Source    string `json:"source"`
	TargetURL string `json:"targetUrl"`

	// Profile is the consumer's name for the configuration the application ran
	// under ("Staging", "Development"). Recorded, never interpreted — cicd
	// has no way to check the claim and does not pretend to.
	Profile string `json:"profile,omitempty"`
	// Authenticated is whether the scan exercised a real login.
	Authenticated bool `json:"authenticated"`

	Readiness readinessResult `json:"readiness"`

	// URLsWithAlerts is a floor on coverage, not a measure of it. See
	// zapParsed.URLsWithAlerts.
	URLsWithAlerts int `json:"urlsWithAlerts"`
	// URLsRequested is how many URLs ZAP held when the scan ended, taken from
	// the packaged scan's own "Total of N URLs". It is the closest thing to a
	// reach measurement this leg has, and unlike URLsWithAlerts it does not
	// shrink when the target is clean. A pointer, because the scan not saying
	// and the scan saying zero are different facts. See zapScope.
	URLsRequested *int `json:"urlsRequested,omitempty"`
	// URLsImported is the same tree measured immediately after the API
	// document was imported — api mode only. It is what separates "ZAP read
	// the document and requested what it declared" from "ZAP read the document
	// and got nothing out of it", which endpointsFromSpec cannot, because that
	// number is cicd's reading of the document and not ZAP's.
	URLsImported *int `json:"urlsImported,omitempty"`
	// EndpointsFromSpec is the operation count of the API document, present
	// only in api mode where a real denominator exists. A pointer, so "the
	// document declared no operations" and "there was no document" are
	// different values rather than the same zero.
	EndpointsFromSpec *int     `json:"endpointsFromSpec,omitempty"`
	APIPaths          []string `json:"apiPaths,omitempty"`
	// APIReach is the reconciliation of those declared paths against the URLs
	// ZAP actually requested. Nil means no reconciliation happened — not api
	// mode, no readable document, or cicd could not read ZAP's site tree — and
	// in the last of those a warning says so. See apiReachReport.
	APIReach *apiReachReport `json:"apiReach,omitempty"`

	RuleSettings []zapRuleSetting `json:"ruleSettings,omitempty"`

	// PassiveAlertCapPerRule is the number of alerts the packaged scan allowed
	// each passive rule to raise. Recorded on every completed scan because the
	// cap is a property of the pinned image rather than of anything a reader
	// can see in the report, and an envelope that cannot be re-read after a
	// pin bump is an envelope with a shelf life.
	PassiveAlertCapPerRule int `json:"passiveAlertCapPerRule,omitempty"`
	// RulesAtAlertCap lists the rules that raised exactly that many alerts,
	// sorted. See rulesAtAlertCap for why this is a question and not a verdict.
	RulesAtAlertCap []string `json:"rulesAtAlertCap,omitempty"`

	ScanDurationSeconds int `json:"scanDurationSeconds"`
	// ZapExitCode is recorded because ZAP's exit codes carry information the
	// alert list does not — and because throwing it away is the defect this
	// work exists to fix.
	ZapExitCode int `json:"zapExitCode"`

	// ScanCompleted is whether ZAP ran and left a report cicd could parse.
	//
	// The alert list cannot answer that question, and neither can any other
	// field here. A ZAP that died during startup and a target with nothing to
	// find both produce zero alerted URLs, and Readiness is OK in both: the
	// probe runs before ZAP and succeeded either way. This flag is the only
	// thing separating them, which is why the disclosure below reads it and
	// not the probe.
	ScanCompleted bool `json:"scanCompleted"`

	// StartAndPassiveBudgetSeconds is the wall clock ZAP was given to start up
	// and to finish passive scanning — the packaged scans' -T, in seconds.
	//
	// Recorded on every scan because exceeding it is invisible everywhere else,
	// including in ZAP's own report. See startAndPassiveBudgetWarning for why
	// it is a field on every run and a warning on only some of them.
	StartAndPassiveBudgetSeconds int `json:"startAndPassiveBudgetSeconds,omitempty"`
	// StartAndPassiveBudgetDefaulted is whether that number came from ZAP
	// rather than from the consumer — true when no --max-duration-minutes was
	// given and ZAP applied its own 600 seconds.
	StartAndPassiveBudgetDefaulted bool `json:"startAndPassiveBudgetDefaulted,omitempty"`

	// ZapLog is the tail of ZAP's two output streams, kept when the scan did
	// not complete and when it completed while recording an errors[] entry
	// anyway. See zapLogTail.
	ZapLog *zapLogTail `json:"zapLog,omitempty"`

	// APIImport is ZAP's own account of refusing the API document, present
	// only when it refused one. See zapImportReport.
	APIImport *zapImportReport `json:"apiImport,omitempty"`

	// PassiveRuleAddOn is whether the pinned pscanrulesBeta artifact loaded:
	// one of zapAddOnStatusOK, zapAddOnStatusMissing, zapAddOnStatusMismatch.
	//
	// A field on every scan and not only on the unhappy answers, for the
	// reason StartAndPassiveBudgetSeconds is: the rule set a scan ran is part
	// of what its finding count measures, and two envelopes whose counts
	// differ are only comparable if each says which rules were loaded. The
	// warning and the error live in zapaddons.go; this is the value they were
	// derived from, kept so a reader need not re-derive it from prose.
	PassiveRuleAddOn string `json:"passiveRuleAddOn,omitempty"`

	// ZapReport is ZAP's alert report with unbounded request, response and
	// evidence captures removed. The normalized envelope findings remain the
	// authoritative actionable rows.
	ZapReport json.RawMessage `json:"zapReport,omitempty"`
}

// webDisclosureWarnings states what this scan did not, or could not, test.
//
// Every line here is a warning and never an error: nothing failed to run, so
// none of it may clear `ran`. The non-run cases — an unreachable target, a ZAP
// that died — are errors[] entries produced elsewhere, and gatedPassed keeps
// the two apart.
//
// Which lines are emitted on every run and which stay silent is a deliberate
// choice per line, following name-the-version-file-cicd-could-not-use rather
// than dotnetLegScopeWarning: silence is kept where an absence is itself the
// answer, and a line is emitted where every run is in the same position and an
// absence would carry nothing.
func webDisclosureWarnings(p dastPayload, threshold Severity, unknownRiskCodes []string) []string {
	var out []string

	// ZAP's maximum risk is High. A CRITICAL threshold is therefore a gate that
	// cannot fail over findings — the same envelope a passing gate produces,
	// with no field separating them. A warning and not an error, because the
	// value is legal at every other cicd entry point and refusing it only here
	// would be a surprise; but never silent.
	if threshold == SeverityCritical {
		out = append(out, "dast: THRESHOLD UNREACHABLE — ZAP's maximum risk rating is High, "+
			"so no finding this scan can produce will ever fail --fail-on CRITICAL. Use HIGH.")
	}

	// Provenance. The container source is silent, which is what makes the
	// warning informative: its absence means cicd built and started the thing
	// it scanned.
	if p.Source == webSourceURL || p.Source == webSourceService {
		out = append(out, "dast: PROVENANCE NOT ATTESTED — the application was started outside cicd, "+
			"so this evidence records the commit that triggered the run and cannot show the running code was built from it.")
	}

	// Authentication is a choice, and both of its values are worth stating —
	// but only the unauthenticated one changes what the findings mean, so only
	// it is emitted.
	if !p.Authenticated {
		out = append(out, "dast: NOT AUTHENTICATED — the scan exercised no login, "+
			"so every authorisation and access-control rule reports on the anonymous surface only.")
	}

	// A profile is a claim the consumer made. An unset profile is a consumer
	// who made no claim, and inventing a caveat about it would be noise on
	// every run of every repository.
	if pr := strings.TrimSpace(p.Profile); pr != "" {
		out = append(out, "dast: PROFILE "+pr+" — the application ran under a non-production configuration; "+
			"transport security, security headers and error verbosity are properties of the deployed ingress and were not tested here.")
	}

	switch p.Mode {
	case webModeBaseline:
		out = append(out, "dast: BASELINE ONLY — passive scan; no attack payload was sent, "+
			"so injection, traversal and deserialisation rules did not run.")
	case webModeAPI:
		out = append(out, apiScanWarning(p))
	}

	out = append(out, startAndPassiveBudgetWarning(p)...)
	out = append(out, scopeUnreadWarning(p)...)
	out = append(out, alertCapWarning(p)...)

	// A successful scan that produced no alert URL at all. Not an error — a
	// genuinely clean target produces it — but the readiness status belongs
	// beside it, because that pair is what separates "nothing to find" from
	// "nothing was reached".
	//
	// Gated on ScanCompleted and not on Readiness.OK. The probe runs before
	// ZAP and passes in both of the cases this line exists to tell apart, so
	// reading it here made the sentence "the scan completed and no URL
	// produced an alert" appear in the same comment.md as "zap: did not run
	// (exit 3)" — cicd's own dast smoke, on main, printed both.
	if p.ScanCompleted && p.URLsWithAlerts == 0 {
		out = append(out, "dast: NO ALERTED URL — the scan completed and no URL produced an alert. "+
			"The readiness probe answered "+strconv.Itoa(p.Readiness.Status)+" at "+p.Readiness.URL+
			", so the target was reachable; ZAP's report does not enumerate the URLs it visited and found nothing on.")
	}

	if len(unknownRiskCodes) > 0 {
		out = append(out, "dast: UNKNOWN RISK CODE — the report carried risk code(s) "+
			strings.Join(unknownRiskCodes, ", ")+" that ZAP does not document; they are counted as MEDIUM rather than dropped.")
	}

	return append(out, ruleConfigWarnings(p.RuleSettings)...)
}

// apiScanWarning states the bound an api-mode scan ran under, and both of the
// numbers a reader needs to judge whether it held.
//
// The sentence this replaces said "only the N operation(s) the API document
// declares were requested", which asserts something cicd had not checked and
// which a real run falsified: ZAP's own log said it ended the scan holding
// only API-document URLs rather than the application's declared endpoints.
// The envelope paired the declared operation count with a small alert count
// and read as a scan of the API despite not reaching those endpoints.
//
// So the claim is narrowed to the one thing that is true by construction — the
// document is the scan's upper bound — and the two measurements are printed
// beside each other, cicd's reading of the document and ZAP's reading of its
// own tree. They are deliberately NOT reconciled here: an operation is a
// method on a path and a URL is a path, so they differ on a healthy run, and
// turning the gap into a verdict needs a comparison this change does not make.
// Stating the pair is what lets a reader ask the question at all.
func apiScanWarning(p dastPayload) string {
	msg := "dast: API SCAN — the scan is bounded by the API document, " +
		"so anything the application serves that the document omits was not scanned."
	switch {
	case p.EndpointsFromSpec != nil && p.URLsRequested != nil:
		msg += " cicd read " + strconv.Itoa(*p.EndpointsFromSpec) + " operation(s) in the document, " +
			"and ZAP's log says it finished holding " + strconv.Itoa(*p.URLsRequested) + " URL(s)"
		if p.URLsImported != nil {
			msg += " (" + strconv.Itoa(*p.URLsImported) + " of them present the moment the document was imported)"
		}
		msg += ". The two count different things — an operation is a method on a path, a URL is a path — " +
			"so cicd does not reconcile them and a gap between them is a question for the reader, not a verdict."
	case p.EndpointsFromSpec != nil:
		msg += " cicd read " + strconv.Itoa(*p.EndpointsFromSpec) + " operation(s) in the document; " +
			"ZAP's log did not say how many URLs it ended up requesting, so there is nothing to compare that against."
	case p.URLsRequested != nil:
		msg += " ZAP's log says it finished holding " + strconv.Itoa(*p.URLsRequested) + " URL(s); " +
			"cicd could not count the document's operations, so that number has no denominator here."
	}
	return msg
}

// scopeUnreadWarning fires when a scan completed and said nothing cicd could
// read about how far it got.
//
// The packaged scans print "Total of N URLs" on stdout on every run — the only
// switch that suppresses it is -s, which cicd never passes and a consumer rule
// config cannot add — so on the pinned image this line is unreachable. It is
// here because the alternative to a disclosure is an envelope with no examined
// count, and an absent count is indistinguishable from a producer that has not
// been converted. If a pin bump moves the log format, this says so in the
// comment instead of quietly reverting the leg to "not stated".
//
// Silent unless the scan completed: a scan that did not run has an errors[]
// entry saying so, and reporting that its log was unreadable as well would
// describe the same silence twice.
func scopeUnreadWarning(p dastPayload) []string {
	if !p.ScanCompleted || p.URLsRequested != nil {
		return nil
	}
	return []string{"dast: SCOPE NOT READ — the scan completed and cicd found no URL count in either of ZAP's " +
		"output streams, so this envelope states no denominator for what was reached. The packaged scans print " +
		"\"Total of N URLs\" on stdout unless -s is passed, which cicd does not, so a missing line means the log " +
		"format moved with the pinned image (zaproxy " + zapVersion + ")."}
}

// alertCapWarning names the rules sitting exactly on the packaged scan's
// per-rule alert cap.
//
// The cap is the quietest way this leg can under-report. zap_tune calls
// pscan.set_max_alerts_per_rule(10) on every run of all three packaged scans,
// unconditionally, and a rule that hits it simply stops raising alerts: the
// report is valid, the exit status is unchanged, the finding list is complete
// as far as it goes, and the URLs the rule would have named next are absent.
// A truncated finding list renders identically to a complete one.
//
// Emitted only when some rule is actually at the cap, which is the opposite
// call from startAndPassiveBudgetWarning's and for the same reason stated in
// reverse: here an absence IS the answer — no rule at the cap means nothing
// was truncated — so a line on every run would be a constant nobody reads.
//
// It names rules and stops short of calling them truncated. ZAP's JSON report
// carries no field saying which rules are passive, and ten is a number an
// active rule or an honest passive one can reach on its own, so the sentence
// says where the question arises and leaves the answer to the reader.
func alertCapWarning(p dastPayload) []string {
	if len(p.RulesAtAlertCap) == 0 || p.PassiveAlertCapPerRule <= 0 {
		return nil
	}
	return []string{"dast: FINDINGS MAY BE TRUNCATED — rule(s) " + strings.Join(p.RulesAtAlertCap, ", ") +
		" each raised exactly " + strconv.Itoa(p.PassiveAlertCapPerRule) + " alerts, which is the per-rule cap the " +
		"packaged scan applies to passive scan rules on every run and records nowhere. A rule at the cap stopped " +
		"raising alerts rather than ran out of things to report, so its share of the finding list is a floor. " +
		"ZAP's report does not say which rules are passive, so a rule named here may instead have found exactly " +
		strconv.Itoa(p.PassiveAlertCapPerRule) + " of something."}
}

// startAndPassiveBudgetWarning names the clock ZAP ran against while it started
// up and passively scanned, when that clock is one nobody chose.
//
// The packaged scans' -T is documented as "max time in minutes to wait for ZAP
// to start and the passive scan to run" — it is not a cap on the whole scan,
// and the active scan is not on it. Observed in the pinned image's
// zap_common.py (zaproxy 2.17.0): when elapsed time exceeds a configured
// passive-scan timeout, the wait loop exits and logs the timeout at DEBUG.
//
// A passive scan that runs out of budget therefore stops waiting, and the run
// continues and collects the alerts it happens to have. The report carries no
// field saying so, the exit status is unchanged, and the notice is logged at
// DEBUG, which the packaged scans do not enable. Partial passive coverage is
// byte-for-byte a completed passive scan.
//
// cicd cannot detect the overrun, so cicd states the budget instead — the same
// move as the API SCAN line: name a denominator the reader would otherwise
// assume was total.
//
// The line is emitted only when the budget was inherited rather than chosen.
// Omitting -T is not "no budget": wait_for_zap_start falls back to 600 seconds,
// so a consumer who named no duration is running against a ten-minute clock
// they were never told about, and that absence is the surprise worth a line.
// A consumer who passed --max-duration-minutes already knows the number, and
// this file's silence is load-bearing: TestWebDisclosureIsSilentWhenThereIsNothingToDisclose
// asserts a configured, clean, container-source run discloses nothing at all,
// because a line on every run is a line a reader stops seeing.
//
// What that leaves uncovered is stated rather than papered over: a passive scan
// can also run out of a budget the consumer chose, and cicd is equally blind to
// it. The number is in the envelope on every run so the question can at least
// be asked. See the Known residue section of
// specs/tell-a-dead-zap-from-a-clean-one.md.
func startAndPassiveBudgetWarning(p dastPayload) []string {
	if p.StartAndPassiveBudgetSeconds <= 0 || !p.StartAndPassiveBudgetDefaulted {
		return nil
	}
	return []string{"dast: PASSIVE SCAN BUDGET NOT SET — no --max-duration-minutes was given, so ZAP applied its own " +
		strconv.Itoa(p.StartAndPassiveBudgetSeconds) + " seconds to start up and to finish passive scanning (-T). " +
		"Had passive scanning not finished in it, ZAP would have stopped waiting and reported the alerts it had; " +
		"its report does not say whether that happened. Set --max-duration-minutes to choose this clock yourself."}
}
