package main

import (
	"strings"
	"testing"
)

// cleanPayload is a run that went perfectly: cicd built the image, started it,
// probed it, scanned it, and found alerts. Every test below takes this and
// changes one thing, so a line that appears is caused by that one thing.
func cleanPayload() dastPayload {
	return dastPayload{
		Mode:          webModeFull,
		Source:        webSourceContainer,
		TargetURL:     "http://app-under-test:8080/",
		Authenticated: true,
		Readiness: readinessResult{
			URL: "http://app-under-test:8080/health", Status: 200, Attempts: 2, WaitedSeconds: 4, OK: true,
		},
		URLsWithAlerts: 3,
		// A clean payload is a scan that finished. Every disclosure that reads
		// this flag is asking "did ZAP run", and the answer for a fixture named
		// clean is yes.
		ScanCompleted:                true,
		StartAndPassiveBudgetSeconds: 900,
		// A finished scan has always printed "Total of N URLs" — the packaged
		// scans emit it on every run unless -s is passed, which cicd never
		// does. So a fixture named clean carries a count; leaving it nil would
		// make the reference run a pin-drift run, and scopeUnreadWarning would
		// be asserted silent by the one test whose whole job is silence.
		URLsRequested: intp(17),
	}
}

// intp is here because every scope count in this file is a pointer, and the
// pointer is the point: absent means the scan said nothing, which is a
// different fact from a scan that said zero.
func intp(n int) *int { return &n }

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// TestWebDisclosureIsSilentWhenThereIsNothingToDisclose.
//
// The silence is the design, not an omission: PROVENANCE NOT ATTESTED is
// informative precisely because the container source does not emit it, so a
// reader who sees no provenance line knows cicd built the thing it scanned.
// A line on every run is a line a reader stops seeing.
func TestWebDisclosureIsSilentWhenThereIsNothingToDisclose(t *testing.T) {
	if got := webDisclosureWarnings(cleanPayload(), SeverityHigh, nil); len(got) != 0 {
		t.Errorf("a container-source, authenticated, full scan with alerts disclosed %v", got)
	}
}

// TestWebDisclosureWarnsWhenTheGateCannotFire. ZAP's maximum risk is High, so
// --fail-on CRITICAL produces the same envelope a passing gate produces with no
// field separating them.
func TestWebDisclosureWarnsWhenTheGateCannotFire(t *testing.T) {
	got := webDisclosureWarnings(cleanPayload(), SeverityCritical, nil)
	if !hasLine(got, "THRESHOLD UNREACHABLE") {
		t.Errorf("--fail-on CRITICAL was not disclosed: %v", got)
	}
	if !hasLine(got, "Use HIGH") {
		t.Errorf("the line names no remedy, so it gets read and ignored: %v", got)
	}

	for _, threshold := range []Severity{SeverityHigh, SeverityMedium, SeverityLow, SeverityNone} {
		if hasLine(webDisclosureWarnings(cleanPayload(), threshold, nil), "THRESHOLD UNREACHABLE") {
			t.Errorf("--fail-on %s can fail over a HIGH and must not warn", threshold)
		}
	}
}

// TestWebDisclosureSeparatesTheSourcesByProvenance is the whole W1/W2 split in
// one assertion: only the container source may leave the claim unqualified.
func TestWebDisclosureSeparatesTheSourcesByProvenance(t *testing.T) {
	for _, tc := range []struct {
		source   string
		wantLine bool
	}{
		{webSourceURL, true},
		{webSourceService, true},
		{webSourceContainer, false},
	} {
		p := cleanPayload()
		p.Source = tc.source
		got := webDisclosureWarnings(p, SeverityHigh, nil)
		if hasLine(got, "PROVENANCE NOT ATTESTED") != tc.wantLine {
			t.Errorf("source %s: provenance line present = %v, want %v (%v)",
				tc.source, !tc.wantLine, tc.wantLine, got)
		}
	}
}

func TestWebDisclosureSaysWhenNoLoginWasExercised(t *testing.T) {
	p := cleanPayload()
	p.Authenticated = false
	got := webDisclosureWarnings(p, SeverityHigh, nil)
	if !hasLine(got, "NOT AUTHENTICATED") {
		t.Errorf("an anonymous scan was not disclosed: %v", got)
	}
	if !hasLine(got, "anonymous surface") {
		t.Errorf("the line does not say what the findings therefore describe: %v", got)
	}
}

// TestWebDisclosureQuotesTheProfileTheConsumerClaimed. An unset profile is a
// consumer who made no claim; inventing a caveat about it would be noise on
// every run of every repository.
func TestWebDisclosureQuotesTheProfileTheConsumerClaimed(t *testing.T) {
	p := cleanPayload()
	p.Profile = "Staging"
	got := webDisclosureWarnings(p, SeverityHigh, nil)
	if !hasLine(got, "PROFILE Staging") {
		t.Errorf("the profile was not disclosed: %v", got)
	}

	for _, profile := range []string{"", "   "} {
		p := cleanPayload()
		p.Profile = profile
		if hasLine(webDisclosureWarnings(p, SeverityHigh, nil), "PROFILE") {
			t.Errorf("an unset profile produced a profile line: %q", profile)
		}
	}
}

// TestWebDisclosureStatesWhatEachModeDidNotTest. A baseline report and a full
// report that found nothing are the same document; only this line separates
// them for a reader.
func TestWebDisclosureStatesWhatEachModeDidNotTest(t *testing.T) {
	baseline := cleanPayload()
	baseline.Mode = webModeBaseline
	got := webDisclosureWarnings(baseline, SeverityHigh, nil)
	if !hasLine(got, "BASELINE ONLY") {
		t.Errorf("a passive scan was not disclosed as one: %v", got)
	}
	if !hasLine(got, "injection") {
		t.Errorf("the line does not name a rule class that did not run: %v", got)
	}

	// full is the mode that tests the most, so it has no scope caveat of its
	// own — the profile and authentication lines carry what it still cannot say.
	full := webDisclosureWarnings(cleanPayload(), SeverityHigh, nil)
	if hasLine(full, "BASELINE ONLY") || hasLine(full, "API SCAN") {
		t.Errorf("a full scan claimed a narrower scope than it had: %v", full)
	}
}

// TestWebDisclosureStatesBothAPIScopeNumbersAndReconcilesNeither.
//
// The sentence this test used to assert — "only the N operation(s) the API
// document declares were requested" — was a claim cicd had never checked, and
// a scan can import only document-serving URLs without reaching its declared
// API routes. The disclosure therefore prints cicd's count beside ZAP's own
// and refuses to divide them.
//
// EndpointsFromSpec stays a pointer for the reason it always was: "the document
// declared no operations" and "there was no document to count" must not be the
// same zero.
func TestWebDisclosureStatesBothAPIScopeNumbersAndReconcilesNeither(t *testing.T) {
	counted := cleanPayload()
	counted.Mode = webModeAPI
	counted.EndpointsFromSpec = intp(3)
	counted.URLsImported = intp(4)
	got := webDisclosureWarnings(counted, SeverityHigh, nil)
	for _, want := range []string{
		"cicd read 3 operation(s)",
		"finished holding 17 URL(s)",
		"(4 of them present the moment the document was imported)",
		"does not reconcile them",
	} {
		if !hasLine(got, want) {
			t.Errorf("%q missing from the API scope disclosure: %v", want, got)
		}
	}

	zero := cleanPayload()
	zero.Mode = webModeAPI
	zero.EndpointsFromSpec = intp(0)
	if !hasLine(webDisclosureWarnings(zero, SeverityHigh, nil), "cicd read 0 operation(s)") {
		t.Error("a document declaring no operations must say 0, not go quiet")
	}

	// Synthetic mismatch: many declared operations, few held URLs. These
	// invented counts test disclosure, not a coverage ratio or a verdict.
	dead := cleanPayload()
	dead.Mode = webModeAPI
	dead.EndpointsFromSpec = intp(64)
	dead.URLsRequested = intp(9)
	dead.URLsImported = intp(5)
	got = webDisclosureWarnings(dead, SeverityHigh, nil)
	if !hasLine(got, "cicd read 64 operation(s)") || !hasLine(got, "finished holding 9 URL(s)") {
		t.Errorf("the gap between the document and the scan is not visible: %v", got)
	}

	uncounted := cleanPayload()
	uncounted.Mode = webModeAPI
	got = webDisclosureWarnings(uncounted, SeverityHigh, nil)
	if !hasLine(got, "API SCAN") {
		t.Errorf("an api scan cicd could not count still owes a scope line: %v", got)
	}
	if hasLine(got, "operation(s) in the document,") {
		t.Errorf("a count was claimed for a document that was never counted: %v", got)
	}
	if !hasLine(got, "no denominator here") {
		t.Errorf("ZAP's count was printed with nothing saying it stands alone: %v", got)
	}

	// Neither number: the line narrows to the bound that is true by
	// construction and claims nothing else.
	blind := cleanPayload()
	blind.Mode = webModeAPI
	blind.URLsRequested = nil
	got = webDisclosureWarnings(blind, SeverityHigh, nil)
	if !hasLine(got, "bounded by the API document") {
		t.Errorf("the one claim that needs no measurement went missing: %v", got)
	}
	if hasLine(got, "cicd read") || hasLine(got, "finished holding") {
		t.Errorf("a number was reported by a scan that produced none: %v", got)
	}
}

// TestWebDisclosurePutsTheReadinessStatusBesideAnEmptyScan.
//
// "nothing to find" and "nothing was reached" produce the same alert list. The
// probe status is the only thing in the envelope that separates them, so it
// belongs in the line rather than three fields away.
func TestWebDisclosurePutsTheReadinessStatusBesideAnEmptyScan(t *testing.T) {
	p := cleanPayload()
	p.URLsWithAlerts = 0
	got := webDisclosureWarnings(p, SeverityHigh, nil)
	if !hasLine(got, "NO ALERTED URL") {
		t.Errorf("a scan with no alerted URL was not disclosed: %v", got)
	}
	if !hasLine(got, "answered 200 at http://app-under-test:8080/health") {
		t.Errorf("the readiness status is not beside the empty result: %v", got)
	}

	// A target that never answered is an errors[] entry, and the caller emits
	// NOT SCANNED. Saying "the scan completed" here as well would be a second
	// claim about a scan that never started.
	down := cleanPayload()
	down.URLsWithAlerts = 0
	down.ScanCompleted = false
	down.Readiness = readinessResult{URL: "http://app-under-test:8080/health", OK: false}
	if hasLine(webDisclosureWarnings(down, SeverityHigh, nil), "NO ALERTED URL") {
		t.Error("an unreachable target was reported as a completed scan that found nothing")
	}
}

// TestWebDisclosureIsSilentWhenZAPDiedAfterAGoodProbe is the regression test for
// the sentence this whole change exists to delete.
//
// The probe runs before ZAP and answers 200 whether or not ZAP later survives,
// so a readiness-gated disclosure cannot tell a dead scanner from a clean
// target. On cicd's own dast smoke against main, this exact payload shape put
//
//	dast: NO ALERTED URL — the scan completed and no URL produced an alert.
//
// in the same comment.md as
//
//	zap: did not run (exit 3): Failed to connect to ZAP after 600 seconds
//
// A reader skimming that comment sees a clean DAST result.
func TestWebDisclosureIsSilentWhenZAPDiedAfterAGoodProbe(t *testing.T) {
	dead := cleanPayload()
	dead.URLsWithAlerts = 0
	dead.ScanCompleted = false
	dead.ZapExitCode = 3

	got := webDisclosureWarnings(dead, SeverityHigh, nil)
	if hasLine(got, "NO ALERTED URL") {
		t.Errorf("a ZAP that never started was disclosed as a completed scan: %v", got)
	}
	if hasLine(got, "the scan completed") {
		t.Errorf("a non-run claimed completion: %v", got)
	}

	// And the readiness probe having succeeded must not be what rescues it:
	// that is precisely the field the broken guard read.
	if !dead.Readiness.OK {
		t.Fatal("fixture no longer exercises the case — the probe must have succeeded")
	}
}

// TestWebDisclosureNamesABudgetNobodyChose.
//
// Omitting -T is not "no budget": ZAP applies 600 seconds, and a passive scan
// that runs out of it stops waiting and reports the alerts it had, silently.
// A consumer who named a duration knows their clock and gets no line, because
// the silence in this file is load-bearing.
func TestWebDisclosureNamesABudgetNobodyChose(t *testing.T) {
	inherited := cleanPayload()
	inherited.StartAndPassiveBudgetSeconds = 600
	inherited.StartAndPassiveBudgetDefaulted = true

	got := webDisclosureWarnings(inherited, SeverityHigh, nil)
	if !hasLine(got, "PASSIVE SCAN BUDGET NOT SET") {
		t.Errorf("a budget inherited from ZAP was not disclosed: %v", got)
	}
	if !hasLine(got, "600 seconds") {
		t.Errorf("the inherited budget is not named: %v", got)
	}

	chosen := cleanPayload()
	chosen.StartAndPassiveBudgetSeconds = 900
	chosen.StartAndPassiveBudgetDefaulted = false
	if hasLine(webDisclosureWarnings(chosen, SeverityHigh, nil), "PASSIVE SCAN BUDGET") {
		t.Error("a consumer who chose the clock was told about it anyway")
	}
}

func TestWebDisclosureNamesRiskCodesItDidNotRecognise(t *testing.T) {
	got := webDisclosureWarnings(cleanPayload(), SeverityHigh, []string{"4", "9"})
	if !hasLine(got, "UNKNOWN RISK CODE") {
		t.Errorf("an unknown risk code was not disclosed: %v", got)
	}
	if !hasLine(got, "4, 9") {
		t.Errorf("the codes are not named: %v", got)
	}
	if !hasLine(got, "counted as MEDIUM rather than dropped") {
		t.Errorf("the line does not say what happened to the findings: %v", got)
	}
}

func TestWebDisclosureCarriesTheRuleConfigLines(t *testing.T) {
	settings, err := parseZAPRuleConfig("10038\tIGNORE\tset at the ingress\n")
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	p := cleanPayload()
	p.RuleSettings = markFiredRules(settings, nil)
	if !hasLine(webDisclosureWarnings(p, SeverityHigh, nil), "RULES SUPPRESSED") {
		t.Error("a rule config's disclosure did not reach the envelope")
	}
}

// TestWebDisclosureLinesCarryNoBacktick. notify renders each warning into a
// markdown code span; codeSpan fences correctly, but a line authored here has
// no reason to test that machinery — the same rule
// say-what-no-artifact-left-unattested applies to its own warning.
func TestWebDisclosureLinesCarryNoBacktick(t *testing.T) {
	p := cleanPayload()
	p.Source = webSourceURL
	p.Authenticated = false
	p.Mode = webModeBaseline
	p.Profile = "Development"
	p.URLsWithAlerts = 0
	settings, err := parseZAPRuleConfig("10038\tIGNORE\n10021\tWARN\n40012\tFAIL\n")
	if err != nil {
		t.Fatalf("parseZAPRuleConfig: %v", err)
	}
	p.RuleSettings = markFiredRules(settings, nil)

	lines := webDisclosureWarnings(p, SeverityCritical, []string{"4"})
	if len(lines) < 8 {
		t.Fatalf("expected every disclosure to fire, got %d: %v", len(lines), lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "`") {
			t.Errorf("warning carries a backtick: %s", l)
		}
		if !strings.HasPrefix(l, "dast: ") {
			t.Errorf("warning is not attributed to this leg: %s", l)
		}
	}
}

// TestWebDisclosureSaysWhenItCouldNotReadTheScansOwnReach.
//
// This warning is unreachable on the pinned image and that is the design: the
// packaged scans print the total on every run, so the only way here is a log
// format that moved under a pin bump. The alternative to saying so is an
// envelope with no examined count, which is indistinguishable from a producer
// nobody has converted yet.
func TestWebDisclosureSaysWhenItCouldNotReadTheScansOwnReach(t *testing.T) {
	p := cleanPayload()
	p.URLsRequested = nil
	got := webDisclosureWarnings(p, SeverityHigh, nil)
	if !hasLine(got, "SCOPE NOT READ") {
		t.Errorf("a scan that stated no reach said nothing about it: %v", got)
	}
	if !hasLine(got, zapVersion) {
		t.Errorf("the line does not name the pin whose drift is the only cause: %v", got)
	}
}

// TestScopeIsNotReportedUnreadableOnAScanThatNeverRan. A dead scan already has
// an errors[] entry saying it did not run; adding that its log carried no URL
// count describes the same silence twice and buries the entry that matters.
func TestScopeIsNotReportedUnreadableOnAScanThatNeverRan(t *testing.T) {
	p := cleanPayload()
	p.ScanCompleted = false
	p.URLsRequested = nil
	if hasLine(webDisclosureWarnings(p, SeverityHigh, nil), "SCOPE NOT READ") {
		t.Error("a scan that never ran was faulted for not saying how far it got")
	}
}

// TestWebDisclosureNamesRulesSittingOnThePerRuleAlertCap.
//
// The cap is the quietest way this leg under-reports: a rule that hits it stops
// raising alerts, the exit status is unchanged, and a truncated finding list
// renders identically to a complete one.
func TestWebDisclosureNamesRulesSittingOnThePerRuleAlertCap(t *testing.T) {
	p := cleanPayload()
	p.PassiveAlertCapPerRule = zapPassiveAlertCapPerRule
	p.RulesAtAlertCap = []string{"10015", "10038"}
	got := webDisclosureWarnings(p, SeverityHigh, nil)
	if !hasLine(got, "FINDINGS MAY BE TRUNCATED") {
		t.Errorf("a rule at the cap was not disclosed: %v", got)
	}
	if !hasLine(got, "10015, 10038") {
		t.Errorf("the line does not name the rules, so nobody can check them: %v", got)
	}
	// It says where the question arises and stops. ZAP's report carries no
	// field saying which rules are passive, and ten is a number an honest rule
	// can reach, so calling these truncated would be a verdict cicd cannot make.
	if !hasLine(got, "may instead have found exactly") {
		t.Errorf("the line asserts truncation it cannot prove: %v", got)
	}
}

// TestNoRuleAtTheCapDisclosesNothing. Here an absence IS the answer — nothing
// was truncated — which is the opposite call from the budget line and for the
// reason stated in reverse: a line on every run is a constant nobody reads.
func TestNoRuleAtTheCapDisclosesNothing(t *testing.T) {
	p := cleanPayload()
	p.PassiveAlertCapPerRule = zapPassiveAlertCapPerRule
	if hasLine(webDisclosureWarnings(p, SeverityHigh, nil), "TRUNCATED") {
		t.Error("a scan where no rule reached the cap warned about the cap anyway")
	}
}

// TestTheCapIsNotDisclosedWithoutTheNumberItIsACapOf. The rule list is only
// readable beside the limit; a list with no number is a list of rules that did
// something unstated.
func TestTheCapIsNotDisclosedWithoutTheNumberItIsACapOf(t *testing.T) {
	p := cleanPayload()
	p.RulesAtAlertCap = []string{"10015"}
	if hasLine(webDisclosureWarnings(p, SeverityHigh, nil), "TRUNCATED") {
		t.Error("rules were named as capped by a payload that records no cap")
	}
}
