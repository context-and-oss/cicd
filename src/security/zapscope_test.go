package main

import (
	"strings"
	"testing"
)

// zapAPIScanStderr uses invented counts and timestamps in the packaged scan's
// logging shape. The local app-under-test alias is a fixture stand-in. Noise
// around the import line ensures the parser finds it inside a full stream.
const zapAPIScanStderr = `2000-01-02 03:04:00,100 Params: ['zap-api-scan.py', '-t', 'http://app-under-test:5000/swagger/v1/swagger.json']
2000-01-02 03:04:10,200 Using override, new target: http://app-under-test:5000/
2000-01-02 03:04:10,300 Number of Imported URLs: 246
2000-01-02 03:04:11,400 Active Scan started id=0
2000-01-02 03:05:20,500 Active Scan progress %: 100
`

// zapAPIScanStdout has an invented total in the bare print() output shape.
// No timestamp: the total pattern is anchored, unlike the import pattern.
const zapAPIScanStdout = `Total of 281 URLs
PASS: Vulnerable JS Library [10003]
WARN-NEW: Re-examine Cache-control Directives [10015] x 10
`

func TestScopeReadsBothCountsFromTheStreamsTheyLandOn(t *testing.T) {
	got := parseZAPScope(zapAPIScanStdout, zapAPIScanStderr)
	if got.Imported == nil {
		t.Fatal("imported count not read; the import line is the only evidence that ZAP got anything out of the API document")
	}
	if *got.Imported != 246 {
		t.Errorf("imported = %d, want 246", *got.Imported)
	}
	if got.Requested == nil {
		t.Fatal("requested count not read; without it the envelope states no denominator")
	}
	if *got.Requested != 281 {
		t.Errorf("requested = %d, want 281", *got.Requested)
	}
}

// TestScopeReadsTheBuildThatLooksCleanAndScannedNothing is a synthetic small-
// reach scenario: a green verdict alone cannot show whether the import reached
// the intended API. Keep imported and requested counts distinct and readable.
func TestScopeReadsTheBuildThatLooksCleanAndScannedNothing(t *testing.T) {
	stderr := "2000-01-02 03:04:03,600 Number of Imported URLs: 3\n"
	got := parseZAPScope("Total of 11 URLs\n", stderr)
	if got.Imported == nil || *got.Imported != 3 {
		t.Fatalf("imported = %v, want 3 — import reach must remain visible", got.Imported)
	}
	if got.Requested == nil || *got.Requested != 11 {
		t.Fatalf("requested = %v, want 11", got.Requested)
	}
}

// TestAnUnsaidCountIsNilAndNeverZero is the founding doctrine inside one
// struct field: a scan that printed no number must not be recorded as a scan
// that reached nothing, because the second is a measurement and the first is
// its absence.
func TestAnUnsaidCountIsNilAndNeverZero(t *testing.T) {
	got := parseZAPScope("", "")
	if got.Imported != nil {
		t.Errorf("imported = %d, want nil — nothing said so", *got.Imported)
	}
	if got.Requested != nil {
		t.Errorf("requested = %d, want nil — nothing said so", *got.Requested)
	}
}

// TestZeroURLsIsReadFromTheWarningBecauseTheTotalLineCannotCarryIt pins the
// one branch where the packaged scan logs a sentence instead of a number.
// Reading only "Total of N URLs" would make zero — the value that matters
// most — the one value that is always absent.
func TestZeroURLsIsReadFromTheWarningBecauseTheTotalLineCannotCarryIt(t *testing.T) {
	stderr := "2000-01-02 03:04:10,300 " + zapNoURLsNotice +
		" Local services may not be accessible from the Docker container\n"
	got := parseZAPScope("", stderr)
	if got.Requested == nil {
		t.Fatal("requested = nil; ZAP said it had no URLs, which is a claim, not a silence")
	}
	if *got.Requested != 0 {
		t.Errorf("requested = %d, want 0", *got.Requested)
	}
}

// TestTheTotalPatternDoesNotMatchProse guards the anchoring. An unanchored
// pattern would read a number out of any future sentence containing these
// words and report it as the scan's reach.
func TestTheTotalPatternDoesNotMatchProse(t *testing.T) {
	for _, line := range []string{
		"Skipping: a Total of 99 URLs were excluded by the context",
		"Total of 99 URLs found in the sitemap but not scanned",
		"Total of ninety-nine URLs",
	} {
		if got := parseZAPScope(line+"\n", ""); got.Requested != nil {
			t.Errorf("%q yielded requested = %d; a sentence is not a measurement", line, *got.Requested)
		}
	}
}

// TestTheLastCountWins: zap-api-scan.py logs the import line once per import
// branch, so a run that takes two reports two numbers and only the last
// describes the tree the scan ran against.
func TestTheLastCountWins(t *testing.T) {
	stderr := "Number of Imported URLs: 3\nNumber of Imported URLs: 41\n"
	got := parseZAPScope("", stderr)
	if got.Imported == nil || *got.Imported != 41 {
		t.Fatalf("imported = %v, want 41", got.Imported)
	}
}

// TestScopeIsFoundWhicheverStreamCarriesIt — which file a line lands in is the
// packaged scan's logging configuration, not a fact about the scan.
func TestScopeIsFoundWhicheverStreamCarriesIt(t *testing.T) {
	swapped := parseZAPScope(zapAPIScanStderr, zapAPIScanStdout)
	if swapped.Imported == nil || *swapped.Imported != 246 {
		t.Errorf("imported = %v with the streams swapped, want 246", swapped.Imported)
	}
	if swapped.Requested == nil || *swapped.Requested != 281 {
		t.Errorf("requested = %v with the streams swapped, want 281", swapped.Requested)
	}
}

func TestExaminedIsAbsentWhenTheScanDidNotSay(t *testing.T) {
	if got := zapExamined(nil); got != nil {
		t.Errorf("examined = %+v, want nil — \"not stated\" is the honest cell", *got)
	}
}

// TestExaminedZeroIsARealClaim: the tool looked and reached nothing, which is
// the loudest thing this field can say and the one a nil would mute.
func TestExaminedZeroIsARealClaim(t *testing.T) {
	zero := 0
	got := zapExamined(&zero)
	if got == nil {
		t.Fatal("examined = nil for a measured zero")
	}
	if got.Count != 0 || got.Unit != zapExaminedUnit {
		t.Errorf("examined = %+v, want 0 %s", *got, zapExaminedUnit)
	}
}

// TestExaminedNeverBorrowsTheSpecCountAsItsTotal pins the one tempting wrong
// move. Examined.Total is a denominator in the SAME unit as Count; the
// operation count is in a different one, so filling it in would render as a
// coverage percentage between two things that do not divide.
func TestExaminedNeverBorrowsTheSpecCountAsItsTotal(t *testing.T) {
	n := 7
	got := zapExamined(&n)
	if got == nil {
		t.Fatal("examined = nil")
	}
	if got.Total != 0 {
		t.Errorf("total = %d, want 0 — this scan cannot see its own denominator in URLs and must not imply one", got.Total)
	}
}

func TestRulesAtTheCapAreNamedAndNothingElseIs(t *testing.T) {
	got := rulesAtAlertCap(map[string]int{
		"10015": zapPassiveAlertCapPerRule,
		"10038": zapPassiveAlertCapPerRule - 1,
		"90004": zapPassiveAlertCapPerRule,
		"10049": 1,
	}, zapPassiveAlertCapPerRule)
	if strings.Join(got, ",") != "10015,90004" {
		t.Errorf("rules at cap = %v, want [10015 90004] sorted", got)
	}
}

// TestARuleAboveTheCapIsNotReportedAsAtIt: the cap is enforced by ZAP, so a
// count above it means the cap is not what this build believes. Folding that
// into "at the cap" would hide the more interesting fact.
func TestARuleAboveTheCapIsNotReportedAsAtIt(t *testing.T) {
	got := rulesAtAlertCap(map[string]int{"10015": zapPassiveAlertCapPerRule + 4}, zapPassiveAlertCapPerRule)
	if len(got) != 0 {
		t.Errorf("rules at cap = %v, want none", got)
	}
}

func TestNoRuleAtTheCapNamesNoRules(t *testing.T) {
	if got := rulesAtAlertCap(map[string]int{"10015": 3, "10038": 1}, zapPassiveAlertCapPerRule); len(got) != 0 {
		t.Errorf("rules at cap = %v, want none — silence is the answer when nothing was truncated", got)
	}
}
