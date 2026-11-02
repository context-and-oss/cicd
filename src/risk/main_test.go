package main

import (
	"strings"
	"testing"
)

func TestParseConftestViolations_extractsMsgs(t *testing.T) {
	input := `[{"failures":[{"msg":"violation 1"},{"msg":"violation 2"}]},{"failures":[{"msg":"violation 3"}]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 violations, got %d: %v", len(got), got)
	}
	if got[0].Msg != "  - violation 1" {
		t.Fatalf("expected '  - violation 1', got %q", got[0].Msg)
	}
}

func TestParseConftestViolations_readsWarnings(t *testing.T) {
	input := `[{"failures":[],"warnings":[{"msg":"warn 1"},{"msg":"warn 2"}]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 violations from warnings, got %d: %v", len(got), got)
	}
}

func TestParseConftestViolations_failuresAndWarningsCombined(t *testing.T) {
	input := `[{"failures":[{"msg":"fail 1"}],"warnings":[{"msg":"warn 1"}]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 combined, got %d", len(got))
	}
}

// An empty result list is not an empty verdict. conftest writes a result per
// input file, so `[]` or `null` means it evaluated nothing; both used to read as
// zero violations.
func TestParseConftestViolations_emptyResultIsAnError(t *testing.T) {
	for _, in := range []string{"[]", "null", " null\n"} {
		got, err := parseConftestViolations(in)
		if err == nil || !strings.Contains(err.Error(), "names no evaluated file") {
			t.Errorf("%q: err = %v, want a refusal", in, err)
		}
		if len(got) != 0 {
			t.Errorf("%q: %d violations from output that evaluated nothing", in, len(got))
		}
	}
}

func TestParseConftestViolations_cleanResult(t *testing.T) {
	got, err := parseConftestViolations(`[{"filename":"/input.json","namespace":"main","successes":2}]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(got))
	}
}

// Output that is not conftest JSON is an error, never a violation. It used to
// return a synthetic HIGH reading "Failed to parse conftest JSON output", which
// claimed a policy failure no policy produced and — being a *finding* — was
// suppressed entirely by --fail-on NONE.
func TestParseConftestViolations_invalidJSONIsAnError(t *testing.T) {
	got, err := parseConftestViolations("not json")
	if err == nil {
		t.Fatal("unparseable output must be an error, not a violation")
	}
	if len(got) != 0 {
		t.Fatalf("no violations may be fabricated, got %d: %v", len(got), got)
	}
	if !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("error must say the output was not JSON, got %q", err)
	}
}

// Empty stdout is separated from a decode failure: conftest --output json always
// writes a document, so nothing at all means the tool produced no output. Before
// this it decoded to the same synthetic HIGH as garbage input.
func TestParseConftestViolations_emptyOutputIsAnError(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t\n"} {
		got, err := parseConftestViolations(in)
		if err == nil {
			t.Fatalf("empty output %q must be an error", in)
		}
		if len(got) != 0 {
			t.Fatalf("no violations may be fabricated, got %v", got)
		}
		if !strings.Contains(err.Error(), "no output") {
			t.Fatalf("error must say the tool wrote no output, got %q", err)
		}
	}
}

func TestParseConftestViolations_skipsEmptyMsg(t *testing.T) {
	input := `[{"failures":[{"msg":""},{"msg":"real violation"}]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 violation (empty msg skipped), got %d", len(got))
	}
	if got[0].Msg != "  - real violation" {
		t.Fatalf("got %q", got[0].Msg)
	}
}

// Regression: rego rules of the form
//
//	violation contains finding if { ... finding := {..., "severity": "medium", ...} }
//
// emit `metadata.severity` on each failure entry. The parser must preserve it
// so downstream classification can use the policy's own severity instead of
// hardcoding HIGH.
func TestParseConftestViolations_preservesPolicySeverity(t *testing.T) {
	input := `[{"failures":[
		{"msg":"PIPE-003: unpinned action","metadata":{"severity":"medium","id":"PIPE-003"}},
		{"msg":"PIPE-002: pull_request_target","metadata":{"severity":"high","id":"PIPE-002"}}
	]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 violations, got %d: %#v", len(got), got)
	}
	if got[0].Severity != "medium" {
		t.Fatalf("PIPE-003 severity = %q, want medium", got[0].Severity)
	}
	if got[1].Severity != "high" {
		t.Fatalf("PIPE-002 severity = %q, want high", got[1].Severity)
	}
}

func TestParseConftestViolations_preservesPolicyIdentity(t *testing.T) {
	input := `[{"filename":"/inputs/f0000","failures":[
		{"msg":"PIPE-003: Action \"example-org/triage-action@v1\" is not pinned to a commit SHA","metadata":{"severity":"medium","id":"PIPE-003","resource":"example-org/triage-action@v1","query":"data.risk.pipeline.violation"}},
		{"msg":"PIPE-003: Action \"example-org/triage-action@v1\" is not pinned to a commit SHA","metadata":{"query":"data.risk.pipeline.deny"}}
	]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped violation, got %d: %#v", len(got), got)
	}
	if got[0].PolicyID != "PIPE-003" {
		t.Fatalf("PolicyID = %q, want PIPE-003", got[0].PolicyID)
	}
	if got[0].Filename != "/inputs/f0000" {
		t.Fatalf("Filename = %q, want /inputs/f0000", got[0].Filename)
	}
	if got[0].Resource != "example-org/triage-action@v1" {
		t.Fatalf("Resource = %q, want example-org/triage-action@v1", got[0].Resource)
	}
}

// Regression: rego policies pair `violation contains finding` with
// `deny contains msg if { some f in violation; msg := f.msg }`. Conftest
// reports both as failures with the same msg — once with metadata.severity,
// once without. The parser must collapse them to a single entry and prefer
// the variant that carries severity. Both entries originate from the same
// input file, so the per-file dedup key matches.
func TestParseConftestViolations_dedupesViolationAndDeny(t *testing.T) {
	input := `[{"filename":"/inputs/release.yml","failures":[
		{"msg":"PIPE-003: unpinned action","metadata":{"severity":"medium","query":"data.risk.pipeline.violation"}},
		{"msg":"PIPE-003: unpinned action","metadata":{"query":"data.risk.pipeline.deny"}}
	]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped violation, got %d: %#v", len(got), got)
	}
	if got[0].Severity != "medium" {
		t.Fatalf("expected severity preserved from violation rule, got %q", got[0].Severity)
	}
}

// Regression: when only the bare-msg `deny` variant arrives first (e.g. due
// to rule ordering), the later `violation` entry with metadata must upgrade
// the stored severity rather than being silently dropped.
func TestParseConftestViolations_upgradesSeverityOnDedup(t *testing.T) {
	input := `[{"filename":"/inputs/release.yml","failures":[
		{"msg":"PIPE-003: unpinned action","metadata":{"query":"data.risk.pipeline.deny"}},
		{"msg":"PIPE-003: unpinned action","metadata":{"severity":"medium","id":"PIPE-003","resource":"actions/checkout@v6","query":"data.risk.pipeline.violation"}}
	]}]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped violation, got %d", len(got))
	}
	if got[0].Severity != "medium" {
		t.Fatalf("expected severity upgraded to medium, got %q", got[0].Severity)
	}
	if got[0].PolicyID != "PIPE-003" {
		t.Fatalf("expected policy id upgraded to PIPE-003, got %q", got[0].PolicyID)
	}
}

// Regression: conftest emits one result entry per scanned input file. The
// same msg appearing in two files is a legitimately separate finding (e.g.,
// the same unpinned action in release.yml and security.yml). Dedup must be
// scoped to filename — collapsing across files underreports findings.
func TestParseConftestViolations_keepsCrossFileFindingsDistinct(t *testing.T) {
	input := `[
		{"filename":"/inputs/release.yml","failures":[
			{"msg":"PIPE-003: unpinned action","metadata":{"severity":"medium"}}
		]},
		{"filename":"/inputs/security.yml","failures":[
			{"msg":"PIPE-003: unpinned action","metadata":{"severity":"medium"}}
		]}
	]`
	got, err := parseConftestViolations(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct findings (one per file), got %d: %#v", len(got), got)
	}
	for _, v := range got {
		if v.Severity != "medium" {
			t.Fatalf("expected severity preserved on both, got %q", v.Severity)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"medium", SeverityMedium},
		{"MEDIUM", SeverityMedium},
		{"  high  ", SeverityHigh},
		{"critical", SeverityCritical},
		{"low", SeverityLow},
		// Unknown or missing severity falls back to HIGH (conservative — keeps
		// the finding visible at the default fail-on threshold).
		{"", SeverityHigh},
		{"unknown", SeverityHigh},
		{"info", SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeSeverity(tc.in); got != tc.want {
				t.Fatalf("normalizeSeverity(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	cases := []struct {
		name      string
		counts    map[Severity]int
		threshold Severity
		wantFail  bool
	}{
		// NONE threshold never fails, regardless of findings
		{"none-with-critical", map[Severity]int{SeverityCritical: 5, SeverityHigh: 3}, SeverityNone, false},
		{"none-empty", map[Severity]int{}, SeverityNone, false},
		// Empty findings never fail any threshold
		{"empty-critical", map[Severity]int{}, SeverityCritical, false},
		{"empty-high", map[Severity]int{}, SeverityHigh, false},
		{"empty-medium", map[Severity]int{}, SeverityMedium, false},
		{"empty-low", map[Severity]int{}, SeverityLow, false},
		// Threshold is inclusive: findings AT or ABOVE threshold cause failure
		{"critical-at-critical", map[Severity]int{SeverityCritical: 1}, SeverityCritical, true},
		{"high-at-high", map[Severity]int{SeverityHigh: 2}, SeverityHigh, true},
		{"medium-at-medium", map[Severity]int{SeverityMedium: 1}, SeverityMedium, true},
		{"low-at-low", map[Severity]int{SeverityLow: 1}, SeverityLow, true},
		// Findings above threshold still fail
		{"critical-above-high", map[Severity]int{SeverityCritical: 1}, SeverityHigh, true},
		{"critical-above-medium", map[Severity]int{SeverityCritical: 1}, SeverityMedium, true},
		{"high-above-medium", map[Severity]int{SeverityHigh: 1}, SeverityMedium, true},
		// Findings below threshold do not fail
		{"medium-below-high", map[Severity]int{SeverityMedium: 3}, SeverityHigh, false},
		{"low-below-high", map[Severity]int{SeverityLow: 5}, SeverityHigh, false},
		{"low-below-medium", map[Severity]int{SeverityLow: 1}, SeverityMedium, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldFail(tc.counts, tc.threshold)
			if got != tc.wantFail {
				t.Fatalf("shouldFail(%v, %s) = %v, want %v", tc.counts, tc.threshold, got, tc.wantFail)
			}
		})
	}
}
