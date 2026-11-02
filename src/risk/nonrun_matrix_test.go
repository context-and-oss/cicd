package main

import (
	"strings"
	"testing"
	"time"
)

// The founding rule as a matrix, for what risk.Validate reads: every document
// that is not a policy result or a scan's output must come out as a non-run or
// a refusal, never as zero violations, at every threshold, `--fail-on NONE`
// included. Each fold has a positive control proving the matrix does not pass
// because the fold refuses everything.

var nonRunThresholds = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone}

var notConftestOutput = []string{``, ` `, `null`, `[]`, `{}`, `"x"`, `not json`, `[{"filename":`}

func assertFoldNeverPasses(t *testing.T, name string, f *validateFold) {
	t.Helper()
	if f.ran || len(f.errs) == 0 {
		t.Errorf("%s: ran=%v errs=%q, want a non-run with its reason", name, f.ran, f.errs)
	}
	for _, th := range nonRunThresholds {
		if gatedPassed(f.ran, true, th) {
			t.Errorf("%s: passed at --fail-on %s", name, th)
		}
	}
}

func TestNonRunMatrixConftestFindingsPass(t *testing.T) {
	for _, out := range notConftestOutput {
		f := newValidateFold()
		f.addFindingsPass(out)
		assertFoldNeverPasses(t, "findings pass "+out, f)
	}
	f := newValidateFold()
	f.addFindingsPass(`[{"filename":"/input.json","namespace":"risk.findings","successes":2},{"filename":"/input.json","namespace":"risk.findings_test","successes":0},{"filename":"/input.json","namespace":"risk.severity","successes":1}]`)
	if !f.ran || f.total() != 0 {
		t.Fatalf("control: a clean findings pass: ran=%v errs=%q", f.ran, f.errs)
	}

	// Measured against conftest v0.58.0 with --all-namespaces: a file gets one
	// row per namespace, the *_test packages at 0. Only rows that sum to 0
	// across every namespace mean no rule read the input.
	f = newValidateFold()
	f.addFindingsPass(`[{"filename":"/input.json","namespace":"risk.findings_test","successes":0},{"filename":"/input.json","namespace":"risk.severity_test","successes":0}]`)
	assertFoldNeverPasses(t, "findings pass evaluating no rule", f)
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "evaluated no rule for /input.json") {
		t.Errorf("findings pass evaluating no rule: errs=%q", f.errs)
	}
}

func TestNonRunMatrixConftestInfraGroup(t *testing.T) {
	group := infraGroup{Parser: "yaml", Namespace: "risk.pipeline", Paths: []string{"a.yml", "b.yml"}}
	_, mounts := conftestGroupPlan(group)
	for _, out := range notConftestOutput {
		f := newValidateFold()
		f.addInfraGroup(out, group, mounts, nil, time.Now())
		assertFoldNeverPasses(t, "infra group "+out, f)
	}

	// Ran on part of the group: the violation it did report is kept, and the
	// file it never named makes the group a non-run.
	partial := conftestFailure("/inputs/f0000", "unpinned", "LOW", "PIPE-003", "x")
	f := newValidateFold()
	f.addInfraGroup(partial, group, mounts, nil, time.Now())
	assertFoldNeverPasses(t, "half the group", f)
	if f.total() != 1 {
		t.Errorf("half the group: total=%d, want the one violation conftest did report", f.total())
	}
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "reported on 1 of 2 file(s)") || !strings.Contains(f.errs[0], "b.yml") {
		t.Errorf("half the group: errs=%q, want the unevaluated file named", f.errs)
	}

	// conftest names a file and evaluates nothing for it when the namespace
	// has no package: measured against v0.58.0 as successes 0, no failures.
	// That read CLEAN at every threshold.
	for name, out := range map[string]string{
		"no rule for either file": `[{"filename":"/inputs/f0000","namespace":"risk.pipeline","successes":0},{"filename":"/inputs/f0001","namespace":"risk.pipeline","successes":0}]`,
		"no rule for one file":    `[{"filename":"/inputs/f0000","namespace":"risk.pipeline","successes":3},{"filename":"/inputs/f0001","namespace":"risk.pipeline","successes":0}]`,
		"no successes field":      `[{"filename":"/inputs/f0000","namespace":"risk.pipeline"},{"filename":"/inputs/f0001","namespace":"risk.pipeline","successes":3}]`,
	} {
		f = newValidateFold()
		f.addInfraGroup(out, group, mounts, nil, time.Now())
		assertFoldNeverPasses(t, name, f)
		if len(f.errs) != 1 || !strings.Contains(f.errs[0], "evaluated no rule in namespace risk.pipeline for") {
			t.Errorf("%s: errs=%q, want the rule-less file named", name, f.errs)
		}
	}

	// A failure is an evaluated rule even with no successes beside it.
	onlyFailures := conftestFailures(
		conftestFailure("/inputs/f0000", "unpinned", "LOW", "PIPE-003", "x"),
		conftestFailure("/inputs/f0001", "unpinned", "LOW", "PIPE-003", "y"))
	f = newValidateFold()
	f.addInfraGroup(onlyFailures, group, mounts, nil, time.Now())
	if !f.ran || f.total() != 2 {
		t.Fatalf("control: failures are evaluations: ran=%v errs=%q total=%d", f.ran, f.errs, f.total())
	}

	clean := `[{"filename":"/inputs/f0000","namespace":"risk.pipeline","successes":3},{"filename":"/inputs/f0001","namespace":"risk.pipeline","successes":3}]`
	f = newValidateFold()
	f.addInfraGroup(clean, group, mounts, nil, time.Now())
	if !f.ran || f.total() != 0 {
		t.Fatalf("control: a clean group: ran=%v errs=%q", f.ran, f.errs)
	}
}

// Validate refuses risk files it cannot use with a hard error before any
// envelope exists, so the matrix asserts the refusal itself.
func TestNonRunMatrixRiskFiles(t *testing.T) {
	for _, findings := range []string{``, `null`, `{}`, `[]`, `"x"`, `{"findings":null}`, `{"schema_version":"1.0"}`} {
		if _, err := parseRiskInputs(findings, `{}`); err == nil || !strings.HasPrefix(err.Error(), "parse findings.json:") {
			t.Errorf("findings %q: err = %v, want a refusal naming findings.json", findings, err)
		}
	}
	for _, decisions := range []string{``, `null`, `[]`, `"x"`} {
		if _, err := parseRiskInputs(`{"findings":[]}`, decisions); err == nil || !strings.HasPrefix(err.Error(), "parse decisions.json:") {
			t.Errorf("decisions %q: err = %v, want a refusal naming decisions.json", decisions, err)
		}
	}
	if _, err := parseRiskInputs(`{"schema_version":"1.0","findings":[]}`, `{}`); err != nil {
		t.Fatalf("control: an empty review is a review: %v", err)
	}
}
