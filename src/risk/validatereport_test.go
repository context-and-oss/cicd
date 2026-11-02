package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const conftestClean = `[{"filename":"/inputs/f0000","namespace":"risk.pipeline","successes":3}]`

func conftestFailure(filename, msg, severity, id, resource string) string {
	out, _ := json.Marshal([]map[string]any{{
		"filename":  filename,
		"namespace": "risk.pipeline",
		"failures": []map[string]any{{
			"msg":      msg,
			"metadata": map[string]string{"severity": severity, "id": id, "resource": resource},
		}},
	}})
	return string(out)
}

// conftestFailures concatenates single-result conftest documents into one,
// the shape conftest writes for a group of files.
func conftestFailures(docs ...string) string {
	var all []json.RawMessage
	for _, d := range docs {
		var one []json.RawMessage
		if err := json.Unmarshal([]byte(d), &one); err != nil {
			panic(err)
		}
		all = append(all, one...)
	}
	out, _ := json.Marshal(all)
	return string(out)
}

func TestFoldFindingsPassMapsEveryViolationToCritical(t *testing.T) {
	f := newValidateFold()
	f.addFindingsPass(conftestFailure("/input.json", "finding abc has no decision", "LOW", "", ""))
	if !f.ran || len(f.errs) != 0 {
		t.Fatalf("a parseable result is a run: ran=%v errs=%v", f.ran, f.errs)
	}
	if f.bySeverity[SeverityCritical] != 1 || f.total() != 1 {
		t.Errorf("bySeverity = %v", f.bySeverity)
	}
	if f.violations[0].Severity != "CRITICAL" || f.violations[0].Msg != "  - finding abc has no decision" {
		t.Errorf("violations = %#v", f.violations)
	}
}

func TestFoldUnparseableOutputIsANonRunNeverZeroViolations(t *testing.T) {
	// The doctrine's door: conftest exited, printed something that is not its
	// JSON, and the fold must say the engine did not run — not that it found
	// nothing.
	t.Run("findings pass", func(t *testing.T) {
		f := newValidateFold()
		f.addFindingsPass("panic: rego compile error")
		if f.ran {
			t.Fatal("ran must be false")
		}
		if len(f.errs) != 1 || !strings.HasPrefix(f.errs[0], "conftest findings/decisions pass: ") {
			t.Errorf("errs = %q", f.errs)
		}
		if f.total() != 0 || len(f.violations) != 0 {
			t.Errorf("a non-run must fabricate no violation: %#v", f.violations)
		}
	})
	t.Run("infra group", func(t *testing.T) {
		f := newValidateFold()
		group := infraGroup{Parser: "yaml", Namespace: "pipeline", Paths: []string{"ci.yml"}}
		_, mounts := conftestGroupPlan(group)
		f.addInfraGroup("not json", group, mounts, nil, time.Now())
		if f.ran {
			t.Fatal("ran must be false")
		}
		if len(f.errs) != 1 || !strings.Contains(f.errs[0], "parser yaml, namespace pipeline") || !strings.Contains(f.errs[0], "did not run") {
			t.Errorf("errs = %q", f.errs)
		}
		if f.total() != 0 {
			t.Errorf("bySeverity = %v", f.bySeverity)
		}
	})
}

func TestFoldInfraGroupResolvesMountsAndAppliesDecisions(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	group := infraGroup{Parser: "yaml", Namespace: "pipeline", Paths: []string{
		".github/workflows/ci.yml", ".github/workflows/other.yml",
	}}
	_, mounts := conftestGroupPlan(group)
	decisions := map[string]Decision{
		policyDecisionKey("PIPE-003", ".github/workflows/ci.yml", "x/y@v1"): validPolicyDecision(),
	}
	both := conftestFailures(
		conftestFailure("/inputs/f0000", "unpinned action", "HIGH", "PIPE-003", "x/y@v1"),
		conftestFailure("/inputs/f0001", "unpinned action", "high", "PIPE-003", "x/y@v1"),
	)

	f := newValidateFold()
	f.addInfraGroup(both, group, mounts, decisions, now)
	if !f.ran {
		t.Fatalf("errs = %v", f.errs)
	}
	if len(f.overridden) != 1 || f.overridden[0].File != ".github/workflows/ci.yml" {
		t.Errorf("overridden = %#v", f.overridden)
	}
	if len(f.violations) != 1 {
		t.Fatalf("violations = %#v", f.violations)
	}
	v := f.violations[0]
	if v.File != ".github/workflows/other.yml" {
		t.Errorf("filename must resolve from the mount to the repository path, got %q", v.File)
	}
	if v.Severity != "HIGH" || v.PolicyID != "PIPE-003" || v.Resource != "x/y@v1" {
		t.Errorf("violation = %#v", v)
	}
	if f.bySeverity[SeverityHigh] != 1 || f.total() != 1 {
		t.Errorf("bySeverity = %v (an overridden violation must not be counted)", f.bySeverity)
	}
}

func TestBuildValidateEnvelope(t *testing.T) {
	repo := RepoContext{RepoURL: "https://example.com", CommitSHA: "abc", Branch: "main"}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	group := infraGroup{Parser: "yaml", Namespace: "pipeline", Paths: []string{"ci.yml"}}
	_, mounts := conftestGroupPlan(group)

	t.Run("clean over examined files", func(t *testing.T) {
		f := newValidateFold()
		f.addInfraGroup(conftestClean, group, mounts, nil, start)
		env, err := buildValidateEnvelope(f, infraScan{Scanned: 1, Candidates: 3}, repo, SeverityHigh, start)
		if err != nil {
			t.Fatal(err)
		}
		if !env.Passed || env.Outcome != OutcomeClean {
			t.Errorf("passed=%v outcome=%v", env.Passed, env.Outcome)
		}
		if env.Examined == nil || env.Examined.Count != 1 || env.Examined.Total != 3 || env.Examined.Unit != "infrastructure files" {
			t.Errorf("examined = %#v", env.Examined)
		}
		if env.GenericFormat != "ctx-risk-validate/1.0" || env.Concern != ConcernIaC || env.ModuleName != moduleName {
			t.Errorf("identity: %q %q %q", env.GenericFormat, env.Concern, env.ModuleName)
		}
		var rpt validateReport
		if err := json.Unmarshal(env.GenericReport, &rpt); err != nil {
			t.Fatal(err)
		}
		if rpt.Violations == nil || rpt.InfraFilesScanned != 1 {
			t.Errorf("report = %#v (violations must be [] not null)", rpt)
		}
		if len(env.SARIFReport) == 0 {
			t.Error("SARIF report missing")
		}
	})
	t.Run("nothing examined is SKIPPED not CLEAN", func(t *testing.T) {
		f := newValidateFold()
		env, err := buildValidateEnvelope(f, infraScan{Scanned: 0, Candidates: 8, ScopedToDiff: true}, repo, SeverityHigh, start)
		if err != nil {
			t.Fatal(err)
		}
		if env.Outcome != OutcomeSkipped || !env.Passed {
			t.Errorf("passed=%v outcome=%v", env.Passed, env.Outcome)
		}
		if env.Examined.Count != 0 || env.Examined.Total != 8 {
			t.Errorf("examined = %#v: 0 of 8 must not read as 0 of 0", env.Examined)
		}
	})
	t.Run("findings fail at threshold and NONE collects them", func(t *testing.T) {
		f := newValidateFold()
		f.addInfraGroup(conftestFailure("/inputs/f0000", "unpinned", "HIGH", "PIPE-003", "x/y@v1"), group, mounts, nil, start)
		env, _ := buildValidateEnvelope(f, infraScan{Scanned: 1, Candidates: 1}, repo, SeverityHigh, start)
		if env.Passed || env.Outcome != OutcomeFindings || env.FindingsCount != 1 || env.FindingsBySeverity[SeverityHigh] != 1 {
			t.Errorf("HIGH: passed=%v outcome=%v count=%d", env.Passed, env.Outcome, env.FindingsCount)
		}
		env, _ = buildValidateEnvelope(f, infraScan{Scanned: 1, Candidates: 1}, repo, SeverityNone, start)
		if !env.Passed || env.Outcome != OutcomeFindings || env.FindingsCount != 1 {
			t.Errorf("NONE: passed=%v outcome=%v count=%d (NONE collects, the outcome is stated before the gate)", env.Passed, env.Outcome, env.FindingsCount)
		}
		env, _ = buildValidateEnvelope(f, infraScan{Scanned: 1, Candidates: 1}, repo, SeverityCritical, start)
		if !env.Passed {
			t.Error("a HIGH finding must pass a CRITICAL threshold")
		}
	})
	t.Run("a non-run fails at every threshold, NONE included", func(t *testing.T) {
		f := newValidateFold()
		f.addInfraGroup("garbage", group, mounts, nil, start)
		for _, th := range []Severity{SeverityNone, SeverityLow, SeverityCritical} {
			env, err := buildValidateEnvelope(f, infraScan{Scanned: 1, Candidates: 1}, repo, th, start)
			if err != nil {
				t.Fatal(err)
			}
			if env.Passed || env.Outcome != OutcomeError {
				t.Errorf("%s: passed=%v outcome=%v", th, env.Passed, env.Outcome)
			}
			if len(env.Errors) != 1 || env.FindingsCount != 0 {
				t.Errorf("%s: errors=%v count=%d", th, env.Errors, env.FindingsCount)
			}
		}
	})
	t.Run("warnings and findingsReviewed ship", func(t *testing.T) {
		f := newValidateFold()
		f.warnings = append(f.warnings, "no risk files found")
		f.findingsReviewed = 7
		env, _ := buildValidateEnvelope(f, infraScan{}, repo, SeverityHigh, start)
		if len(env.Warnings) != 1 {
			t.Errorf("warnings = %v", env.Warnings)
		}
		var rpt validateReport
		_ = json.Unmarshal(env.GenericReport, &rpt)
		if rpt.FindingsReviewed != 7 {
			t.Errorf("findingsReviewed = %d", rpt.FindingsReviewed)
		}
	})
}
