// What a Validate run folds its two conftest passes into, and the outcome
// it states before the gate.
//
// Untagged (no //go:build !unit_test): opa.go carries the Dagger build tag, and
// gating.go holds only gatedPassed, byte-identical across three modules and
// guarded as such, so risk's own fold and outcome rules live here. The fold is
// where the doctrine's door sits: a conftest that exited without parseable
// output must land in errors[] with ran=false, never as zero violations.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// validateFold accumulates what the two passes produced. ran is tracked
// separately from the violation counts because `--fail-on NONE` must suppress
// violations and must never suppress "conftest did not run" — see
// gatedPassed. Anything that clears ran also records why in errs.
type validateFold struct {
	ran              bool
	bySeverity       map[Severity]int
	violations       []reportViol
	overridden       []policyOverrideReport
	warnings         []string
	errs             []string
	findingsReviewed int
}

func newValidateFold() *validateFold {
	return &validateFold{ran: true, bySeverity: map[Severity]int{}}
}

// nonRun records that a pass could not be evaluated. The message is the
// errors[] entry; the verdict can no longer pass at any threshold.
func (f *validateFold) nonRun(msg string) {
	f.errs = append(f.errs, msg)
	f.ran = false
}

// addFindingsPass folds conftest's output for the findings/decisions pass.
// Unparseable output is a non-run, not a violation: it used to become a
// synthetic CRITICAL, which read as "your findings review is broken" when the
// truth was "we cannot tell". Every violation this pass does produce is a
// findings-review hygiene rule and gates regardless of policy-declared
// severity, so it maps to CRITICAL.
func (f *validateFold) addFindingsPass(out string) {
	parsed, err := parseConftestViolations(out)
	if err != nil {
		f.nonRun("conftest findings/decisions pass: " + err.Error())
		return
	}
	if files := filesEvaluatingNoRule(conftestRulesEvaluated(out)); len(files) > 0 {
		f.nonRun("conftest findings/decisions pass: conftest evaluated no rule for " + namedSample(files, 5) +
			", so this is not a review of the findings (no rego package under policy/findings was evaluated)")
	}
	for _, v := range parsed {
		f.violations = append(f.violations, reportViol{Msg: v.Msg, Severity: string(SeverityCritical)})
		f.bySeverity[SeverityCritical]++
	}
}

// addInfraGroup folds conftest's output for one infra group: filenames are
// resolved from their mount back to repository paths, accepted decisions
// move a violation to the overridden list, and the rest are counted by
// severity. Output the parser refuses is a non-run for that group, filed
// under the group's parser and namespace so the reader knows which policy
// family went unevaluated.
func (f *validateFold) addInfraGroup(out string, group infraGroup, mounts []conftestMount, decisions map[string]Decision, now time.Time) {
	parsed, err := parseConftestViolations(out)
	if err != nil {
		f.nonRun(conftestFailureMessage(group.Parser, group.Namespace, err.Error(), ""))
		return
	}
	if missing := unevaluatedMounts(out, mounts); len(missing) > 0 {
		// Folded alongside whatever conftest did report: those violations are
		// real, but the group as a whole is not a verdict on the files it
		// skipped.
		f.nonRun(fmt.Sprintf("conftest infra pass (parser %s, namespace %s): conftest reported on %d of %d file(s), so this is not a policy verdict on %s",
			group.Parser, group.Namespace, len(mounts)-len(missing), len(mounts), namedSample(missing, 5)))
	}
	if ruleless := ruleLessMounts(conftestRulesEvaluated(out), mounts); len(ruleless) > 0 {
		// conftest writes a result for a file even when the namespace it was
		// asked for has no package: successes 0, no failures, which read as
		// CLEAN at every threshold. A policy rename would have emptied the
		// group without a word.
		f.nonRun(fmt.Sprintf("conftest infra pass (parser %s, namespace %s): conftest evaluated no rule in namespace %s for %s, so no policy read %s",
			group.Parser, group.Namespace, group.Namespace, namedSample(ruleless, 5), pluralThem(len(ruleless))))
	}
	mountToRel := mountMap(mounts)
	for i := range parsed {
		parsed[i].Filename = resolveConftestFilename(parsed[i].Filename, mountToRel)
	}
	remaining, overridden := applyPolicyDecisions(parsed, decisions, now)
	f.overridden = append(f.overridden, overridden...)
	for _, v := range remaining {
		sev := normalizeSeverity(v.Severity)
		f.violations = append(f.violations, reportViol{
			Msg:      v.Msg,
			Severity: string(sev),
			PolicyID: v.PolicyID,
			File:     v.Filename,
			Resource: v.Resource,
		})
		f.bySeverity[sev]++
	}
}

// total is the violation count across every severity.
func (f *validateFold) total() int {
	n := 0
	for _, c := range f.bySeverity {
		n += c
	}
	return n
}

// validateReport is the generic report Validate ships, format
// ctx-risk-validate/1.0.
type validateReport struct {
	Violations           []reportViol           `json:"violations"`
	OverriddenViolations []policyOverrideReport `json:"overriddenViolations,omitempty"`
	InfraFilesScanned    int                    `json:"infraFilesScanned"`
	// InfraFilesNotAssessed is the Terraform/HCL files in scope that no policy
	// read. The warning carries the count too, because buildCombined drops
	// this payload from the audit bundle.
	InfraFilesNotAssessed []string `json:"infraFilesNotAssessed,omitempty"`
	FindingsReviewed      int      `json:"findingsReviewed"`
}

// buildValidateEnvelope states the verdict and the outcome.
//
// The verdict is gatedPassed(ran, severityOK, threshold): ran=false fails at
// every threshold, NONE included, and NONE suppresses the severity half only.
// The outcome is stated before the gate and never derived from it, and a
// CLEAN over zero files is downgraded to SKIPPED: on this repository's own
// shadow run infraFilesScanned=0 with no violations read as CLEAN, with "no
// risk files found" sitting in warnings[] as the only record. A policy engine
// with nothing in scope has not cleared the repository — it has not looked.
// Examined carries both numbers for the same reason: 0 of 0 is a repository
// with no infrastructure and 0 of 8 is a scan that looked at none of it.
func buildValidateEnvelope(f *validateFold, scan infraScan, repo RepoContext, threshold Severity, start time.Time) (*Envelope, error) {
	total := f.total()
	violations := f.violations
	if violations == nil {
		violations = []reportViol{}
	}
	genericRpt, err := json.Marshal(validateReport{
		Violations:            violations,
		OverriddenViolations:  f.overridden,
		InfraFilesScanned:     scan.Scanned,
		InfraFilesNotAssessed: scan.NotAssessed,
		FindingsReviewed:      f.findingsReviewed,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal risk report: %w", err)
	}
	sarifRpt, err := buildRiskSARIF(violations, f.ran, f.errs)
	if err != nil {
		return nil, fmt.Errorf("marshal risk SARIF: %w", err)
	}
	return &Envelope{
		SchemaVersion:      SchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               ToolInfo{Name: riskToolName, Version: riskToolVersion},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(f.ran, !shouldFail(f.bySeverity, threshold), threshold),
		Outcome:            skippedIfNothingExamined(scanOutcome(f.ran, total), f.ran, scan.Scanned),
		Concern:            ConcernIaC,
		Examined:           &Examined{Unit: "infrastructure files", Count: scan.Scanned, Total: scan.Candidates},
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: f.bySeverity,
		SARIFReport:        sarifRpt,
		GenericFormat:      "ctx-risk-validate/1.0",
		GenericReport:      json.RawMessage(genericRpt),
		Warnings:           f.warnings,
		Errors:             f.errs,
	}, nil
}

// scanOutcome states what a tool found, before the gate.
//
// It is deliberately NOT derived from gatedPassed's result. Under
// `fail-on: NONE` that result is true whatever the tool saw, which is the
// documented contract and the reason this function exists: a consumer building
// a customer report needs the un-gated answer, and reading it back out of a
// gated boolean is impossible by construction.
//
// Restated here rather than synced: risk keeps a hand-trimmed schema.go, so
// scripts/sync-schema.py's helper appendix never reaches this module.
func scanOutcome(ran bool, findings int) Outcome {
	switch {
	case !ran:
		return OutcomeError
	case findings > 0:
		return OutcomeFindings
	default:
		return OutcomeClean
	}
}

// skippedIfNothingExamined downgrades a CLEAN verdict to SKIPPED when the tool
// had nothing in scope to look at.
//
// It exists because "the scan found nothing" and "the scan had nothing to scan"
// arrive at the same place through scanOutcome — zero findings, no error — and
// a report that renders both as a green tick is claiming coverage the run never
// had. Only CLEAN is downgraded: findings, a failure or an error are all
// results, and a tool that produced one plainly did examine something.
//
// Restated here rather than synced: risk keeps a hand-trimmed schema.go, so
// scripts/sync-schema.py's helper appendix never reaches this module.
func skippedIfNothingExamined(o Outcome, ran bool, examined int) Outcome {
	if ran && examined == 0 && o == OutcomeClean {
		return OutcomeSkipped
	}
	return o
}

// unevaluatedMounts lists, as repository paths, the files the group mounted
// and conftest's output never names. A result per file is what conftest
// writes, so a file missing from the output is a file no policy read, and a
// group verdict that covered half its files must not read as covering all.
func unevaluatedMounts(out string, mounts []conftestMount) []string {
	evaluated := conftestRulesEvaluated(out)
	var missing []string
	for _, m := range mounts {
		if _, ok := evaluated[m.Mount]; !ok {
			missing = append(missing, m.Rel)
		}
	}
	return missing
}

// conftestRulesEvaluated sums, per filename, every rule outcome conftest
// reports: successes, failures, warnings and exceptions. With --all-namespaces
// a file gets one result per namespace (the *_test packages included, at 0),
// so the sum is taken across them. A file conftest named but no rule read sums
// to 0; a file it never named is absent. nil only for output
// parseConftestViolations has already refused.
func conftestRulesEvaluated(out string) map[string]int {
	var results []struct {
		Filename   string            `json:"filename"`
		Successes  int               `json:"successes"`
		Failures   []json.RawMessage `json:"failures"`
		Warnings   []json.RawMessage `json:"warnings"`
		Exceptions []json.RawMessage `json:"exceptions"`
	}
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		// parseConftestViolations accepted the same bytes; unreachable.
		return nil
	}
	counts := make(map[string]int, len(results))
	for _, r := range results {
		counts[r.Filename] += r.Successes + len(r.Failures) + len(r.Warnings) + len(r.Exceptions)
	}
	return counts
}

// filesEvaluatingNoRule lists, sorted, the filenames whose summed rule count
// is 0.
func filesEvaluatingNoRule(counts map[string]int) []string {
	var none []string
	for name, n := range counts {
		if n == 0 {
			none = append(none, name)
		}
	}
	sort.Strings(none)
	return none
}

// ruleLessMounts lists, as repository paths in mount order, the mounted files
// conftest named and evaluated no rule for. A file it never named is
// unevaluatedMounts' to report.
func ruleLessMounts(counts map[string]int, mounts []conftestMount) []string {
	var none []string
	for _, m := range mounts {
		if n, ok := counts[m.Mount]; ok && n == 0 {
			none = append(none, m.Rel)
		}
	}
	return none
}

func pluralThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// namedSample names up to max paths and counts the rest, so the errors[] line
// says which files without growing with the repository.
func namedSample(paths []string, max int) string {
	if len(paths) <= max {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(paths[:max], ", "), len(paths)-max)
}
