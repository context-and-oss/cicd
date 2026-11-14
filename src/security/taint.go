// ScanTaint's policy: which rules run with Opengrep's interfile analysis, how
// the two runs become one report, and what the evidence says about both.
//
// Deliberately untagged (no //go:build !unit_test): manifest parsing, argument
// building and SARIF arithmetic, so taint_test.go drives all of it under
// `-tags unit_test`. main.go only runs the two scans and writes the envelope.
//
// Why a separate entry rather than a flag on ScanSource. ScanSource's Opengrep
// pass follows taint inside one function. A request parameter handed to a
// helper in another file, and concatenated into SQL there, is not found. The
// interfile analysis follows it, and on a mid-sized Go repository it cost
// over ten times the single-function scan's time and more than twice its
// memory; on a large tree it was killed for memory. The cost is set by the
// analysis rather than by how many rules ask for it. That is a
// price a merge gate should not pay by default, and a finding class a
// consumer replacing a hosted code-scanning product should not lose. So it is
// its own step, advisory unless a consumer says otherwise, with the same
// rule that a scan that could not run is never clean.
//
// See specs/report-cross-file-taint-as-advice.md.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// taintPackName is the plan name the manifest below is requested by. Not
	// a registry id: nothing outside this module can ask for it.
	taintPackName = "cicd/interfile-taint"
	// taintToolName is the row, and the SARIF run's automationDetails.id, so
	// the aggregate can tell this run from ScanSource's Opengrep run.
	taintToolName = "opengrep-interfile"

	taintGateEnforce = "gate"
	taintGateWarn    = "warn"
)

//go:embed rules/opengrep-interfile.txt
var opengrepInterfileManifest string

// loadTaintPlan parses the interfile manifest and plans it against the other
// pinned manifests, which are what tell the plan the co-located rules each
// staged file brings with it, so they can be excluded.
func loadTaintPlan() (semgrepPlan, error) {
	packs, err := loadSemgrepPacks()
	if err != nil {
		return semgrepPlan{}, err
	}
	tp, err := parseSemgrepPack(opengrepInterfileManifest)
	if err != nil {
		return semgrepPlan{}, errors.New("opengrep: " + taintPackName + " " + strings.TrimPrefix(err.Error(), "opengrep: "))
	}
	tp.Name = taintPackName
	return semgrepPlanFor(taintPackName, append(packs, tp))
}

// validateTaintGate refuses a mode that is not one of the two. There is no
// "off": a consumer who does not want the advice does not call the step.
func validateTaintGate(mode string) error {
	switch mode {
	case taintGateEnforce, taintGateWarn:
		return nil
	}
	return fmt.Errorf("taint-gate must be %q or %q, got %q", taintGateEnforce, taintGateWarn, mode)
}

// validateInterfileDepth accepts a positive depth or -1 (no limit). Zero is
// refused although Opengrep accepts it: a search that follows no call is the
// single-function scan ScanSource already runs, so the step would report
// nothing at the cost of a second engine pass.
func validateInterfileDepth(depth int) error {
	if depth == -1 || depth >= 1 {
		return nil
	}
	return fmt.Errorf("interfile-depth must be a positive number of calls or -1 for no limit, got %d", depth)
}

// taintInterfileArgs is the plan's arguments plus the interfile switch. The
// baseline run gets plan.Args alone.
//
// The depth is joined with "=": Opengrep's option parser reads a separate
// "-1" as an unknown option and exits 2, so "no limit" spelled as two
// arguments is a scan that never ran.
func taintInterfileArgs(plan semgrepPlan, depth int) []string {
	args := append([]string{}, plan.Args...)
	return append(args, "--enable-interfile", "--interfile-depth="+strconv.Itoa(depth))
}

// taintResult is the step's one row.
type taintResult struct {
	SARIF      json.RawMessage
	BySeverity map[Severity]int
	Examined   *Examined
	Rules      *RuleSet
	// Errs are each a reason the row is not a measurement; any one fails the
	// gate at every threshold, warn mode included.
	Errs     []string
	Warnings []string
}

// analyseTaint turns the two runs into the row. baseline is the same pack
// without interfile analysis; interfile is the same pack with it.
//
// Only the difference is reported. Every finding the single-function run also
// makes is a finding ScanSource reports under p/security-audit, and the
// aggregate sums findings across envelopes, so carrying them here would count
// one defect twice. The difference is a multiset on (rule, file, line,
// column), as the zizmor shadow is: two identical findings, one reported by
// both runs, still leave one.
func analyseTaint(baseline, interfile semgrepScan, baseErr, interErr error, plan semgrepPlan, depth int) taintResult {
	var res taintResult
	if interErr != nil {
		res.Errs = append(res.Errs, taintRunError("interfile", interErr))
	}
	if baseErr != nil {
		res.Errs = append(res.Errs, taintRunError("single-function baseline", baseErr)+
			" — without it, the findings ScanSource also reports cannot be told apart, so the ones below are not only cross-function ones")
	}

	if len(interfile.SARIF) > 0 {
		rs, err := semgrepRuleSet(interfile.SARIF, plan)
		res.Rules = rs
		if err != nil {
			res.Errs = append(res.Errs, err.Error())
		}
	}
	if baseErr == nil && len(baseline.SARIF) > 0 {
		if _, err := semgrepRuleSet(baseline.SARIF, plan); err != nil {
			res.Errs = append(res.Errs, "single-function baseline: "+err.Error())
		}
	}

	res.Examined = interfile.Examined
	if res.Examined != nil {
		res.Examined.Partial = parseSemgrepNotifications(interfile.SARIF).partialFiles()
	}

	res.Warnings = append(res.Warnings, taintScopeWarning(depth))
	res.Warnings = append(res.Warnings, interfile.Warnings...)

	if len(interfile.SARIF) == 0 {
		return res
	}
	res.Warnings = append(res.Warnings, semgrepNotificationWarnings(interfile.SARIF)...)

	sarif := interfile.SARIF
	if baseErr == nil && len(baseline.SARIF) > 0 {
		kept, lost, err := taintDelta(baseline.SARIF, interfile.SARIF)
		if err != nil {
			res.Errs = append(res.Errs, taintToolName+": could not separate cross-function findings from the "+
				"single-function ones: "+err.Error())
		} else {
			sarif = kept
			if lost > 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d finding(s) the single-function scan of "+
					"the same rules reports did not come back from the interfile run; ScanSource still "+
					"reports them and gates on them.",
					taintToolName, lost))
			}
		}
	}
	stamped, err := stampSARIFAutomationID(sarif, taintToolName)
	if err != nil {
		res.Errs = append(res.Errs, taintToolName+": could not encode the SARIF: "+err.Error())
		return res
	}
	res.SARIF = stamped
	res.BySeverity = parseSarifSeverities(stamped)
	if w := sarifSuppressionWarning(taintToolName, stamped); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	return res
}

// taintRunError names which of the two runs failed, and the likeliest cause
// when the kernel killed it: interfile analysis holds the whole program's
// call graph in memory, and an out-of-memory kill is exit 137.
func taintRunError(which string, err error) string {
	msg := taintToolName + ": the " + which + " run did not complete: " + err.Error()
	if strings.Contains(err.Error(), "(exit 137)") {
		msg += " — exit 137 is a kill signal, which for interfile analysis is most often the engine " +
			"running out of memory; a lower --interfile-depth or a narrower --path reduces what it holds"
	}
	return msg
}

// taintScopeWarning is stated on every run, so the advice is read as what it
// is: a narrow rule set, and only the findings ScanSource cannot make.
func taintScopeWarning(depth int) string {
	d := strconv.Itoa(depth)
	if depth == -1 {
		d = "unlimited"
	}
	return taintToolName + ": cross-function and cross-file taint over the " + taintPackName +
		" rules (the pinned audit and OWASP rules whose authors marked them interfile: Go, Java, " +
		"JavaScript and TypeScript; none for C#), call depth " + d + ". Findings the single-function " +
		"scan of the same rules also makes are left to ScanSource and not repeated here."
}

// taintAdvisoryWarning is the warn-mode line: without it, an envelope with
// HIGH findings and passed=true reads as a gate that failed to fire.
func taintAdvisoryWarning(total int) string {
	return fmt.Sprintf("%s: %d cross-function finding(s). taint-gate is %q, so they are reported and not enforced.",
		taintToolName, total, taintGateWarn)
}

// taintDelta drops from interfile each result baseline also has, one for one,
// and returns the remainder and how many baseline results interfile did not
// have.
func taintDelta(baseline, interfile json.RawMessage) (json.RawMessage, int, error) {
	baseResults, err := sarifRunResults(baseline)
	if err != nil {
		return nil, 0, fmt.Errorf("baseline SARIF: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(interfile, &doc); err != nil {
		return nil, 0, fmt.Errorf("interfile SARIF: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		return nil, 0, fmt.Errorf("interfile SARIF: expected one run, got %d", len(runs))
	}
	run, _ := runs[0].(map[string]any)
	if run == nil {
		return nil, 0, errors.New("interfile SARIF: run is not an object")
	}
	remaining := map[string]int{}
	for _, r := range baseResults {
		k, _, _, _ := sarifResultKey(r)
		remaining[k]++
	}
	results, _ := run["results"].([]any)
	kept := make([]any, 0, len(results))
	for _, raw := range results {
		r, _ := raw.(map[string]any)
		if r == nil {
			return nil, 0, errors.New("interfile SARIF: a result is not an object")
		}
		k, _, _, _ := sarifResultKey(r)
		if remaining[k] > 0 {
			remaining[k]--
			continue
		}
		kept = append(kept, r)
	}
	lost := 0
	for _, n := range remaining {
		lost += n
	}
	run["results"] = kept
	out, err := json.Marshal(doc)
	return out, lost, err
}

// sarifRunResults returns the results of a one-run SARIF document.
func sarifRunResults(raw json.RawMessage) ([]map[string]any, error) {
	var doc struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Runs) != 1 {
		return nil, fmt.Errorf("expected one run, got %d", len(doc.Runs))
	}
	return doc.Runs[0].Results, nil
}

// stampSARIFAutomationID sets automationDetails.id on every run, so the
// aggregate keys this run apart from ScanSource's Opengrep run, which has the
// same driver name.
func stampSARIFAutomationID(raw json.RawMessage, id string) (json.RawMessage, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	runs, _ := doc["runs"].([]any)
	for _, r := range runs {
		if run, ok := r.(map[string]any); ok {
			run["automationDetails"] = map[string]any{"id": id}
		}
	}
	return json.Marshal(doc)
}
