// Consumer-owned ZAP rule configuration, and the disclosure that goes with it.
//
// ZAP takes a rule config with -c and cicd could simply hand the file over. It
// does not: the file is parsed here first, so every rule the consumer switched
// off is named in the evidence. A suppression nobody can see in the report is
// the same shape as a scanner that did not run — the report is quiet, and the
// quiet has a cause nobody is told about.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger.
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ZAP rule actions, as the -c config file spells them.
const (
	zapRuleIgnore = "IGNORE"
	zapRuleWarn   = "WARN"
	zapRuleFail   = "FAIL"
)

// zapRuleSetting is one line of a ZAP rule config.
type zapRuleSetting struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Note   string `json:"note,omitempty"`
	// Fired is whether the scan produced an alert for this rule id. Only
	// meaningful after the report has been parsed; it is what turns "this rule
	// is suppressed" into "this rule is suppressed and matched nothing", which
	// say-what-the-licence-scan-covered requires an exclusion to state.
	Fired bool `json:"fired"`
}

// parseZAPRuleConfig reads a ZAP -c rule config.
//
// A line it cannot parse is an error and not a skip. The output of this
// function is a disclosure, and a disclosure assembled by dropping the entries
// it did not understand is worse than no disclosure: it reads as complete.
func parseZAPRuleConfig(content string) ([]zapRuleSetting, error) {
	var out []zapRuleSetting
	seen := map[string]bool{}

	for i, raw := range strings.Split(content, "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// ZAP writes the file tab-separated; hand-edited copies routinely use
		// spaces. Both are accepted, because a config that ZAP reads and cicd
		// refuses would make the disclosure the reason a scan cannot run.
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == '\t' })
		if len(fields) < 2 {
			fields = strings.Fields(line)
		}
		for j := range fields {
			fields[j] = strings.TrimSpace(fields[j])
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("zap rule config line %d: expected \"<rule id> <IGNORE|WARN|FAIL> [note]\", got %s",
				lineNo, strconv.Quote(line))
		}

		id := fields[0]
		action := strings.ToUpper(fields[1])
		switch action {
		case zapRuleIgnore, zapRuleWarn, zapRuleFail:
		default:
			return nil, fmt.Errorf("zap rule config line %d: unknown action %s for rule %s: expected IGNORE, WARN or FAIL",
				lineNo, strconv.Quote(fields[1]), strconv.Quote(id))
		}
		if seen[id] {
			return nil, fmt.Errorf("zap rule config line %d: rule %s is configured twice; ZAP keeps one of them and cicd cannot say which",
				lineNo, strconv.Quote(id))
		}
		seen[id] = true

		note := ""
		if len(fields) > 2 {
			note = strings.TrimSpace(strings.Join(fields[2:], " "))
		}
		out = append(out, zapRuleSetting{ID: id, Action: action, Note: note})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// markFiredRules records, for each configured rule, whether the scan produced
// an alert under that id.
func markFiredRules(settings []zapRuleSetting, firedIDs []string) []zapRuleSetting {
	fired := map[string]bool{}
	for _, id := range firedIDs {
		fired[id] = true
	}
	out := make([]zapRuleSetting, len(settings))
	copy(out, settings)
	for i := range out {
		out[i].Fired = fired[out[i].ID]
	}
	return out
}

// ruleConfigWarnings states what the rule config changed, one line per claim.
//
// Three rules, inherited from say-what-the-licence-scan-covered and applied to
// a scanner instead of a licence scan:
//
//  1. It narrows scope, never findings — so the suppressed ids are named, not
//     counted.
//  2. Nothing is excluded silently — so a config that is present always
//     produces a line, even one that suppresses nothing.
//  3. A pattern that matched nothing says so — so a suppressed rule that never
//     fired is called out separately. It is the one entry a reader can act on
//     immediately: it is either stale, or it is evidence the suppression was
//     never needed.
func ruleConfigWarnings(settings []zapRuleSetting) []string {
	if len(settings) == 0 {
		return nil
	}

	var ignored, downgraded, escalated []string
	for _, s := range settings {
		switch s.Action {
		case zapRuleIgnore:
			ignored = append(ignored, s.ID)
		case zapRuleWarn:
			downgraded = append(downgraded, s.ID)
		case zapRuleFail:
			escalated = append(escalated, s.ID)
		}
	}

	var out []string
	if len(ignored) > 0 {
		out = append(out, "dast: RULES SUPPRESSED — the rule config sets "+
			strconv.Itoa(len(ignored))+" rule(s) to IGNORE, so any alert they would have raised is absent from this report: "+
			strings.Join(ignored, ", "))
	}
	if len(downgraded) > 0 {
		out = append(out, "dast: RULES DOWNGRADED — set to WARN by the rule config: "+strings.Join(downgraded, ", "))
	}
	if len(escalated) > 0 {
		out = append(out, "dast: RULES ESCALATED — set to FAIL by the rule config: "+strings.Join(escalated, ", "))
	}

	var unmatched []string
	for _, s := range settings {
		if s.Action == zapRuleIgnore && !s.Fired {
			unmatched = append(unmatched, s.ID)
		}
	}
	if len(unmatched) > 0 {
		out = append(out, "dast: SUPPRESSION MATCHED NOTHING — these rules are set to IGNORE and raised no alert on this target, so the suppression is either stale or was never needed: "+
			strings.Join(unmatched, ", "))
	}
	return out
}
