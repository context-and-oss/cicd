// Disclosure of the findings a gitleaks suppression removed.
//
// Deliberately untagged (no //go:build !unit_test), so gitleakssuppress_test.go
// can drive it: the runner in secrets_source.go only fetches the files.
//
// gitleaks has three ways to drop a finding, and none of them leaves a trace in
// its report: an inline `gitleaks:allow` on the line, a fingerprint in
// .gitleaksignore, and an [allowlist] (or a rule set that omits or narrows a
// default rule) in .gitleaks.toml. Each is a legitimate acceptance and each is
// written by the repository being graded, so a pass that rests on one reads
// exactly like a pass on a clean tree. That is the doctrine rule "an
// acceptance nobody can read is indistinguishable from a bug".
//
// The mechanism is a second tree scan — the shadow — with every suppression
// turned off: .gitleaks.toml and .gitleaksignore removed from a copy of the
// tree, and --ignore-gitleaks-allow. A finding the shadow reports and the real
// scan does not is one a suppression removed. It goes back into the report
// carrying a SARIF suppression, so it is visible and is not counted, and
// warnings[] names it under the mechanism that removed it.
//
// The shadow is run only when there is something to measure: a config or an
// ignore file at the root, or a mark (or an unreadable mark list). A tree with
// none of the three pays nothing.
//
// The history leg is not shadowed. A finding suppressed in history is not
// disclosed; see specs/disclose-gitleaks-suppressions.md.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// gitleaksConfigFile and gitleaksIgnoreFile are the two files gitleaks reads
// from the root of the scanned tree. Only the root: gitleaks loads neither
// from a subdirectory.
const (
	gitleaksConfigFile = ".gitleaks.toml"
	gitleaksIgnoreFile = ".gitleaksignore"
)

// gitleaksSuppressionFiles reports which of gitleaks' suppression files the
// tree's root carries, from the root's Entries(). A directory of the same name
// is not the file: Dagger reports a directory with a trailing separator.
func gitleaksSuppressionFiles(entries []string) (hasConfig, hasIgnore bool) {
	for _, e := range entries {
		switch e {
		case gitleaksConfigFile:
			hasConfig = true
		case gitleaksIgnoreFile:
			hasIgnore = true
		}
	}
	return hasConfig, hasIgnore
}

// gitleaksShadowNeeded reports whether any suppression could have removed a
// finding. Unknown marks count as present: a tree whose mark list could not be
// read is not a tree known to have none.
func gitleaksShadowNeeded(hasConfig, hasIgnore bool, marks []gitleaksMark, marksKnown bool) bool {
	return hasConfig || hasIgnore || len(marks) > 0 || !marksKnown
}

// gitleaksMark is one `gitleaks:allow` in the tree.
type gitleaksMark struct {
	File string
	Line int
}

// parseGitleaksAllowMarks reads gitleaksAllowMarksScript's output: one
// "./path:line:gitleaks:allow" per mark, and grep's exit status. It returns
// false when the list is unknown — any exit but 0 (found) or 1 (none found).
func parseGitleaksAllowMarks(raw, exit string) ([]gitleaksMark, bool) {
	switch strings.TrimSpace(exit) {
	case "0", "1":
	default:
		return nil, false
	}
	var out []gitleaksMark
	seen := map[gitleaksMark]bool{}
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSuffix(l, ":gitleaks:allow")
		i := strings.LastIndexByte(l, ':')
		if i < 0 {
			continue
		}
		n, err := strconv.Atoi(l[i+1:])
		if err != nil {
			continue
		}
		m := gitleaksMark{File: gitleaksRelPath(l[:i]), Line: n}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out, true
}

// gitleaksFingerprint is one .gitleaksignore entry gitleaks applied, as its
// debug log names it: "file:rule:line" for the tree leg.
type gitleaksFingerprint struct {
	File string
	Rule string
	Line int
}

// parseGitleaksIgnored reads gitleaks.ignored: the fingerprint of each finding
// a .gitleaksignore entry removed. It splits from the right, because a path
// may hold a colon and a rule id and a line number may not.
func parseGitleaksIgnored(raw string) []gitleaksFingerprint {
	var out []gitleaksFingerprint
	for _, l := range strings.Split(raw, "\n") {
		l = gitleaksLogPath(l)
		j := strings.LastIndexByte(l, ':')
		if j < 0 {
			continue
		}
		n, err := strconv.Atoi(l[j+1:])
		if err != nil {
			continue
		}
		i := strings.LastIndexByte(l[:j], ':')
		if i < 0 {
			continue
		}
		out = append(out, gitleaksFingerprint{File: gitleaksRelPath(l[:i]), Rule: l[i+1 : j], Line: n})
	}
	return out
}

// gitleaksRelPath puts a path from grep ("./a.go"), from the log and from the
// SARIF on one spelling, so the three can be compared.
func gitleaksRelPath(p string) string {
	return strings.TrimPrefix(p, "./")
}

// gitleaksSuppression is one way a finding was removed, in the order the
// warnings name them.
type gitleaksSuppression int

const (
	suppressedByIgnoreFile gitleaksSuppression = iota
	suppressedByAllowMark
	suppressedByConfig
	suppressedUnattributed
)

// what is the mechanism as the warning names it; kind is the SARIF
// suppression kind: a mark sits in the source, the other files beside it.
func (s gitleaksSuppression) what() (what, kind string) {
	switch s {
	case suppressedByIgnoreFile:
		return "a fingerprint in " + gitleaksIgnoreFile, "external"
	case suppressedByAllowMark:
		return "an inline gitleaks:allow", "inSource"
	case suppressedByConfig:
		return "the scanned tree's " + gitleaksConfigFile +
			" (an [allowlist] entry, or a default rule it disables, narrows or does not load)", "external"
	default:
		return "a suppression cicd could not identify (a gitleaks:allow inside an archive, " +
			"or in a tree whose marks could not be listed)", "external"
	}
}

// gitleaksDiscloseSuppressions returns primary with every finding a
// suppression removed put back as a suppressed result, and one warning per
// mechanism that removed anything, plus one naming the default rules the
// tree's config does not load.
//
// shadow is the same tree scanned with every suppression off. ignored and
// marks attribute what the difference holds; marksKnown false means the mark
// list could not be read, and a finding no fingerprint explains is then not
// pinned on the config either, because a mark cicd could not see may be what
// removed it.
//
// A primary that cannot be rewritten is returned as it was, with a warning
// saying the suppressed findings could not be attached: the disclosure is
// lost, never the scan.
func gitleaksDiscloseSuppressions(primary, shadow json.RawMessage, ignored []gitleaksFingerprint,
	marks []gitleaksMark, marksKnown, hasConfig bool, scope string) (json.RawMessage, []string) {
	var warnings []string
	if hasConfig {
		if w := gitleaksNarrowedRules(primary, shadow, scope); w != "" {
			warnings = append(warnings, w)
		}
	}

	// A multiset, so a rule that fires twice on one line in the shadow and
	// once in the real scan leaves one suppressed result, not zero.
	inPrimary := map[string]int{}
	for _, raw := range gitleaksRawResults(primary) {
		var r gitleaksSARIFResult
		if err := json.Unmarshal(raw, &r); err == nil && !r.suppressed() {
			inPrimary[r.key()]++
		}
	}
	ignoredSet := map[gitleaksFingerprint]bool{}
	for _, f := range ignored {
		ignoredSet[f] = true
	}
	marked := map[gitleaksMark]bool{}
	for _, m := range marks {
		marked[m] = true
	}

	byMechanism := map[gitleaksSuppression][]string{}
	var extra []any
	for _, raw := range gitleaksRawResults(shadow) {
		var r gitleaksSARIFResult
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		if inPrimary[r.key()] > 0 {
			inPrimary[r.key()]--
			continue
		}
		file := gitleaksRelPath(r.file())
		how := suppressedUnattributed
		switch {
		case ignoredSet[gitleaksFingerprint{File: file, Rule: r.RuleID, Line: r.line()}]:
			how = suppressedByIgnoreFile
		case gitleaksMarkedSpan(marked, file, r.line(), r.endLine()):
			how = suppressedByAllowMark
		// The mark grep cannot open an archive, so inside one a mark is never
		// ruled out, and pinning the finding on the config could be wrong.
		case marksKnown && hasConfig && !strings.Contains(file, "!"):
			how = suppressedByConfig
		}
		byMechanism[how] = append(byMechanism[how], file+":"+strconv.Itoa(r.line())+" "+r.RuleID)

		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		what, kind := how.what()
		v["suppressions"] = []any{map[string]any{
			"kind":          kind,
			"status":        "accepted",
			"justification": "removed by " + what + "; reported by cicd, not counted",
		}}
		extra = append(extra, v)
	}

	for how := suppressedByIgnoreFile; how <= suppressedUnattributed; how++ {
		names := byMechanism[how]
		if len(names) == 0 {
			continue
		}
		what, _ := how.what()
		list, _ := gitleaksNameList(names)
		warnings = append(warnings, "gitleaks: SUPPRESSED — "+plural(len(names), "finding", "findings")+
			" in the "+scope+" "+oneOrMany(len(names), "was", "were")+" removed by "+what+
			" and "+oneOrMany(len(names), "is", "are")+" not counted: "+list)
	}

	if len(extra) == 0 {
		return primary, warnings
	}
	out, ok := gitleaksAppendResults(primary, extra)
	if !ok {
		return primary, append(warnings, "gitleaks: the "+plural(len(extra), "suppressed finding", "suppressed findings")+
			" named above could not be attached to the SARIF report, which lists only the counted findings")
	}
	return out, warnings
}

// gitleaksMarkedSpan reports whether a mark sits on any line of the finding.
// gitleaks honours the mark on the finding's line, and for a multi-line secret
// on any line of it.
func gitleaksMarkedSpan(marked map[gitleaksMark]bool, file string, start, end int) bool {
	for l := start; l <= end; l++ {
		if marked[gitleaksMark{File: file, Line: l}] {
			return true
		}
	}
	return false
}

// gitleaksNarrowedRules names the default rules the tree's config does not
// load: the shadow ran on gitleaks' defaults, so its rule list is the default
// set, and an id missing from the real scan's list is a rule nothing applied.
// Zero rules is not reached here: gitleaksRunError refuses it as a non-run.
func gitleaksNarrowedRules(primary, shadow json.RawMessage, scope string) string {
	loaded := gitleaksRuleIDs(primary)
	defaults := gitleaksRuleIDs(shadow)
	have := map[string]bool{}
	for _, id := range loaded {
		have[id] = true
	}
	var missing []string
	for _, id := range defaults {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	list, _ := gitleaksNameList(missing)
	return "gitleaks: NARROWED RULES — the " + scope + "'s " + gitleaksConfigFile + " loads " +
		plural(len(loaded), "rule", "rules") + " and leaves out " + strconv.Itoa(len(missing)) +
		" of gitleaks' " + strconv.Itoa(len(defaults)) + " default rules, which searched for nothing: " + list
}

// gitleaksRuleIDs lists the rule ids a report says gitleaks loaded.
func gitleaksRuleIDs(raw json.RawMessage) []string {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []string
	for _, run := range doc.Runs {
		for _, r := range run.Tool.Driver.Rules {
			out = append(out, r.ID)
		}
	}
	return out
}

// gitleaksAppendResults appends results to the first run of doc.
func gitleaksAppendResults(doc json.RawMessage, results []any) (json.RawMessage, bool) {
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, false
	}
	runs, ok := m["runs"].([]any)
	if !ok || len(runs) == 0 {
		return nil, false
	}
	run0, ok := runs[0].(map[string]any)
	if !ok {
		return nil, false
	}
	existing, _ := run0["results"].([]any)
	run0["results"] = append(existing, results...)
	out, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return out, true
}
