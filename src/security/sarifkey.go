package main

import "strconv"

// sarifResultKey identifies a finding across two runs of one tool: the rule
// and its primary location, start line and column. A location is part of a
// finding's identity, so two template injections in one file are two
// findings. Shared by the zizmor shadow (what a suppression removed) and the
// interfile taint delta (what the single-function run already reports); both
// are multiset differences over this key, and must agree on what "the same
// finding" means.
func sarifResultKey(r map[string]any) (key, uri, rule string, line int) {
	rule, _ = r["ruleId"].(string)
	locs, _ := r["locations"].([]any)
	if len(locs) > 0 {
		loc, _ := locs[0].(map[string]any)
		phys, _ := loc["physicalLocation"].(map[string]any)
		art, _ := phys["artifactLocation"].(map[string]any)
		uri, _ = art["uri"].(string)
		region, _ := phys["region"].(map[string]any)
		l, _ := region["startLine"].(float64)
		c, _ := region["startColumn"].(float64)
		line = int(l)
		return rule + "\x00" + uri + "\x00" + strconv.Itoa(int(l)) + ":" + strconv.Itoa(int(c)), uri, rule, line
	}
	return rule + "\x00", "", rule, 0
}
