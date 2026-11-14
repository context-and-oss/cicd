package main

import (
	_ "embed"
	"encoding/json"
	"strings"
)

const (
	semgrepGHACurlPipeRuleID = "yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell"
	semgrepGHAFallbackRuleID = "cicd.yaml.github-actions.security.gha-curl-pipe-shell"
	semgrepGHAFallbackPath   = "/" + semgrepCicdRuleDir + "/gha-curl-pipe-shell.yml"
	semgrepGHAAdapterPath    = "/cicd-semgrep-pack/gha.py"
	// semgrepCicdRuleDir is where cicd's rule configs are written. Semgrep
	// names a rule from a config outside its working directory by that
	// directory, so the id it loads is not the rule's own: measured on 1.162.0,
	// the fallback loads as semgrepGHAFallbackLoadedID. That loaded id is what
	// semgrepRuleLanguage sees, and a test fed the YAML id passed against a
	// classifier that never matched a real scan.
	semgrepCicdRuleDir         = "cicd-rules"
	semgrepGHAFallbackLoadedID = semgrepCicdRuleDir + "." + semgrepGHAFallbackRuleID
	semgrepGHAFallbackWarning  = "opengrep: RULE FALLBACK — the upstream " + semgrepGHACurlPipeRuleID +
		" rule could not parse one or more GitHub Actions run blocks, so cicd reran the scan with that rule excluded and its runtime-adapted parser-safe equivalent enabled; no affected file was left on the first pass's partial verdict."
)

// Only the first-party adapter is distributed. Upstream structural patterns
// and their notices are read from the pinned checkout in the scan container.
//
//go:embed semgrep_gha.py
var semgrepGHAAdapter string

func semgrepUsesGHAFallback(args []string) bool {
	for i := 1; i < len(args); i += 2 {
		if args[i-1] == "--config" && args[i] == semgrepGHAFallbackPath {
			return true
		}
	}
	return false
}

// semgrepNeedsGHACurlPipeFallback is deliberately exact. A generic syntax
// notification remains a partial-scan warning; only the measured upstream rule
// has an equivalent implementation cicd can substitute without losing a check.
func semgrepNeedsGHACurlPipeFallback(raw json.RawMessage) bool {
	var doc sarifInvocationsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	for _, run := range doc.Runs {
		for _, inv := range run.Invocations {
			for _, note := range inv.ToolExecutionNotifications {
				if note.Descriptor != nil && note.Descriptor.ID == semgrepNoticeSyntax &&
					strings.Contains(note.Message.Text, semgrepGHACurlPipeRuleID) {
					return true
				}
			}
		}
	}
	return false
}

// semgrepGHAFallbackArgs preserves every caller-selected config and changes
// exactly one rule: the parser-fragile registry implementation is excluded and
// the runtime-adapted equivalent is added. A fresh slice keeps the first invocation's
// arguments immutable for Dagger's graph.
//
// A pinned pack that held the upstream rule is planned with the adapted one
// already (semgrepPlanFor), so the fallback can only fire for a live pack that
// brought the upstream rule back.
// The generated config is then not added twice: one rule id loaded from one
// path twice is a duplicate semgrep has no reason to tolerate.
func semgrepGHAFallbackArgs(configs []string) []string {
	out := append([]string(nil), configs...)
	out = append(out, "--exclude-rule", semgrepGHACurlPipeRuleID)
	for i := 1; i < len(configs); i += 2 {
		if configs[i-1] == "--config" && configs[i] == semgrepGHAFallbackPath {
			return out
		}
	}
	return append(out, "--config", semgrepGHAFallbackPath)
}
