// Withholding the source text semgrep copies into its SARIF report.
//
// Deliberately untagged (no //go:build !unit_test): this is JSON rewriting,
// none of which needs Dagger, so semgrepredact_test.go can drive it under
// `go test -tags unit_test`.
//
// Why this file exists. semgrep writes the matched source into every result —
// region.snippet.text holds the whole matched line — and that SARIF is passed
// into the evidence envelope's sarifReport, which is a build artifact anyone
// with repository read access can download. p/security-audit carries the
// generic.secrets.* rules, so the matched line is, by construction, the line
// holding the credential. Measured on the pinned semgrep 1.162.0 against a
// file with an AWS key: the key appeared verbatim in the envelope, in the one scanner the
// gitleaks leg's --redact never governed. See specs/redact-semgrep-snippets.md.
//
// Three fields can carry source text, and all three are rewritten:
//
//   - every "snippet" key at any depth inside a result — physicalLocation,
//     contextRegion, relatedLocations, codeFlows — is removed. Lines and
//     columns stay, so the finding still points at its line;
//   - "fixes" is removed. 87 of the pinned rule files carry fix: or
//     fix-regex:, whose replacement text is built from the matched source;
//   - message.text is replaced with the rule's own message as the rule set
//     declares it, from tool.driver.rules[].fullDescription. semgrep
//     interpolates metavariables into the result's message, and 82 of the
//     pinned rule files do so — yaml/kubernetes/security/secrets-in-config-file
//     writes "Secrets ($VALUE) should not be stored…" with the secret in $VALUE.
//     The rule's declared message keeps the placeholder. Every other nested
//     message inside a result (a codeFlows step, a related location) is
//     removed, because semgrep writes those from the matched code too.
//
// One more field carries source text, and it is not in a result: the
// notification semgrep writes for a file its parser rejected quotes what it
// rejected between backticks. Measured on 1.162.0, the quote is whatever the
// parser gave up on, up to the whole line — a JavaScript file gave
// "Syntax error at line b.js:1:\n `function f( { const k = \"…\" }` was
// unexpected", string literal included — so a credential on a line the parser
// cannot read is copied into the report and into the PARTIAL SCAN warning
// semgrepnotifications.go builds from it. withholdSemgrepQuotedSource replaces
// the quote in every notification's message, keeping the path, the line and
// any rule id, which semgrep quotes with single quotes and
// semgrepNeedsGHACurlPipeFallback reads.
//
// What stays is everything triage and the rest of this module need: ruleId,
// uri, lines, columns, suppressions, fingerprints, properties, the rule
// catalogue and the notifications, less the source they quoted.
//
// The rewrite cannot fail open. A report this file cannot read is refused
// rather than passed through: an unreadable document is exactly the one whose
// text cicd cannot prove it withheld.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// semgrepSourceWithheld stands where a notification quoted source. Square
// brackets, not angle brackets: notify renders warnings as markdown, where
// <source withheld> would be swallowed as an HTML tag and read as nothing.
const semgrepSourceWithheld = "[source withheld]"

// semgrepWithheldMessage is the message a result gets when its rule is not in
// the report's rule catalogue, so there is no declared message to fall back
// to. It still names the rule.
func semgrepWithheldMessage(ruleID string) string {
	return "semgrep rule " + ruleID + " matched here; its message is withheld because semgrep writes it from the matched source"
}

// redactSemgrepSARIF returns raw with every piece of matched source text
// removed from its results, and an error when raw cannot be read as a SARIF
// document.
func redactSemgrepSARIF(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps every line, column and count exactly as semgrep wrote
	// it instead of round-tripping it through float64.
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("semgrep: could not read the report to withhold its source text, so it is not passed on: " + err.Error())
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return nil, errors.New("semgrep: the report has no runs array, so cicd cannot prove it withheld the matched source text, and it is not passed on")
	}
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			return nil, errors.New("semgrep: a run in the report is not an object, so its source text cannot be withheld")
		}
		if err := withholdSemgrepNotificationSource(run); err != nil {
			return nil, err
		}
		messages := semgrepRuleMessages(run)
		results, _ := run["results"].([]any)
		for _, res := range results {
			result, ok := res.(map[string]any)
			if !ok {
				return nil, errors.New("semgrep: a result in the report is not an object, so its source text cannot be withheld")
			}
			ruleID, _ := result["ruleId"].(string)
			stripSemgrepSource(result)
			text, ok := messages[ruleID]
			if !ok {
				text = semgrepWithheldMessage(ruleID)
			}
			result["message"] = map[string]any{"text": text}
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("semgrep: could not re-encode the report after withholding its source text: " + err.Error())
	}
	return out, nil
}

// semgrepRuleMessages maps each rule id in run's catalogue to the message the
// rule declares, uninterpolated.
func semgrepRuleMessages(run map[string]any) map[string]string {
	out := map[string]string{}
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		id, _ := rule["id"].(string)
		full, _ := rule["fullDescription"].(map[string]any)
		if text, _ := full["text"].(string); id != "" && text != "" {
			out[id] = text
		}
	}
	return out
}

// stripSemgrepSource removes from one result every field semgrep fills from
// the matched source: snippets and nested messages at any depth, and fixes.
// The result's own message is replaced by the caller.
func stripSemgrepSource(result map[string]any) {
	delete(result, "fixes")
	for key, v := range result {
		if key == "message" {
			continue
		}
		stripSemgrepSourceIn(v)
	}
}

func stripSemgrepSourceIn(v any) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "snippet")
		delete(t, "message")
		for _, child := range t {
			stripSemgrepSourceIn(child)
		}
	case []any:
		for _, child := range t {
			stripSemgrepSourceIn(child)
		}
	}
}

// withholdSemgrepQuotedSource replaces the source a notification message
// quotes with semgrepSourceWithheld.
//
// The span is the first backtick to the LAST one, not each backtick pair. The
// quoted text is source, and source can hold backticks itself — a JavaScript
// template literal, a shell command substitution — so pairing them would hand
// back whatever sat between the second and third. Greedy can over-withhold
// prose between two quotes; that is the side to err on. A lone backtick
// withholds to the end of the message for the same reason.
func withholdSemgrepQuotedSource(text string) string {
	first := strings.IndexByte(text, '`')
	if first < 0 {
		return text
	}
	last := strings.LastIndexByte(text, '`')
	if last == first {
		return text[:first] + semgrepSourceWithheld
	}
	return text[:first] + semgrepSourceWithheld + text[last+1:]
}

// withholdSemgrepNotificationSource rewrites every notification in run's
// invocations: the quoted source in each message, and any snippet at any
// depth. Configuration notifications get the same treatment as execution
// ones; semgrep has not been measured quoting source there, and the rewrite
// changes nothing in a message that quotes none.
//
// A notification list cicd cannot walk is an error, for the reason
// redactSemgrepSARIF gives: what it cannot read it cannot prove it withheld.
func withholdSemgrepNotificationSource(run map[string]any) error {
	raw, present := run["invocations"]
	if !present {
		return nil
	}
	invocations, ok := raw.([]any)
	if !ok {
		return errors.New("semgrep: the report's invocations are not an array, so the source text its notifications quote cannot be withheld")
	}
	for _, i := range invocations {
		invocation, ok := i.(map[string]any)
		if !ok {
			return errors.New("semgrep: an invocation in the report is not an object, so the source text its notifications quote cannot be withheld")
		}
		for _, key := range []string{"toolExecutionNotifications", "toolConfigurationNotifications"} {
			raw, present := invocation[key]
			if !present {
				continue
			}
			notes, ok := raw.([]any)
			if !ok {
				return errors.New("semgrep: the report's " + key + " are not an array, so the source text they quote cannot be withheld")
			}
			for _, n := range notes {
				if _, ok := n.(map[string]any); !ok {
					return errors.New("semgrep: a notification in the report is not an object, so the source text it quotes cannot be withheld")
				}
				withholdSemgrepNotificationSourceIn(n)
			}
		}
	}
	return nil
}

func withholdSemgrepNotificationSourceIn(v any) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "snippet")
		if message, ok := t["message"].(map[string]any); ok {
			for _, field := range []string{"text", "markdown"} {
				if text, ok := message[field].(string); ok {
					message[field] = withholdSemgrepQuotedSource(text)
				}
			}
		}
		for _, child := range t {
			withholdSemgrepNotificationSourceIn(child)
		}
	case []any:
		for _, child := range t {
			withholdSemgrepNotificationSourceIn(child)
		}
	}
}
