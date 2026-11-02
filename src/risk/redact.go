// Secret-value scrubbing for the snippets the AI scan quotes into findings.
// src/quality/redact.go is the sibling, not a copy: it removes a whole
// credential shape from tool output, while this file keeps the key of a
// suspected assignment and blanks only its value, because a reviewer
// triaging a finding needs to see what was assigned.
package main

import (
	"regexp"
	"strings"
)

// redactedMarker replaces the value portion of suspected secret assignments
// in finding snippets. The file path and line numbers stay intact so triage
// still has somewhere to look.
const redactedMarker = "<redacted>"

// secretKeyHint matches identifier tokens that signal the adjacent value is a
// credential. Case-insensitive substring match over the *key* portion of a
// KEY=VAL / "key":"val" / key: val expression.
var secretKeyHint = regexp.MustCompile(`(?i)secret|token|password|passwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?key|credential|bearer`)

// Env-file assignment: KEY=value, captured up to EOL / comment / quote close.
var envAssignPattern = regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*("([^"]*)"|'([^']*)'|[^\r\n#]*)`)

// JSON / TOML quoted assignment: "key": "value"  or  "key" = "value".
var quotedAssignPattern = regexp.MustCompile(`("([A-Za-z_][A-Za-z0-9_.-]*)"[ \t]*[:=][ \t]*)"([^"]*)"`)

// YAML / generic indented mapping: key: value, accepting double-quoted,
// single-quoted, or unquoted scalars on the right-hand side.
var yamlAssignPattern = regexp.MustCompile(`(?m)^([ \t]*)([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*:[ \t]+)("[^"\r\n]*"|'[^'\r\n]*'|[^"\s#\r\n][^\r\n#]*)`)

// PEM-armoured block — replace the base64 body, keep the BEGIN/END markers
// so the kind of credential is still obvious.
var pemBlockPattern = regexp.MustCompile(`(?s)(-----BEGIN [A-Z0-9 ]+-----)\s*(.+?)\s*(-----END [A-Z0-9 ]+-----)`)

// redactSnippet replaces credential-like values in a finding's evidence
// snippet with redactedMarker. It is deliberately conservative — it only
// redacts when the key/identifier next to the value hints at a secret, so
// ordinary code containing the word "password" in prose isn't touched.
//
// Patterns covered:
//   - KEY=value (env files)
//   - "key": "value" / "key" = "value" (JSON, TOML)
//   - key: value (YAML)
//   - PEM-armoured blocks (the base64 body is wiped, BEGIN/END stay)
func redactSnippet(s string) string {
	if s == "" {
		return s
	}

	s = pemBlockPattern.ReplaceAllString(s, "$1\n"+redactedMarker+"\n$3")

	s = envAssignPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := envAssignPattern.FindStringSubmatch(m)
		if !secretKeyHint.MatchString(sub[1]) {
			return m
		}
		return sub[1] + "=" + redactedMarker
	})

	s = quotedAssignPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := quotedAssignPattern.FindStringSubmatch(m)
		if !secretKeyHint.MatchString(sub[2]) {
			return m
		}
		return sub[1] + `"` + redactedMarker + `"`
	})

	s = yamlAssignPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := yamlAssignPattern.FindStringSubmatch(m)
		if !secretKeyHint.MatchString(sub[2]) {
			return m
		}
		// Preserve the operator's quoting style — a quoted value redacted
		// without quotes would change the YAML scalar's parsed type.
		value := sub[4]
		switch {
		case strings.HasPrefix(value, `"`):
			return sub[1] + sub[2] + sub[3] + `"` + redactedMarker + `"`
		case strings.HasPrefix(value, `'`):
			return sub[1] + sub[2] + sub[3] + `'` + redactedMarker + `'`
		default:
			return sub[1] + sub[2] + sub[3] + redactedMarker
		}
	})

	return s
}

// redactFindings runs redactSnippet over every finding's Evidence.Snippet
// before findings.json is written. README tells operators to commit that
// file — without this pass, a credential the scan flagged would be
// re-committed verbatim alongside the warning about it.
func redactFindings(findings []Finding) []Finding {
	for i := range findings {
		findings[i].Evidence.Snippet = redactSnippet(findings[i].Evidence.Snippet)
	}
	return findings
}
