// conftest non-run message composition.
//
// Deliberately untagged (no //go:build !unit_test): shaping the errors[] entry is
// pure string work, so conftestrun_test.go can drive the real thing under
// `go test -tags unit_test ./...`. Unwrapping Dagger's *dagger.ExecError needs the
// SDK and therefore stays in opa.go.
package main

import "strings"

// conftestStderrBudget bounds how much of conftest's stderr reaches the evidence
// envelope. The envelope is read in PR comments and Teams cards, and a rego
// compile failure can print hundreds of lines — enough to bury every other entry.
// The head is kept rather than the tail because the first diagnostic is the cause
// and the rest is usually its consequences.
const conftestStderrBudget = 400

// conftestFailureMessage composes the errors[] entry for a conftest that could not
// run. It states which group was being evaluated, because a repository has several
// (one per parser/namespace) and knowing "the yaml one" narrows the cause
// immediately, and it says plainly that this is not a policy verdict — the failure
// mode it replaces was a synthetic violation, and a reader who has seen those needs
// telling that this line means the engine never spoke.
func conftestFailureMessage(parser, namespace, errText, stderr string) string {
	msg := "conftest infra pass (parser " + parser + ", namespace " + namespace +
		"): the policy engine did not run, so this is not a policy verdict"
	if e := strings.TrimSpace(errText); e != "" {
		msg += ": " + e
	}
	if s := boundedStderr(stderr); s != "" {
		msg += " — stderr: " + s
	}
	return msg
}

// boundedStderr collapses stderr to a single bounded line. Newlines become " | "
// so the entry survives being rendered in a markdown list, where a raw newline
// silently ends the item and drops everything after it.
func boundedStderr(stderr string) string {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return ""
	}
	var parts []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			parts = append(parts, line)
		}
	}
	s = strings.Join(parts, " | ")
	if len(s) > conftestStderrBudget {
		// Byte truncation can split a multi-byte rune; trimming the invalid tail
		// keeps the string valid UTF-8 so JSON marshalling does not replace it.
		s = strings.ToValidUTF8(s[:conftestStderrBudget], "") + "…"
	}
	return s
}
