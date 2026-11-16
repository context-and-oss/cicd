// cicd's own Opengrep rules: what each one is, where the scan finds it, and
// the id it loads under.
//
// Deliberately untagged (no //go:build !unit_test): constants and embedded
// rule bodies, which the plan and the rule-set check read under unit tests.
package main

import _ "embed"

// semgrepFirstParty is one rule file cicd writes into the scan container. A
// plan that adds it also requires it: a first-party rule that did not load is
// a default scan that is smaller than it says, the same as a pinned rule
// below the floor.
type semgrepFirstParty struct {
	// ID is the rule's own id, as written in the file.
	ID string
	// File is the file name under semgrepCicdRuleDir.
	File string
	// Body is the embedded rule file.
	Body string
	// Interfile is true when the rule sets options.interfile, which is what
	// puts it in ScanTaint's plan as well as ScanSource's.
	Interfile bool
	// What names the rule in the error raised when it did not load.
	What string
}

// Path is where the rule file is written, and the --config that loads it.
func (r semgrepFirstParty) Path() string { return "/" + semgrepCicdRuleDir + "/" + r.File }

// LoadedID is the id the scan reports: Opengrep prefixes a rule from a config
// outside its working directory with that directory (see semgrepCicdRuleDir).
func (r semgrepFirstParty) LoadedID() string { return semgrepCicdRuleDir + "." + r.ID }

//go:embed rules/dom-text-to-html.yml
var semgrepDOMRuleBody string

//go:embed rules/csharp-log-forging.yml
var semgrepCSharpLogForgingBody string

//go:embed rules/csharp-secret-in-log.yml
var semgrepCSharpSecretInLogBody string

var (
	semgrepDOMRule = semgrepFirstParty{
		ID: "cicd.javascript.dom-text-to-html", File: "dom-text-to-html.yml",
		Body: semgrepDOMRuleBody, What: "DOM-text-to-HTML",
	}
	semgrepCSharpLogForging = semgrepFirstParty{
		ID: "cicd.csharp.log-forging", File: "csharp-log-forging.yml",
		Body: semgrepCSharpLogForgingBody, Interfile: true, What: "C# log-forging",
	}
	semgrepCSharpSecretInLog = semgrepFirstParty{
		ID: "cicd.csharp.secret-in-log", File: "csharp-secret-in-log.yml",
		Body: semgrepCSharpSecretInLogBody, Interfile: true, What: "C# secret-in-log",
	}
)

// semgrepFirstPartyRules is every first-party rule, in the order a plan
// passes them. The audit and OWASP defaults carry all of them; ScanTaint
// carries the ones marked Interfile.
func semgrepFirstPartyRules() []semgrepFirstParty {
	return []semgrepFirstParty{semgrepDOMRule, semgrepCSharpLogForging, semgrepCSharpSecretInLog}
}

// semgrepInterfileFirstParty is the first-party rules ScanTaint adds to the
// interfile manifest.
func semgrepInterfileFirstParty() []semgrepFirstParty {
	var out []semgrepFirstParty
	for _, r := range semgrepFirstPartyRules() {
		if r.Interfile {
			out = append(out, r)
		}
	}
	return out
}
