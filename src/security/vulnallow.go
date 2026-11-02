// Accepted vulnerabilities: --vuln-accept, the reasoned exception to the
// vulnerability gate.
//
// Every other escape hatch in this module narrows what a scan *looks at*. This
// one narrows what a scan *reports*, which is the dangerous direction, so it is
// built to the only shape that is defensible: an acceptance is a decision, and
// a decision that nobody can read is indistinguishable from a bug.
//
// The need is this repository's own. Four go.mod files carry
// `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlplog{grpc,http}` at
// v0.16.0, and that version is not cicd's to set — `dagger develop` writes the
// four `replace` lines from dagger.io/dagger's own go.mod on every run, per
// module. CAPS-058 measured the alternative: committing a higher pin leaves
// go.mod advertising a version the build does not use, which is a green scan
// over a dependency that is not there. So eight MEDIUM rows sit on the dogfood
// gate that no commit in this repository can clear.
//
// The mechanism that already existed for that is `.trivyignore`, and it is the
// wrong one. Trivy drops an ignored ID before it writes the report, so the row
// is absent from the native document, absent from findings[], absent from the
// counts and absent from the evidence envelope. Four of this repository's eight
// rows were invisible in its own evidence for exactly that reason. A consumer
// reading the PR comment could not tell an accepted vulnerability from one
// nobody had ever seen. That is the founding false pass wearing a policy's
// clothes.
//
// So an acceptance here is loud. Four rules, and they are what this file is:
//
//  1. It NARROWS, never widens. An acceptance can only stop a row Trivy already
//     reported from reaching the counts and the gate. It cannot reach Trivy's
//     flags, cannot suppress a whole severity, and cannot make a scan examine
//     less. trivyflags.go still pins every filtering knob on the command line.
//  2. A reason is MANDATORY. `--vuln-accept CVE-2026-81871` alone is refused;
//     it must be `CVE-2026-81871=<why>`. cicd does not grade the reason and
//     says so — the point is that a human wrote one, and that the next reader
//     gets it instead of a bare identifier. This is the whole difference
//     between an acceptance and a suppression.
//  3. It names ONE identifier. No wildcards, no severity-wide acceptance, no
//     package globs. An acceptance covering a set covers the member of that set
//     that nobody has read yet, including the one disclosed next week.
//  4. Nothing is accepted silently, and a stale acceptance is louder than a
//     live one. Every acceptance reaches warnings[] with the rows it covered,
//     and one that covered nothing gets its own line — because an acceptance
//     kept past its finding is a standing permission for that ID to come back
//     unreviewed, and it is also the signal that upstream finally fixed it.
//
// warnings[] is the deliberate channel, not genericReport. cross-cutting/
// evidence drops genericReport on the way into combined-evidence.json and
// propagates warnings[] verbatim, and notify renders them into the PR comment —
// so an acceptance recorded only in the payload would be as invisible to a
// reviewer as the .trivyignore entry this replaces.
//
// Untagged, no Dagger: vulnallow_test.go pins all of it.
package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// vulnAcceptance is one accepted vulnerability identifier and the reason its
// author gave.
type vulnAcceptance struct {
	// Raw is what the caller typed, kept verbatim for every message. A warning
	// quoting a normalised form is a warning whose subject the reader cannot
	// find in their own pipeline definition.
	Raw string
	// ID is the vulnerability identifier, upper-cased for comparison.
	ID string
	// Reason is the caller's stated justification, whitespace-collapsed. cicd
	// never interprets it.
	Reason  string
	hits    int
	covered []vulnCovered
}

// vulnCovered is one row an acceptance took out of the report, kept so the
// warning can say what was accepted rather than only how much.
type vulnCovered struct {
	Severity Severity
	Pkg      string
	Version  string
	Target   string
}

// vulnAccepter holds the acceptances for one scan.
type vulnAccepter struct {
	acceptances []*vulnAcceptance
}

// vulnIDRe is the shape of a vulnerability identifier: a leading alphanumeric
// token and at least one more `-`-separated one. It admits CVE-2026-81871,
// GHSA-xxxx-yyyy-zzzz, RUSTSEC-2021-0001, DSA-5678-1 and TEMP-0000000-A0B1C2.
//
// Deliberately a shape check and not a list of known prefixes. Trivy's advisory
// sources grow, and a prefix table inside cicd would reject a real identifier
// from a source added upstream — turning "this ID is not in cicd's table" into
// "your acceptance does not work", with no way to tell it from a typo. The
// shape is what stops `CVE-2026-*` and `MEDIUM` from being read as an ID.
var vulnIDRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9.]+)+$`)

// vulnWildcardChars are refused inside an identifier with their own message,
// because the mistake they represent is not a typo — it is an attempt to accept
// a set, and rule 3 exists to refuse that specifically rather than through a
// generic shape error the reader would read as "cicd does not like my CVE".
const vulnWildcardChars = "*?[]"

// maxNamedAcceptedRows bounds how many covered rows a warning names before it
// counts the rest. Three is enough to recognise what was accepted; a scan that
// accepts hundreds of rows under one ID has a different problem, and printing
// them all turns the one line a reviewer must read into a page they will not.
const maxNamedAcceptedRows = 3

// parseVulnAcceptance reads one `<id>=<reason>` entry.
//
// Split on the FIRST `=`: a reason is free prose and may contain more.
func parseVulnAcceptance(raw string) (*vulnAcceptance, error) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept was given an " +
			"empty entry. An empty acceptance narrows nothing and usually means the caller's " +
			"splitting dropped the text; remove it, or pass it as \"<vulnerability-id>=<reason>\"")
	}
	id, reason, found := strings.Cut(entry, "=")
	if !found {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q names no "+
			"reason. A reason is mandatory — write it as \"%s=<why this vulnerability is "+
			"accepted here>\". cicd does not grade the reason; it requires one so the next "+
			"reader of this evidence meets a decision instead of a bare identifier", entry,
			strings.TrimSpace(id))
	}
	id = strings.TrimSpace(id)
	reason = normaliseVulnReason(reason)
	if id == "" {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q names a "+
			"reason but no vulnerability identifier. Write it as \"<vulnerability-id>=<reason>\"",
			entry)
	}
	if strings.ContainsAny(id, vulnWildcardChars) {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q uses a "+
			"pattern. An acceptance names exactly one vulnerability identifier, because a "+
			"pattern also covers the finding nobody has read yet — including the one disclosed "+
			"after this pipeline was written. List each accepted identifier separately", entry)
	}
	if !vulnIDRe.MatchString(id) {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q does not "+
			"look like a vulnerability identifier. Expected the form a scanner reports — "+
			"CVE-2026-81871, GHSA-xxxx-yyyy-zzzz, RUSTSEC-2021-0001 — which is a leading "+
			"alphanumeric token followed by at least one \"-\" and more. cicd matches the "+
			"identifier Trivy prints, so copy it from the finding", id)
	}
	if reason == "" {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q gives an "+
			"empty reason for %s. A reason is mandatory — an acceptance with nothing written "+
			"beside it is a suppression, which is what .trivyignore already does and what this "+
			"flag exists not to be", entry, id)
	}
	if !strings.ContainsFunc(reason, isVulnReasonLetter) {
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept %q gives %q as "+
			"the reason for %s, which contains no letter. cicd does not grade a reason, but a "+
			"reason that says nothing defeats the only thing this flag adds over suppressing "+
			"the finding outright", entry, reason, id)
	}
	return &vulnAcceptance{Raw: entry, ID: strings.ToUpper(id), Reason: reason}, nil
}

// isVulnReasonLetter reports whether r is a letter in any script, so a reason
// written in a language other than English is not rejected as empty.
func isVulnReasonLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127
}

// normaliseVulnReason collapses whitespace so a reason wrapped across lines in
// a pipeline definition renders as one sentence.
func normaliseVulnReason(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// splitVulnAcceptances cuts the raw --vuln-accept value into entries on
// NEWLINES, and on nothing else.
//
// The separator is not a style choice, and neither is the parameter being one
// string rather than a []string. Both were measured against the Dagger CLI
// (v0.20.8) with a probe module, because the first version of this flag was a
// []string and the dogfood run it was built for failed on its own reason:
//
//	--vuln-accept "CVE-2026-81871=upstream ships no fixed version, so cicd
//	cannot pin the fix" arrived as THREE separate acceptances, cut at every
//	comma, and the second fragment was refused for naming no reason.
//
// Dagger exposes a []string parameter as a pflag StringSlice, which CSV-parses
// its value: it splits on commas, and it TRUNCATES at the first newline with no
// error at all. Repeating the flag does not help — each occurrence is split
// again. So a []string cannot carry prose by any spelling, and one of its two
// destruction modes is silent, which is this module's founding failure wearing
// an argument parser's clothes. A String scalar round-trips commas and newlines
// byte for byte, so the whole multi-line value arrives intact and cicd does the
// splitting itself, where the rule is written down and tested.
//
// A comma cannot be the separator here for the same reason --license-allow can
// use one: that flag takes identifiers, this one takes a sentence a human wrote,
// and a reason truncated at its first comma still looks like a decision was
// recorded. An entry is therefore a line. Blank lines are skipped so a value
// pasted from a YAML block scalar with a trailing newline is not an empty
// acceptance, and each entry is trimmed of surrounding whitespace so the
// indentation of that block scalar does not become part of an identifier.
func splitVulnAcceptances(raw string) []string {
	var entries []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	return entries
}

// newVulnAccepter parses every entry of the raw value, refusing the whole set
// on the first problem.
//
// A bad entry is a hard error and not a skipped one, for the reason
// resolveIncludeNames is: a narrowing the caller asked for and did not get must
// never arrive as an ordinary result. Here the direction is worse — a dropped
// acceptance produces a RED gate rather than a green one, which sounds safe
// until the remedy a consumer reaches for is the flag that turns the scanner
// off. Either way, the error names the entry.
//
// Two entries for the same identifier with different reasons is refused too:
// only one of them would end up in the evidence, and a reader could not tell
// which. Two byte-identical entries are the same acceptance typed twice, and
// are collapsed.
func newVulnAccepter(raw string) (*vulnAccepter, error) {
	entries := splitVulnAcceptances(raw)
	if len(entries) == 0 && raw != "" {
		// Whitespace only. Not the same as an unset flag: the caller wrote
		// something, and every acceptance in it went missing between them and
		// here. Going quiet would report that as "no acceptances asked for",
		// which is the one reading that cannot be told from the truth.
		return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept was given a value "+
			"that holds no acceptance (%q). Each line must read \"<id>=<reason>\"; clear the flag "+
			"to gate on every finding", raw)
	}
	acc := &vulnAccepter{}
	byID := map[string]*vulnAcceptance{}
	for _, entry := range entries {
		parsed, err := parseVulnAcceptance(entry)
		if err != nil {
			return nil, err
		}
		if prev, ok := byID[parsed.ID]; ok {
			if prev.Reason == parsed.Reason {
				continue
			}
			return nil, fmt.Errorf("security vulnerability acceptance: --vuln-accept names %s "+
				"twice with different reasons (%q and %q). Only one of them could be recorded "+
				"in the evidence and a reader could not tell which, so state the acceptance "+
				"once", parsed.ID, prev.Reason, parsed.Reason)
		}
		byID[parsed.ID] = parsed
		acc.acceptances = append(acc.acceptances, parsed)
	}
	return acc, nil
}

// empty reports whether nothing was accepted, so callers can skip the whole
// path and leave the report untouched.
func (a *vulnAccepter) empty() bool { return a == nil || len(a.acceptances) == 0 }

// accepts reports whether id is accepted, recording the covered row.
func (a *vulnAccepter) accepts(id string, row vulnCovered) bool {
	if a.empty() {
		return false
	}
	want := strings.ToUpper(strings.TrimSpace(id))
	for _, acc := range a.acceptances {
		if acc.ID != want {
			continue
		}
		acc.hits++
		if len(acc.covered) < maxNamedAcceptedRows {
			acc.covered = append(acc.covered, row)
		}
		return true
	}
	return false
}

// partition returns a copy of doc holding only the vulnerabilities that were
// not accepted, and reports how many rows were taken out.
//
// The copy is deliberate. Everything downstream that judges the scan — the
// severity counts, findings[], the gate — reads the returned document, so an
// acceptance cannot apply to one of them and not another. Two things keep
// reading the ORIGINAL and the distinction is load-bearing:
//
//   - trivyResolvedTypes, because a Result carrying only accepted
//     vulnerabilities and no packages would vanish from the resolved list, and
//     ecosystems.go would then report the ecosystem unresolved. An acceptance
//     must never be able to manufacture a non-run.
//   - the CycloneDX document, which is Trivy's own and is attached to the
//     envelope whole. An accepted row stays in it, so the evidence still holds
//     the vulnerability a reader may want to look up.
func (a *vulnAccepter) partition(doc *trivyNativeDoc) (*trivyNativeDoc, int) {
	if a.empty() || doc == nil {
		return doc, 0
	}
	out := &trivyNativeDoc{}
	removed := 0
	for _, res := range doc.Results {
		kept := res.Vulnerabilities[:0:0]
		for _, v := range res.Vulnerabilities {
			row := vulnCovered{
				Severity: trivySeverity(v.Severity),
				Pkg:      v.PkgName,
				Version:  v.InstalledVersion,
				Target:   res.Target,
			}
			if a.accepts(v.VulnerabilityID, row) {
				removed++
				continue
			}
			kept = append(kept, v)
		}
		res.Vulnerabilities = kept
		out.Results = append(out.Results, res)
	}
	return out, removed
}

// disclosures is every line this accepter contributes to warnings[]: one per
// acceptance that covered something, then one per acceptance that covered
// nothing.
//
// Both are warnings and neither is an error. An accepted vulnerability is a
// decision the caller is entitled to make, and a stale acceptance is a
// housekeeping problem rather than a broken scan — failing on it would make
// the first upstream fix turn a consumer's pipeline red for having been right.
func (a *vulnAccepter) disclosures() []string {
	if a.empty() {
		return nil
	}
	var live, stale []string
	for _, acc := range a.acceptances {
		if acc.hits == 0 {
			stale = append(stale, fmt.Sprintf(
				"security: VULN ACCEPTANCE UNUSED — --vuln-accept names %s, and this scan "+
					"reports no finding with that identifier. Either it is fixed and the "+
					"acceptance is stale, or the scan never reached the dependency that "+
					"carries it — those two look identical from here. An acceptance kept past "+
					"its finding is a standing permission for that identifier to return "+
					"unreviewed. Reason on file: %q",
				acc.ID, acc.Reason))
			continue
		}
		live = append(live, fmt.Sprintf(
			"security: VULN ACCEPTED — %s covered %d finding(s) (%s) and is excluded from the "+
				"vulnerability counts, from findings[] and from the gate. Reason given: %q. "+
				"cicd does not grade this reason. The rows remain in the CycloneDX report "+
				"attached to this envelope, and the scan itself was not narrowed.",
			acc.ID, acc.hits, describeCoveredRows(acc), acc.Reason))
	}
	sort.Strings(live)
	sort.Strings(stale)
	return append(live, stale...)
}

// describeCoveredRows renders up to maxNamedAcceptedRows of what an acceptance
// took out, then counts the rest.
func describeCoveredRows(acc *vulnAcceptance) string {
	if len(acc.covered) == 0 {
		return "no row detail recorded"
	}
	parts := make([]string, 0, len(acc.covered)+1)
	for _, row := range acc.covered {
		pkg := row.Pkg
		if pkg == "" {
			pkg = "unnamed package"
		}
		desc := fmt.Sprintf("%s %s %s", row.Severity, pkg, row.Version)
		if row.Target != "" {
			desc += " in " + row.Target
		}
		parts = append(parts, strings.TrimSpace(desc))
	}
	if rest := acc.hits - len(acc.covered); rest > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", rest))
	}
	return strings.Join(parts, "; ")
}

// vulnAcceptedSummary is the one-line count of everything accepted in a scan,
// for callers that want a single sentence rather than the per-acceptance lines.
func vulnAcceptedSummary(a *vulnAccepter, removed int) string {
	if a.empty() || removed == 0 {
		return ""
	}
	return fmt.Sprintf("security: %d vulnerability finding(s) across %d accepted "+
		"identifier(s) were excluded from this gate by --vuln-accept; each is named above "+
		"with the reason given for it", removed, len(a.acceptances))
}
