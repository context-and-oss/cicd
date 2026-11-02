// Gitleaks run classification and report merging.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so gitleaksreport_test.go can drive it with `go test -tags unit_test ./...`.
//
// Two things live here, and both exist because gitleaks reports "no leaks
// found" in situations where it searched nothing at all.
package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// gitleaksRunError classifies a gitleaks invocation from its exit status,
// stderr and the SARIF it left behind, returning "" when the scan is
// trustworthy and an error string otherwise.
//
// gitleaks is run with --exit-code 0, so "leaks were found" is not an error
// status and any non-zero code means it did not scan. That is not the
// dangerous case, though. When gitleaks shells out to git and git fails —
// no repository, an unreadable object store — it logs the failure, reports
// "0 commits scanned", says "no leaks found" and still **exits 0**. Measured
// against gitleaks v8.30.1 on a directory with no .git:
//
//	ERR [git] fatal: not a git repository (or any parent up to mount point /)
//	ERR error="stderr is not empty"
//	INF 0 commits scanned.
//	INF no leaks found
//	exit 0
//
// gitleaks knows it failed and still exits clean, so the exit status alone can
// never discriminate. wantHistory therefore demands positive proof that the
// history leg examined commits: an absent or zero commit count is an error.
func gitleaksRunError(exitCode, stderr, report string, wantHistory bool) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "gitleaks: unreadable exit status " + strconv.Quote(code)
	case n != 0:
		return withGitleaksReason("gitleaks: did not run (exit "+code+")", stderr)
	}

	if strings.TrimSpace(report) == "" {
		return "gitleaks: exited 0 but wrote no report"
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(report), &doc); err != nil {
		return "gitleaks: report is not valid SARIF: " + err.Error()
	}
	if len(doc.Runs) == 0 {
		return withGitleaksReason("gitleaks: exited 0 but reported no scan runs, so nothing was examined", stderr)
	}
	// A scan with no rules searched for nothing, and says "no leaks found"
	// exactly as a clean one does. gitleaks reaches it without complaint: a
	// .gitleaks.toml at the root of the scanned tree replaces the default rules
	// unless it carries [extend] useDefault = true, so one that only sets an
	// [allowlist] leaves zero. Measured on v8.30.1 against this repository's
	// own config, which did exactly that: 0 rules, every scan clean. The SARIF's
	// rule list is gitleaks' own record of what it loaded, so it is read rather
	// than the config, which gitleaks may resolve differently.
	rules := 0
	for _, run := range doc.Runs {
		rules += len(run.Tool.Driver.Rules)
	}
	if rules == 0 {
		return "gitleaks: exited 0 having loaded no rules, so nothing was searched for secrets — " +
			"a .gitleaks.toml at the root of the scanned tree that defines no [[rules]] replaces " +
			"gitleaks' default rules with nothing; add [extend] useDefault = true to keep them"
	}

	if wantHistory {
		commits, ok := gitleaksCommitCount(stderr)
		switch {
		case !ok:
			// The count line is how the history leg proves it read the
			// repository. If a future gitleaks renames it, fail here rather
			// than fall back to trusting "no leaks found" — the whole point of
			// this function is that the clean verdict is not self-validating.
			return withGitleaksReason("gitleaks: history scan did not report how many commits it scanned, "+
				"so it cannot be distinguished from a scan that read no history", stderr)
		case commits == 0:
			// Reachable two ways, and neither may read as clean: an object
			// store git cannot open, or a repository with no commits yet. Both
			// mean the history verdict is worthless, so name both rather than
			// leave the reader guessing which they hit.
			return withGitleaksReason("gitleaks: history scan examined 0 commits, so no commit was searched for secrets — "+
				"the checkout has an unreadable .git or carries no commits yet", stderr)
		}
	}
	return ""
}

// withGitleaksReason appends gitleaks' own explanation to msg when it gave one.
func withGitleaksReason(msg, stderr string) string {
	if s := firstGitleaksErrorLine(stderr); s != "" {
		return msg + ": " + s
	}
	return msg
}

// gitleaksCommitCountRE matches the "N commits scanned." progress line. The
// leading boundary keeps "10 commits scanned" from reading as a zero count.
var gitleaksCommitCountRE = regexp.MustCompile(`(?:^|[^0-9])([0-9]+) commits scanned`)

// gitleaksCommitCount returns how many commits gitleaks reported scanning, and
// false when it reported no count at all.
func gitleaksCommitCount(stderr string) (int, bool) {
	m := gitleaksCommitCountRE.FindStringSubmatch(stderr)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// firstGitleaksErrorLine returns the first actionable line of gitleaks' stderr.
//
// Note this is the mirror image of lastNonEmptyLine, which is correct for
// semgrep. gitleaks writes levelled log lines (ERR/FTL) and cobra writes a
// usage error as "Error: unknown flag: --x" followed by ~39 lines of help text,
// so taking the last line here would report a flag description ("-v, --verbose
// show verbose output from scan") as the cause of the failure.
//
// Runs are given --no-color, so the level markers arrive unescaped.
func firstGitleaksErrorLine(stderr string) string {
	var firstLine string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if firstLine == "" {
			firstLine = l
		}
		if strings.Contains(l, " ERR ") || strings.Contains(l, " FTL ") ||
			strings.HasPrefix(l, "Error:") || strings.HasPrefix(l, "fatal:") {
			return l
		}
	}
	// No recognised marker: the first line is a better guess than nothing, and
	// staying silent about a failure we already know happened is worse.
	return firstLine
}

// --- report shape ---------------------------------------------------------

type gitleaksSARIFResult struct {
	RuleID  string `json:"ruleId"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	// Suppressions is set only by gitleaksDiscloseSuppressions: gitleaks never
	// writes one, because what it suppresses it leaves out of the report.
	Suppressions []sarifDocSuppression `json:"suppressions"`
}

// suppressed reports whether the result is one cicd put back into the report
// as removed by a suppression: kept for the reader, never counted.
func (r gitleaksSARIFResult) suppressed() bool {
	return sarifResultIsSuppressed(sarifDocResult{Suppressions: r.Suppressions})
}

func (r gitleaksSARIFResult) file() string {
	if len(r.Locations) == 0 {
		return ""
	}
	return r.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

func (r gitleaksSARIFResult) line() int {
	if len(r.Locations) == 0 {
		return 0
	}
	return r.Locations[0].PhysicalLocation.Region.StartLine
}

// endLine is the last line the finding spans; gitleaks writes endLine only for
// a multi-line secret (a private key), so a single-line finding ends where it
// starts.
func (r gitleaksSARIFResult) endLine() int {
	if len(r.Locations) == 0 {
		return 0
	}
	if end := r.Locations[0].PhysicalLocation.Region.EndLine; end > r.line() {
		return end
	}
	return r.line()
}

// key identifies one leaked credential by location and rule.
//
// It deliberately excludes the commit: the same secret found in the working
// tree and in the commit that introduced it is one leak needing one
// remediation, and gitleaks' own fingerprint differs between the legs only by
// a commit prefix ("cfg.py:github-pat:1" vs "<sha>:cfg.py:github-pat:1"), so
// keying on the fingerprint would count it twice.
//
// It also excludes the secret value, because runs pass --redact and the value
// is never in the report to compare (see runGitleaksLeg). The residue is that
// two *different* secrets caught by the same rule at the same file and line in
// different commits collapse into one finding. That under-counts by one in a
// case where the reported location and remediation are identical anyway, which
// is a better trade than inflating every tree secret to two findings.
func (r gitleaksSARIFResult) key() string {
	return r.RuleID + "\x00" + r.file() + "\x00" + strconv.Itoa(r.line())
}

// gitleaksRawResults returns the results of every run, still encoded, so a
// result can be re-emitted without losing fields this file does not model.
func gitleaksRawResults(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var doc struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []json.RawMessage
	for _, run := range doc.Runs {
		out = append(out, run.Results...)
	}
	return out
}

// gitleaksFindings converts a gitleaks SARIF document into the finding slice
// the envelope counts.
//
// Counting from the same document the evidence carries is the point. The
// previous implementation ran gitleaks a *second* time with
// --report-format json purely to count, and discarded that run's error
// (`if jsonErr == nil`), so a failed counting run produced zero findings
// alongside a SARIF report that listed them — findingsCount and sarifReport
// could disagree, and the gate believed the count.
func gitleaksFindings(raw json.RawMessage) []finding {
	var out []finding
	for _, rawResult := range gitleaksRawResults(raw) {
		var r gitleaksSARIFResult
		if err := json.Unmarshal(rawResult, &r); err != nil || r.suppressed() {
			continue
		}
		out = append(out, finding{
			RuleID:      r.RuleID,
			Description: r.Message.Text,
			File:        r.file(),
			Line:        r.line(),
		})
	}
	return out
}

// mergeGitleaksSARIF appends to tree every history result naming a location
// tree did not already report.
//
// tree is the base rather than a peer run because both legs emit the full
// gitleaks rule catalogue — 222 rules, ~49 KB, measured — and merging two whole
// documents would put a second copy of it in every evidence envelope for no
// information gain.
func mergeGitleaksSARIF(tree, history json.RawMessage) json.RawMessage {
	if len(history) == 0 {
		return tree
	}
	if len(tree) == 0 {
		return history
	}

	// A suppressed tree result does not stand for its location. The history
	// leg is not accounted for suppressions (gitleakssuppress.go), so a
	// history result at the same location is one gitleaks reported there
	// anyway, and hiding it behind a result that is not counted would lose it.
	seen := map[string]bool{}
	for _, rawResult := range gitleaksRawResults(tree) {
		var r gitleaksSARIFResult
		if err := json.Unmarshal(rawResult, &r); err == nil && !r.suppressed() {
			seen[r.key()] = true
		}
	}

	var extra []any
	for _, rawResult := range gitleaksRawResults(history) {
		var r gitleaksSARIFResult
		// An unparseable result cannot be deduplicated, so it is kept. Dropping
		// it would silently lose a reported secret; keeping it can at worst
		// duplicate one, and this module never trades an under-report for a
		// tidier number.
		if err := json.Unmarshal(rawResult, &r); err == nil {
			if seen[r.key()] {
				continue
			}
			seen[r.key()] = true
		}
		var v any
		if err := json.Unmarshal(rawResult, &v); err != nil {
			continue
		}
		extra = append(extra, v)
	}
	if len(extra) == 0 {
		return tree
	}
	out, ok := gitleaksAppendResults(tree, extra)
	if !ok {
		return tree
	}
	return out
}
