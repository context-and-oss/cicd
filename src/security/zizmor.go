// The GitHub Actions leg of SAST: zizmor over every workflow, composite action
// and Dependabot file in the tree.
//
// Deliberately untagged, so zizmor_test.go can drive every decision; the
// container half is zizmorexec.go.
//
// zizmor's own answers are read, never re-derived. It decides what it collects
// (its walk, --collect all, so .gitignore cannot hide a tracked workflow), what
// each audit finds and how severe that is. cicd reads three things it says only
// in passing and makes them part of the evidence:
//
//   - Which inputs it audited and which it could not parse. An unparseable
//     workflow is a WARN on stderr and the run still exits 0, so a tree whose
//     only risky workflow has a YAML error reads exactly like a clean one. The
//     verbose log names every input it registers and every input it completes;
//     the difference is the set it did not audit.
//   - Which audits it skipped. Offline, the audits that need the GitHub API
//     (impostor commits, known-vulnerable actions, …) do not run. That is a
//     narrowing, and it is named.
//   - What an ignore comment or the repository's zizmor configuration removed.
//     Both drop a finding without a trace in the SARIF. A second run with
//     --no-config --no-ignores (the shadow) reports what zizmor finds on its
//     own defaults; a finding only the shadow has goes back into the report
//     with an accepted suppression, uncounted and named. Same mechanism as the
//     gitleaks shadow (gitleakssuppress.go).
//
// See specs/audit-github-actions-with-zizmor.md.
package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// zizmorToolName is the row and the SARIF driver name.
const zizmorToolName = "zizmor"

// zizmorExamined is the unit the row counts in.
const zizmorExamined = "workflow, action and Dependabot files"

// zizmorMount is where the tree is copied; zizmorOutDir where the script
// leaves everything cicd reads back.
const (
	zizmorMount  = "/src"
	zizmorOutDir = "/zizmor-out"
)

// zizmorExamplesShown caps every list a warning names. The cap is stated in
// the warning itself whenever it bites.
const zizmorExamplesShown = 10

// zizmorCommonArgs are the flags both runs share. --collect all ignores
// .gitignore: a committed workflow a .gitignore pattern happens to match is
// still a workflow GitHub runs. --offline keeps the scan from contacting the
// GitHub API at all, and the audits that need it are named as skipped.
var zizmorCommonArgs = []string{"--offline", "--no-progress", "--color", "never", "--collect", "all", "--format", "sarif"}

// zizmorScript runs the primary scan (the repository's configuration and
// ignore comments honoured, verbose so the log names every input) and the
// shadow (neither honoured). It always exits 0 and writes each run's stdout,
// stderr and exit status, so an unreadable file means the exec itself did not
// complete.
func zizmorScript() string {
	args := strings.Join(zizmorCommonArgs, " ")
	return "cd " + zizmorMount + "\n" +
		"mkdir -p " + zizmorOutDir + "\n" +
		"zizmor -v " + args + " . >" + zizmorOutDir + "/primary.sarif 2>" + zizmorOutDir + "/primary.err\n" +
		"echo $? >" + zizmorOutDir + "/primary.exit\n" +
		"zizmor --no-config --no-ignores " + args + " . >" + zizmorOutDir + "/shadow.sarif 2>" + zizmorOutDir + "/shadow.err\n" +
		"echo $? >" + zizmorOutDir + "/shadow.exit\n" +
		"exit 0\n"
}

// zizmorRun is one invocation, as the script left it.
type zizmorRun struct {
	SARIF, Stderr, Exit string
}

// zizmorResult is the leg's contribution to the envelope.
type zizmorResult struct {
	// Present is false when the tree has no input zizmor collects: the leg
	// has no row, as the Roslyn leg has none for a tree without a project.
	Present    bool
	SARIF      json.RawMessage
	BySeverity map[Severity]int
	Examined   *Examined
	Rules      *RuleSet
	Warnings   []string
	Err        error
}

// zizmorExitNoInputs is zizmor's "no inputs collected": the tree had nothing
// it audits, or nothing it could parse. The log says which.
const zizmorExitNoInputs = "3"

var (
	zizmorRegistered = regexp.MustCompile(`registering [a-z -]+ input with key file://(\S+)`)
	zizmorInfo       = regexp.MustCompile(`^\s*INFO `)
	zizmorCompleted  = regexp.MustCompile(`\bcompleted (\S+)\s*$`)
	zizmorSkipped    = regexp.MustCompile(`skipping ([a-z0-9-]+): can't run without`)
	zizmorScheduled  = regexp.MustCompile(`scheduling ([a-z0-9-]+) on file://`)
	// A collection failure: invalid YAML ("failed to parse input"), or valid
	// YAML that is not a workflow or action ("failed to validate file://X").
	zizmorCollectFail = regexp.MustCompile(`WARN .*failed to (?:parse input|validate (?:file://(\S+))?)`)
)

// zizmorLog is what the verbose stderr says about collection.
type zizmorLog struct {
	Registered []string
	Completed  []string
	// Failures counts collection WARNs; Unparsed is every registered input
	// that was not completed — the ones the failures were about.
	Failures int
	Unparsed []string
	Skipped  []string
	// Audits is every audit zizmor scheduled on at least one input: the
	// rule set the findings were measured with.
	Audits []string
}

// zizmorRelative strips zizmor's "./" so a path reads the way SARIF writes it.
func zizmorRelative(p string) string {
	p = strings.TrimPrefix(p, "./")
	return strings.TrimPrefix(p, zizmorMount+"/")
}

func parseZizmorLog(stderr string) zizmorLog {
	var l zizmorLog
	completed := map[string]bool{}
	seen := map[string]bool{}
	skipped := map[string]bool{}
	audits := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		if m := zizmorRegistered.FindStringSubmatch(line); m != nil {
			p := zizmorRelative(m[1])
			if !seen[p] {
				seen[p] = true
				l.Registered = append(l.Registered, p)
			}
			continue
		}
		if zizmorCollectFail.MatchString(line) {
			l.Failures++
			continue
		}
		if m := zizmorSkipped.FindStringSubmatch(line); m != nil {
			if !skipped[m[1]] {
				skipped[m[1]] = true
				l.Skipped = append(l.Skipped, m[1])
			}
			continue
		}
		if m := zizmorScheduled.FindStringSubmatch(line); m != nil {
			if !audits[m[1]] {
				audits[m[1]] = true
				l.Audits = append(l.Audits, m[1])
			}
			continue
		}
		if zizmorInfo.MatchString(line) {
			if m := zizmorCompleted.FindStringSubmatch(line); m != nil {
				p := zizmorRelative(m[1])
				if !completed[p] {
					completed[p] = true
					l.Completed = append(l.Completed, p)
				}
			}
		}
	}
	for _, p := range l.Registered {
		if !completed[p] {
			l.Unparsed = append(l.Unparsed, p)
		}
	}
	sort.Strings(l.Completed)
	sort.Strings(l.Unparsed)
	sort.Strings(l.Skipped)
	sort.Strings(l.Audits)
	return l
}

// zizmorFatal is the first line of zizmor's own diagnosis of a failed run.
func zizmorFatal(stderr string) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "INFO ") || strings.HasPrefix(t, "DEBUG ") || strings.HasPrefix(t, "TRACE ") {
			continue
		}
		lines = append(lines, t)
		if len(lines) == 3 {
			break
		}
	}
	if len(lines) == 0 {
		return "zizmor wrote no diagnosis"
	}
	return strings.Join(lines, " / ")
}

// zizmorSeverity is cicd's grade for one result: zizmor's own severity, read
// from the SARIF level it wrote, with one exception.
//
// unpinned-uses is HIGH in zizmor and MEDIUM here. Referencing an action or a
// reusable workflow by tag rather than by commit is how most repositories —
// including every consumer of cicd's own templates, which reference cicd by
// release tag — call actions, so HIGH would make the default gate one nearly
// every GitHub consumer fails on the day it is turned on. MEDIUM keeps it
// counted and gating at --fail-on MEDIUM. The same reasoning grades weak
// hashes MEDIUM in the Roslyn leg (roslynSeverity).
func zizmorSeverity(ruleID, level string) Severity {
	if strings.TrimPrefix(ruleID, "zizmor/") == "unpinned-uses" {
		return SeverityMedium
	}
	return severityFromSARIFLevel(level)
}

func zizmorLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	}
	return "note"
}

// zizmorDoc is the part of zizmor's SARIF cicd reads; every result is kept
// whole as raw JSON and only its level and suppressions are rewritten.
type zizmorDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name            string            `json:"name"`
				SemanticVersion string            `json:"semanticVersion"`
				Rules           []json.RawMessage `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []map[string]any `json:"results"`
	} `json:"runs"`
}

type zizmorKeyed struct {
	key    string
	uri    string
	rule   string
	line   int
	result map[string]any
}

func zizmorResults(raw string) ([]zizmorKeyed, string, []json.RawMessage, error) {
	var doc zizmorDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, "", nil, err
	}
	if len(doc.Runs) != 1 {
		return nil, "", nil, fmt.Errorf("expected one SARIF run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	out := make([]zizmorKeyed, 0, len(run.Results))
	for _, r := range run.Results {
		k, uri, rule, line := sarifResultKey(r)
		out = append(out, zizmorKeyed{key: k, uri: uri, rule: rule, line: line, result: r})
	}
	return out, run.Tool.Driver.SemanticVersion, run.Tool.Driver.Rules, nil
}

func zizmorSARIFLevel(r map[string]any) string {
	level, _ := r["level"].(string)
	if level == "" {
		// zizmor writes a level on every result it reports; an absent one is
		// read the way SARIF defines it rather than guessed upward.
		return "warning"
	}
	return level
}

// analyseZizmor turns the two runs into the leg's result.
func analyseZizmor(primary, shadow zizmorRun) zizmorResult {
	log := parseZizmorLog(primary.Stderr)
	exit := strings.TrimSpace(primary.Exit)
	res := zizmorResult{Present: true}

	examined := func() *Examined {
		return &Examined{Unit: zizmorExamined, Count: len(log.Completed),
			Total: len(log.Completed) + max(len(log.Unparsed), log.Failures)}
	}

	switch exit {
	case "0":
	case zizmorExitNoInputs:
		if log.Failures == 0 && len(log.Registered) == 0 && strings.Contains(primary.Stderr, "no inputs collected") {
			// Nothing in the tree is a workflow, an action or a Dependabot
			// file. No row, as Opengrep has no C# row for a Go repository.
			return zizmorResult{}
		}
		// zizmor found inputs and could parse none of them.
		res.Examined = examined()
		res.Err = fmt.Errorf("%s: SAST did not run — zizmor collected %d workflow, action or Dependabot %s "+
			"and could parse none of them: %s", zizmorToolName, res.Examined.Total,
			pick(res.Examined.Total, "file", "files"), zizmorFileList(log.Unparsed, log.Failures))
		return res
	default:
		res.Err = fmt.Errorf("%s: SAST did not run — zizmor exited %s: %s", zizmorToolName, exit, zizmorFatal(primary.Stderr))
		return res
	}

	results, version, rules, err := zizmorResults(primary.SARIF)
	if err != nil {
		res.Err = fmt.Errorf("%s: SAST did not run — zizmor's SARIF could not be read: %w", zizmorToolName, err)
		return res
	}
	res.Examined = examined()

	// Every result must be in a file the log says was audited. A result
	// anywhere else means the log no longer reads the way this parser
	// expects, and the examined count beside the findings would be a guess.
	completed := map[string]bool{}
	for _, p := range log.Completed {
		completed[p] = true
	}
	for _, r := range results {
		if r.uri != "" && !completed[r.uri] {
			res.Err = fmt.Errorf("%s: could not read which files zizmor audited — it reported a finding in %s, "+
				"which its log does not name as audited; the examined count would be a guess", zizmorToolName, r.uri)
			return res
		}
	}

	if len(log.Completed) > 0 && len(log.Audits) == 0 {
		res.Err = fmt.Errorf("%s: could not read which audits zizmor ran — it audited %d %s and its log "+
			"names no audit it scheduled; the findings would have no rule set beside them", zizmorToolName,
			len(log.Completed), pick(len(log.Completed), "file", "files"))
		return res
	}

	if n := res.Examined.Total - res.Examined.Count; n > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: PARTIAL SCAN — zizmor could not parse %d of %d "+
			"workflow, action or Dependabot files and did not audit %s (invalid YAML, or not a valid workflow "+
			"or action): %s", zizmorToolName, n, res.Examined.Total, pick(n, "it", "them"),
			zizmorFileList(log.Unparsed, n)))
	}
	if len(log.Skipped) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: NARROWED AUDITS — the scan runs offline, so %d "+
			"%s that need%s the GitHub API did not run: %s", zizmorToolName, len(log.Skipped),
			pick(len(log.Skipped), "audit", "audits"), pick(len(log.Skipped), "s", ""), strings.Join(log.Skipped, ", ")))
	} else {
		res.Warnings = append(res.Warnings, zizmorToolName+": NARROWED AUDITS — the scan runs offline, so "+
			"zizmor's online audits did not run; zizmor did not name which")
	}

	// The shadow: what zizmor finds with no repository configuration and no
	// ignore comment. It must have run, or a pass may rest on an acceptance
	// nobody can read.
	shadowExit := strings.TrimSpace(shadow.Exit)
	if shadowExit != "0" {
		res.Err = fmt.Errorf("%s: could not measure what the repository's zizmor configuration and ignore "+
			"comments removed, so a pass may rest on an acceptance nobody can read — the unsuppressed run "+
			"exited %s: %s", zizmorToolName, shadowExit, zizmorFatal(shadow.Stderr))
		return res
	}
	shadowResults, _, shadowRules, err := zizmorResults(shadow.SARIF)
	if err != nil {
		res.Err = fmt.Errorf("%s: could not measure what the repository's zizmor configuration and ignore "+
			"comments removed — the unsuppressed run's SARIF could not be read: %w", zizmorToolName, err)
		return res
	}
	remaining := map[string]int{}
	for _, r := range results {
		remaining[r.key]++
	}
	var suppressed []zizmorKeyed
	for _, r := range shadowResults {
		if remaining[r.key] > 0 {
			remaining[r.key]--
			continue
		}
		suppressed = append(suppressed, r)
	}

	res.BySeverity = map[Severity]int{}
	out := make([]map[string]any, 0, len(results)+len(suppressed))
	for _, r := range results {
		sev := zizmorSeverity(r.rule, zizmorSARIFLevel(r.result))
		r.result["level"] = zizmorLevel(sev)
		res.BySeverity[sev]++
		out = append(out, r.result)
	}
	sort.SliceStable(suppressed, func(i, j int) bool {
		si := severityRank(zizmorSeverity(suppressed[i].rule, zizmorSARIFLevel(suppressed[i].result)))
		sj := severityRank(zizmorSeverity(suppressed[j].rule, zizmorSARIFLevel(suppressed[j].result)))
		if si != sj {
			return si > sj
		}
		return suppressed[i].key < suppressed[j].key
	})
	var named []string
	for _, r := range suppressed {
		sev := zizmorSeverity(r.rule, zizmorSARIFLevel(r.result))
		r.result["level"] = zizmorLevel(sev)
		r.result["suppressions"] = []map[string]string{{
			"kind":          "external",
			"status":        "accepted",
			"justification": "removed by a zizmor ignore comment or the repository's zizmor configuration",
		}}
		out = append(out, r.result)
		named = append(named, fmt.Sprintf("%s %s at %s:%d", sev, strings.TrimPrefix(r.rule, "zizmor/"), r.uri, r.line))
	}
	if n := len(suppressed); n > 0 {
		list := strings.Join(firstN(named, zizmorExamplesShown), "; ")
		if n > zizmorExamplesShown {
			list += fmt.Sprintf("; and %d more (highest severity shown first)", n-zizmorExamplesShown)
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d %s removed by a zizmor ignore comment or the "+
			"repository's zizmor configuration %s not counted: %s", zizmorToolName, n, pick(n, "finding", "findings"),
			pick(n, "is", "are"), list))
	}

	// The run carries the rules of both runs, so a suppressed result's rule
	// resolves; zizmor lists only the rules it reported.
	ruleSeen := map[string]bool{}
	var allRules []json.RawMessage
	for _, rs := range [][]json.RawMessage{rules, shadowRules} {
		for _, raw := range rs {
			var id struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &id) == nil && !ruleSeen[id.ID] {
				ruleSeen[id.ID] = true
				allRules = append(allRules, raw)
			}
		}
	}
	driver := map[string]any{"name": zizmorToolName, "informationUri": "https://docs.zizmor.sh/"}
	if version != "" {
		driver["semanticVersion"] = version
	}
	if allRules != nil {
		driver["rules"] = allRules
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":              map[string]any{"driver": driver},
			"automationDetails": map[string]any{"id": zizmorToolName},
			"results":           out,
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		res.Err = fmt.Errorf("%s: could not encode the SARIF: %w", zizmorToolName, err)
		return res
	}
	res.SARIF = raw
	// The audits the verbose log says were scheduled, under the pinned
	// release's bundled set. The offline-skipped ones are not among them and
	// are named in the NARROWED AUDITS warning.
	res.Rules = &RuleSet{Count: len(log.Audits), Pinned: "zizmor " + zizmorVersion + " (bundled audits, regular persona)"}
	return res
}

// zizmorFileList names the unaudited files, or says zizmor did not.
func zizmorFileList(files []string, failures int) string {
	if len(files) == 0 {
		return fmt.Sprintf("zizmor reported %d collection %s without naming the %s", failures,
			pick(failures, "failure", "failures"), pick(failures, "file", "files"))
	}
	list := strings.Join(firstN(files, zizmorExamplesShown), ", ")
	if len(files) > zizmorExamplesShown {
		list += fmt.Sprintf(", and %d more (alphabetical, first %d shown)", len(files)-zizmorExamplesShown, zizmorExamplesShown)
	}
	return list
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}
