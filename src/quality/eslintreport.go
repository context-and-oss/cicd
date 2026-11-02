// ESLint report parsing and run-status classification.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so eslintreport_test.go can drive it with `go test -tags unit_test ./...`.
// The classification below is what stops a lint step that never ran from being
// indistinguishable from a lint step that found nothing.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

type eslintResult struct {
	FilePath string `json:"filePath"`
	Messages []struct {
		Severity int    `json:"severity"` // 1=warn, 2=error
		Message  string `json:"message"`
		Line     int    `json:"line"`
		RuleID   string `json:"ruleId"`
	} `json:"messages"`
}

// eslintRunError classifies an ESLint invocation from its exit status, stderr
// and stdout, returning "" when the run is trustworthy and an error string
// otherwise.
//
// ESLint's contract: 0 = no problems, 1 = problems reported, >=2 = it could not
// run (bad config, unresolvable plugin). The shell contributes 127 when
// node_modules/.bin/eslint does not exist — a repo that does not depend on
// ESLint, or one whose package.json is not at the linted root. Any of those must
// surface as an error, because the alternative is an empty report that parses as
// "clean".
//
// The message matters as much as the failure: these are the three non-runs a
// consumer actually hits, and each one has a different fix, so the error string
// carries the remedy rather than making them go read a container log.
//
// install is the dependency install this leg ran and what it exited with:
// empty when this leg did not run one (a prepared container), so nothing is
// known about it.
func eslintRunError(exitCode, stderr, report string, install installRecord) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "eslint: unreadable exit status " + strconv.Quote(code)
	case n == 0 || n == 1:
		// Ran. A trustworthy run always emits a JSON array, even when empty.
		if strings.TrimSpace(report) == "" {
			return "eslint: exited " + code + " but wrote an empty report"
		}
		return ""
	default:
		msg := "eslint: did not run (exit " + code + ")"
		if s := eslintStderrMessage(stderr); s != "" {
			msg += ": " + s
		}
		if n != 127 {
			if ie, failed := install.failed(); failed {
				// A plugin or parser the config names that is not in
				// node_modules fails the same way a broken config does; the
				// install is the likelier cause, and only this leg saw it.
				msg += " (" + install.name() + " exited " + ie + ", so the project's dependencies may be incomplete)"
			}
		}
		return msg + eslintRemedy(n, stderr, install)
	}
}

// eslintRemedy appends the fix for the non-runs consumers actually hit. Each
// string was written against a measured failure (eslint 8.57.1 and 9.39.5).
//
// Exit 127 used to say "add eslint to devDependencies" whatever the cause. Two
// of the causes it covered need the opposite advice: an install that failed
// (the project declares eslint; adding it again changes nothing), and an npm
// workspace member, whose eslint the install hoists to the root's
// node_modules/.bin. The second is closed by eslintScript resolving through
// `npx --no` (reachable once a leg runs in a member); the first is told apart
// by the install's recorded exit.
func eslintRemedy(exit int, stderr string, install installRecord) string {
	const declare = "add eslint to devDependencies, point --src at the directory holding" +
		" package.json, or drop \"node\" from --include so cicd does not claim to lint this repo"
	switch {
	case exit == 127:
		// The binary is not there. Fetching one off the network instead would
		// mean gating on a version nobody chose, so this is a hard stop.
		if ie, failed := install.failed(); failed {
			return " — " + install.name() + " exited " + ie + ", so eslint is not installed in this Node" +
				" project, and cicd does not fetch one: fix the install (" + installFailureCauses(install) + ")"
		}
		if !install.known() {
			// The install ran elsewhere (a prepared container) or left no
			// readable exit, so either cause is possible: name both.
			return " — eslint is not installed in this Node project, and cicd cannot see" +
				" whether the dependency install succeeded: check that install, then " + declare
		}
		return " — eslint is not installed in this Node project: " + declare
	case eslintMissingConfig(stderr):
		// ESLint 9 needs eslint.config.js; ESLint 8 needs .eslintrc.*. cicd
		// deliberately does not substitute a config of its own — a lint run
		// against rules the team never agreed to is noise wearing a gate's hat.
		return " — no ESLint config found: commit eslint.config.js (ESLint 9+)" +
			" or .eslintrc.* (ESLint 8), or drop \"node\" from --include"
	default:
		return ""
	}
}

// eslintMissingConfig recognises the "there is no config" non-run across both
// config eras. Verbatim first lines from the two versions:
//
//	9.39.5: ESLint couldn't find an eslint.config.(js|mjs|cjs) file.
//	8.57.1: ESLint couldn't find a configuration file. To set up a configuration file for this project, please run:
func eslintMissingConfig(stderr string) bool {
	for _, pat := range []string{
		"couldn't find an eslint.config",
		"couldn't find a configuration file",
		"No ESLint configuration found",
	} {
		if strings.Contains(stderr, pat) {
			return true
		}
	}
	return false
}

// eslintStderrMessage extracts the one actionable line from an ESLint crash.
//
// lastNonEmptyLine is wrong here, which is why this exists: ESLint prints a
// banner first and a documentation URL *last*, so taking the final line yields
// "https://eslint.org/chat/help to chat with the team." while the real
// diagnostic sits in the middle. Measured layouts:
//
//	no config:      Oops! / ESLint: 9.39.5 / ESLint couldn't find ... / From ESLint v9 ... / https://...
//	bad rule:       Oops! / ESLint: 9.39.5 / TypeError: Key "rules": ... / at throwRuleNotFoundError (...)
//	removed flag:   Invalid option '--eslintrc' ... / You're using eslint.config.js, ...
//	missing binary: sh: 4: ./node_modules/.bin/eslint: not found
//
// So: first line that is not banner, version echo, stack frame, URL or migration
// prose. Falls back to the last line rather than to nothing.
func eslintStderrMessage(stderr string) string {
	skipPrefix := []string{
		"Oops!",
		"ESLint: ",       // version echo in the crash banner
		"at ",            // stack frames
		"http",           // documentation links
		"From ESLint v",  // migration prose
		"If you ",        // "If you are using a .eslintrc.* file, ..."
		"to update your", // continuation of the same sentence
	}
	for _, raw := range strings.Split(stderr, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		skip := false
		for _, p := range skipPrefix {
			if strings.HasPrefix(line, p) {
				skip = true
				break
			}
		}
		if !skip {
			return line
		}
	}
	return lastNonEmptyLine(stderr)
}

// eslintVersionLabel normalises `eslint --version` output ("v9.39.5") for the
// evidence envelope. Unresolvable is reported as "unknown" rather than as a
// plausible-looking constant: the evidence must not attribute findings to a
// version that never ran.
func eslintVersionLabel(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "v")
	if v == "" || strings.ContainsAny(v, " \n\t") {
		return "unknown"
	}
	return v
}

// lastNonEmptyLine returns the final non-blank line of s, trimmed. Tool stderr
// puts the actionable message last, after any progress noise.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// parseEslintJSON converts ESLint's --format json output into SARIF plus
// severity counts. A nil SARIF means the payload was not an ESLint report at
// all; callers must treat that as an error, never as "no findings".
//
// version is the ESLint the consumer's lockfile actually resolved, passed in
// rather than read from a constant here: the binary belongs to their repository,
// so a compiled-in version would attribute every finding to a build that never
// ran. Callers pass eslintVersionLabel's output, which is "unknown" when the
// version could not be read.
func parseEslintJSON(data []byte, version string) (json.RawMessage, map[Severity]int) {
	var results []eslintResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, nil
	}

	counts := map[Severity]int{}
	for _, r := range results {
		for _, m := range r.Messages {
			if m.Severity == 2 {
				counts[SeverityHigh]++
			} else {
				counts[SeverityMedium]++
			}
		}
	}

	sarif := buildEslintSarif(results, version)
	raw, _ := json.Marshal(sarif)
	return json.RawMessage(raw), counts
}

func buildEslintSarif(results []eslintResult, version string) map[string]any {
	var sarifResults []map[string]any
	for _, r := range results {
		for _, m := range r.Messages {
			level := "warning"
			if m.Severity == 2 {
				level = "error"
			}
			sarifResults = append(sarifResults, map[string]any{
				"ruleId":  m.RuleID,
				"level":   level,
				"message": map[string]any{"text": m.Message},
				"locations": []map[string]any{{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": r.FilePath},
						"region":           map[string]any{"startLine": m.Line},
					},
				}},
			})
		}
	}
	return singleRunSARIF("eslint", version, sarifResults)
}

// foldEslintRun turns what the ESLint leg read back into its result: the SARIF
// and counts, or the error that makes the leg a non-run. eslintRunError judges
// the exit status; this adds the one case it cannot see. Exit 0 or 1 with a
// report that is not ESLint's JSON array (truncated, or a formatter's HTML)
// used to parse to nil, which the caller skipped, so the leg read as clean.
func foldEslintRun(exitCode, stderr, report, version string, install installRecord) (json.RawMessage, map[Severity]int, string) {
	if msg := eslintRunError(exitCode, stderr, report, install); msg != "" {
		return nil, nil, msg
	}
	if !strings.HasPrefix(strings.TrimSpace(report), "[") {
		return nil, nil, "eslint: exited " + strings.TrimSpace(exitCode) + " but its report is not ESLint JSON"
	}
	sarifRaw, bySeverity := parseEslintJSON([]byte(report), eslintVersionLabel(version))
	if sarifRaw == nil {
		return nil, nil, "eslint: exited " + strings.TrimSpace(exitCode) + " but its report is not ESLint JSON"
	}
	return sarifRaw, bySeverity, ""
}

// eslintFilesLinted is how many files ESLint reported on: its JSON formatter
// writes one result per file it linted, findings or not, so the array's length
// is the leg's denominator. -1 when the report does not parse, which
// foldEslintRun has already refused by the time this is asked.
func eslintFilesLinted(report string) int {
	var results []json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(report)), &results); err != nil {
		return -1
	}
	return len(results)
}

// eslintExamined sums the per-project file counts. It says nothing — nil —
// when the leg did not run cleanly or any project's count is unknown: a sum
// over some of the projects would read as the whole leg's scope.
func eslintExamined(perProject []int, ran bool) *Examined {
	if !ran || len(perProject) == 0 {
		return nil
	}
	total := 0
	for _, n := range perProject {
		if n < 0 {
			return nil
		}
		total += n
	}
	return &Examined{Unit: "files", Count: total}
}

// eslintMissingStderr is what eslintScript writes to the stderr file when no
// eslint resolves. The exit beside it is 127 because `npx --no` reports a
// package it will not fetch as exit 1, which is ESLint's own "found problems",
// and yarn berry does the same. eslintScript echoes it inside single quotes,
// so it must never contain one.
const eslintMissingStderr = "eslint: not found (the package manager resolved no eslint from this directory)"

// eslintScript is the script the ESLint leg runs, installing and resolving
// through pm (nodeinstall.go). install is false when the container was
// prepared, which installed the dependencies already; the
// install exit is then never written, and eslintRemedy reads its absence as
// unknown.
//
// ESLint is resolved through `npx --no`, never ./node_modules/.bin/eslint: in
// an npm workspace member the install hoists eslint to the workspace root's
// node_modules (measured, npm 10.8.2 and eslint 9.39.1), so the member's own
// .bin has none and a project that declares eslint exited 127. nodeProjectDirs
// picks only the topmost package.json today, so no leg runs in a member yet;
// this is the resolver the vitest leg uses, so the two agree when one does.
// `npx --no`
// walks up the way node does and refuses to fetch, so a project with no
// eslint still gets none. --version runs first: it is both the version the
// evidence reports and the proof eslint resolved before it is asked to lint.
// A failed --version empties the file, because yarn berry prints its usage
// error for an unknown binary on stdout, which would otherwise read as a
// version.
func eslintScript(pm nodePM, install bool) string {
	var b strings.Builder
	if install {
		// The exit is recorded, not swallowed with `|| true`: an install that
		// failed is the reason eslint is missing, and the remedy differs.
		b.WriteString(pm.installLine() + "\n")
	}
	b.WriteString(pm.exec() + " eslint --version > " + eslintVersionPath + " 2>/dev/null || : > " + eslintVersionPath + "\n")
	b.WriteString("if [ -s " + eslintVersionPath + " ]; then\n")
	b.WriteString("  " + pm.exec() + " eslint --format json . > " + eslintReportPath + " 2>" + eslintStderrPath + "\n")
	b.WriteString("  echo $? > " + eslintExitPath + "\n")
	b.WriteString("else\n")
	b.WriteString("  : > " + eslintReportPath + "; echo '" + eslintMissingStderr + "' > " + eslintStderrPath + "; echo 127 > " + eslintExitPath + "\n")
	b.WriteString("fi\n")
	b.WriteString("exit 0")
	return b.String()
}

// Where eslintScript writes what the leg reads back.
const (
	eslintVersionPath = "/tmp/eslint.version"
	eslintReportPath  = "/tmp/eslint.json"
	eslintStderrPath  = "/tmp/eslint.err"
	eslintExitPath    = "/tmp/eslint.exit"
)
