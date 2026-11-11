// Semgrep invocation policy: which --config flags a scan gets, and how to tell
// a scan that ran from one that died.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so semgreprun_test.go can drive it with `go test -tags unit_test ./...`.
package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// defaultSastRulesets is the ruleset list used when a consumer names none.
//
// It is deliberately *not* semgrep's "auto". `semgrep scan --config auto`
// refuses to run when telemetry is disabled — "Cannot create auto config when
// metrics are off", exit 2, no report written — and every scanner cicd runs
// carries --metrics=off so a client's source tree is never reported to a third
// party. The two are mutually exclusive, so "auto" could only ever yield an
// empty report. Do not restore it as the default: semgrepConfigFlags rejects it
// outright rather than let it silently scan nothing.
const defaultSastRulesets = "p/security-audit"

// semgrepConfigFlags turns a comma-separated ruleset list into semgrep --config
// arguments, or returns an error explaining why the list cannot produce a scan.
//
// Both error cases are silent-false-pass shapes: a config semgrep will not
// accept, and an empty list that makes semgrep scan with no rules at all and
// report zero findings. Neither may reach the container — a scan that cannot
// run has to fail loudly, not return "clean".
//
// The returned values are passed to the container as positional arguments, never
// spliced into a shell script, and each is character-validated here, so a
// ruleset string cannot smuggle shell syntax into the scan step.
func semgrepConfigFlags(rulesets string) ([]string, error) {
	var out []string
	for _, r := range strings.Split(rulesets, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == "auto" {
			return nil, errors.New(`semgrep: --sast-rulesets "auto" cannot be used: ` +
				`semgrep refuses --config auto while telemetry is off, and cicd always runs with --metrics=off. ` +
				`Name explicit packs (e.g. "` + defaultSastRulesets + `,p/owasp-top-ten") or a config path in the scanned tree (e.g. "./semgrep.yml")`)
		}
		if err := validateSemgrepConfig(r); err != nil {
			return nil, err
		}
		out = append(out, "--config", r)
	}
	if len(out) == 0 {
		return nil, errors.New(`semgrep: --sast-rulesets resolved to no configs; ` +
			`semgrep would scan with no rules and report zero findings. ` +
			`Omit the flag to use "` + defaultSastRulesets + `" rather than passing an empty value`)
	}
	return out, nil
}

// validateSemgrepConfig accepts the shapes semgrep takes as a --config value: a
// registry id (p/…, r/…, a bare pack name) or a path inside the scanned tree.
// Anything else is rejected here so a typo fails with a readable message
// instead of an opaque container error.
func validateSemgrepConfig(r string) error {
	for _, c := range r {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '.', c == '-', c == '_':
		default:
			return errors.New("semgrep: invalid ruleset " + strconv.Quote(r) +
				": expected a registry id (e.g. p/security-audit) or a relative config path (e.g. ./semgrep.yml)")
		}
	}
	if strings.HasPrefix(r, "/") {
		return errors.New("semgrep: invalid ruleset " + strconv.Quote(r) +
			": a config path must be relative to the scanned tree")
	}
	return nil
}

// semgrepRunError classifies a semgrep invocation from its exit status, stderr
// and the report it left behind, returning "" when the scan is trustworthy and
// an error string otherwise.
//
// semgrep's contract: 0 = scan completed, 1 = findings found (only reachable
// with --error, which cicd does not pass), and every other code means it did not
// scan — 2 invalid config or usage, 3 internal error, 4 unsupported language,
// 7 all rules failed. The previous implementation ended the command in
// `|| echo '{"runs":[]}' > report.sarif`, so all of those produced an empty
// report that counted as zero findings and passed the gate.
//
// A completed scan always emits at least one run. An exit-zero scan with no runs
// is therefore also a non-run, not a clean bill of health.
func semgrepRunError(exitCode, stderr, report string) string {
	code := strings.TrimSpace(exitCode)
	n, err := strconv.Atoi(code)
	switch {
	case err != nil:
		return "semgrep: unreadable exit status " + strconv.Quote(code)
	case n != 0 && n != 1:
		msg := "semgrep: did not run (exit " + code + ")"
		if s := lastNonEmptyLine(stderr); s != "" {
			msg += ": " + s
		}
		return msg
	}

	if strings.TrimSpace(report) == "" {
		return "semgrep: exited " + code + " but wrote no report"
	}
	var doc struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal([]byte(report), &doc); err != nil {
		return "semgrep: report is not valid SARIF: " + err.Error()
	}
	if len(doc.Runs) == 0 {
		msg := "semgrep: exited " + code + " but reported no scan runs, so no rules were applied"
		if s := lastNonEmptyLine(stderr); s != "" {
			msg += ": " + s
		}
		return msg
	}
	return ""
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

// semgrepScript runs semgrep, records its exit status, and always exits 0 so
// the classification below — not Dagger's exec failure — decides what
// happened.
//
// It lives here rather than beside the Dagger call because it IS invocation
// policy, which is this file's subject, and because a build tag is no place to
// put something a test must read. sast.go carries //go:build !unit_test, so a
// script declared there is invisible to the tests that pin its flags — and the
// flags are the mechanism: --json-output is what turns "semgrep found nothing"
// into "semgrep read 1,204 files and found nothing", and dropping it would
// break that quietly, with every other test still green.
//
// The rulesets arrive as positional arguments and are referenced as "$@", so a
// consumer-supplied value is never part of the script text and cannot be
// re-parsed as shell syntax. stdout and stderr are captured rather than
// discarded: when semgrep cannot run, its own message is the only thing that
// tells the team why.
//
// The count is taken here, in the container, because semgrep's JSON names
// every file it scanned and only the length of that list is wanted. Reading
// the list across the Dagger boundary to call len() on it would move the
// largest document this container produces for a number that fits in five
// bytes. /tmp/semgrep.scanned is truncated BEFORE the scan, so a semgrep that
// dies leaves an empty file — "did not state" — rather than a stale count from
// an earlier layer, and every failure in the counting step lands there too:
// a missing report.json, a JSON shape semgrep changed, a python that is not
// there. None of them are worth failing a scan whose SARIF is good.
//
// When the pinned pack is mounted, the script stages it first (see
// semgreppack.go) and refuses to scan on any staging failure: a root path the
// image already has, or a file it could not copy. A scan with part of the
// pinned rules would report fewer findings and look like a cleaner tree, so
// the script writes exit 2 and no report, and sast.go reports what
// semgrepPackErrPath says. semgrepRuleSet checks the loaded rules afterwards
// as well; this step only makes the first failure the one that is named.
const semgrepScript = `set -u
: > /tmp/semgrep.err
: > /tmp/semgrep.scanned
: > ` + semgrepPackErrPath + `
if [ -f ` + semgrepPackFiles + ` ]; then
  while read -r top; do
    [ -n "$top" ] || continue
    if [ -e "/$top" ]; then echo "/$top already exists in the scan image" >> ` + semgrepPackErrPath + `; fi
  done < ` + semgrepPackTops + `
  if [ ! -s ` + semgrepPackErrPath + ` ]; then
    while read -r f d; do
      [ -n "$f" ] || continue
      { mkdir -p "$d" && cp "` + semgrepPackSrc + `/$f" "$d/"; } 2>> ` + semgrepPackErrPath + ` || echo "could not stage $f" >> ` + semgrepPackErrPath + `
    done < ` + semgrepPackFiles + `
  fi
fi
# Generate only for an exact --config pair, never an excluded rule or twice.
need_gha=0
previous=
for arg in "$@"; do
  if [ "$previous" = --config ] && [ "$arg" = ` + semgrepGHAFallbackPath + ` ]; then need_gha=1; fi
  previous="$arg"
done
if [ "$need_gha" = 1 ] && [ ! -s ` + semgrepPackErrPath + ` ]; then
  python3 ` + semgrepGHAAdapterPath + ` --upstream ` + semgrepPackSrc + ` --output ` + semgrepGHAFallbackPath + ` 2>> ` + semgrepPackErrPath + ` || echo "could not adapt workflow rule" >> ` + semgrepPackErrPath + `
fi
if [ -s ` + semgrepPackErrPath + ` ]; then
  echo 2 > /tmp/semgrep.exit
  : > /tmp/report.sarif
  exit 0
fi
# The engine is pinned; optional update-service retries must not consume scan time.
semgrep scan --disable-version-check --sarif-output=/tmp/report.sarif --json-output=/tmp/report.json --metrics=off "$@" . >/tmp/semgrep.out 2>/tmp/semgrep.err
code=$?
echo "$code" > /tmp/semgrep.exit
[ -f /tmp/report.sarif ] || : > /tmp/report.sarif
# Optional metadata projection; never changes findings, severity or scan status.
python3 ` + semgrepMetadataPath + ` --json /tmp/report.json --sarif /tmp/report.sarif 2>/dev/null || :
if [ "$code" -le 1 ] && [ -f ` + semgrepInlinePlanPath + ` ]; then
  python3 ` + semgrepInlinePath + ` --plan ` + semgrepInlinePlanPath + ` --source /src \
    --json /tmp/report.json --sarif /tmp/report.sarif --warnings ` + semgrepInlineWarnings + ` \
    2>>/tmp/semgrep.err || echo 125 > /tmp/semgrep.exit
fi
python3 -c "import json;p=json.load(open('/tmp/report.json'))['paths']['scanned'];print(len(p)) if isinstance(p,list) else None" > /tmp/semgrep.scanned 2>/dev/null || : > /tmp/semgrep.scanned
exit 0`

// semgrepExamined turns the scanned-file count the container wrote into the
// denominator a zero finding count needs.
//
// Semgrep's SARIF says nothing about scope. It lists what was found and stops,
// so "semgrep: 0 findings" has meant either "it read every file in the
// repository and there is nothing" or "it matched no targets at all" — and the
// report rendered both as the reassuring one. Semgrep's JSON output does carry
// it, under paths.scanned, and one scan emits both formats, so this costs a
// second output file and no second pass over the source.
//
// The unit is files and there is no total, because paths.skipped only appears
// under --verbose. A total is a claim about what existed in scope, and the run
// has no basis for one; guessing it from a directory walk would be this module
// inventing a denominator out of a file count semgrep never agreed to.
//
// An empty or unparseable value is nil, meaning "did not state". A count of
// zero is NOT nil and is the whole reason this reads a string rather than an
// int: "semgrep examined 0 files" is the alarm — a misconfigured include
// filter, a ruleset matching no language present — and it is exactly what a
// bare zero from a failed read would be mistaken for.
func semgrepExamined(scanned string) *Examined {
	n, err := strconv.Atoi(strings.TrimSpace(scanned))
	if err != nil || n < 0 {
		return nil
	}
	return &Examined{Count: n, Unit: "files"}
}
