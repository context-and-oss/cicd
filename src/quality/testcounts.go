package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Counting `go test -v` output rather than asking for `-json` is deliberate.
// The verbose stream is already captured — runGoTest redirects it to
// /tmp/gotest.out and stores it on the envelope as RawOutputRef — so counting it
// changes no command, no container and no contract, and the parser stays a pure
// function over a string. `-json` would be a tidier input and a wider change:
// a different invocation whose failure mode is a silently uncountable run on any
// toolchain that formats it differently.
var (
	goRunLine    = regexp.MustCompile(`(?m)^=== RUN\s`)
	goResultLine = regexp.MustCompile(`(?m)^\s*--- (PASS|FAIL|SKIP):\s`)
	goPkgLine    = regexp.MustCompile(`(?m)^(ok|FAIL|\?|---)\s`)
	goPkgTime    = regexp.MustCompile(`(?m)^(?:ok|FAIL)\s+\S+\s+([0-9]+\.[0-9]+)s`)
	goPkgCached  = regexp.MustCompile(`(?m)^ok\s+\S+\s+\(cached\)`)
	ansiEscape   = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

	// Vitest prints one summary line per invocation. The text between `Tests`
	// and the parenthesised total is parsed separately so ordering changes
	// (`failed | passed` versus `passed | skipped`) do not change the result.
	vitestTestsLine   = regexp.MustCompile(`(?m)^\s*Tests\s+(.+?)\s+\(([0-9]+)\)\s*$`)
	vitestResultCount = regexp.MustCompile(`([0-9]+)\s+(passed|failed|skipped|todo)\b`)

	// Microsoft.Testing.Platform's console summary uses one key per line.
	// VSTest uses the compact `Passed! - Failed: ...` form. A BYO .NET command
	// can legitimately select either runner, so both are understood.
	dotnetSummaryStart = regexp.MustCompile(`(?i)^Test run summary:\s*(?:Passed|Failed)!?\s*$`)
	dotnetSummaryCount = regexp.MustCompile(`(?i)^(total|failed|succeeded|skipped):\s*([0-9]+)\s*$`)
	dotnetVSTestLine   = regexp.MustCompile(`(?mi)^\s*(?:Passed|Failed)!\s*-\s*Failed:\s*([0-9]+),\s*Passed:\s*([0-9]+),\s*Skipped:\s*([0-9]+),\s*Total:\s*([0-9]+)(?:,|\s|$)`)

	// pytest's terminal summary is deliberately recognised by its surrounding
	// `====` banner. Matching a bare "2 passed" in arbitrary command output
	// would turn a package-manager message into test evidence.
	pytestSummaryLine = regexp.MustCompile(`(?m)^=+\s*(.*?)\s+in\s+[0-9]+(?:\.[0-9]+)?s\s*=+\s*$`)
	pytestNoTestsLine = regexp.MustCompile(`(?m)^=+\s*no tests ran\s+in\s+[0-9]+(?:\.[0-9]+)?s\s*=+\s*$`)
	pytestResultCount = regexp.MustCompile(`([0-9]+)\s+(passed|failed|skipped|xfailed|xpassed|error|errors|deselected)\b`)
)

// parseGoTestCounts reads the executed-test accounting out of `go test -v`
// output. ok is false when the payload is not that output at all, which must
// never be read as "zero tests failed" — an unrecognised payload counts to zero,
// and zero is exactly what a clean run of an empty suite looks like. This is the
// same distinction parseTrxAll draws for .NET by returning a document count.
//
// Subtests are counted at every depth, because that is the number cicd already
// reports for its own suite: scripts/test-module-units.sh counts `^=== RUN`,
// which matches subtests too (`=== RUN TestFoo/sub` is unindented; only the
// corresponding `--- PASS:` is indented). Counting top-level tests only would
// give a smaller, equally defensible figure that disagrees with the one a
// maintainer sanity-checks against, so the convention is followed rather than
// improved on.
//
// Total comes from the RUN lines and the breakdown from the result lines, so
// they can disagree — and when they do, the gap is the point. A suite that
// panics mid-run emits RUN lines with no verdict, and reporting Total as
// Passed+Failed+Skipped would quietly discard the tests whose outcome nobody
// knows. See the TestCounts type comment.
func parseGoTestCounts(out string) (TestCounts, bool) {
	if strings.TrimSpace(out) == "" {
		return TestCounts{}, false
	}
	// Evidence that this is go test output at all: either tests ran, or a
	// package verdict was printed (including "? pkg [no test files]", which is
	// a legitimate zero).
	if !goRunLine.MatchString(out) && !goPkgLine.MatchString(out) {
		return TestCounts{}, false
	}

	counts := TestCounts{Total: len(goRunLine.FindAllString(out, -1))}
	for _, m := range goResultLine.FindAllStringSubmatch(out, -1) {
		switch m[1] {
		case "PASS":
			counts.Passed++
		case "FAIL":
			counts.Failed++
		case "SKIP":
			counts.Skipped++
		}
	}

	// Per-package elapsed time, summed — but only when every package actually
	// ran. A cached package prints "(cached)" in place of a duration, so summing
	// across a partly-cached run yields the elapsed time of whichever packages
	// missed the cache, presented as the figure for the whole suite. Fifty-nine
	// tests in eight milliseconds is what that looks like on the wire, and a
	// consumer has no field to check and no reason to doubt it.
	//
	// So a cache hit withholds the duration rather than shrinking it. This is
	// the same rule the rest of this file holds: a partial measurement is not a
	// small measurement. The counts themselves are unaffected, because a cached
	// package still reports every test it ran.
	//
	// Packages that ran concurrently are still summed, so the figure is test
	// time consumed rather than wall-clock elapsed. "? pkg [no test files]" is
	// not a cache hit and correctly contributes nothing.
	if !goPkgCached.MatchString(out) {
		var seconds float64
		for _, m := range goPkgTime.FindAllStringSubmatch(out, -1) {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil {
				seconds += v
			}
		}
		counts.DurationMS = int64(seconds * 1000)
	}

	return counts, true
}

// trxTestCounts converts .NET's TRX counters into the envelope's accounting.
//
// parsedDocs, not the counter values, decides whether there is an accounting at
// all — parseTrxAll's own comment makes the point: an unparseable payload sums
// to zero, which is exactly what a passing run of no tests looks like. So zero
// readable documents is withheld, never reported as a run of nothing.
//
// TRX reports total, executed and failed; passed and skipped are the arithmetic
// gaps. If either comes out negative the document is internally inconsistent —
// more failures than executions, or more executions than tests — and nothing
// sensible can be recovered from it. Clamping to zero would turn a corrupt
// report into a plausible one, so the whole accounting is withheld instead.
//
// DurationMS is left unset: the counters carry no timing, and the TestRun times
// attributes describe the run's span rather than test time. Unset reads as "not
// measured", which is true.
func trxTestCounts(sum trxSummary, parsedDocs int) (TestCounts, bool) {
	if parsedDocs <= 0 {
		return TestCounts{}, false
	}
	skipped := sum.Total - sum.Executed
	passed := sum.Executed - sum.Failed
	if skipped < 0 || passed < 0 {
		return TestCounts{}, false
	}
	return TestCounts{
		Total:   sum.Total,
		Passed:  passed,
		Failed:  sum.Failed,
		Skipped: skipped,
	}, true
}

// parseVitestTestCounts reads Vitest's final `Tests` line. ANSI styling is
// removed first because Vitest colours every label and number even when its
// output is redirected, as BYO test output is.
//
// Total comes from Vitest's parenthesised total. Skipped is the remainder after
// passed and failed, so todo tests and any future non-executed verdict remain
// visible instead of disappearing from the accounting. A negative remainder
// rejects the summary as internally inconsistent.
func parseVitestTestCounts(out string) (TestCounts, bool) {
	clean := ansiEscape.ReplaceAllString(out, "")
	matches := vitestTestsLine.FindAllStringSubmatch(clean, -1)
	if len(matches) == 0 {
		return TestCounts{}, false
	}

	var total TestCounts
	for _, match := range matches {
		count, err := strconv.Atoi(match[2])
		if err != nil {
			return TestCounts{}, false
		}
		var passed, failed int
		for _, result := range vitestResultCount.FindAllStringSubmatch(match[1], -1) {
			n, err := strconv.Atoi(result[1])
			if err != nil {
				return TestCounts{}, false
			}
			switch result[2] {
			case "passed":
				passed += n
			case "failed":
				failed += n
			}
		}
		if passed+failed > count {
			return TestCounts{}, false
		}
		total.Total += count
		total.Passed += passed
		total.Failed += failed
		total.Skipped += count - passed - failed
	}
	return total, true
}

// parsePytestTestCounts reads pytest's terminal summary. Expected failures,
// ordinary skips and deselected tests are all tests pytest did not execute to a
// successful verdict, so they map to Skipped. Setup/collection errors map to
// Failed: the customer-facing question is how many tests did not succeed, and
// TestCounts has no separate error bucket.
func parsePytestTestCounts(out string) (TestCounts, bool) {
	clean := ansiEscape.ReplaceAllString(out, "")
	if pytestNoTestsLine.MatchString(clean) {
		return TestCounts{}, true
	}
	matches := pytestSummaryLine.FindAllStringSubmatch(clean, -1)
	if len(matches) == 0 {
		return TestCounts{}, false
	}

	var total TestCounts
	found := false
	for _, match := range matches {
		var one TestCounts
		for _, result := range pytestResultCount.FindAllStringSubmatch(match[1], -1) {
			n, err := strconv.Atoi(result[1])
			if err != nil {
				return TestCounts{}, false
			}
			found = true
			switch result[2] {
			case "passed", "xpassed":
				one.Passed += n
			case "failed", "error", "errors":
				one.Failed += n
			case "skipped", "xfailed", "deselected":
				one.Skipped += n
			}
		}
		one.Total = one.Passed + one.Failed + one.Skipped
		total = addTestCounts(total, one)
	}
	return total, found
}

// parseDotnetConsoleTestCounts reads either Microsoft.Testing.Platform's
// multiline aggregate or VSTest's compact summary. It is used only for
// caller-owned commands; the native .NET leg continues to prefer TRX, whose
// structured counters are stronger evidence than console text.
func parseDotnetConsoleTestCounts(out string) (TestCounts, bool) {
	clean := ansiEscape.ReplaceAllString(out, "")
	lines := strings.Split(clean, "\n")
	var total TestCounts
	found := false

	for i := 0; i < len(lines); i++ {
		if !dotnetSummaryStart.MatchString(strings.TrimSpace(lines[i])) {
			continue
		}
		values := map[string]int{}
		for j := i + 1; j < len(lines); j++ {
			line := strings.TrimSpace(lines[j])
			if j > i+1 && dotnetSummaryStart.MatchString(line) {
				break
			}
			if match := dotnetSummaryCount.FindStringSubmatch(line); match != nil {
				n, err := strconv.Atoi(match[2])
				if err != nil {
					return TestCounts{}, false
				}
				values[strings.ToLower(match[1])] = n
			}
		}
		if len(values) != 4 {
			continue
		}
		one := TestCounts{
			Total:   values["total"],
			Passed:  values["succeeded"],
			Failed:  values["failed"],
			Skipped: values["skipped"],
		}
		if one.Passed+one.Failed+one.Skipped > one.Total {
			return TestCounts{}, false
		}
		total = addTestCounts(total, one)
		found = true
	}

	for _, match := range dotnetVSTestLine.FindAllStringSubmatch(clean, -1) {
		failed, e1 := strconv.Atoi(match[1])
		passed, e2 := strconv.Atoi(match[2])
		skipped, e3 := strconv.Atoi(match[3])
		count, e4 := strconv.Atoi(match[4])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || passed+failed+skipped > count {
			return TestCounts{}, false
		}
		total = addTestCounts(total, TestCounts{Total: count, Passed: passed, Failed: failed, Skipped: skipped})
		found = true
	}
	return total, found
}

// parseBYOTestCounts selects a parser from the language the caller declared.
// A BYO command is arbitrary; an unrecognised payload is therefore absent
// accounting, never a zero-test pass.
func parseBYOTestCounts(language, out string) (TestCounts, bool) {
	switch language {
	case "go":
		return parseGoTestCounts(out)
	case "node":
		return parseVitestTestCounts(out)
	case "python":
		return parsePytestTestCounts(out)
	case "dotnet":
		return parseDotnetConsoleTestCounts(out)
	default:
		return TestCounts{}, false
	}
}

func addTestCounts(a, b TestCounts) TestCounts {
	return TestCounts{
		Total:      a.Total + b.Total,
		Passed:     a.Passed + b.Passed,
		Failed:     a.Failed + b.Failed,
		Skipped:    a.Skipped + b.Skipped,
		DurationMS: a.DurationMS + b.DurationMS,
	}
}

// mergeLegTestCounts totals legs by language only when every leg for that
// language was countable. Publishing one Node leg's 973 tests while silently
// dropping its sibling's unknown count would put a partial number beside the
// word total, which is less honest than withholding the aggregate.
func mergeLegTestCounts(byLang map[string][]*TestCounts) map[string]TestCounts {
	out := map[string]TestCounts{}
	for lang, suites := range byLang {
		if len(suites) == 0 {
			continue
		}
		var total TestCounts
		complete := true
		for _, suite := range suites {
			if suite == nil {
				complete = false
				break
			}
			total = addTestCounts(total, *suite)
		}
		if complete {
			out[lang] = total
		}
	}
	return out
}
