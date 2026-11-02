#!/usr/bin/env python3
"""
Transform internal/evidence/schema.go into a module-local schema.go.

Module copies differ from the canonical internal package in three ways:
  1. package main  (not package evidence)
  2. Unexported type names: envelope / toolInfo / repoContext
  3. No ValidSeverity or MultiLangEnvelope; severityOrder + shouldFail appended

Usage: python3 scripts/sync-schema.py src/internal/evidence/schema.go > src/<module>/schema.go
"""
import re
import sys


def strip_top_level_block(src: str, header_re: str) -> str:
    """Remove a top-level Go func/type block whose first line matches header_re,
    plus any contiguous `//` comment lines immediately above it.

    Brace-balanced: walks `{` and `}` from the block header forward so inner
    constructs (switch, nested struct literals) don't trip the parse — this is
    the bug the previous non-greedy `[^}]+\\}` regex had on ValidSeverity, which
    contains a switch and so terminates at the switch's `}` instead of the
    function's.
    """
    m = re.search(header_re, src, flags=re.MULTILINE)
    if not m:
        return src

    start = m.start()
    while start > 0:
        prev_nl = src.rfind('\n', 0, start - 1)
        line_start = prev_nl + 1 if prev_nl >= 0 else 0
        line = src[line_start:start - 1]
        if line.lstrip().startswith('//'):
            start = line_start
        else:
            break

    open_idx = src.index('{', m.start())
    depth = 0
    i = open_idx
    while i < len(src):
        c = src[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                i += 1
                break
        i += 1
    if i < len(src) and src[i] == '\n':
        i += 1

    out = src[:start] + src[i:]
    return re.sub(r'\n\n\n+', '\n\n', out)


src = open(sys.argv[1]).read()

# 1. Package
src = src.replace('package evidence\n', 'package main\n')

# 2. Const name
src = src.replace('const SchemaVersion ', 'const evidenceSchemaVersion ')

# 3. Struct definition names
src = src.replace('type ToolInfo struct', 'type toolInfo struct')
src = src.replace('type RepoContext struct', 'type repoContext struct')
src = src.replace('type Envelope struct', 'type envelope struct')

# 4. Field type references inside struct bodies
src = re.sub(r'(\bTool\s{6,})ToolInfo\b', lambda m: m.group(1) + 'toolInfo', src)
src = re.sub(r'(\bRepo\s{7,})RepoContext\b', lambda m: m.group(1) + 'repoContext', src)

# 5. Remove ValidSeverity (func) and MultiLangEnvelope (type), brace-balanced
src = strip_top_level_block(src, r'^func ValidSeverity\b')
src = strip_top_level_block(src, r'^type MultiLangEnvelope\b')

# 6. Append module helpers
helpers = """
func severityOrder(s Severity) int {
\tswitch s {
\tcase SeverityCritical:
\t\treturn 4
\tcase SeverityHigh:
\t\treturn 3
\tcase SeverityMedium:
\t\treturn 2
\tcase SeverityLow:
\t\treturn 1
\tdefault:
\t\treturn 0
\t}
}

// shouldFail returns true if any finding severity meets or exceeds the threshold.
func shouldFail(counts map[Severity]int, threshold Severity) bool {
\tif threshold == SeverityNone {
\t\treturn false
\t}
\tthresh := severityOrder(threshold)
\tfor sev, count := range counts {
\t\tif count > 0 && severityOrder(sev) >= thresh {
\t\t\treturn true
\t\t}
\t}
\treturn false
}

// outcomeRank orders the outcomes by how much they should worry a reader.
//
// ERROR outranks FAILED outranks FINDINGS outranks CLEAN, on the same reasoning
// gatedPassed uses for ran: not knowing is worse than knowing something bad,
// because a tool that did not run tells you nothing about what it would have
// found. A findings count can be judged; an absent count cannot.
//
// SKIPPED sits between CLEAN and FINDINGS, and the placement is the whole
// design of the value. Above CLEAN, so a run where any check was skipped cannot
// report a clean headline — "everything we looked at was fine" must not be
// rendered as "everything is fine" when three checks never looked. Below
// FINDINGS, so a real finding still wins the headline: incomplete coverage is
// worth degrading a green to, never worth burying a HIGH under.
//
// Unset is rank 0 and is not an outcome. It is the absence of one.
var outcomeRank = map[Outcome]int{
\tOutcomeClean:    1,
\tOutcomeSkipped:  2,
\tOutcomeFindings: 3,
\tOutcomeFailed:   4,
\tOutcomeError:    5,
}

// worstOutcome folds a run's outcomes into the one its envelope reports.
//
// A single unset input collapses the whole result to unset. A leg with no
// outcome is a producer that has not been converted, and folding it in as if it
// were CLEAN would manufacture the exact claim this field exists to stop being
// manufactured: an envelope reporting CLEAN because one of its legs declined to
// answer.
//
// It takes the whole set rather than folding pairwise for that reason. A
// pairwise accumulator seeded with unset cannot stay collapsed: "" means both
// "nothing folded yet" and "something declined to answer", so the next valid
// input revives the fold and the decline is lost. Reading them all at once
// removes the ambiguity.
//
// Folding nothing yields unset too, which is the right answer for a run with no
// legs: an aggregate over zero tools has not observed a clean tree, it has
// observed nothing.
func worstOutcome(outcomes []Outcome) Outcome {
\tif len(outcomes) == 0 {
\t\treturn ""
\t}
\tworst := OutcomeClean
\tfor _, o := range outcomes {
\t\tif outcomeRank[o] == 0 {
\t\t\treturn ""
\t\t}
\t\tif outcomeRank[o] > outcomeRank[worst] {
\t\t\tworst = o
\t\t}
\t}
\treturn worst
}

// sourcesOutcome folds the per-tool rows an envelope declares into the outcome
// the envelope itself reports. Derived from the rows that actually ship rather
// than recomputed from the same inputs, so the two cannot disagree.
func sourcesOutcome(rows []SourceStatus) Outcome {
\tout := make([]Outcome, 0, len(rows))
\tfor _, r := range rows {
\t\tout = append(out, r.Outcome)
\t}
\treturn worstOutcome(out)
}

// scanOutcome states what a tool found, before the gate.
//
// It is deliberately NOT derived from gatedPassed's result. Under
// `fail-on: NONE` that result is true whatever the tool saw, which is the
// documented contract and the reason this function exists: a consumer building
// a customer report needs the un-gated answer, and reading it back out of a
// gated boolean is impossible by construction.
//
// ran is the same signal gatedPassed takes: false when the tool could not
// produce a usable result, which is a different claim from a clean tree.
func scanOutcome(ran bool, findings int) Outcome {
\tswitch {
\tcase !ran:
\t\treturn OutcomeError
\tcase findings > 0:
\t\treturn OutcomeFindings
\tdefault:
\t\treturn OutcomeClean
\t}
}

// runOutcome states how a tool that executes a subject fared, before the gate.
//
// The difference from scanOutcome is FAILED, and it is the whole reason both
// exist. A linter's verdict IS its findings count; a test runner's is not. A
// suite with failing tests reports zero findings and a real failure, so
// scanOutcome would call it CLEAN, which is what a consumer reading only passed
// already suffers under `fail-on: NONE`, restated one field over.
//
// subjectPassed is the un-gated result: the tests passed, the build succeeded.
// It is exactly gatedPassed's second argument for these call sites, read before
// NONE has a chance to suppress it.
func runOutcome(ran, subjectPassed bool) Outcome {
\tswitch {
\tcase !ran:
\t\treturn OutcomeError
\tcase !subjectPassed:
\t\treturn OutcomeFailed
\tdefault:
\t\treturn OutcomeClean
\t}
}

// testOutcome states how a test leg fared, letting the runner's own accounting
// overrule its exit status.
//
// A real run showed why the exit status alone is not enough. A consumer's .NET
// leg recorded total:N passed:N failed:0 alongside "dotnet test failed (exit
// 1)". runOutcome reads only "did the subject pass", sees the failure, and
// reports FAILED — so a report generator would have printed "N of N tests
// passed" directly beneath "tests: FAILED", and sent someone hunting for a
// broken assertion that does not exist. `dotnet test` under VSTest exits
// non-zero for a test project that will not build, for a crashed host, and for
// runner diagnostics after the suite finished, none of which is a failing test.
//
// So counts overrule, they are not a prerequisite:
//
//   - counts say something failed -> FAILED. Positive evidence.
//   - counts say nothing failed, yet the leg did not pass -> ERROR. The
//     runner's own accounting contradicts its exit status, and the honest
//     reading is that we do not know what went wrong, only that something did.
//   - no counts at all -> FAILED, on the exit status alone. For `go test`,
//     pytest and vitest a non-zero exit overwhelmingly does mean failing
//     tests, and downgrading every one of those to ERROR would trade a rare
//     wrong verdict for a systematic one.
//
// That last branch is why populating Tests is worth doing per leg rather than
// treating it as decoration: it is the only thing that can tell these apart.
func testOutcome(ran, subjectPassed bool, counts *TestCounts) Outcome {
\tswitch {
\tcase !ran:
\t\treturn OutcomeError
\tcase subjectPassed:
\t\treturn OutcomeClean
\tcase counts == nil:
\t\treturn OutcomeFailed
\tcase counts.Failed > 0:
\t\treturn OutcomeFailed
\tdefault:
\t\treturn OutcomeError
\t}
}
"""

sys.stdout.write(src.rstrip('\n') + '\n' + helpers)
