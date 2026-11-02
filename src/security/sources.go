package main

// Per-tool verdicts for the modules that fuse several scanners under one
// envelope.
//
// src/quality/sources.go is the sibling, not a copy: quality fuses one lint
// and one test leg per detected language, so its rows carry a concern and a
// language rather than a scanner name, and the two files diverge by design.
//
// ScanSource runs Semgrep, Gitleaks and Trivy and reports ONE `security-source`
// verdict; ScanArchive does the same for Gitleaks and Trivy under
// `security-archive`. The merge happens before anything downstream can see it,
// so a consumer cannot say "SAST clean, SCA failed" — it can only reconstruct
// the findings split by string-matching Finding.Tool, and a per-tool VERDICT is
// not recoverable that way at all, because it was never written down.
//
// This file lives outside the `!unit_test` build so the verdict arithmetic is
// testable without Dagger. moduleName and moduleStage live here for the same
// reason: they identify the rows, and a row built in a test must carry the same
// identity as one built in main.go.
const (
	moduleName  = "security"
	moduleStage = "domain"
)

// The fused envelopes, named once so the envelope's Tool.Name, its rows' Scope
// and the SARIF automation id it stamps cannot drift apart. A consumer joins on
// these strings; three literals would let one of the three be renamed alone.
const (
	scopeSource  = "security-source"
	scopeArchive = "security-archive"
	scopeImage   = "security-image"
	scopeLicense = "security-license"
)

// toolResult is one scanner's contribution to a fused envelope.
//
// Warnings is a COUNT, not the strings: warnings are merged into the envelope's
// own Warnings list and would be duplicated by carrying them twice. Err is the
// scanner's run error, which is a different claim from "found nothing" — see
// gatedPassed.
type toolResult struct {
	Name       string
	BySeverity map[Severity]int
	Err        error
	Warnings   int
	// Skipped is an intentional, non-gating non-run: there was no applicable
	// scope. It must be explicit because empty counts otherwise mean CLEAN.
	Skipped bool
	// Examined is how much this scanner looked at, when it counts in a unit
	// it can name. Nil for the scanners that do not report one yet — absent
	// says "did not state", which is the honest reading and is why this is
	// not an int that would default to a confident zero.
	Examined *Examined
	// Rules is the rule set the scanner applied, for a scanner whose rules
	// can change under a fixed commit. Nil when it did not say.
	Rules *RuleSet
	// Concern is the question this scanner answers. Set at every construction
	// site rather than defaulted, because the default would be the empty
	// string and a silently unclassified scanner is exactly what declaring
	// the concern is meant to prevent.
	Concern Concern
}

// perToolSources turns each scanner's own counts into a SourceStatus row,
// gated at the same threshold the fused envelope uses.
//
// The rows AND together to the fused verdict rather than restating it: a tool
// trips its own gate exactly when its findings reach the threshold, and the
// fused gate trips exactly when the merged counts do — which is the same
// condition, because merging is addition and the threshold is a floor. The same
// holds for run errors, where the split is strictly more informative: today a
// Gitleaks execution failure sets ran=false for the WHOLE envelope, so a clean
// Semgrep result is reported under a failed verdict with the reason sitting
// unread in errors[]. After the split the Semgrep row still passes and the
// Gitleaks row carries the failure, while the fused verdict is unchanged.
//
// Note what is deliberately NOT here: a per-tool duration or timestamp. The
// scanners run concurrently against one filtered tree, so splitting the
// envelope's single duration between them would be an invention.
func perToolSources(scope string, threshold Severity, results ...toolResult) []SourceStatus {
	out := make([]SourceStatus, 0, len(results))
	for _, r := range results {
		total := 0
		for _, c := range r.BySeverity {
			total += c
		}
		errCount := 0
		if r.Err != nil {
			errCount = 1
		}
		outcome := scanOutcome(r.Err == nil, total)
		// Findings outrank a contradictory skipped marker. Constructors never
		// produce that shape, but keeping the precedence here prevents an
		// accidental future caller from hiding a real result as N/A.
		if r.Skipped && r.Err == nil && total == 0 {
			outcome = OutcomeSkipped
		}
		out = append(out, SourceStatus{
			ModuleName: moduleName,
			Stage:      moduleStage,
			Tool:       r.Name,
			Scope:      scope,
			Concern:    r.Concern,
			Passed: gatedPassed(
				r.Err == nil,
				!shouldFail(r.BySeverity, threshold),
				threshold,
			),
			Outcome:       outcome,
			Examined:      r.Examined,
			Rules:         r.Rules,
			FindingsCount: total,
			ErrorsCount:   errCount,
			WarningsCount: r.Warnings,
		})
	}
	return out
}

// licenseScanErr is the error that decided a licence scan's fate.
//
// The scan is two stages: trivy produces a report, then evaluateLicenses reads
// it against the policy. Either can fail, and the second failing on a report
// the first produced happily is not a rare shape — a schema change in trivy's
// output lands there.
//
// The source row was wired to the first stage's error alone. So an unparseable
// report left the row's Err nil while errs, ran and the gate all said the scan
// had failed, and perToolSources — correctly, on what it was given — emitted
// CLEAN under an envelope that had already failed. The row said nothing
// happened while the gate blocked.
//
// One function, so the two stages are one decision that cannot drift apart
// again, and out here rather than in main.go because main.go carries the Dagger
// build tag and nothing tagged can be reached by a test.
func licenseScanErr(scanErr, evalErr error) error {
	if scanErr != nil {
		return scanErr
	}
	return evalErr
}

// concatWarnings folds per-scanner warning lists into the fused envelope's
// single warnings[], in row order, and stays nil when every list is empty so
// the envelope's `omitempty` still omits the key on a run with nothing to say.
//
// The per-row WarningsCount is the length of each input; this is the only
// place the strings themselves are joined, so a row's count and the envelope's
// list cannot disagree about whose warning is whose.
func concatWarnings(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}
