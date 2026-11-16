//go:build unit_test

package main

import (
	"errors"
	"testing"
)

func byTool(rows []SourceStatus) map[string]SourceStatus {
	out := map[string]SourceStatus{}
	for _, r := range rows {
		out[r.Tool] = r
	}
	return out
}

// The whole point of per-tool rows. A single fused verdict cannot say which of three
// scanners tripped it; three rows can. Semgrep is clean, Trivy found a HIGH —
// the fused envelope reports one `passed: false` and the consumer is left to
// guess, or to reconstruct the split by string-matching Finding.Tool, which
// never recovers a per-tool verdict because it was never written down.
func TestPerToolSources_verdictsAreIndependent(t *testing.T) {
	rows := perToolSources(scopeSource, SeverityHigh,
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{SeverityLow: 4}},
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{}},
		toolResult{Name: "trivy", BySeverity: map[Severity]int{SeverityHigh: 1}},
	)
	if len(rows) != 3 {
		t.Fatalf("want one row per scanner, got %d", len(rows))
	}
	got := byTool(rows)
	if !got["opengrep"].Passed {
		t.Errorf("semgrep found only LOW under a HIGH threshold — must pass")
	}
	if !got["gitleaks"].Passed {
		t.Errorf("gitleaks found nothing — must pass")
	}
	if got["trivy"].Passed {
		t.Errorf("trivy found a HIGH under a HIGH threshold — must fail")
	}
}

// The rows must AND together to the verdict the fused envelope computes over
// the merged counts, or the split would silently change what the gate does.
// Merging is addition and the threshold is a floor, so "some tool reached the
// threshold" and "the merged counts reached it" are the same claim — this
// pins that they stay the same claim.
func TestPerToolSources_andEqualsTheFusedVerdict(t *testing.T) {
	cases := []struct {
		name       string
		sast, vuln map[Severity]int
	}{
		{"both clean", map[Severity]int{}, map[Severity]int{}},
		{"one below threshold", map[Severity]int{SeverityLow: 9}, map[Severity]int{}},
		{"one at threshold", map[Severity]int{SeverityHigh: 1}, map[Severity]int{}},
		{"the other at threshold", map[Severity]int{}, map[Severity]int{SeverityCritical: 2}},
		{"both at threshold", map[Severity]int{SeverityHigh: 1}, map[Severity]int{SeverityHigh: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threshold := SeverityHigh
			merged := mergeSeverity(tc.sast, tc.vuln)
			fused := gatedPassed(true, !shouldFail(merged, threshold), threshold)

			rows := perToolSources(scopeSource, threshold,
				toolResult{Name: "opengrep", BySeverity: tc.sast},
				toolResult{Name: "trivy", BySeverity: tc.vuln},
			)
			and := true
			for _, r := range rows {
				and = and && r.Passed
			}
			if and != fused {
				t.Fatalf("AND of rows = %v, fused verdict = %v — the split changed the gate", and, fused)
			}
		})
	}
}

// A scanner that could not execute is a different claim from a scanner that
// found nothing, and gatedPassed already refuses to let any threshold suppress
// it. What the split adds is attribution: today one failed scanner sets
// ran=false for the WHOLE envelope, so a clean Semgrep is reported under a
// failed verdict with the reason sitting unread in errors[].
func TestPerToolSources_aRunErrorFailsOnlyItsOwnTool(t *testing.T) {
	rows := perToolSources(scopeSource, SeverityNone,
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{}},
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{}, Err: errStub{}},
	)
	got := byTool(rows)
	if !got["opengrep"].Passed {
		t.Errorf("semgrep ran and found nothing — gitleaks failing must not fail it")
	}
	if got["gitleaks"].Passed {
		t.Errorf("a scanner that could not run must fail at every threshold, NONE included")
	}
	if got["gitleaks"].ErrorsCount != 1 {
		t.Errorf("errorsCount = %d, want 1", got["gitleaks"].ErrorsCount)
	}
	if got["opengrep"].ErrorsCount != 0 {
		t.Errorf("opengrep errorsCount = %d, want 0", got["opengrep"].ErrorsCount)
	}
}

func TestPerToolSources_explicitSkipIsPassingNotClean(t *testing.T) {
	row := perToolSources(scopeSource, SeverityHigh, toolResult{
		Name: "trivy", Concern: ConcernSCA, Skipped: true, Warnings: 1,
	})[0]
	if !row.Passed || row.Outcome != OutcomeSkipped || row.ErrorsCount != 0 || row.WarningsCount != 1 {
		t.Errorf("row = %+v, want passing warned SKIPPED", row)
	}
}

// One scanner over two scopes is otherwise indistinguishable — and that
// ambiguity reaches customers as "gitleaks, gitleaks" in a release report.
// Scope is what tells the source-tree gitleaks from the build-output one.
func TestPerToolSources_scopeDistinguishesTheSameScannerTwice(t *testing.T) {
	src := perToolSources(scopeSource, SeverityHigh,
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{}},
	)
	archive := perToolSources(scopeArchive, SeverityHigh,
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{SeverityHigh: 1}},
	)
	if src[0].Scope != scopeSource || archive[0].Scope != scopeArchive {
		t.Fatalf("scopes not stamped: %q / %q", src[0].Scope, archive[0].Scope)
	}
	if src[0].Tool != archive[0].Tool {
		t.Fatalf("both rows describe gitleaks; only the scope may differ")
	}
	if src[0].Passed == archive[0].Passed {
		t.Fatalf("the two scopes reached different verdicts and must be able to say so")
	}
}

// Counts must sum to the fused envelope's FindingsCount, because a consumer
// reading the propagated rows sees these INSTEAD OF a row for the envelope.
// If they did not sum, replacing one row with three would change the total.
func TestPerToolSources_countsSumToTheFusedTotal(t *testing.T) {
	sast := map[Severity]int{SeverityLow: 2, SeverityMedium: 1}
	secrets := map[Severity]int{SeverityHigh: 3}
	vuln := map[Severity]int{SeverityCritical: 1, SeverityLow: 5}

	merged := mergeSeverity(sast, secrets, vuln)
	fusedTotal := 0
	for _, c := range merged {
		fusedTotal += c
	}

	rows := perToolSources(scopeSource, SeverityHigh,
		toolResult{Name: "opengrep", BySeverity: sast},
		toolResult{Name: "gitleaks", BySeverity: secrets},
		toolResult{Name: "trivy", BySeverity: vuln},
	)
	sum := 0
	for _, r := range rows {
		sum += r.FindingsCount
	}
	if sum != fusedTotal {
		t.Fatalf("rows sum to %d, fused envelope reports %d", sum, fusedTotal)
	}
	if fusedTotal != 12 {
		t.Fatalf("guard on the fixture itself: want 12, got %d", fusedTotal)
	}
}

// Every row must be identifiable as this module's, or a consumer joining the
// combined envelope's sources back to a module cannot place them.
func TestPerToolSources_rowsCarryModuleIdentity(t *testing.T) {
	rows := perToolSources(scopeImage, SeverityHigh,
		toolResult{Name: "trufflehog", BySeverity: map[Severity]int{}, Warnings: 2},
	)
	if rows[0].ModuleName != moduleName || rows[0].Stage != moduleStage {
		t.Fatalf("row identity = %q/%q, want %q/%q",
			rows[0].ModuleName, rows[0].Stage, moduleName, moduleStage)
	}
	if rows[0].WarningsCount != 2 {
		t.Fatalf("warningsCount = %d, want 2", rows[0].WarningsCount)
	}
}

type errStub struct{}

func (errStub) Error() string { return "scanner did not run" }

// Every row a fused envelope declares states what its own scanner found, before
// the gate. Without it "SAST clean, SCA failed" is expressible as two passed
// booleans only while the threshold is not NONE; under NONE both are true and
// the split the rows exist to preserve is erased one field over.
func TestEachRowStatesWhatItsScannerFound(t *testing.T) {
	rows := byTool(perToolSources(scopeSource, SeverityNone,
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{SeverityHigh: 14}},
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{}},
		toolResult{Name: "trivy", Err: errStub{}},
	))

	for name, want := range map[string]Outcome{
		"opengrep": OutcomeFindings,
		"gitleaks": OutcomeClean,
		"trivy":    OutcomeError,
	} {
		if got := rows[name].Outcome; got != want {
			t.Errorf("%s: outcome = %q, want %q", name, got, want)
		}
	}

	// The two verdicts against each other, at the threshold where they diverge
	// most. NONE suppresses the findings verdict, so semgrep's 14 HIGH findings
	// pass the gate while the row still reports FINDINGS — which is exactly the
	// information Passed cannot carry. A non-run is not a finding and NONE does
	// not suppress it, so trivy fails the gate AND reports ERROR.
	for name, wantPassed := range map[string]bool{"opengrep": true, "gitleaks": true, "trivy": false} {
		if rows[name].Passed != wantPassed {
			t.Errorf("%s: passed = %v at threshold NONE, want %v; the gate contract must not move with this field",
				name, rows[name].Passed, wantPassed)
		}
	}
}

// The envelope's outcome is folded from the rows that ship rather than
// recomputed from the same inputs, so the two cannot disagree about what was
// counted.
func TestTheEnvelopeOutcomeIsTheWorstOfItsRows(t *testing.T) {
	rows := perToolSources(scopeSource, SeverityNone,
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{}},
		toolResult{Name: "gitleaks", BySeverity: map[Severity]int{SeverityHigh: 3}},
	)
	if got := sourcesOutcome(rows); got != OutcomeFindings {
		t.Errorf("sourcesOutcome = %q, want FINDINGS", got)
	}

	rows = perToolSources(scopeSource, SeverityNone,
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{SeverityHigh: 3}},
		toolResult{Name: "gitleaks", Err: errStub{}},
	)
	if got := sourcesOutcome(rows); got != OutcomeError {
		t.Errorf("sourcesOutcome = %q, want ERROR — a scanner that could not run outranks one that found something", got)
	}
}

// A zero finding count needs a denominator. "0 licences outside policy" reads
// identically whether the scan read 365 declarations or reached none, and a row
// carrying only findingsCount cannot tell a customer which happened.
func TestARowCarriesTheDenominatorItsZeroNeeds(t *testing.T) {
	rows := perToolSources("security-license", SeverityNone,
		toolResult{
			Name:       "trivy-license",
			BySeverity: map[Severity]int{},
			Examined:   &Examined{Unit: "licence declarations", Count: 365},
		},
		// A scanner that does not count in a unit it can name says nothing,
		// rather than claiming a zero it never measured.
		toolResult{Name: "opengrep", BySeverity: map[Severity]int{SeverityHigh: 10}},
	)

	if rows[0].Examined == nil {
		t.Fatal("trivy-license row lost its examined count")
	}
	if got := rows[0].Examined.Count; got != 365 {
		t.Errorf("examined.count = %d, want 365", got)
	}
	if rows[0].FindingsCount != 0 {
		t.Errorf("findingsCount = %d, want 0", rows[0].FindingsCount)
	}
	if rows[1].Examined != nil {
		t.Errorf("semgrep row invented an examined count: %+v", *rows[1].Examined)
	}
}

// TestASecondStageFailureIsStillAScanFailure pins the licence scan's two stages
// as one decision.
//
// The row used to be built from the trivy error alone, so a report that trivy
// produced fine and the evaluator could not parse reached perToolSources with a
// nil Err and came back CLEAN — under an envelope whose own errs had already
// set ran=false and failed the gate. A row saying nothing happened beneath a
// gate that blocked.
func TestASecondStageFailureIsStillAScanFailure(t *testing.T) {
	scanFailed := errors.New("trivy: exit 1")
	evalFailed := errors.New("parse license report: unexpected end of JSON input")

	cases := []struct {
		name    string
		scanErr error
		evalErr error
		want    error
	}{
		{name: "both stages clean", want: nil},
		{name: "the scanner failed", scanErr: scanFailed, want: scanFailed},
		{name: "the regression: scanner fine, evaluator could not read it", evalErr: evalFailed, want: evalFailed},
		{name: "the scanner's failure wins — the evaluator never saw a report", scanErr: scanFailed, evalErr: evalFailed, want: scanFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := licenseScanErr(tc.scanErr, tc.evalErr)
			if got != tc.want {
				t.Fatalf("licenseScanErr(%v, %v) = %v, want %v", tc.scanErr, tc.evalErr, got, tc.want)
			}

			// And the consequence the row must carry: an error at either stage
			// is a scan that did not produce a usable result.
			rows := perToolSources("license", SeverityHigh, toolResult{Name: "trivy-license", Err: got})
			wantOutcome := OutcomeClean
			if tc.want != nil {
				wantOutcome = OutcomeError
			}
			if rows[0].Outcome != wantOutcome {
				t.Fatalf("row outcome = %q, want %q", rows[0].Outcome, wantOutcome)
			}
		})
	}
}
