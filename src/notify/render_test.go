package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func baseEnv() *envelope {
	e := &envelope{Passed: false, FindingsCount: 1}
	e.Repo.CommitSHA = "abc123"
	e.Repo.Branch = "feature/x"
	e.FindingsBySeverity = map[Severity]int{SeverityHigh: 1}
	return e
}

// TestBuildMarkdownFindingsDetail verifies the detail table renders the actual
// finding (the answer to "what tripped the gate"), escaping table-breaking
// characters.
func TestBuildMarkdownFindingsDetail(t *testing.T) {
	e := baseEnv()
	e.Findings = []Finding{
		{Severity: SeverityHigh, Tool: "intent-gate", Rule: "min-causal-language",
			ArtifactPath: ".capsules/x.yaml", Message: "artifact contains no causal | language"},
	}
	out := buildMarkdown("precommit", "", e)

	if !strings.Contains(out, "**Findings:**") {
		t.Fatal("expected a Findings detail section")
	}
	if !strings.Contains(out, "intent-gate / min-causal-language") {
		t.Error("expected combined tool/rule source")
	}
	if !strings.Contains(out, "`.capsules/x.yaml`") {
		t.Error("expected artifact path rendered as code")
	}
	if !strings.Contains(out, "no causal \\| language") {
		t.Error("expected pipe in message to be escaped")
	}
}

// TestBuildMarkdownFindingsCap verifies the cap engages and that the overflow
// note claims only what it can see. The aggregator caps its own detail list, so
// a note that counted "all the findings" or sent a reader to
// combined-evidence.json for them would be wrong on exactly the runs big enough
// for anyone to go looking.
func TestBuildMarkdownFindingsCap(t *testing.T) {
	e := baseEnv()
	total := maxRenderedFindings + 7
	for i := 0; i < total; i++ {
		e.Findings = append(e.Findings, Finding{Severity: SeverityHigh, Tool: "trivy", Message: "vuln"})
	}
	out := buildMarkdown("commit", "", e)

	rows := strings.Count(out, "| trivy | ")
	if rows != maxRenderedFindings {
		t.Errorf("expected %d rendered rows, got %d", maxRenderedFindings, rows)
	}
	if !strings.Contains(out, "+7 more") {
		t.Errorf("expected overflow note for 7 hidden findings, got:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("%d rows in this envelope", total)) {
		t.Errorf("overflow note must scope its count to this envelope's %d rows, got:\n%s", total, out)
	}
	if !strings.Contains(out, "findings.sarif") || !strings.Contains(out, "parts/") {
		t.Errorf("overflow note must point at the files that hold every row, got:\n%s", out)
	}
	if strings.Contains(out, "see the evidence artifact (combined-evidence.json)") {
		t.Error("overflow note still sends readers to a file that may itself be truncated")
	}
}

// TestBuildMarkdownNoFindings verifies the detail section is omitted entirely
// when there are no findings (e.g. a passing run).
func TestBuildMarkdownNoFindings(t *testing.T) {
	e := &envelope{Passed: true}
	e.Repo.CommitSHA = "deadbeef"
	out := buildMarkdown("precommit", "https://ci/run/1", e)

	if strings.Contains(out, "**Findings:**") {
		t.Error("did not expect a Findings detail section with zero findings")
	}
	if !strings.Contains(out, "✅ Passed") {
		t.Error("expected passed status")
	}
}

// TestFindingLocationRendersPathAndLine pins the location cell as `path:line`,
// the form an editor or terminal turns into a jump. A bare line number is not a
// location a reader can act on, and `path:0` claims a line the tool never
// reported.
func TestFindingLocationRendersPathAndLine(t *testing.T) {
	cases := []struct {
		name string
		in   Finding
		want string
	}{
		{"path and line", Finding{ArtifactPath: "src/db.go", Line: 42}, "src/db.go:42"},
		{"path only", Finding{ArtifactPath: "src/db.go"}, "src/db.go"},
		{"zero line is no line", Finding{ArtifactPath: "src/db.go", Line: 0}, "src/db.go"},
		{"negative line is no line", Finding{ArtifactPath: "src/db.go", Line: -1}, "src/db.go"},
		{"a line with no path is not a location", Finding{Line: 42}, ""},
		{"nothing", Finding{}, ""},
	}
	for _, tc := range cases {
		if got := findingLocation(tc.in); got != tc.want {
			t.Errorf("%s: findingLocation(%+v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestBuildMarkdownFindingsShowTheLine is the visible half: two findings that
// differ only by line must render as two distinguishable rows. Under the old
// Finding they were one row, and the aggregator had already dropped the second.
func TestBuildMarkdownFindingsShowTheLine(t *testing.T) {
	e := baseEnv()
	e.FindingsCount = 2
	e.FindingsBySeverity = map[Severity]int{SeverityHigh: 2}
	e.Findings = []Finding{
		{Severity: SeverityHigh, Tool: "gitleaks", Rule: "aws-key", ArtifactPath: ".env", Message: "leak", Line: 4},
		{Severity: SeverityHigh, Tool: "gitleaks", Rule: "aws-key", ArtifactPath: ".env", Message: "leak", Line: 19},
	}
	out := buildMarkdown("precommit", "", e)

	for _, want := range []string{"`.env:4`", "`.env:19`"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in the findings table:\n%s", want, out)
		}
	}
	// Scoped to the detail table, which is the table this rule is about: a row
	// there stands for one finding, so a bare path is a line silently dropped.
	// The location rollup above it renders the same path with no line on
	// purpose — three findings on three lines of one file are one file to open
	// — and it carries an explicit count column saying how many, so it cannot
	// be misread as the one finding this assertion exists to protect.
	detail := out[strings.Index(out, "**Findings:**"):]
	if strings.Contains(detail, "`.env` |") {
		t.Error("a located finding must not render a bare path")
	}
}

func TestFormatDuration(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   int64
		want string
	}{
		// An invented sub-second duration guards against rounding a non-zero
		// measurement down to "0s". The aggregator's clock is separate.
		{"a sub-second value keeps its milliseconds", 143, "143ms"},
		{"just under a second", 999, "999ms"},
		{"exactly a second", 1000, "1s"},
		{"a second and a half rounds", 1500, "2s"},
		{"a long run", 27*60*1000 + 15*1000 + 400, "27m15s"},
		{"an hour-long run", 3*60*60*1000 + 90*1000, "3h1m30s"},

		// build.NoArtifact sets DurationMS 0 on purpose because nothing ran.
		// "0s" would read as an instant run; it is an absent measurement.
		{"zero is an absent measurement, not an instant run", 0, "not measured"},
		{"a negative duration is not a duration", -5, "not measured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatDuration(tc.ms); got != tc.want {
				t.Errorf("formatDuration(%d) = %q, want %q", tc.ms, got, tc.want)
			}
		})
	}
}

func TestBuildMarkdownDoesNotRenderASubSecondRunAsZero(t *testing.T) {
	env := &envelope{Passed: true, DurationMS: 143}
	md := buildMarkdown("commit", "", env)

	if strings.Contains(md, "| **Duration** | 0s |") {
		t.Error("a 143ms run rendered as 0s — the regression is back")
	}
	if !strings.Contains(md, "| **Duration** | 143ms |") {
		t.Errorf("want the duration row to say 143ms, got:\n%s", md)
	}
}

func TestBuildCardAndMarkdownAgreeOnDuration(t *testing.T) {
	// The synthetic duration must render identically in both views, rather
	// than rounding to "0s" only in the table. One envelope, one formatter.
	env := &envelope{Passed: false, FindingsCount: 3, DurationMS: 143}
	md := buildMarkdown("commit", "", env)
	card := buildTeamsCard("commit", "", env)

	blob, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	want := formatDuration(env.DurationMS)
	if !strings.Contains(md, want) {
		t.Errorf("markdown is missing %q", want)
	}
	if !strings.Contains(string(blob), want) {
		t.Errorf("card is missing %q:\n%s", want, blob)
	}
}
