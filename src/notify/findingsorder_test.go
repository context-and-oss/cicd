package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestWriteFindingsDetailKeepsTheAggregatorsOrder pins that the 25-row table is
// the head of the list as the aggregator ordered it — not a re-sort. The
// aggregator ranks rows of equal severity by producing module (security before
// style), a fact a Finding does not carry, so a sort here could only be by
// severity and would put whatever style row happened to come first back ahead
// of the security row the aggregator placed there. Two caps, one rule: the
// rule lives upstream and this renderer inherits it.
func TestWriteFindingsDetailKeepsTheAggregatorsOrder(t *testing.T) {
	var sb strings.Builder
	in := []Finding{
		{Severity: SeverityMedium, Tool: "Semgrep OSS", Rule: "unsafe-path-combine", Message: "traversal", ArtifactPath: "a.cs", Line: 1},
		{Severity: SeverityMedium, Tool: "dotnet-format", Rule: "WHITESPACE", Message: "ws", ArtifactPath: "b.cs", Line: 1},
		// Deliberately out of severity order: the renderer must not "fix" it,
		// because fixing it would be a second ordering rule.
		{Severity: SeverityHigh, Tool: "gitleaks", Rule: "generic-api-key", Message: "leak", ArtifactPath: ".env", Line: 2},
	}
	writeFindingsDetail(&sb, in)
	out := sb.String()
	semgrep, dotnet, gitleaks := strings.Index(out, "Semgrep OSS"), strings.Index(out, "dotnet-format"), strings.Index(out, "gitleaks")
	if semgrep < 0 || dotnet < 0 || gitleaks < 0 {
		t.Fatalf("a row is missing from the table:\n%s", out)
	}
	if semgrep >= dotnet || dotnet >= gitleaks {
		t.Errorf("rows were reordered by the renderer (positions %d, %d, %d):\n%s", semgrep, dotnet, gitleaks, out)
	}
}

// TestWriteFindingsDetailOverflowSaysWhichRowsItShows requires the overflow
// note to say the visible rows are the head of the envelope's order, so a
// reader does not take 25 rows for a sample.
func TestWriteFindingsDetailOverflowSaysWhichRowsItShows(t *testing.T) {
	var sb strings.Builder
	in := make([]Finding, maxRenderedFindings+1)
	for i := range in {
		in[i] = Finding{Severity: SeverityLow, Tool: "eslint", Message: fmt.Sprintf("row %d", i)}
	}
	writeFindingsDetail(&sb, in)
	if want := fmt.Sprintf("the first %d in the envelope's order (most severe first)", maxRenderedFindings); !strings.Contains(sb.String(), want) {
		t.Errorf("overflow note omits %q:\n%s", want, sb.String())
	}
}
