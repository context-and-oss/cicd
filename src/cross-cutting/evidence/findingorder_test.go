package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// styleRows fabricates n MEDIUM formatter findings at distinct locations to
// exercise a style flood without replaying a consumer's table.
func styleRows(n int) []Finding {
	out := make([]Finding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Finding{
			Severity:     SeverityMedium,
			Tool:         "dotnet-format",
			Rule:         "WHITESPACE",
			Message:      "Fix whitespace formatting.",
			ArtifactPath: fmt.Sprintf("src/File%04d.cs", i/10),
			Line:         1 + i%10,
		})
	}
	return out
}

// securityMediumRows contains invented rules, messages and locations. The
// security module, not the rule ID or tool name, supplies their ordering class.
var securityMediumRows = []Finding{
	{Severity: SeverityMedium, Tool: "Semgrep OSS", Rule: "synthetic.security.unchecked-destination", Message: "Synthetic destination check missing", ArtifactPath: "src/ParcelSender.cs", Line: 23},
	{Severity: SeverityMedium, Tool: "Semgrep OSS", Rule: "synthetic.security.unbounded-upload", Message: "Synthetic upload bound missing", ArtifactPath: "src/UploadGate.cs", Line: 57},
	{Severity: SeverityMedium, Tool: "Semgrep OSS", Rule: "synthetic.security.untrusted-template", Message: "Synthetic template input unchecked", ArtifactPath: "web/PreviewPanel.tsx", Line: 16},
}

// TestCapKeepsSecurityRowsAheadOfStyleRows is the regression test for the
// synthetic stress case: 1,536 style MEDIUM rows and 3 security MEDIUM rows share a
// tier, the cap lands inside that tier, and every security row must survive
// while the LOW — a lower tier, whatever its class — must not. Severity still
// wins across tiers; the class only orders within one.
func TestCapKeepsSecurityRowsAheadOfStyleRows(t *testing.T) {
	low := Finding{Severity: SeverityLow, Tool: "Semgrep OSS", Rule: "generic.note", Message: "informational", ArtifactPath: "src/Other.cs", Line: 3}
	// quality before security, as the stage-2 composite collects them — the
	// order that let module order decide the table before this change.
	merged := mergeFindings([]*envelope{
		{ModuleName: "quality", Findings: styleRows(1536)},
		{ModuleName: "security", Findings: append(append([]Finding{}, securityMediumRows...), low)},
	})
	if len(merged) != 1540 {
		t.Fatalf("merged %d rows, want 1540 (dedupe must not collapse distinct locations)", len(merged))
	}

	kept, warn := capFindings(merged)
	if len(kept) != maxCombinedFindings {
		t.Fatalf("kept %d rows, want %d", len(kept), maxCombinedFindings)
	}
	have := make(map[Finding]bool, len(kept))
	for _, f := range kept {
		have[f] = true
	}
	for _, want := range securityMediumRows {
		if !have[want] {
			t.Errorf("security MEDIUM row dropped under the cap: %s", want.Rule)
		}
	}
	if have[low] {
		t.Error("a LOW row survived while MEDIUM rows were dropped: severity must win across tiers")
	}
	// The security rows are not merely present; they head the MEDIUM tier, so
	// the 25-row comment sees them too.
	for i, want := range []string{"Semgrep OSS", "Semgrep OSS", "Semgrep OSS", "dotnet-format"} {
		if kept[i].Tool != want {
			t.Errorf("row %d is from %s, want %s", i, kept[i].Tool, want)
		}
	}

	if warn == "" {
		t.Fatal("a truncated list with no warning is indistinguishable from a quiet run")
	}
	// The warning states the rule, in the comparator's own words, so a reader
	// can tell from the document why one MEDIUM row is listed and another is not.
	if !strings.Contains(warn, findingOrderRule) {
		t.Errorf("warning does not quote the ordering rule:\n%s", warn)
	}
	for _, want := range []string{"most severe kept", "security findings before style findings", "1000 of 1540"} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning omits %q: %s", want, warn)
		}
	}
}

// TestOrderIsTotalAndIgnoresCollectionOrder shuffles the same rows across
// envelopes and within them and requires one answer. The composite's parts
// list is an accident of how it was wired; the row at position 1000 must not be.
func TestOrderIsTotalAndIgnoresCollectionOrder(t *testing.T) {
	var pool []classedFinding
	for _, f := range styleRows(40) {
		pool = append(pool, classedFinding{Finding: f, class: classQuality})
	}
	for _, f := range securityMediumRows {
		pool = append(pool, classedFinding{Finding: f, class: classSecurity})
	}
	pool = append(pool,
		classedFinding{Finding: Finding{Severity: SeverityHigh, Tool: "eslint", Rule: "no-eval", Message: "eval", ArtifactPath: "a.js", Line: 1}, class: classQuality},
		classedFinding{Finding: Finding{Severity: SeverityHigh, Tool: "gitleaks", Rule: "generic-api-key", Message: "leak", ArtifactPath: ".env", Line: 2}, class: classSecurity},
		classedFinding{Finding: Finding{Severity: SeverityMedium, Tool: "risk-validate", Message: "runs as root"}, class: classRisk},
		classedFinding{Finding: Finding{Severity: SeverityMedium, Tool: "intent-gate", Rule: "no-weasel-words", Message: "robust", ArtifactPath: ".capsules/x.yaml"}, class: classIntent},
		classedFinding{Finding: Finding{Severity: SeverityMedium, Tool: "new-scanner", Rule: "r", Message: "m"}, class: classUnclassified},
		classedFinding{Finding: Finding{Severity: SeverityLow, Tool: "gitleaks", Rule: "note", Message: "n"}, class: classSecurity},
	)

	want := orderFindings(append([]classedFinding{}, pool...))
	rng := rand.New(rand.NewSource(20260906))
	for round := 0; round < 25; round++ {
		in := append([]classedFinding{}, pool...)
		rng.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
		if got := orderFindings(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: a shuffled input produced a different order", round)
		}
	}

	// Severity first, whatever the class: the HIGH quality row precedes every
	// MEDIUM security row. Then class within the tier, in the documented order.
	sequence := []string{"gitleaks", "eslint", "Semgrep OSS", "Semgrep OSS", "Semgrep OSS", "risk-validate", "intent-gate", "new-scanner", "dotnet-format"}
	for i, tool := range sequence {
		if want[i].Tool != tool {
			t.Errorf("position %d: %s (%s), want %s", i, want[i].Tool, want[i].Severity, tool)
		}
	}
	if last := want[len(want)-1]; last.Severity != SeverityLow {
		t.Errorf("last row is %s, want the LOW", last.Severity)
	}

	// The same rows through mergeFindings, with the envelopes in either order,
	// give the same list — module order in the parts list decides nothing.
	q := &envelope{ModuleName: "quality", Findings: styleRows(40)}
	s := &envelope{ModuleName: "security", Findings: securityMediumRows}
	if a, b := mergeFindings([]*envelope{q, s}), mergeFindings([]*envelope{s, q}); !reflect.DeepEqual(a, b) {
		t.Error("envelope order changed the merged order")
	}
}

// TestCapLeavesAMixedListUnderTheCapAlone runs the whole path — merge, order,
// cap — on exactly as many rows as fit, across classes, and requires every row
// back with no warning. A warning on a complete list would teach readers to
// ignore the warning.
func TestCapLeavesAMixedListUnderTheCapAlone(t *testing.T) {
	merged := mergeFindings([]*envelope{
		{ModuleName: "quality", Findings: styleRows(maxCombinedFindings - len(securityMediumRows))},
		{ModuleName: "security", Findings: securityMediumRows},
	})
	kept, warn := capFindings(merged)
	if len(kept) != maxCombinedFindings || warn != "" {
		t.Errorf("kept %d rows with warning %q; want %d and none", len(kept), warn, maxCombinedFindings)
	}
}

// TestDedupeIgnoresClass pins the seam between deduplication and ordering: the
// class describes the producer, not the finding, so one row stated by two
// modules is still one row.
func TestDedupeIgnoresClass(t *testing.T) {
	f := Finding{Severity: SeverityHigh, Tool: "gitleaks", Rule: "aws-key", Message: "leak", ArtifactPath: ".env", Line: 4}
	got := orderFindings([]classedFinding{
		{Finding: f, class: classQuality},
		{Finding: f, class: classSecurity},
	})
	if len(got) != 1 {
		t.Errorf("got %d rows, want 1: class must not widen the dedupe key", len(got))
	}
}

// TestFindingClassCoversEveryModule holds findingClassOf to the set of modules
// this repository actually ships, read from their source. A module is either
// classified or listed here as one that produces no findings — an unknown
// module would land in classUnclassified silently, and this test is what makes
// that arm unreachable from within the repository. Zero module names found is
// a failure, not a pass: a walk that read nothing cannot vouch for anything.
func TestFindingClassCoversEveryModule(t *testing.T) {
	// Modules whose envelopes carry no findings, so they need no class. A name
	// here that no module declares any more is an error too — the list must
	// not outlive the module it excuses.
	producesNoFindings := map[string]bool{
		"build":                  true, // attests the artifact; no rows
		"notify":                 true, // renders evidence, produces none
		"cross-cutting/evidence": true, // this aggregator
	}

	root := filepath.Join("..", "..")
	decl := regexp.MustCompile(`(?m)^\s*moduleName\s*=\s*"([^"]+)"`)
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "internal", "dagger", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllSubmatch(src, -1) {
			found[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(found) == 0 {
		t.Fatalf("no moduleName declarations found under %s — the walk read nothing, so it proves nothing", root)
	}

	for name := range found {
		classified := findingClassOf(name) != classUnclassified
		switch {
		case classified && producesNoFindings[name]:
			t.Errorf("module %q is both classified and listed as producing no findings", name)
		case !classified && !producesNoFindings[name]:
			t.Errorf("module %q has no finding class: add it to findingClassOf, or to producesNoFindings if its envelope never carries rows", name)
		}
	}
	for name := range producesNoFindings {
		if !found[name] {
			t.Errorf("producesNoFindings lists %q, which no module under %s declares", name, root)
		}
	}
	// The four classes the order is documented against must all be reachable
	// from a real module, or the rule in the warning describes modules that do
	// not exist.
	for _, want := range []string{"security", "risk", "intent", "quality"} {
		if !found[want] {
			t.Errorf("module %q named by findingOrderRule was not found in the tree", want)
		}
	}
}
