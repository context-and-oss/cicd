// Proof for what the infrastructure scan looked at, and for what it could have.
//
// The defect these cover produced no error and no finding: a commit-stage
// run over a repository holding eight parseable infrastructure files reported
// `examined: {count: 0}` and outcome SKIPPED, which is byte-for-byte what a
// repository with no infrastructure at all reports. Every assertion below is
// about telling those two apart.

package main

import (
	"strings"
	"testing"
)

func TestResolveInfraScope(t *testing.T) {
	for _, tc := range []struct {
		name         string
		scope        string
		wantScoped   bool
		wantRejected bool
	}{
		// The empty string is the default arriving over the wire: Dagger's Go
		// client drops an optional argument holding its zero value, so a caller
		// passing "changed" and a caller passing nothing must land here alike.
		{name: "empty is the default", scope: "", wantScoped: true},
		{name: "changed", scope: "changed", wantScoped: true},
		{name: "changed with whitespace", scope: "  changed\n", wantScoped: true},
		{name: "tree", scope: "tree", wantScoped: false},
		{name: "tree with whitespace", scope: " tree ", wantScoped: false},
		// Refused, never resolved: falling back to "tree" turns a typo into a
		// scan nobody asked for, and falling back to "changed" turns it into a
		// scan that looks at almost nothing — the defect this knob ends.
		{name: "unknown word", scope: "whole", wantRejected: true},
		{name: "wrong case", scope: "Tree", wantRejected: true},
		{name: "an unexpanded macro", scope: "$(INFRA_SCOPE)", wantRejected: true},
		{name: "a boolean", scope: "true", wantRejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scoped, err := resolveInfraScope(tc.scope)
			if tc.wantRejected {
				if err == nil {
					t.Fatalf("resolveInfraScope(%q) = %v, nil; an unrecognised scope must be refused", tc.scope, scoped)
				}
				if !strings.Contains(err.Error(), tc.scope) {
					t.Errorf("error %q does not quote the value the caller passed", err)
				}
				if !strings.Contains(err.Error(), infraScopeChanged) || !strings.Contains(err.Error(), infraScopeTree) {
					t.Errorf("error %q does not name the accepted scopes", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveInfraScope(%q): unexpected error %v", tc.scope, err)
			}
			if scoped != tc.wantScoped {
				t.Errorf("resolveInfraScope(%q) = %v, want %v", tc.scope, scoped, tc.wantScoped)
			}
		})
	}
}

// The tree a repository like the one behind this fix presents: parseable infrastructure
// sitting in the checkout, plus files conftest has no parser for.
var infraTree = []string{
	"Dockerfile",
	"api/Dockerfile.build",
	".github/workflows/commit.yml",
	".github/workflows/precommit.yml",
	"infra/azuredeploy.json",
	"infra/main.bicep",
	"src/app.go",
	"package.json",
	"",
	"  ",
}

// Six of the entries above are parseable; bicep, Go, package.json and the blank
// lines are not. The count has to be what *this* scanner could have read, or a
// repository of Bicep would carry a denominator no change could ever move.
const infraTreeCandidates = 5

func TestPlanInfraScanCountsCandidatesBeforeScoping(t *testing.T) {
	changed := map[string]bool{".github/workflows/commit.yml": true}
	scan := planInfraScan(infraTree, changed, true)

	if scan.Candidates != infraTreeCandidates {
		t.Errorf("Candidates = %d, want %d — the denominator is counted before the scope narrows it",
			scan.Candidates, infraTreeCandidates)
	}
	if scan.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", scan.Scanned)
	}
	if !scan.ScopedToDiff {
		t.Error("ScopedToDiff = false; the caller asked for a change-scoped scan")
	}
	var got []string
	for _, g := range scan.Groups {
		got = append(got, g.Paths...)
	}
	if len(got) != 1 || got[0] != ".github/workflows/commit.yml" {
		t.Errorf("scanned paths = %v, want only the changed file", got)
	}
}

// This is the run the issue measured: infrastructure in the tree, none of it
// touched by the push. Candidates must survive the scope, or the envelope says
// 0 and there is nothing to read it against.
func TestPlanInfraScanKeepsTheDenominatorWhenTheScopeExcludesEverything(t *testing.T) {
	scan := planInfraScan(infraTree, map[string]bool{"src/app.go": true}, true)

	if scan.Scanned != 0 {
		t.Fatalf("Scanned = %d, want 0", scan.Scanned)
	}
	if scan.Candidates != infraTreeCandidates {
		t.Errorf("Candidates = %d, want %d — a scan that examined nothing must still say of how many",
			scan.Candidates, infraTreeCandidates)
	}
	if len(scan.Groups) != 0 {
		t.Errorf("Groups = %v, want none", scan.Groups)
	}
}

func TestPlanInfraScanUnscopedReadsTheWholeTree(t *testing.T) {
	scan := planInfraScan(infraTree, nil, false)

	if scan.Scanned != infraTreeCandidates || scan.Candidates != infraTreeCandidates {
		t.Errorf("Scanned/Candidates = %d/%d, want %d/%d",
			scan.Scanned, scan.Candidates, infraTreeCandidates, infraTreeCandidates)
	}
	if scan.ScopedToDiff {
		t.Error("ScopedToDiff = true for an unscoped scan")
	}
	// A change set is supplied but must be ignored: "tree" means tree.
	withChanges := planInfraScan(infraTree, map[string]bool{"Dockerfile": true}, false)
	if withChanges.Scanned != infraTreeCandidates {
		t.Errorf("Scanned = %d with a change set present under tree scope, want %d",
			withChanges.Scanned, infraTreeCandidates)
	}
}

// Group order is observable: violations arrive in it, and `combined.findings`
// caps at 1000 rows, so a map's iteration order would mean two runs over an
// identical tree keep different findings.
func TestPlanInfraScanGroupsAreStablyOrdered(t *testing.T) {
	first := planInfraScan(infraTree, nil, false)
	var want []string
	for _, g := range first.Groups {
		want = append(want, g.Parser+":"+g.Namespace)
	}
	if len(want) < 2 {
		t.Fatalf("fixture produced %d group(s); the ordering claim needs at least two", len(want))
	}
	for i := 0; i < 50; i++ {
		var got []string
		for _, g := range planInfraScan(infraTree, nil, false).Groups {
			got = append(got, g.Parser+":"+g.Namespace)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("group order changed between runs: %v then %v", want, got)
		}
	}
	sorted := append([]string(nil), want...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] > sorted[i] {
			t.Errorf("groups are not sorted: %v", want)
			break
		}
	}
}

func TestInfraScopeWarnings(t *testing.T) {
	t.Run("silent when nothing was excluded", func(t *testing.T) {
		// A line on every run is noise, and `examined` already carries the
		// numbers for anyone who wants them.
		for _, scan := range []infraScan{
			{Candidates: 5, Scanned: 5, ScopedToDiff: true},
			{Candidates: 5, Scanned: 5, ScopedToDiff: false},
			{Candidates: 0, Scanned: 0, ScopedToDiff: false},
		} {
			if got := infraScopeWarnings(scan); got != nil {
				t.Errorf("infraScopeWarnings(%+v) = %v, want none", scan, got)
			}
		}
	})

	t.Run("the scope excluded everything", func(t *testing.T) {
		got := infraScopeWarnings(infraScan{Candidates: 8, Scanned: 0, ScopedToDiff: true})
		if len(got) != 1 {
			t.Fatalf("infraScopeWarnings = %v, want exactly one line", got)
		}
		line := got[0]
		if !strings.Contains(line, "NOTHING IN SCOPE") {
			t.Errorf("line does not name the state: %s", line)
		}
		// The denominator has to be in the sentence, not only in the structured
		// field: `cross-cutting/evidence` propagates warnings[] into the pull
		// request comment, and that is where this was misread.
		if !strings.Contains(line, "8") {
			t.Errorf("line does not say how many files were not looked at: %s", line)
		}
		if !strings.Contains(line, "SKIPPED") {
			t.Errorf("line does not explain the outcome it accompanies: %s", line)
		}
	})

	t.Run("the scope excluded some", func(t *testing.T) {
		got := infraScopeWarnings(infraScan{Candidates: 8, Scanned: 3, ScopedToDiff: true})
		if len(got) != 1 {
			t.Fatalf("infraScopeWarnings = %v, want exactly one line", got)
		}
		line := got[0]
		if !strings.Contains(line, "PARTIAL SCOPE") {
			t.Errorf("line does not name the state: %s", line)
		}
		for _, n := range []string{"3", "8", "5"} {
			if !strings.Contains(line, n) {
				t.Errorf("line is missing the count %s: %s", n, line)
			}
		}
	})

	// A tree-scoped scan that read nothing is a repository with no parseable
	// infrastructure. That is a resting state, not a narrowing, so it gets no
	// warning — `examined: 0 of 0` is the whole statement.
	t.Run("silent when the tree holds no infrastructure", func(t *testing.T) {
		if got := infraScopeWarnings(infraScan{Candidates: 0, Scanned: 0, ScopedToDiff: true}); got != nil {
			t.Errorf("infraScopeWarnings = %v, want none — 0 of 0 says it already", got)
		}
	})
}
