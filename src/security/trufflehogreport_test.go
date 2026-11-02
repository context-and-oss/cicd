package main

// Untagged, like the code it covers, so `make test-module-units` runs it. The
// argument-shape test below lived behind //go:build !unit_test until the
// location work moved its subject out, where a green lint-repo said nothing
// about whether it had executed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestTruffleHogArgs pins the ADR-005 "heavier secrets" contract: --only-verified
// is present iff verifySecrets is true, and the default (false) leaves the base
// argument list untouched.
func TestTruffleHogArgs(t *testing.T) {
	contains := func(args []string, want string) bool {
		for _, a := range args {
			if a == want {
				return true
			}
		}
		return false
	}

	t.Run("verifySecrets on adds --only-verified", func(t *testing.T) {
		args := trufflehogArgs(true)
		if !contains(args, "--only-verified") {
			t.Fatalf("verifySecrets=true: expected --only-verified in %v", args)
		}
	})

	t.Run("verifySecrets off (default) omits --only-verified", func(t *testing.T) {
		args := trufflehogArgs(false)
		if contains(args, "--only-verified") {
			t.Fatalf("verifySecrets=false: --only-verified must be absent in %v", args)
		}
	})

	// The base invocation must be unchanged regardless of the flag: default
	// behaviour stays a plain filesystem scan of the mounted image root.
	t.Run("base args unchanged", func(t *testing.T) {
		for _, verify := range []bool{false, true} {
			args := trufflehogArgs(verify)
			for _, want := range []string{"trufflehog", "filesystem", "/target", "--json", "--no-update"} {
				if !contains(args, want) {
					t.Fatalf("verifySecrets=%v: expected base arg %q in %v", verify, want, args)
				}
			}
		}
	})
}

// trufflehogLine is one result in the shape TruffleHog 3.78.0 actually prints —
// verified against the pinned image, see MEASURED below. SourceName is the
// scan's source and never a path; the path and the 0-based line offset sit in
// SourceMetadata.Data.Filesystem. Pass offset < 0 to omit the key entirely, the
// way TruffleHog's omitempty does for a secret on the first line.
func trufflehogLine(detector, file string, offset int) string {
	fs := map[string]any{"file": file}
	if offset >= 0 {
		fs["line"] = offset
	}
	doc := map[string]any{
		"SourceMetadata": map[string]any{
			"Data": map[string]any{"Filesystem": fs},
		},
		"SourceName":   "trufflehog - filesystem",
		"DetectorName": detector,
		"DecoderName":  "PLAIN",
		"Verified":     false,
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// MEASURED is the literal stdout of the pinned trufflehog 3.78.0 scanning a
// fixture with three GitHub tokens — one on line 3 of other.yaml, one on line 7
// of .env, one on line 1 of .env — with every field except the location
// stripped, and the credential-bearing fields (Raw, RawV2, Redacted,
// StructuredData) dropped rather than neutered, since a scanner's own fixture is
// no place to commit something shaped like a token. The three location shapes
// are byte-for-byte what TruffleHog emitted, which is the part being pinned:
// 0-based, and absent for the first line.
const MEASURED = `{"SourceMetadata":{"Data":{"Filesystem":{"file":"/target/app/other.yaml","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":8,"DetectorName":"Github","DecoderName":"PLAIN","Verified":false}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/target/app/.env","line":6}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":8,"DetectorName":"Github","DecoderName":"PLAIN","Verified":false}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/target/app/.env"}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":8,"DetectorName":"Github","DecoderName":"PLAIN","Verified":false}`

// TestTruffleHogRealOutput runs the parser over those measured bytes. Every
// other test here builds its input; this one does not, so a fixture that drifted
// from the tool cannot make the rest of the file agree with itself and be wrong.
func TestTruffleHogRealOutput(t *testing.T) {
	findings, errs := parseTrufflehogOutput(MEASURED, nil)
	if len(errs) > 0 {
		t.Fatalf("real output must parse cleanly: %v", errs)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	want := []finding{
		{RuleID: "Github", File: "/app/other.yaml", Line: 3},
		{RuleID: "Github", File: "/app/.env", Line: 7},
		{RuleID: "Github", File: "/app/.env", Line: 0},
	}
	for i, w := range want {
		got := findings[i]
		if got.File != w.File || got.Line != w.Line || got.RuleID != w.RuleID {
			t.Errorf("finding %d = %s:%d (%s), want %s:%d (%s)",
				i, got.File, got.Line, got.RuleID, w.File, w.Line, w.RuleID)
		}
	}

	// The two .env secrets are the pair that matters: they differ only by
	// location, so if either the path or the line is lost they become one row.
	if findings[1] == findings[2] {
		t.Errorf("the two .env secrets are indistinguishable: %+v", findings[1])
	}
}

func TestTruffleHogFindingsCarryTheirOwnLocation(t *testing.T) {
	// Two secrets from the same detector in two different files, plus a third
	// in the same file as the first. Under the old parse all three carried
	// File="trufflehog - filesystem" and no line, which made them one finding.
	output := strings.Join([]string{
		trufflehogLine("AWS", "/target/app/.env", 3),
		trufflehogLine("AWS", "/target/app/config.yaml", 10),
		trufflehogLine("AWS", "/target/app/.env", 18),
	}, "\n")

	findings, errs := parseTrufflehogOutput(output, nil)
	if len(errs) > 0 {
		t.Fatalf("clean output must not report errors: %v", errs)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	seen := map[string]bool{}
	for _, f := range findings {
		if f.File == "" || f.Line == 0 {
			t.Fatalf("finding lost its location: %+v", f)
		}
		if strings.Contains(f.File, "trufflehog") {
			t.Fatalf("SourceName was reported as a path: %+v", f)
		}
		if strings.HasPrefix(f.File, trufflehogMountRoot) {
			t.Fatalf("the mount root leaked into the reported path: %+v", f)
		}
		key := fmt.Sprintf("%s|%s|%d", f.RuleID, f.File, f.Line)
		if seen[key] {
			t.Fatalf("two findings are still indistinguishable: %+v", f)
		}
		seen[key] = true
	}

	// Offset 3 is line 4: the increment happens once, in one place.
	if findings[0].File != "/app/.env" || findings[0].Line != 4 {
		t.Fatalf("expected /app/.env:4, got %s:%d", findings[0].File, findings[0].Line)
	}
}

func TestTruffleHogAbsentLineIsNotInvented(t *testing.T) {
	// omitempty makes "offset 0" and "no offset" the same bytes, so a first-line
	// secret arrives with no line. It keeps its path and reports no line, rather
	// than claiming the more precise of two readings — a fabricated location is
	// worse than a missing one because it reads as exact.
	findings, errs := parseTrufflehogOutput(trufflehogLine("Github", "/target/x.go", -1), nil)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors %v", errs)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Line != 0 {
		t.Fatalf("an absent offset must not become a line, got %d", findings[0].Line)
	}
	if findings[0].File != "/x.go" {
		t.Fatalf("expected the path to survive, got %q", findings[0].File)
	}

	// An offset present as 0 is unambiguous — it is line 1.
	zero, errs := parseTrufflehogOutput(trufflehogLine("Github", "/target/x.go", 0), nil)
	if len(errs) > 0 || len(zero) != 1 {
		t.Fatalf("offset 0: errs=%v findings=%+v", errs, zero)
	}
	if zero[0].Line != 1 {
		t.Fatalf("offset 0 is line 1, got %d", zero[0].Line)
	}

	// And a negative offset is nonsense no arithmetic should launder into a line.
	neg, errs := parseTrufflehogOutput(strings.Replace(
		trufflehogLine("Github", "/target/x.go", 5), `"line":5`, `"line":-3`, 1), nil)
	if len(errs) > 0 || len(neg) != 1 {
		t.Fatalf("negative offset: errs=%v findings=%+v", errs, neg)
	}
	if neg[0].Line != 0 {
		t.Fatalf("a negative offset must report no line, got %d", neg[0].Line)
	}
}

func TestTruffleHogOutputItCannotReadIsAnError(t *testing.T) {
	// Output that stops making sense halfway is a scan whose result is unknown.
	// Returning the findings parsed so far would report a shorter list, which
	// reads exactly like a cleaner image — and the previous `continue` also
	// never advanced the decoder past the bad bytes, so it hung.
	output := trufflehogLine("AWS", "/target/a.env", 1) + "\n{\"DetectorName\": tru"

	done := make(chan struct{})
	var findings []finding
	var errs []string
	go func() {
		findings, errs = parseTrufflehogOutput(output, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parseTrufflehogOutput did not terminate on malformed output")
	}

	if len(errs) == 0 {
		t.Fatalf("malformed output must be a run error, got findings %+v", findings)
	}
	if findings != nil {
		t.Fatalf("no findings may be reported from output that could not be read: %+v", findings)
	}
	if !strings.Contains(errs[0], "trufflehog") {
		t.Fatalf("the error must name the tool: %q", errs[0])
	}
}

func TestTruffleHogRunErrorIsNotAnEmptyResult(t *testing.T) {
	findings, errs := parseTrufflehogOutput("", errors.New("exit status 2"))
	if len(errs) != 1 || !strings.Contains(errs[0], "exit status 2") {
		t.Fatalf("expected the run error verbatim, got %v", errs)
	}
	if findings != nil {
		t.Fatalf("a scan that did not run reports no findings, got %+v", findings)
	}
}

func TestTruffleHogSARIFCarriesTheLocation(t *testing.T) {
	raw := buildTrufflehogSARIF([]finding{
		{RuleID: "AWS", Description: "Secret detected by AWS", File: "/app/.env", Line: 4},
		{RuleID: "AWS", Description: "Secret detected by AWS", File: "/app/.env", Line: 19},
		{RuleID: "Github", Description: "Secret detected by Github", File: "/app/x.go"},
		{RuleID: "Slack", Description: "Secret detected by Slack"},
	})

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the document must be valid SARIF JSON: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 4 {
		t.Fatalf("expected 1 run of 4 results, got %+v", doc.Runs)
	}
	results := doc.Runs[0].Results

	// The two .env secrets differ only by line, which is exactly the pair the
	// aggregator used to collapse. The SARIF has to carry the difference.
	for i, wantLine := range map[int]int{0: 4, 1: 19} {
		loc := results[i].Locations
		if len(loc) != 1 {
			t.Fatalf("result %d: expected one location, got %d", i, len(loc))
		}
		if got := loc[0].PhysicalLocation.ArtifactLocation.URI; got != "/app/.env" {
			t.Fatalf("result %d: expected /app/.env, got %q", i, got)
		}
		if loc[0].PhysicalLocation.Region == nil {
			t.Fatalf("result %d: expected a region carrying line %d", i, wantLine)
		}
		if got := loc[0].PhysicalLocation.Region.StartLine; got != wantLine {
			t.Fatalf("result %d: expected startLine %d, got %d", i, wantLine, got)
		}
	}

	// A path with no line: located, but no region claiming a line 0.
	if len(results[2].Locations) != 1 {
		t.Fatalf("a finding with a path must be located: %+v", results[2])
	}
	if results[2].Locations[0].PhysicalLocation.Region != nil {
		t.Fatalf("no line means no region, got %+v", results[2].Locations[0].PhysicalLocation.Region)
	}

	// No path at all: no location, rather than one naming nothing.
	if len(results[3].Locations) != 0 {
		t.Fatalf("a finding with no path must emit no location: %+v", results[3])
	}

	if !strings.Contains(string(raw), `"version":"2.1.0"`) {
		t.Fatalf("the document must declare SARIF 2.1.0: %s", raw)
	}
}
