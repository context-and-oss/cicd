//go:build unit_test

package main

// Unit tests for the witnessed-test-leg rules in testlegs.go. Run with:
//
//	cd src/quality && go test -tags unit_test ./...
//
// (or `make test-module-units`, the canonical runner). No Dagger session
// needed — testlegs.go is untagged for exactly this reason.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseTestLegsAcceptsAValidDocument(t *testing.T) {
	raw := `[
	  {"label":"api","language":"dotnet","cmd":"dotnet test","coveragePath":"cov/cobertura.xml"},
	  {"label":"web","language":"NODE","cmd":"  cd src/web && npm ci && npm test  ","toolchainImage":"node:22-alpine"}
	]`

	legs, err := parseTestLegs(raw)
	if err != nil {
		t.Fatalf("parseTestLegs: unexpected error: %v", err)
	}
	if len(legs) != 2 {
		t.Fatalf("want 2 legs, got %d", len(legs))
	}
	if legs[0].Label != "api" || legs[0].Language != "dotnet" || legs[0].CoveragePath != "cov/cobertura.xml" {
		t.Errorf("leg 0 wrong: %+v", legs[0])
	}
	// Language is normalised, so "NODE" keys coverage the same way "node" does.
	if legs[1].Language != "node" {
		t.Errorf("language not normalised: %q", legs[1].Language)
	}
	if legs[1].ToolchainImage != "node:22-alpine" {
		t.Errorf("toolchainImage wrong: %q", legs[1].ToolchainImage)
	}
	// The command goes to `sh -c` verbatim: trimming it would silently rewrite
	// a heredoc or a trailing continuation.
	if legs[1].Cmd != "  cd src/web && npm ci && npm test  " {
		t.Errorf("cmd was altered: %q", legs[1].Cmd)
	}
	// coveragePath absent means this leg measures nothing, not "".
	if legs[1].CoveragePath != "" {
		t.Errorf("want empty coveragePath, got %q", legs[1].CoveragePath)
	}
}

func TestParseTestLegsEmptyInputYieldsNoLegs(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n\t"} {
		legs, err := parseTestLegs(raw)
		if err != nil {
			t.Fatalf("parseTestLegs(%q): unexpected error: %v", raw, err)
		}
		if legs != nil {
			t.Errorf("parseTestLegs(%q): want nil legs, got %+v", raw, legs)
		}
	}
}

func TestParseTestLegsRejections(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		contains string
	}{
		{
			// A tolerant decoder would read this as a leg with no coverage at
			// all, which the ratchet then reports as "skipped" rather than as
			// the typo it is.
			name:     "unknown field",
			raw:      `[{"label":"a","language":"go","cmd":"go test ./...","coverage_path":"c.out"}]`,
			contains: "coverage_path",
		},
		{name: "not json", raw: `not json at all`, contains: "test-legs:"},
		{name: "object not array", raw: `{"label":"a"}`, contains: "test-legs:"},
		{name: "trailing content", raw: `[{"label":"a","language":"go","cmd":"go test"}] [{"label":"b"}]`, contains: "trailing content"},
		{name: "empty array", raw: `[]`, contains: "declares no legs"},
		{name: "blank label", raw: `[{"label":"  ","language":"go","cmd":"go test"}]`, contains: "label must not be empty"},
		{name: "label with space", raw: `[{"label":"a b","language":"go","cmd":"go test"}]`, contains: "letters, digits"},
		{name: "label with newline", raw: `[{"label":"a\nb","language":"go","cmd":"go test"}]`, contains: "letters, digits"},
		{
			name:     "duplicate label",
			raw:      `[{"label":"a","language":"go","cmd":"go test"},{"label":"a","language":"node","cmd":"npm test"}]`,
			contains: "already used by test-legs[0]",
		},
		{name: "blank cmd", raw: `[{"label":"a","language":"go","cmd":"   "}]`, contains: "cmd must not be empty"},
		{name: "missing language", raw: `[{"label":"a","cmd":"go test"}]`, contains: "is not one of"},
		// Aliases are rejected on purpose: the language is also the
		// coverageByLanguage key the ratchet baseline is compared on, and two
		// spellings would be two keys that never meet.
		{name: "language alias", raw: `[{"label":"a","language":"typescript","cmd":"npm test"}]`, contains: "is not one of"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legs, err := parseTestLegs(tc.raw)
			if err == nil {
				t.Fatalf("want an error, got legs %+v", legs)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.contains)
			}
		})
	}
}

func TestParseTestLegsMatchesKeysCaseInsensitively(t *testing.T) {
	// encoding/json matches field names case-insensitively, so "coveragepath"
	// is not an unknown field — and that is not a hole: the value IS applied,
	// so the leg measures the coverage it named. What DisallowUnknownFields
	// catches is the case where the value would be dropped. Pinned here so a
	// future "stricter" rewrite knows this was measured, not overlooked.
	legs, err := parseTestLegs(`[{"LABEL":"a","LANGUAGE":"go","CMD":"go test ./...","coveragepath":"c.out"}]`)
	if err != nil {
		t.Fatalf("parseTestLegs: unexpected error: %v", err)
	}
	if len(legs) != 1 || legs[0].Label != "a" || legs[0].Language != "go" || legs[0].CoveragePath != "c.out" {
		t.Fatalf("case-insensitive keys were not applied: %+v", legs)
	}
}

func TestParseTestLegsRefusesMoreLegsThanTheLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i <= testLegLimit; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"label":"leg`)
		b.WriteString(string(rune('a' + i)))
		b.WriteString(`","language":"go","cmd":"go test ./..."}`)
	}
	b.WriteString("]")

	_, err := parseTestLegs(b.String())
	if err == nil {
		t.Fatal("want an error over the leg limit, got none")
	}
	// Over the limit must be an error, never a truncated run: witnessing some
	// legs and reporting success is the partial-reads-as-complete failure this
	// whole file exists to prevent.
	if !strings.Contains(err.Error(), "exceeds the limit") {
		t.Errorf("error %q does not name the limit", err.Error())
	}
}

func TestExclusiveTestInput(t *testing.T) {
	leg := []testLeg{{Label: "a", Language: "go", Cmd: "go test ./..."}}

	if err := exclusiveTestInput("go test ./...", nil); err != nil {
		t.Errorf("test-cmd alone must be accepted, got %v", err)
	}
	if err := exclusiveTestInput("", leg); err != nil {
		t.Errorf("test-legs alone must be accepted, got %v", err)
	}
	// Both set is refused rather than resolved by precedence: silently running
	// half of what was asked and reporting success is the false pass.
	if err := exclusiveTestInput("go test ./...", leg); err == nil {
		t.Error("both set must be an error")
	} else if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error %q does not say they are mutually exclusive", err.Error())
	}
	if err := exclusiveTestInput("   ", nil); err == nil {
		t.Error("neither set must be an error")
	}
}

func TestLegsExcludeCoveragePath(t *testing.T) {
	leg := []testLeg{{Label: "a", Language: "go", Cmd: "go test ./...", CoveragePath: "a/cov.out"}}

	if err := legsExcludeCoveragePath("cov/summary.json", leg); err == nil {
		t.Error("a run-wide coverage-path beside legs must be refused")
	} else if !strings.Contains(err.Error(), "move it into the leg") {
		t.Errorf("error %q does not name the remedy", err.Error())
	}
	if err := legsExcludeCoveragePath("cov/summary.json", nil); err != nil {
		t.Errorf("coverage-path alone must be accepted: %v", err)
	}
	if err := legsExcludeCoveragePath("  ", leg); err != nil {
		t.Errorf("an unset coverage-path must be accepted: %v", err)
	}
}

func TestToolchainImageLegScopeWarningNamesTheImage(t *testing.T) {
	// This one warns rather than fails: in the commit composite the same flag
	// also selects the archive build's image, so refusing it would make
	// --artifact archive and test-legs mutually exclusive.
	msg := toolchainImageLegScopeWarning("node:20-alpine", "")
	if !strings.Contains(msg, "node:20-alpine") || !strings.Contains(msg, "does not apply to test-legs") {
		t.Errorf("warning is not specific enough: %q", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("warning must be a single line: %q", msg)
	}

	prepared := toolchainImageLegScopeWarning("node:20-alpine", "api")
	if !strings.Contains(prepared, "node:20-alpine") || !strings.Contains(prepared, `prepared test leg "api"`) {
		t.Errorf("prepared-leg warning is not specific enough: %q", prepared)
	}
	if strings.Contains(prepared, "does not apply") || strings.Contains(prepared, "No test leg ran") {
		t.Errorf("prepared-leg warning contradicts the prepared execution: %q", prepared)
	}
	if strings.Contains(prepared, "\n") {
		t.Errorf("prepared-leg warning must be a single line: %q", prepared)
	}
}

func TestLegacyTestLegTakesTheFirstDetectedLanguage(t *testing.T) {
	leg := legacyTestLeg("npm test", "cov/summary.json", "", []string{"go", "node"})
	if leg.Language != "go" {
		t.Errorf("want the first detected language, got %q", leg.Language)
	}
	if leg.Label != legacyLegLabel {
		t.Errorf("want label %q, got %q", legacyLegLabel, leg.Label)
	}

	// Nothing detected: the language stays empty rather than being guessed, so
	// the coverage key stays "unknown" and the could-not-resolve-a-toolchain
	// error still fires exactly as it did before legs existed.
	bare := legacyTestLeg("npm test", "", "node:20-alpine", nil)
	if bare.Language != "" {
		t.Errorf("want an empty language, got %q", bare.Language)
	}
	if bare.ToolchainImage != "node:20-alpine" {
		t.Errorf("toolchain image not carried: %q", bare.ToolchainImage)
	}
}

func TestWitnessedAndUnwitnessedLanguages(t *testing.T) {
	legs := []testLeg{
		{Label: "web", Language: "node"},
		{Label: "pkg", Language: "node"},
		{Label: "api", Language: "dotnet"},
		{Label: "orphan", Language: ""},
	}

	witnessed := witnessedLanguages(legs)
	// Deduped and in canonical order, because evidence has to be stable across
	// runs and Go map iteration is not.
	if got, want := strings.Join(witnessed, ","), "node,dotnet"; got != want {
		t.Errorf("witnessed = %q, want %q", got, want)
	}

	unwitnessed := unwitnessedLanguages([]string{"go", "node", "python", "dotnet"}, witnessed)
	if got, want := strings.Join(unwitnessed, ","), "go,python"; got != want {
		t.Errorf("unwitnessed = %q, want %q", got, want)
	}

	// A fully witnessed repo yields an empty list, never a nil that reads as
	// "no answer".
	if got := unwitnessedLanguages([]string{"node"}, []string{"node"}); len(got) != 0 || got == nil {
		t.Errorf("want an empty non-nil slice, got %#v", got)
	}
}

func TestNotWitnessedWarningNamesBothSides(t *testing.T) {
	msg := notWitnessedWarning([]string{"dotnet"}, []string{"node"})
	for _, want := range []string{"NOT WITNESSED", "dotnet", "tests for node only", "test-legs", "include"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning %q does not mention %q", msg, want)
		}
	}
	// One line only: notify renders warnings verbatim into a PR comment.
	if strings.Contains(msg, "\n") {
		t.Errorf("warning must be a single line: %q", msg)
	}

	nothing := notWitnessedWarning([]string{"go"}, nil)
	if !strings.Contains(nothing, "no language at all") {
		t.Errorf("warning %q must say nothing was witnessed", nothing)
	}
}

func TestLegPrefixOnlyLabelsWhenThereIsMoreThanOneLeg(t *testing.T) {
	// A single-command consumer's evidence keeps the exact strings it had
	// before legs existed.
	if got := legPrefix("test-cmd", 1); got != "" {
		t.Errorf("want no prefix for a single leg, got %q", got)
	}
	if got := legPrefix("web", 3); got != "test-leg web" {
		t.Errorf("prefix = %q", got)
	}
}

func TestMergeLegCoverageWeightsByCoverableLines(t *testing.T) {
	merged, lines := mergeLegCoverage(map[string][]nodeCoverage{
		"node": {{Percent: 100, Lines: 5}, {Percent: 40, Lines: 5000}},
		"dotnet": {
			{Percent: 80, Lines: 1000},
		},
	})

	// Weighted, not averaged: an unweighted mean would report 70% for node and
	// clear a 60% gate on a 40%-covered 5000-line package.
	wantNode := (100*5.0 + 40*5000.0) / 5005.0
	if got := merged["node"]; got < wantNode-1e-9 || got > wantNode+1e-9 {
		t.Errorf("node coverage = %v, want %v", got, wantNode)
	}
	if lines["node"] != 5005 {
		t.Errorf("node coverable lines = %d, want 5005", lines["node"])
	}
	// A single reading is passed through exactly, not round-tripped.
	if merged["dotnet"] != 80 {
		t.Errorf("dotnet coverage = %v, want exactly 80", merged["dotnet"])
	}
	if lines["dotnet"] != 1000 {
		t.Errorf("dotnet coverable lines = %d, want 1000", lines["dotnet"])
	}
}

func TestFoldCoverage(t *testing.T) {
	if pct, lines := foldCoverage(nil); pct != nil || lines != nil {
		t.Errorf("no readings must yield no figure, got %v/%v", pct, lines)
	}

	// Exactness for the single-leg case: x*n/n is not guaranteed to be x, and
	// the figure has to be the number the tool reported.
	odd := 100.0 / 3.0
	pct, lines := foldCoverage([]nodeCoverage{{Percent: odd, Lines: 7}})
	if pct == nil || *pct != odd {
		t.Errorf("single reading = %v, want exactly %v", pct, odd)
	}
	if lines == nil || *lines != 7 {
		t.Errorf("single reading lines = %v, want 7", lines)
	}

	// No coverable lines anywhere: fall back to the unweighted mean rather than
	// reporting nothing.
	pct, lines = foldCoverage([]nodeCoverage{{Percent: 100, Lines: 0}, {Percent: 50, Lines: 0}})
	if pct == nil || *pct != 75 {
		t.Errorf("zero-line fallback = %v, want 75", pct)
	}
	if lines != nil {
		t.Errorf("zero-line fallback must report no coverable-line total, got %v", *lines)
	}
}

func TestDeclaredCoveragePaths(t *testing.T) {
	if got := declaredCoveragePaths([]testLeg{{Label: "a"}}); got != "" {
		t.Errorf("want empty so applyRatchet's own wording applies, got %q", got)
	}
	got := declaredCoveragePaths([]testLeg{
		{Label: "a", CoveragePath: "a/cov.json"},
		{Label: "b"},
		{Label: "c", CoveragePath: "c/cov.xml"},
	})
	if got != "a/cov.json, c/cov.xml" {
		t.Errorf("paths = %q", got)
	}
}

func TestLegsReportNeverEmitsNullArrays(t *testing.T) {
	raw, err := json.Marshal(newLegsReport(nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// `null` where an array belongs says nothing at all; `[]` says "asked, and
	// the answer is none".
	if strings.Contains(string(raw), "null") {
		t.Errorf("report contains null: %s", raw)
	}
	for _, want := range []string{`"detectedLanguages":[]`, `"witnessedLanguages":[]`, `"unwitnessedLanguages":[]`, `"legs":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report %s is missing %s", raw, want)
		}
	}
}

func TestLegsReportCarriesPerLegCountsAtVersionOneOne(t *testing.T) {
	counts := &TestCounts{Total: 57, Passed: 55, Skipped: 2}
	raw, err := json.Marshal(newLegsReport(
		[]string{"node"}, []string{"node"}, nil,
		[]legReport{{Label: "worker-ui", Language: "node", Image: "node:20-alpine", Ran: true, Tests: counts}},
	))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"format":"byo-test-legs/1.1"`,
		`"tests":{"total":57,"passed":55,"failed":0,"skipped":2}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report %s is missing %s", raw, want)
		}
	}
}

func TestLegReportKeepsAnExitCodeOfZeroAndOmitsAnAbsentOne(t *testing.T) {
	zero := 0
	raw, err := json.Marshal([]legReport{
		{Label: "ran", Language: "go", Image: "golang:1.26-alpine", Ran: true, ExitCode: &zero},
		{Label: "crashed", Language: "node", Image: "node:20-alpine", Ran: false},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"exitCode":0`) {
		t.Errorf("a real exit 0 must survive: %s", raw)
	}
	// A leg that never ran has no exit code, and a fabricated 0 would say the
	// opposite of what happened.
	if strings.Count(string(raw), `"exitCode"`) != 1 {
		t.Errorf("an absent exit code must be omitted: %s", raw)
	}
	// The consumer's command is deliberately not in the payload: it is
	// author-controlled text that can carry a credential inline.
	if strings.Contains(string(raw), `"cmd"`) {
		t.Errorf("the command must not reach the envelope: %s", raw)
	}
}

func TestOrderByLanguageSortsUnknownsLast(t *testing.T) {
	got := orderByLanguage([]string{"zzz", "dotnet", "unknown", "go"})
	if want := "go,dotnet,unknown,zzz"; strings.Join(got, ",") != want {
		t.Errorf("order = %q, want %q", strings.Join(got, ","), want)
	}
}

// TestToolchainNoteWarnings is the biconditional. A disclosure appears exactly
// when a resolution carries a note, and never otherwise — the second half is
// the one that matters, because a line on every run is a line a reader stops
// seeing, and this warning's whole value is that its presence is unusual.
func TestToolchainNoteWarnings(t *testing.T) {
	legs := []testLeg{
		{Label: "backend", Language: "dotnet", Cmd: "dotnet test"},
		{Label: "frontend", Language: "node", Cmd: "npm test"},
	}

	t.Run("silent when no resolution carries a note", func(t *testing.T) {
		got := toolchainNoteWarnings(legs, []ToolchainResolution{
			{Image: "mcr.microsoft.com/dotnet/sdk:8.0", From: ToolchainFromDefault},
			{Image: "node:22-alpine", From: ToolchainFromNvmrc},
		})
		if len(got) != 0 {
			t.Errorf("expected no warnings, got %v", got)
		}
	})

	t.Run("one line per noted leg, naming that leg", func(t *testing.T) {
		got := toolchainNoteWarnings(legs, []ToolchainResolution{
			{Image: "mcr.microsoft.com/dotnet/sdk:8.0", From: ToolchainFromDefault, Note: "global.json declares no sdk.version, so the pinned default mcr.microsoft.com/dotnet/sdk:8.0 was used instead"},
			{Image: "node:22-alpine", From: ToolchainFromNvmrc},
		})
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 warning, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], "backend") {
			t.Errorf("warning does not name the leg it is about: %q", got[0])
		}
		if strings.Contains(got[0], "frontend") {
			t.Errorf("warning names a leg with no note: %q", got[0])
		}
		// The prefix is this function's to add, because these lines are built
		// by the caller and not returned by a leg. A leg-returned message
		// carrying "test-leg" is the doubled label CAPS-026 removed.
		if !strings.HasPrefix(got[0], "test-leg backend:") {
			t.Errorf("warning is not prefixed by legScopeQualifier: %q", got[0])
		}
	})

	t.Run("single leg keeps the whole-run prefix", func(t *testing.T) {
		got := toolchainNoteWarnings(
			[]testLeg{{Label: "only", Language: "node", Cmd: "npm test"}},
			[]ToolchainResolution{{Image: "node:20-alpine", From: ToolchainFromDefault, Note: ".nvmrc declares \"lts/iron\", which is not a version number, so the pinned default node:20-alpine was used instead"}},
		)
		if len(got) != 1 {
			t.Fatalf("expected 1 warning, got %v", got)
		}
		if !strings.HasPrefix(got[0], "byo-test:") {
			t.Errorf("single leg should keep the byo-test prefix: %q", got[0])
		}
	})

	t.Run("mismatched lengths disclose nothing rather than misattribute", func(t *testing.T) {
		// Attributing one leg's toolchain to another is worse than the silence
		// being replaced: it sends the consumer to correct a file the named leg
		// never read.
		got := toolchainNoteWarnings(legs, []ToolchainResolution{
			{Image: "node:20-alpine", From: ToolchainFromDefault, Note: "some note"},
		})
		if len(got) != 0 {
			t.Errorf("expected no warnings on a length mismatch, got %v", got)
		}
	})
}

// A key the schema does not define, one level down. DisallowUnknownFields
// applies to nested objects too — this pins that, because the day it does not
// is the day a misspelled "readycmd" means a leg waits for nothing while its
// configuration says it waits.
func TestParseTestLegsRejectsUnknownServiceKey(t *testing.T) {
	_, err := parseTestLegs(`[{"label":"a","language":"go","cmd":"go test ./...","services":[{"alias":"db","image":"postgres:16","port":5432,"readyCommand":"pg_isready"}]}]`)
	if err == nil {
		t.Fatal("an unknown key inside a service object was accepted")
	}
	if !strings.Contains(err.Error(), "readyCommand") {
		t.Fatalf("the rejection does not name the offending key: %v", err)
	}
}

// Three places state the accepted key set — the struct, the decoder and this
// sentence — and the sentence is the only one a consumer ever reads. A valid
// document described as invalid is the same defect as the reverse.
func TestParseTestLegsRejectionNamesServices(t *testing.T) {
	_, err := parseTestLegs(`[{"label":"a","language":"go","cmd":"go test","nonsense":1}]`)
	if err == nil {
		t.Fatal("an unknown leg key was accepted")
	}
	for _, want := range []string{"services", "alias", "image", "port", "readyCmd", "readyTimeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the rejection sentence does not mention %q, so a consumer cannot learn the key set from it: %v", want, err)
		}
	}
}

func TestParseTestLegsRejectsTooManyServices(t *testing.T) {
	var b strings.Builder
	b.WriteString(`[{"label":"a","language":"go","cmd":"go test","services":[`)
	for i := 0; i <= serviceLimit; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"alias":"svc%d","image":"redis:7","port":6379}`, i)
	}
	b.WriteString(`]}]`)

	legs, err := parseTestLegs(b.String())
	if err == nil {
		t.Fatalf("%d services were accepted against a limit of %d", serviceLimit+1, serviceLimit)
	}
	if legs != nil {
		t.Fatal("a rejected document still produced legs, so a truncated service list could reach a container")
	}
}

func TestParseTestLegsAcceptsAServiceDeclaration(t *testing.T) {
	legs, err := parseTestLegs(`[{"label":"dotnet","language":"dotnet","cmd":"dotnet test","services":[{"alias":"db","image":"postgres:16","port":5432,"env":{"POSTGRES_PASSWORD":"test"},"readyCmd":"pg_isready -h db","readyTimeout":45}]}]`)
	if err != nil {
		t.Fatalf("parseTestLegs: %v", err)
	}
	if len(legs) != 1 || len(legs[0].Services) != 1 {
		t.Fatalf("declaration did not survive parsing: %+v", legs)
	}
	svc := legs[0].Services[0]
	if svc.Alias != "db" || svc.Image != "postgres:16" || svc.Port != 5432 || svc.ReadyTimeout != 45 {
		t.Fatalf("service fields did not survive parsing: %+v", svc)
	}
	if svc.Env["POSTGRES_PASSWORD"] != "test" {
		t.Fatalf("env did not survive parsing: %+v", svc.Env)
	}
}

// A leg declaring no services parses to no services — not to an empty slice
// that would serialise a services key into a report that had none before.
func TestParseTestLegsLeavesServicesAbsentWhenNoneAreDeclared(t *testing.T) {
	legs, err := parseTestLegs(`[{"label":"a","language":"go","cmd":"go test ./..."}]`)
	if err != nil {
		t.Fatalf("parseTestLegs: %v", err)
	}
	if legs[0].Services != nil {
		t.Fatalf("a leg with no services has a non-nil service list: %+v", legs[0].Services)
	}
}

// TestLegServiceDocumentsParseAsDeclared reads the same corpus
// src/composites/commit/appconfig_test.go reads. app mode marshals []appLeg
// straight into this module's --test-legs, so a key one parser models and the
// other drops is a service the consumer declared and nothing binds. The two
// modules are isolated Go modules and cannot share a type, so the agreement is
// asserted from both ends against one file rather than assumed.
func TestLegServiceDocumentsParseAsDeclared(t *testing.T) {
	raw, err := os.ReadFile("testdata/leg-service-documents.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc struct {
		Documents []struct {
			Name   string `json:"name"`
			Accept bool   `json:"accept"`
			Legs   string `json:"legs"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(doc.Documents) == 0 {
		t.Fatal("corpus is empty — a test that reads no case passes on anything")
	}
	accepted := 0
	for _, c := range doc.Documents {
		_, err := parseTestLegs(c.Legs)
		switch {
		case c.Accept && err != nil:
			t.Errorf("%s: expected accepted, got %v", c.Name, err)
		case !c.Accept && err == nil:
			t.Errorf("%s: expected rejected, was accepted", c.Name)
		}
		if c.Accept {
			accepted++
		}
	}
	if accepted == 0 || accepted == len(doc.Documents) {
		t.Fatalf("corpus must hold both accepted and rejected documents, got %d of %d accepted", accepted, len(doc.Documents))
	}
}
