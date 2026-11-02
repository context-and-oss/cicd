package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestCapFindingsLeavesAShortListAlone guards the ordinary case: no truncation,
// and — the part that matters — no warning claiming one.
func TestCapFindingsLeavesAShortListAlone(t *testing.T) {
	in := make([]Finding, maxCombinedFindings)
	out, warn := capFindings(in)
	if len(out) != maxCombinedFindings {
		t.Errorf("len = %d, want %d", len(out), maxCombinedFindings)
	}
	if warn != "" {
		t.Errorf("a complete list must carry no truncation warning; got %q", warn)
	}
}

// TestCapFindingsKeepsTheSevereEnd is the whole point of truncating a sorted
// list rather than sampling one: a reader who gets 1000 of 100000 rows must get
// the 1000 that tripped the gate, not the 1000 that happened to be first in
// some producer's file.
func TestCapFindingsKeepsTheSevereEnd(t *testing.T) {
	var in []Finding
	in = append(in, Finding{Severity: SeverityCritical, Message: "critical"})
	for i := 0; i < maxCombinedFindings+500; i++ {
		in = append(in, Finding{Severity: SeverityLow, Message: fmt.Sprintf("low %d", i)})
	}
	out, warn := capFindings(in)
	if len(out) != maxCombinedFindings {
		t.Fatalf("len = %d, want %d", len(out), maxCombinedFindings)
	}
	if out[0].Severity != SeverityCritical {
		t.Errorf("the most severe row was dropped: head = %+v", out[0])
	}
	if warn == "" {
		t.Fatal("a truncated list with no warning is indistinguishable from a quiet run")
	}
	// The warning has to be actionable, not merely present: it must say how many
	// rows exist, and where the dropped ones still are.
	for _, want := range []string{
		fmt.Sprintf("%d", len(in)),
		fmt.Sprintf("%d", maxCombinedFindings),
		"findingsCount",
		"findings.sarif",
		"parts/",
	} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning omits %q: %s", want, warn)
		}
	}
}

// TestPartFileNameIsReadableAndOrdered checks the two jobs the name does at
// once: sort order matching collection order, and saying which module wrote it.
func TestPartFileNameIsReadableAndOrdered(t *testing.T) {
	cases := []struct {
		name string
		i    int
		env  envelope
		want string
	}{
		{
			name: "module and tool",
			i:    0,
			env:  envelope{ModuleName: "quality", Tool: toolInfo{Name: "golangci-lint"}},
			want: "01-quality-golangci-lint.json",
		},
		{
			name: "slashes in the module name are not path separators",
			i:    4,
			env:  envelope{ModuleName: "cross-cutting/intent", Tool: toolInfo{Name: "intent-gate"}},
			want: "05-cross-cutting-intent-intent-gate.json",
		},
		{
			name: "a tool that repeats the module name is not repeated",
			i:    1,
			env:  envelope{ModuleName: "build", Tool: toolInfo{Name: "build"}},
			want: "02-build.json",
		},
		{
			name: "no tool",
			i:    2,
			env:  envelope{ModuleName: "security"},
			want: "03-security.json",
		},
		{
			name: "a name of pure punctuation still names something",
			i:    9,
			env:  envelope{ModuleName: "///"},
			want: "10-envelope.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := partFileName(tc.i, &tc.env); got != tc.want {
				t.Errorf("partFileName = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPartFileNamesAreUniquePerRun is the property the ordinal prefix exists
// for: the security module contributes several envelopes under one module name,
// and two of them must not resolve to one file.
func TestPartFileNamesAreUniquePerRun(t *testing.T) {
	envs := []*envelope{
		{ModuleName: "security", Tool: toolInfo{Name: "trivy"}},
		{ModuleName: "security", Tool: toolInfo{Name: "trivy"}},
		{ModuleName: "security", Tool: toolInfo{Name: "trivy"}},
	}
	seen := map[string]bool{}
	for i, e := range envs {
		name := partFileName(i, e)
		if seen[name] {
			t.Fatalf("envelope %d reuses filename %q — one part would overwrite another", i, name)
		}
		seen[name] = true
	}
}

// TestBuildPartsIndexDescribesEveryPart verifies the index is a manifest a
// reader can check the directory against, not a summary of it.
func TestBuildPartsIndexDescribesEveryPart(t *testing.T) {
	envs := []*envelope{
		{
			ModuleName: "quality", Stage: "commit", Tool: toolInfo{Name: "eslint"},
			Passed: false, FindingsCount: 3,
			Errors: []string{"lint failed"}, Warnings: []string{"no config", "no cache"},
		},
		{ModuleName: "build", Stage: "commit", Passed: true},
	}
	names := []string{"01-quality-eslint.json", "02-build.json"}
	sizes := []int{4096, 512}

	idx := buildPartsIndex(envs, names, sizes)
	if len(idx) != len(envs) {
		t.Fatalf("index has %d rows for %d envelopes", len(idx), len(envs))
	}

	first := idx[0]
	if first.File != names[0] || first.ModuleName != "quality" || first.Stage != "commit" || first.Tool != "eslint" {
		t.Errorf("row 0 mis-identifies its part: %+v", first)
	}
	if first.Passed {
		t.Error("row 0 reports passed for a failed envelope")
	}
	if first.FindingsCount != 3 || first.ErrorsCount != 1 || first.WarningsCount != 2 || first.Bytes != 4096 {
		t.Errorf("row 0 counts wrong: %+v", first)
	}
	if idx[1].File != names[1] || !idx[1].Passed || idx[1].Tool != "" {
		t.Errorf("row 1 wrong: %+v", idx[1])
	}
}

func TestSanitiseNameSegment(t *testing.T) {
	cases := map[string]string{
		"quality":                "quality",
		"cross-cutting/evidence": "cross-cutting-evidence",
		"dotnet format":          "dotnet-format",
		"Semgrep OSS":            "Semgrep-OSS",
		"../../etc/passwd":       "etc-passwd",
		"///":                    "",
		"":                       "",
		"a_b-c9":                 "a_b-c9",
	}
	for in, want := range cases {
		if got := sanitiseNameSegment(in); got != want {
			t.Errorf("sanitiseNameSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPartFileNameCannotEscapeTheBundle is the adversarial half of the
// sanitiser's job. Module and tool names reach this from tool output, so a name
// carrying path separators must become a filename, never a path.
func TestPartFileNameCannotEscapeTheBundle(t *testing.T) {
	e := envelope{ModuleName: "../../../etc", Tool: toolInfo{Name: "../passwd"}}
	got := partFileName(0, &e)
	if strings.ContainsAny(got, "/\\") || strings.Contains(got, "..") {
		t.Errorf("partFileName produced a traversable path: %q", got)
	}
}

// TestRawOutputFileNameSurvivesAnUnnameableTool covers the fallback that only
// fires after sanitising: a tool named entirely in punctuation sanitises to
// nothing, and "-output.txt" names no step.
func TestRawOutputFileNameSurvivesAnUnnameableTool(t *testing.T) {
	e := envelope{Tool: toolInfo{Name: "///"}}
	if got := rawOutputFileName(&e, map[string]bool{}); got != "step-output.txt" {
		t.Errorf("rawOutputFileName = %q, want step-output.txt", got)
	}
}

func TestCombinedSpanMeasuresTheRunNotTheAggregator(t *testing.T) {
	// The regression this exists for: a 28-minute run whose combined envelope
	// reported 76ms because the aggregator timed itself.
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	envs := []*envelope{
		{TimestampUTC: base.Add(4 * time.Minute)},
		{TimestampUTC: base}, // earliest, and deliberately not first in the slice
		{TimestampUTC: base.Add(9 * time.Minute)},
	}
	wrapStart := base.Add(28 * time.Minute)
	now := base.Add(28*time.Minute + 76*time.Millisecond)

	began, ms := combinedSpan(envs, wrapStart, now)

	if !began.Equal(base) {
		t.Errorf("began = %s, want the earliest module start %s", began, base)
	}
	if want := int64(28*60*1000 + 76); ms != want {
		t.Errorf("durationMs = %d, want %d (the run, not the %dms the aggregator took)",
			ms, want, 76)
	}
}

func TestCombinedSpanIgnoresAnUnstampedEnvelope(t *testing.T) {
	// A zero TimestampUTC dragged into the minimum reports a duration of two
	// thousand years, which renders as a number no reader can act on.
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	envs := []*envelope{
		{TimestampUTC: time.Time{}}, // never stamped
		{TimestampUTC: base.Add(2 * time.Minute)},
		nil,                         // a nil entry must not panic either
		{TimestampUTC: time.Time{}}, // and neither must a second one
	}
	now := base.Add(5 * time.Minute)

	began, ms := combinedSpan(envs, base, now)

	if !began.Equal(base.Add(2 * time.Minute)) {
		t.Errorf("began = %s, want the earliest STAMPED start", began)
	}
	if want := int64(3 * 60 * 1000); ms != want {
		t.Errorf("durationMs = %d, want %d", ms, want)
	}
}

func TestCombinedSpanFallsBackWhenNothingIsStamped(t *testing.T) {
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	envs := []*envelope{{TimestampUTC: time.Time{}}, {TimestampUTC: time.Time{}}}

	began, ms := combinedSpan(envs, base, base.Add(750*time.Millisecond))

	if !began.Equal(base) {
		t.Errorf("began = %s, want the aggregator's own start as the fallback", began)
	}
	if ms != 750 {
		t.Errorf("durationMs = %d, want 750", ms)
	}
}

func TestCombinedSpanRefusesToReportNegativeTime(t *testing.T) {
	// Clock skew, or a module stamped from a machine running ahead. A negative
	// duration renders as garbage and a far-future start is not evidence.
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	envs := []*envelope{{TimestampUTC: base.Add(time.Hour)}} // stamped after now

	began, ms := combinedSpan(envs, base, base.Add(30*time.Second))

	if !began.Equal(base) {
		t.Errorf("began = %s, want the fallback when the earliest stamp is in the future", began)
	}
	if ms != 30000 {
		t.Errorf("durationMs = %d, want 30000", ms)
	}

	// And a fallback that is itself after now must still not go negative.
	_, ms = combinedSpan(nil, base.Add(time.Hour), base)
	if ms != 0 {
		t.Errorf("durationMs = %d, want 0 — never negative", ms)
	}
}

func TestCombinedSpanHandlesNoEnvelopes(t *testing.T) {
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	began, ms := combinedSpan(nil, base, base.Add(time.Second))
	if !began.Equal(base) || ms != 1000 {
		t.Errorf("combinedSpan(nil) = %s, %d; want %s, 1000", began, ms, base)
	}
}

func TestCombinedSpanNormalisesToUTC(t *testing.T) {
	cph := time.FixedZone("CEST", 2*60*60)
	base := time.Date(2026, 9, 8, 12, 0, 0, 0, cph)
	envs := []*envelope{{TimestampUTC: base}}

	began, _ := combinedSpan(envs, base, base.Add(time.Minute))

	if got := began.Location(); got != time.UTC {
		t.Errorf("began is in %s, want UTC — the field is named timestampUtc", got)
	}
	if !began.Equal(base) {
		t.Errorf("began = %s, want the same instant as %s", began, base)
	}
}

func TestReadByEyeKeepsTheSummariesIndented(t *testing.T) {
	for _, name := range []string{"combined-evidence.json", "parts/index.json", "comment.md"} {
		if !readByEye(name) {
			t.Errorf("%s is read by a person chasing a finding; it must stay indented", name)
		}
	}
	for _, name := range []string{"findings.sarif", "sbom.cdx.json", "audit/findings.sarif"} {
		if readByEye(name) {
			t.Errorf("%s is fed to a tool; indenting it spends transfer budget on nobody", name)
		}
	}
}

func TestMarshalBundleDocCompactsOnlyTheMachineDocuments(t *testing.T) {
	doc := map[string]any{"runs": []any{map[string]any{"tool": "semgrep", "results": []any{}}}}

	compact, err := marshalBundleDoc("findings.sarif", doc)
	if err != nil {
		t.Fatalf("marshal sarif: %v", err)
	}
	if bytes.Contains(compact, []byte("\n")) {
		t.Errorf("findings.sarif still carries indentation: %s", compact)
	}

	indented, err := marshalBundleDoc("combined-evidence.json", doc)
	if err != nil {
		t.Fatalf("marshal combined: %v", err)
	}
	if !bytes.Contains(indented, []byte("\n  ")) {
		t.Errorf("combined-evidence.json lost its indentation: %s", indented)
	}
}

// The point of compacting is that only whitespace changes. If the two forms
// ever decoded differently, every jq expression in the smoke suite and every
// SARIF upload would be reading a different document than the one reviewed.
func TestMarshalBundleDocChangesNothingButWhitespace(t *testing.T) {
	doc := map[string]any{
		"schemaVersion": "2.1.0",
		"message":       "a < b && c > d",
		"runs":          []any{map[string]any{"level": "error", "count": 3.0}},
	}

	compact, err := marshalBundleDoc("findings.sarif", doc)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	indented, err := marshalBundleDoc("combined-evidence.json", doc)
	if err != nil {
		t.Fatalf("indented: %v", err)
	}

	var gotCompact, gotIndented any
	if err := json.Unmarshal(compact, &gotCompact); err != nil {
		t.Fatalf("compact form is not valid json: %v", err)
	}
	if err := json.Unmarshal(indented, &gotIndented); err != nil {
		t.Fatalf("indented form is not valid json: %v", err)
	}
	if !reflect.DeepEqual(gotCompact, gotIndented) {
		t.Errorf("the two forms decode differently:\ncompact  %#v\nindented %#v", gotCompact, gotIndented)
	}
	if len(compact) >= len(indented) {
		t.Errorf("compacting saved nothing: %d compact vs %d indented", len(compact), len(indented))
	}
}

func TestMarshalBundleDocNamesTheFileItCouldNotEncode(t *testing.T) {
	_, err := marshalBundleDoc("findings.sarif", make(chan int))
	if err == nil {
		t.Fatal("expected an error for an unencodable value")
	}
	if !strings.Contains(err.Error(), "findings.sarif") {
		t.Errorf("error does not say which document failed: %v", err)
	}
}
