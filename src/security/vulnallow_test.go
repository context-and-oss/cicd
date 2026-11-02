package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// acceptReport is the shape this mechanism was built for: one vulnerability
// reported four times across four lockfiles, which is what an accepted CVE in a
// monorepo actually looks like, beside findings nobody accepted.
const acceptReport = `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "src/stage-2/go.mod",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Packages": [{"Name":"go.opentelemetry.io/otel"}],
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2026-81871","PkgName":"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc","InstalledVersion":"v0.16.0","Severity":"MEDIUM"},
        {"VulnerabilityID":"CVE-2020-8203","PkgName":"lodash","InstalledVersion":"4.17.15","Severity":"HIGH"}
      ]
    },
    {
      "Target": "src/composites/precommit/go.mod",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Packages": [{"Name":"go.opentelemetry.io/otel"}],
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2026-81871","PkgName":"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc","InstalledVersion":"v0.16.0","Severity":"MEDIUM"}
      ]
    }
  ]
}`

func mustParseAcceptReport(t *testing.T) *trivyNativeDoc {
	t.Helper()
	doc, err := parseTrivyNative(json.RawMessage(acceptReport))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	return doc
}

// mustAccepter joins its entries the way a caller has to: one per line. The
// flag is a single string, so the test drives the same splitter production
// does rather than reaching past it.
func mustAccepter(t *testing.T, entries ...string) *vulnAccepter {
	t.Helper()
	raw := strings.Join(entries, "\n")
	acc, err := newVulnAccepter(raw)
	if err != nil {
		t.Fatalf("newVulnAccepter(%q): %v", raw, err)
	}
	return acc
}

// TestAcceptanceWithoutAReasonIsRefused is rule 2, and it is the whole
// difference between this flag and .trivyignore. A bare identifier is a
// suppression; suppression already exists and is exactly what produced a
// vulnerability nobody could see in the evidence.
func TestAcceptanceWithoutAReasonIsRefused(t *testing.T) {
	for _, entry := range []string{"CVE-2026-81871", "  CVE-2026-81871  "} {
		_, err := newVulnAccepter(entry)
		if err == nil {
			t.Fatalf("--vuln-accept %q was accepted without a reason", entry)
		}
		// The error has to teach the form, or a consumer's next move is the
		// flag that turns the scanner down instead.
		if !strings.Contains(err.Error(), "CVE-2026-81871=") {
			t.Errorf("error does not show the required form: %v", err)
		}
	}
}

// TestAnEmptyOrWordlessReasonIsRefused closes the obvious way around rule 2.
func TestAnEmptyOrWordlessReasonIsRefused(t *testing.T) {
	for _, entry := range []string{
		"CVE-2026-81871=",
		"CVE-2026-81871=   ",
		"CVE-2026-81871=-",
		"CVE-2026-81871=123",
	} {
		if _, err := newVulnAccepter(entry); err == nil {
			t.Errorf("--vuln-accept %q was accepted", entry)
		}
	}
}

// TestAReasonKeepsEverythingAfterTheFirstEquals — a reason is prose, and prose
// contains "=". Splitting on the last one, or refusing a second one, would make
// the mechanism unusable for exactly the reasons worth writing down.
func TestAReasonKeepsEverythingAfterTheFirstEquals(t *testing.T) {
	acc := mustAccepter(t, "CVE-2026-81871=only reachable when OTEL_EXPORTER=grpc, which cicd never sets")
	got := acc.acceptances[0].Reason
	want := "only reachable when OTEL_EXPORTER=grpc, which cicd never sets"
	if got != want {
		t.Fatalf("reason = %q, want %q", got, want)
	}
}

// TestAReasonReadsAsOneSentence — a reason typed with a tab or a run of spaces
// still renders as one sentence in the warning.
//
// It cannot span LINES, and that is the price of the newline being the
// separator. The alternative was a continuation rule, which is worse here: a
// line that fails to parse would be swallowed into the reason above it, and
// the "names no reason" refusal — the loudest thing this mechanism does —
// would quietly stop firing. Long reasons go on one long line; a YAML folded
// scalar writes one comfortably.
func TestAReasonReadsAsOneSentence(t *testing.T) {
	acc := mustAccepter(t, "CVE-2026-81871=the exporter   talks only to\tthe engine")
	if got := acc.acceptances[0].Reason; got != "the exporter talks only to the engine" {
		t.Fatalf("reason = %q", got)
	}
}

// TestASecondLineIsASecondAcceptance, never a continuation of the first.
func TestASecondLineIsASecondAcceptance(t *testing.T) {
	if _, err := newVulnAccepter("CVE-2026-81871=the exporter\n  talks only to the engine"); err == nil {
		t.Fatal("a wrapped reason was accepted; the second line must be read as its own entry")
	}
}

// TestAPatternIsRefusedAndSaysWhy is rule 3. The message must be about covering
// unread findings, not about the identifier being malformed — a reader told
// "that is not a CVE id" will try harder to make the pattern parse.
func TestAPatternIsRefusedAndSaysWhy(t *testing.T) {
	for _, entry := range []string{"CVE-2026-*=known", "GHSA-????-????-????=known", "CVE-2026-[0-9]+=known"} {
		_, err := newVulnAccepter(entry)
		if err == nil {
			t.Fatalf("--vuln-accept %q was accepted", entry)
		}
		if !strings.Contains(err.Error(), "nobody has read yet") {
			t.Errorf("pattern refusal does not explain the risk: %v", err)
		}
	}
}

// TestOnlyAVulnerabilityIdentifierShapeIsAccepted keeps a severity name, a
// package name or a bare word from being read as an identifier that then
// silently matches nothing.
func TestOnlyAVulnerabilityIdentifierShapeIsAccepted(t *testing.T) {
	ok := []string{
		"CVE-2026-81871", "cve-2026-81871",
		"GHSA-xxxx-yyyy-zzzz", "RUSTSEC-2021-0001", "DSA-5678-1",
		"TEMP-0000000-A0B1C2", "ALSA-2021-1.2",
	}
	for _, id := range ok {
		if _, err := newVulnAccepter(id + "=reason"); err != nil {
			t.Errorf("%s was refused: %v", id, err)
		}
	}
	bad := []string{"MEDIUM", "lodash", "all", "-2026-81871", "CVE 2026 81871", "CVE_2026_81871"}
	for _, id := range bad {
		if _, err := newVulnAccepter(id + "=reason"); err == nil {
			t.Errorf("%q was accepted as a vulnerability identifier", id)
		}
	}
}

// TestTheSameIdentifierTwiceWithDifferentReasonsIsRefused — two resolvers for
// one question means one of them is wrong, and the evidence can only carry one.
func TestTheSameIdentifierTwiceWithDifferentReasonsIsRefused(t *testing.T) {
	_, err := newVulnAccepter("CVE-2026-81871=first reason\ncve-2026-81871=second reason")
	if err == nil {
		t.Fatal("two reasons for one identifier were accepted")
	}
	for _, want := range []string{"first reason", "second reason"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not quote %q: %v", want, err)
		}
	}
	// The same acceptance typed twice is not a conflict.
	acc := mustAccepter(t, "CVE-2026-81871=same reason", "CVE-2026-81871=same reason")
	if len(acc.acceptances) != 1 {
		t.Fatalf("identical entries produced %d acceptances", len(acc.acceptances))
	}
}

// TestBlankLinesAreNotAcceptances. A value written as a YAML block scalar
// arrives indented and with a trailing newline, and neither is an acceptance.
// Both are removed before parsing, or the form a pipeline definition actually
// uses would be refused for its own whitespace.
func TestBlankLinesAreNotAcceptances(t *testing.T) {
	acc := mustAccepter(t, "", "  CVE-2026-81871=fine  ", "", "\tCVE-2020-8203=also fine", "   ")
	if len(acc.acceptances) != 2 {
		t.Fatalf("got %d acceptances, want 2", len(acc.acceptances))
	}
	if acc.acceptances[0].ID != "CVE-2026-81871" {
		t.Errorf("indentation reached the identifier: %q", acc.acceptances[0].ID)
	}
}

// TestAValueThatHoldsNoAcceptanceIsRefused. Whitespace only is not an unset
// flag: the caller wrote something and every acceptance in it went missing
// between them and here. A quiet empty accepter reports that as "none asked
// for", which is the one reading indistinguishable from the truth.
func TestAValueThatHoldsNoAcceptanceIsRefused(t *testing.T) {
	if _, err := newVulnAccepter("  \n\t\n "); err == nil {
		t.Fatal("a value holding no acceptance was accepted")
	}
	// An unset flag stays an ordinary empty accepter — every finding gates.
	acc, err := newVulnAccepter("")
	if err != nil {
		t.Fatalf("an unset flag was refused: %v", err)
	}
	if !acc.empty() {
		t.Error("an unset flag produced acceptances")
	}
}

// TestACommaIsPartOfTheReason, never a separator. This is the defect the flag
// shipped with: as a []string parameter the Dagger CLI CSV-split the value
// before cicd saw it, so ONE acceptance arrived as three fragments and the
// second was refused for naming no reason. The separator is the newline, and
// a comma has to survive as prose or the flag cannot carry a sentence worth
// reading.
func TestACommaIsPartOfTheReason(t *testing.T) {
	acc := mustAccepter(t, "CVE-2026-81871=upstream ships no fixed version, so cicd cannot pin the fix, and the exporter only reaches the engine")
	if len(acc.acceptances) != 1 {
		t.Fatalf("a reason with commas produced %d acceptances", len(acc.acceptances))
	}
	if got := acc.acceptances[0].Reason; !strings.Contains(got, "pin the fix, and the exporter") {
		t.Fatalf("reason was cut at a comma: %q", got)
	}
}

// TestAcceptanceRemovesOnlyTheAcceptedRows is the discriminating test: the same
// report, with and without one acceptance, must produce different counts and a
// different findings list — and everything not accepted must survive untouched.
func TestAcceptanceRemovesOnlyTheAcceptedRows(t *testing.T) {
	doc := mustParseAcceptReport(t)

	before := trivySeverities(doc)
	if before[SeverityMedium] != 2 || before[SeverityHigh] != 1 {
		t.Fatalf("fixture drifted: %v", before)
	}

	acc := mustAccepter(t, "CVE-2026-81871=dagger codegen owns this version")
	filtered, removed := acc.partition(doc)
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}

	after := trivySeverities(filtered)
	if after[SeverityMedium] != 0 {
		t.Errorf("accepted rows still counted: %v", after)
	}
	if after[SeverityHigh] != 1 {
		t.Errorf("an unaccepted finding was removed: %v", after)
	}
	for _, f := range trivyFindings(filtered) {
		if strings.Contains(f.Rule, "CVE-2026-81871") || strings.Contains(f.Message, "CVE-2026-81871") {
			t.Errorf("accepted finding survived into findings[]: %+v", f)
		}
	}
	if len(trivyFindings(filtered)) != 1 {
		t.Errorf("findings = %d, want 1", len(trivyFindings(filtered)))
	}
}

// TestPartitionLeavesTheOriginalDocumentAlone. The CycloneDX report attached to
// the envelope is Trivy's own and must still list the accepted vulnerability,
// and nothing downstream may see a mutated original.
func TestPartitionLeavesTheOriginalDocumentAlone(t *testing.T) {
	doc := mustParseAcceptReport(t)
	acc := mustAccepter(t, "CVE-2026-81871=reason")
	acc.partition(doc)
	if got := trivySeverities(doc)[SeverityMedium]; got != 2 {
		t.Fatalf("partition mutated the original document: MEDIUM = %d, want 2", got)
	}
}

// TestFilteringCanHideAnEcosystem is the trap, pinned as behaviour rather than
// as a comment: a Result whose only content was accepted vulnerabilities and no
// packages disappears from trivyResolvedTypes, and ecosystems.go would then
// report the ecosystem unresolved — an acceptance manufacturing a non-run.
//
// This test asserts the filtered document is NOT safe to resolve types from, so
// that anyone who "simplifies" readTrivyResult by passing the filtered doc to
// trivyResolvedTypes breaks a test that says exactly why.
func TestFilteringCanHideAnEcosystem(t *testing.T) {
	const report = `{"Results":[{"Target":"a.csproj","Class":"lang-pkgs","Type":"nuget",
	  "Vulnerabilities":[{"VulnerabilityID":"CVE-2026-81871","PkgName":"x","InstalledVersion":"1","Severity":"MEDIUM"}]}]}`
	doc, err := parseTrivyNative(json.RawMessage(report))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	if got := trivyResolvedTypes(doc); len(got) != 1 || got[0] != "nuget" {
		t.Fatalf("fixture drifted: resolved types = %v", got)
	}
	acc := mustAccepter(t, "CVE-2026-81871=reason")
	filtered, _ := acc.partition(doc)
	if got := trivyResolvedTypes(filtered); len(got) != 0 {
		t.Fatalf("resolved types survived filtering (%v) — the trap this test guards "+
			"has moved, re-read the comment before changing it", got)
	}
}

// TestAnAcceptanceIsDisclosedWithItsReason. warnings[] is the only channel that
// survives into combined-evidence.json and the PR comment, so the line has to
// carry everything a reviewer needs: what, how much, why, and what it did not
// do.
func TestAnAcceptanceIsDisclosedWithItsReason(t *testing.T) {
	doc := mustParseAcceptReport(t)
	const reason = "the exporter only talks to the Dagger engine's own telemetry endpoint"
	acc := mustAccepter(t, "CVE-2026-81871="+reason)
	acc.partition(doc)

	lines := acc.disclosures()
	if len(lines) != 1 {
		t.Fatalf("disclosures = %d lines: %v", len(lines), lines)
	}
	line := lines[0]
	for _, want := range []string{
		"VULN ACCEPTED",
		"CVE-2026-81871",
		"covered 2 finding(s)",
		reason,
		"MEDIUM",
		"src/stage-2/go.mod",
		"CycloneDX",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("disclosure omits %q:\n%s", want, line)
		}
	}
}

// TestAnAcceptanceThatCoveredNothingIsLouder is the anti-rot signal. An
// acceptance kept past its finding is a standing permission for that identifier
// to come back unreviewed — and it is also how anyone learns upstream fixed it.
func TestAnAcceptanceThatCoveredNothingIsLouder(t *testing.T) {
	doc := mustParseAcceptReport(t)
	acc := mustAccepter(t, "CVE-1999-0001=accepted long ago")
	_, removed := acc.partition(doc)
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
	lines := acc.disclosures()
	if len(lines) != 1 || !strings.Contains(lines[0], "VULN ACCEPTANCE UNUSED") {
		t.Fatalf("stale acceptance was not disclosed: %v", lines)
	}
	if !strings.Contains(lines[0], "accepted long ago") {
		t.Errorf("stale disclosure drops the reason on file: %s", lines[0])
	}
}

// TestNothingAcceptedSaysNothing. A line printed on every run is a line a
// reader stops seeing; the same rule zapStartAndPassiveBudget lives under.
func TestNothingAcceptedSaysNothing(t *testing.T) {
	acc := mustAccepter(t)
	if lines := acc.disclosures(); len(lines) != 0 {
		t.Fatalf("an empty accepter disclosed %v", lines)
	}
	doc := mustParseAcceptReport(t)
	filtered, removed := acc.partition(doc)
	if removed != 0 || filtered != doc {
		t.Fatalf("an empty accepter touched the report (removed=%d)", removed)
	}
	if s := vulnAcceptedSummary(acc, 0); s != "" {
		t.Fatalf("empty accepter summarised: %q", s)
	}
	var nilAccepter *vulnAccepter
	if lines := nilAccepter.disclosures(); len(lines) != 0 {
		t.Fatalf("a nil accepter disclosed %v", lines)
	}
}

// TestManyCoveredRowsAreCountedNotListed keeps the one line a reviewer must
// read from becoming a page they will not.
func TestManyCoveredRowsAreCountedNotListed(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[`)
	for i := 0; i < 9; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"VulnerabilityID":"CVE-2026-81871","PkgName":"p","InstalledVersion":"v0.16.0","Severity":"MEDIUM"}`)
	}
	b.WriteString(`]}]}`)
	doc, err := parseTrivyNative(json.RawMessage(b.String()))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	acc := mustAccepter(t, "CVE-2026-81871=reason")
	acc.partition(doc)
	line := acc.disclosures()[0]
	if !strings.Contains(line, "covered 9 finding(s)") {
		t.Errorf("count is wrong: %s", line)
	}
	if !strings.Contains(line, "+6 more") {
		t.Errorf("rows were not bounded: %s", line)
	}
}

// TestSummaryCountsAcrossIdentifiers.
func TestSummaryCountsAcrossIdentifiers(t *testing.T) {
	doc := mustParseAcceptReport(t)
	acc := mustAccepter(t, "CVE-2026-81871=a", "CVE-2020-8203=b")
	_, removed := acc.partition(doc)
	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}
	s := vulnAcceptedSummary(acc, removed)
	if !strings.Contains(s, "3 vulnerability finding(s)") || !strings.Contains(s, "2 accepted") {
		t.Fatalf("summary = %q", s)
	}
}
