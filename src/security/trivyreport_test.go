package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// nativeReport is shaped like a real trivy 0.70.0 `--format json` report: an OS
// result whose packages have no PkgPath, and a language result whose packages
// name the lockfile they came from.
const nativeReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "debian:11.6",
  "Results": [
    {
      "Target": "debian:11.6 (debian 11.6)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2023-45853","PkgName":"zlib1g","InstalledVersion":"1:1.2.11.dfsg-2","Severity":"CRITICAL","SeveritySource":"nvd","Title":"integer overflow in zipOpenNewFileInZip4_64"},
        {"VulnerabilityID":"CVE-2022-3715","PkgName":"bash","InstalledVersion":"5.1-2","FixedVersion":"5.1-2+deb11u1","Severity":"HIGH","SeveritySource":"debian"},
        {"VulnerabilityID":"CVE-2011-3374","PkgName":"apt","InstalledVersion":"2.2.4","Severity":"LOW","SeveritySource":"debian"},
        {"VulnerabilityID":"CVE-2026-53613","PkgName":"perl","InstalledVersion":"5.32.1","Severity":"UNKNOWN"}
      ]
    },
    {
      "Target": "app/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2020-8203","PkgName":"lodash","PkgPath":"app/package-lock.json","InstalledVersion":"4.17.15","FixedVersion":"4.17.19","Severity":"HIGH","SeveritySource":"ghsa","Title":"prototype pollution"},
        {"VulnerabilityID":"CVE-2020-28500","PkgName":"lodash","PkgPath":"app/package-lock.json","InstalledVersion":"4.17.15","FixedVersion":"4.17.21","Severity":"MEDIUM","SeveritySource":"ghsa"}
      ]
    }
  ]
}`

// TestTrivySeveritiesUseTrivysOwnVerdict is the regression guard for the
// severity-selection defect. Every count below comes from the report's own
// Severity field, so no vendor rating ordering can move it.
func TestTrivySeveritiesUseTrivysOwnVerdict(t *testing.T) {
	doc, err := parseTrivyNative(json.RawMessage(nativeReport))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	assertSeverities(t, trivySeverities(doc), map[Severity]int{
		SeverityCritical: 1,
		SeverityHigh:     2,
		SeverityMedium:   1,
		// CVE-2011-3374 (LOW) plus CVE-2026-53613 (UNKNOWN, counted LOW rather
		// than dropped).
		SeverityLow: 2,
	})
}

// TestTrivyUnratedVulnerabilityIsNeverInvisible pins the half of the defect that
// was not about ordering: a severity outside the four known strings matched no
// case in the old parser, so the vulnerability reached neither the counts nor the
// total nor any list. Seven of debian:11.6's 205 disappeared that way.
func TestTrivyUnratedVulnerabilityIsNeverInvisible(t *testing.T) {
	const unrated = `{"Results":[{"Target":"x","Vulnerabilities":[
      {"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"UNKNOWN"},
      {"VulnerabilityID":"CVE-2","PkgName":"b","Severity":""}
    ]}]}`
	doc, err := parseTrivyNative(json.RawMessage(unrated))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}

	total := 0
	for _, c := range trivySeverities(doc) {
		total += c
	}
	if total != 2 {
		t.Errorf("unrated vulnerabilities counted %d times, want 2 — an unrated CVE must never vanish", total)
	}
	if got := len(trivyFindings(doc)); got != 2 {
		t.Errorf("trivyFindings returned %d rows, want 2", got)
	}

	warnings := trivyWarnings(doc)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2 vulnerability") {
		t.Errorf("trivyWarnings = %v, want one warning naming both unrated findings", warnings)
	}
}

// TestParseTrivyNativeRejectsNonScans keeps a Trivy that produced nothing from
// reading as a clean scan — the standing rule in this module.
func TestParseTrivyNativeRejectsNonScans(t *testing.T) {
	cases := []struct {
		name, report, want string
	}{
		{"empty report", "", "nothing was scanned"},
		{"whitespace only", "   \n", "nothing was scanned"},
		{"not json", "Fatal: could not open image", "not valid JSON"},
		{"results absent", `{"SchemaVersion":2}`, "no scan results"},
		{"results null", `{"SchemaVersion":2,"Results":null}`, "no scan results"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTrivyNative(json.RawMessage(tc.report))
			if err == nil {
				t.Fatalf("parseTrivyNative(%q) returned no error", tc.report)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}

	// A scan that ran and found nothing is a *pass*, not an error: Results is
	// present and empty of vulnerabilities. This is the case that must not be
	// confused with the ones above.
	doc, err := parseTrivyNative(json.RawMessage(`{"Results":[{"Target":"go.mod","Class":"lang-pkgs"}]}`))
	if err != nil {
		t.Fatalf("a clean scan must not error: %v", err)
	}
	if n := len(trivySeverities(doc)); n != 0 {
		t.Errorf("clean scan produced %d severity buckets, want 0", n)
	}
	if trivyWarnings(doc) != nil {
		t.Errorf("clean scan produced warnings: %v", trivyWarnings(doc))
	}
}

func TestParseTrivyNativeNamesTheNoTargetsCondition(t *testing.T) {
	_, err := parseTrivyNative(json.RawMessage(`{"SchemaVersion":2,"Results":null}`))
	if !errors.Is(err, errTrivyNoTargets) {
		t.Fatalf("error = %v, want the typed no-targets condition", err)
	}
}

// TestTrivyFindingsCarryRemediation checks the detail rows say what to change.
// A severity with no package, version or fix is a number a reader cannot act on.
func TestTrivyFindingsCarryRemediation(t *testing.T) {
	doc, err := parseTrivyNative(json.RawMessage(nativeReport))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	findings := trivyFindings(doc)
	if len(findings) != 6 {
		t.Fatalf("got %d findings, want 6 (one per package/CVE pair)", len(findings))
	}

	byRule := map[string]Finding{}
	for _, f := range findings {
		byRule[f.Rule] = f
		if f.Tool != "trivy" {
			t.Errorf("%s: tool = %q, want trivy", f.Rule, f.Tool)
		}
		if f.ArtifactPath == "" {
			t.Errorf("%s: no artifactPath — the row cannot be located", f.Rule)
		}
	}

	// A lockfile dependency points at the lockfile, because that is the file
	// someone edits to fix it.
	if got := byRule["CVE-2020-8203"].ArtifactPath; got != "app/package-lock.json" {
		t.Errorf("lockfile finding path = %q, want app/package-lock.json", got)
	}
	// An OS package has no such file, so it falls back to the scan target.
	if got := byRule["CVE-2011-3374"].ArtifactPath; got != "debian:11.6 (debian 11.6)" {
		t.Errorf("os finding path = %q, want the scan target", got)
	}

	if got := byRule["CVE-2020-8203"]; got.Severity != SeverityHigh ||
		!strings.Contains(got.Message, "lodash@4.17.15") ||
		!strings.Contains(got.Message, "fixed in 4.17.19") {
		t.Errorf("CVE-2020-8203 = %+v, want HIGH with the installed and fixed versions", got)
	}
	// The CRITICAL in the fixture has no FixedVersion, which must be stated
	// rather than left blank.
	if got := byRule["CVE-2023-45853"]; got.Severity != SeverityCritical ||
		!strings.Contains(got.Message, "no fix available") {
		t.Errorf("CVE-2023-45853 = %+v, want CRITICAL and an explicit no-fix note", got)
	}
	// The vendor behind the verdict is recorded: "nvd" on a debian image is the
	// signal that debian published no rating.
	if got := byRule["CVE-2023-45853"].Message; !strings.Contains(got, "severity: nvd") {
		t.Errorf("message %q does not name the severity source", got)
	}
}

// TestTrivyFindingsAgreeWithTheCounts is the invariant the old code broke: the
// detail list and the severity map are two views of one report, so a reader can
// never see a total that the rows do not add up to.
func TestTrivyFindingsAgreeWithTheCounts(t *testing.T) {
	doc, err := parseTrivyNative(json.RawMessage(nativeReport))
	if err != nil {
		t.Fatalf("parseTrivyNative: %v", err)
	}
	counts := trivySeverities(doc)
	fromFindings := map[Severity]int{}
	for _, f := range trivyFindings(doc) {
		fromFindings[f.Severity]++
	}
	assertSeverities(t, fromFindings, counts)
}

// TestTrivyResolvedTypesRequireResolvedContent covers the exculpating half of the
// ecosystem reconciliation (see ecosystems.go). A Result heading is not evidence
// that Trivy read a dependency graph: it must carry at least one package or one
// vulnerability, or an empty result would clear the very ecosystem whose silence
// is under suspicion.
func TestTrivyResolvedTypesRequireResolvedContent(t *testing.T) {
	const report = `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "web/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Packages": [{"Name":"lodash","Version":"4.17.15"}]
    },
    {
      "Target": "go.mod",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"golang.org/x/net","Severity":"HIGH"}
      ]
    },
    {
      "Target": "Api/Api.csproj",
      "Class": "lang-pkgs",
      "Type": "nuget"
    },
    {
      "Target": "web/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Packages": [{"Name":"left-pad","Version":"1.3.0"}]
    },
    {
      "Target": "orphan",
      "Class": "lang-pkgs",
      "Type": "",
      "Packages": [{"Name":"x"}]
    }
  ]
}`
	doc, err := parseTrivyNative(json.RawMessage(report))
	if err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}

	got := trivyResolvedTypes(doc)
	want := []string{"npm", "gomod"}
	if len(got) != len(want) {
		t.Fatalf("resolved types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("resolved types = %v, want %v", got, want)
		}
	}
}

// TestTrivyResolvedTypesLowercase pins the case folding, because the
// reconciliation compares against a lowercase table and a "NuGet" would silently
// never match — a false alarm on a repository Trivy did scan.
func TestTrivyResolvedTypesLowercase(t *testing.T) {
	const report = `{"Results":[{"Target":"x","Type":" NuGet ","Packages":[{"Name":"Newtonsoft.Json"}]}]}`
	doc, err := parseTrivyNative(json.RawMessage(report))
	if err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	got := trivyResolvedTypes(doc)
	if len(got) != 1 || got[0] != "nuget" {
		t.Fatalf("resolved types = %v, want [nuget]", got)
	}
}

// TestTrivyExaminedCountsEveryResolvedPackage pins the sum across results.
//
// Two lockfiles that each resolve the same package are two examined entries,
// not one: Trivy checks each against the advisory database and reports
// vulnerabilities for each. Measured on a tree with one package-lock.json
// copied into two directories, Trivy emits two results of one package and ten
// vulnerabilities each. Deduplicating here would report twenty findings over
// one package.
func TestTrivyExaminedCountsEveryResolvedPackage(t *testing.T) {
	const report = `{
  "Results": [
    {"Target":"a/package-lock.json","Type":"npm","Packages":[{"Name":"lodash","Version":"4.17.4"}]},
    {"Target":"b/package-lock.json","Type":"npm","Packages":[{"Name":"lodash","Version":"4.17.4"}]},
    {"Target":"debian 11.6","Type":"debian","Packages":[{"Name":"perl"},{"Name":"bash"}]}
  ]
}`
	doc, err := parseTrivyNative(json.RawMessage(report))
	if err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	got := trivyExamined(doc)
	if got == nil {
		t.Fatal("examined is nil for a report that parsed")
	}
	if got.Count != 4 {
		t.Errorf("count = %d, want 4 — the sum across results, not the 3 distinct packages", got.Count)
	}
	if got.Unit != "resolved packages" {
		t.Errorf("unit = %q, want %q — a bare number is unreportable", got.Unit, "resolved packages")
	}
	if got.Total != 0 {
		t.Errorf("total = %d, want 0 — Trivy cannot see what it failed to resolve, "+
			"and a tool that does not know its denominator must not imply one", got.Total)
	}
}

// TestTrivyExaminedSaysZeroRatherThanNothing is the whole point of the field.
//
// A report Trivy produced having resolved nothing is the loud case, not the
// absent one: "0 vulnerabilities across 0 resolved packages" is a scan that
// reached nothing, and it must not render identically to a clean tree. Absent
// is reserved for a scanner that states no figure at all.
func TestTrivyExaminedSaysZeroRatherThanNothing(t *testing.T) {
	for _, report := range []string{
		`{"Results":[{"Target":"Api/Api.csproj","Type":"nuget"}]}`,
		`{"Results":[{"Target":"Api/Api.csproj","Type":"nuget","Packages":[]}]}`,
	} {
		doc, err := parseTrivyNative(json.RawMessage(report))
		if err != nil {
			t.Fatalf("fixture must parse (%s): %v", report, err)
		}
		got := trivyExamined(doc)
		if got == nil {
			t.Fatalf("examined is nil for %s — absent means the tool did not say, "+
				"but it did say: it resolved nothing", report)
		}
		if got.Count != 0 {
			t.Errorf("count = %d, want 0 for %s", got.Count, report)
		}
	}
}

// TestTrivyExaminedCountsPackagesNotVulnerabilities keeps the denominator from
// tracking the numerator. A result carrying vulnerabilities but no resolved
// package list contributes nothing to the count — the two are separate claims,
// and conflating them would make "findings across examined" self-fulfilling.
func TestTrivyExaminedCountsPackagesNotVulnerabilities(t *testing.T) {
	const report = `{
  "Results": [
    {"Target":"go.mod","Type":"gomod","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2026-0001","PkgName":"golang.org/x/net","Severity":"HIGH"},
      {"VulnerabilityID":"CVE-2026-0002","PkgName":"golang.org/x/net","Severity":"LOW"}
    ]}
  ]
}`
	doc, err := parseTrivyNative(json.RawMessage(report))
	if err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	if got := trivyExamined(doc); got.Count != 0 {
		t.Errorf("count = %d, want 0 — two vulnerabilities are not two examined packages", got.Count)
	}
}

// TestTrivyExaminedNeverSeesAResultlessReport pins the boundary between the two
// zeroes. `"Results": null` is Trivy saying it found no target at all, and
// parseTrivyNative already refuses it — so trivyExamined is never asked to
// describe that state and never has to choose between reporting it as zero
// examined and reporting it as absent. If that guard is ever relaxed, this
// fails and the choice has to be made deliberately rather than inherited.
//
// `"Results": []` says the same as null: Trivy omits an empty Results, so no
// real report carries one, and it used to pass as zero targets examined.
func TestTrivyExaminedNeverSeesAResultlessReport(t *testing.T) {
	for _, report := range []string{`{"SchemaVersion":2}`, `{"Results":null}`, `{"Results":[]}`} {
		if _, err := parseTrivyNative(json.RawMessage(report)); err == nil {
			t.Errorf("%s parsed, but a report naming no target must not reach the "+
				"denominator as a confident zero", report)
		}
	}
}
