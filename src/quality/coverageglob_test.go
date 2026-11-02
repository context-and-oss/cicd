package main

import (
	"strings"
	"testing"
)

// A literal path must keep taking the original single-file code path. The
// evidence for every leg that works today has to stay where it is.
func TestCoveragePathIsGlob(t *testing.T) {
	literal := []string{
		"coverage/coverage-summary.json",
		"/tmp/cov/coverage.cobertura.xml",
		"cov.out",
		"reports/my-app.v2_final/lcov.info",
		"",
	}
	for _, p := range literal {
		if coveragePathIsGlob(p) {
			t.Errorf("%q is a literal path and must not be treated as a pattern", p)
		}
	}
	for _, p := range []string{
		"/tmp/cov/*.cobertura.xml",
		"cov/?.xml",
		"cov/[ab].xml",
	} {
		if !coveragePathIsGlob(p) {
			t.Errorf("%q is a pattern and must be expanded", p)
		}
	}
}

func TestSplitCoverageGlob(t *testing.T) {
	dir, name, err := splitCoverageGlob("/tmp/cov/*.cobertura.xml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir != "/tmp/cov" || name != "*.cobertura.xml" {
		t.Errorf("dir/name = %q/%q, want /tmp/cov/*.cobertura.xml split", dir, name)
	}

	// A bare filename pattern searches the working directory rather than failing.
	if dir, _, err := splitCoverageGlob("*.xml"); err != nil || dir != "." {
		t.Errorf("bare pattern: dir = %q, err = %v; want . and no error", dir, err)
	}

	// A pattern in a directory segment is refused, not approximated. find takes
	// one starting point, and both ways to paper over it change the match set
	// silently — widening it or narrowing it.
	_, _, err = splitCoverageGlob("/tmp/*/cover.xml")
	if err == nil {
		t.Fatal("a pattern in a directory segment must be an error, not a guess")
	}
	for _, want := range []string{"/tmp/*/cover.xml", "directory segment", "/tmp/cover.xml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message missing %q: %v", want, err)
		}
	}

	// A directory with no filename pattern names no report. The message has to
	// carry a usable pattern, because "append a filename pattern" without one
	// costs the reader a guess about which extension cicd can read.
	_, _, err = splitCoverageGlob("/tmp/cov/*/")
	if err == nil {
		t.Fatal("a directory is not a report")
	}
	if _, _, err := splitCoverageGlob("   "); err == nil {
		t.Error("an empty pattern must be an error")
	}
}

func TestBuildCoverageSetDedupesByteIdenticalDocuments(t *testing.T) {
	// MTP writes every report twice — once into the results directory and once
	// into the .trx attachment tree beneath it — and the search descends. Merging
	// both double-weights that project against every other leg in the same
	// language, which moves the figure with nothing failing.
	doc := `<?xml version="1.0"?><coverage line-rate="0.5" lines-valid="100" lines-covered="50"></coverage>`
	set := buildCoverageSet(map[string]string{
		"/tmp/cov/a.cobertura.xml":             doc,
		"/tmp/cov/attach/guid/a.cobertura.xml": doc,
	})
	if set.Matched != 2 {
		t.Errorf("Matched = %d, want 2 — the count is what the pattern found", set.Matched)
	}
	if set.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", set.Duplicates)
	}
	if set.Parsed != 1 || len(set.Readings) != 1 {
		t.Fatalf("Parsed = %d, readings = %d; want one document merged once",
			set.Parsed, len(set.Readings))
	}
	if set.Readings[0].Percent != 50 {
		t.Errorf("percent = %v, want 50 — a deduped document must not be re-weighted",
			set.Readings[0].Percent)
	}
}

func TestBuildCoverageSetCountsWhatItCouldNotRead(t *testing.T) {
	// The sharp case. A pattern matching four reports where three are unreadable
	// yields a figure measured over one of them, and coverage is the figure that
	// is wrong in the direction a ratchet cannot catch — so the count of what was
	// dropped is not derivable from the figure and must be carried separately.
	good := `<?xml version="1.0"?><coverage line-rate="0.8" lines-valid="50" lines-covered="40"></coverage>`
	set := buildCoverageSet(map[string]string{
		"/tmp/cov/good.cobertura.xml":  good,
		"/tmp/cov/junk.xml":            "not a coverage report at all",
		"/tmp/cov/empty.cobertura.xml": "",
	})
	if set.Matched != 3 {
		t.Errorf("Matched = %d, want 3", set.Matched)
	}
	if set.Parsed != 1 {
		t.Errorf("Parsed = %d, want 1", set.Parsed)
	}
	if len(set.Unparsed) != 2 {
		t.Fatalf("Unparsed = %v, want the two unreadable paths", set.Unparsed)
	}
	// Named, not just counted: a reviewer has to be able to go and look.
	joined := strings.Join(set.Unparsed, ",")
	for _, want := range []string{"junk.xml", "empty.cobertura.xml"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Unparsed missing %q: %v", want, set.Unparsed)
		}
	}

	// A generated empty cobertura has <packages />, line-rate="1", and no
	// lines-valid. It carries no measurement and must not arrive as 100%.
	emptyCob := `<?xml version="1.0"?><coverage line-rate="1"><packages /></coverage>`
	only := buildCoverageSet(map[string]string{"/tmp/cov/x.cobertura.xml": emptyCob})
	if only.Parsed != 0 || len(only.Readings) != 0 {
		t.Errorf("an empty cobertura reports no measurement, got parsed=%d readings=%v",
			only.Parsed, only.Readings)
	}
}

func TestBuildCoverageSetIsDeterministic(t *testing.T) {
	// Which document survives dedup decides which path a warning names, and
	// foldCoverage short-circuits on a single reading — so map iteration order
	// must not reach either.
	docs := map[string]string{
		"/tmp/b.cobertura.xml": `<?xml version="1.0"?><coverage line-rate="0.2" lines-valid="10" lines-covered="2"></coverage>`,
		"/tmp/a.cobertura.xml": `<?xml version="1.0"?><coverage line-rate="0.9" lines-valid="10" lines-covered="9"></coverage>`,
		"/tmp/c.xml":           "junk",
	}
	first := buildCoverageSet(docs)
	for i := 0; i < 20; i++ {
		again := buildCoverageSet(docs)
		if again.Parsed != first.Parsed || len(again.Unparsed) != len(first.Unparsed) {
			t.Fatalf("unstable set: %+v vs %+v", again, first)
		}
		if again.Readings[0] != first.Readings[0] {
			t.Fatalf("reading order changed: %v vs %v", again.Readings, first.Readings)
		}
	}
}

func TestCoverageSetWarningsAlwaysStateTheCount(t *testing.T) {
	// cicd cannot know how many reports a consumer's own command should have
	// written — that is the nature of a BYO leg — so it cannot tell a complete
	// harvest from a partial one. The only honest thing it can do is say how many
	// it merged. A figure with no count beside it is a claim about a number of
	// projects nobody stated.
	clean := coverageSetWarnings("/tmp/cov/*.cobertura.xml",
		coverageSet{Matched: 3, Parsed: 3})
	if len(clean) != 1 {
		t.Fatalf("the clean path still reports its count, got %v", clean)
	}
	for _, want := range []string{"/tmp/cov/*.cobertura.xml", "matched 3", "merged 3"} {
		if !strings.Contains(clean[0], want) {
			t.Errorf("clean warning missing %q: %s", want, clean[0])
		}
	}
	// The dedup note appears only when it fired; a note on every run is a note a
	// reader stops seeing.
	if strings.Contains(clean[0], "duplicate") {
		t.Errorf("no duplicates were dropped, so none should be mentioned: %s", clean[0])
	}
	withDupes := coverageSetWarnings("p", coverageSet{Matched: 4, Parsed: 2, Duplicates: 2})
	if !strings.Contains(withDupes[0], "dropped 2 duplicate document(s)") {
		t.Errorf("a dedup that fired must be stated: %s", withDupes[0])
	}

	// Zero matches is the same state as a literal path that was not there, and it
	// must not read as a measurement.
	empty := coverageSetWarnings("/tmp/cov/*.xml", coverageSet{})
	if len(empty) != 1 || !strings.Contains(empty[0], "matched no file") {
		t.Fatalf("an empty harvest must say so: %v", empty)
	}
	if !strings.Contains(empty[0], "contributed no coverage figure") {
		t.Errorf("an empty harvest must not read as zero coverage: %s", empty[0])
	}

	// Unreadable matches get their own line, never a silent drop.
	partial := coverageSetWarnings("p", coverageSet{
		Matched: 4, Parsed: 1, Unparsed: []string{"/tmp/a.xml", "/tmp/b.xml"},
	})
	if len(partial) != 2 {
		t.Fatalf("an unreadable match needs its own warning: %v", partial)
	}
	if !strings.Contains(partial[1], "/tmp/a.xml") || !strings.Contains(partial[1], "2 matched file(s)") {
		t.Errorf("the unreadable warning must count and name them: %s", partial[1])
	}

	// The leg label has exactly one owner, legPrefix in the caller. Two owners is
	// how the evidence came to read "test-leg dotnet: test-leg dotnet: coverage
	// pattern ..." on a three-leg run.
	for _, set := range [][]string{clean, empty, partial, withDupes} {
		for _, w := range set {
			if strings.Contains(w, "test-leg") {
				t.Errorf("the caller owns the leg label; self-labelling doubles it: %s", w)
			}
		}
	}

	// notify renders every warnings[] entry as a markdown code span, so a
	// backtick in one truncates the span and mangles the comment.
	for _, set := range [][]string{clean, empty, partial, withDupes} {
		for _, w := range set {
			if strings.Contains(w, "`") {
				t.Errorf("warning carries a backtick, which notify renders as a code span: %s", w)
			}
		}
	}
}

func TestCoverageFindArgsPassThePatternAsArgv(t *testing.T) {
	// A consumer-supplied pattern spliced into an sh -c body is shell injection
	// whose vector is a coverage report's filename. It reaches find as one argv
	// element or not at all.
	args := coverageFindArgs("/tmp/cov", "*.cobertura.xml")
	if args[0] != "find" {
		t.Fatalf("args = %v", args)
	}
	for _, a := range args {
		if strings.Contains(a, "sh") && a != "*.cobertura.xml" {
			t.Errorf("the search must not go through a shell: %v", args)
		}
	}
	var sawPattern bool
	for _, a := range args {
		if a == "*.cobertura.xml" {
			sawPattern = true
		}
	}
	if !sawPattern {
		t.Errorf("the pattern must survive as its own argv element: %v", args)
	}
	// -print0, because splitting on a newline would silently split one path
	// holding one into two unreadable ones.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-print0") {
		t.Errorf("want -print0: %v", args)
	}
	// Not depth-limited: pooled MTP reports sit at the top of the results
	// directory and a per-project run writes them into each build tree. A limit
	// is right for one layout and quietly wrong for the other.
	if strings.Contains(joined, "-maxdepth") {
		t.Errorf("a depth limit is correct for one layout and wrong for the other: %v", args)
	}
}

func TestSplitFindOutput(t *testing.T) {
	got := splitFindOutput("/tmp/b.xml\x00/tmp/a.xml\x00")
	if len(got) != 2 || got[0] != "/tmp/a.xml" || got[1] != "/tmp/b.xml" {
		t.Errorf("want sorted paths, got %v", got)
	}
	if len(splitFindOutput("")) != 0 {
		t.Error("no output means no matches")
	}
	if len(splitFindOutput("\x00\x00")) != 0 {
		t.Error("empty entries are not paths")
	}
}

func TestCoverageIdentityIgnoresTheTimestamp(t *testing.T) {
	// Independently generated documents below differ only in their timestamps.
	// MTP can publish an attachment as a file copy, but byte identity is a
	// property of that publication mechanism, not of the coverage measurement.
	// Re-serialising the same reading must not change its deduplication key.
	//
	// What a missed pair costs: every project's reading enters the fold twice, the
	// coverable-line weighting stays internally consistent, the percentage stays
	// entirely plausible, and Duplicates reads 0. Nothing errors. That is why the
	// identity must not depend on copy semantics cicd does not control.
	root := `<?xml version="1.0"?><coverage line-rate="0.5" lines-valid="100" ` +
		`lines-covered="50" timestamp="1700000000"><packages><package name="A"/></packages></coverage>`
	attach := strings.Replace(root, `timestamp="1700000000"`, `timestamp="1700000007"`, 1)
	if root == attach {
		t.Fatal("fixture is wrong: the two documents must differ")
	}

	set := buildCoverageSet(map[string]string{
		"/tmp/cov/a.cobertura.xml":         root,
		"/tmp/cov/In/host/a.cobertura.xml": attach,
	})
	if set.Matched != 2 {
		t.Errorf("Matched = %d, want 2", set.Matched)
	}
	if set.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1 — a re-serialized attachment is the same "+
			"measurement, and counting it twice double-weights the project", set.Duplicates)
	}
	if set.Parsed != 1 || len(set.Readings) != 1 {
		t.Fatalf("Parsed = %d, readings = %d; want one measurement", set.Parsed, len(set.Readings))
	}

	// The trade-off is bounded, and the boundary is what this asserts: two
	// documents that differ in anything a measurement is derived from stay two
	// measurements. Same timestamp, different numbers.
	other := `<?xml version="1.0"?><coverage line-rate="0.9" lines-valid="200" ` +
		`lines-covered="180" timestamp="1700000000"><packages><package name="B"/></packages></coverage>`
	two := buildCoverageSet(map[string]string{
		"/tmp/cov/a.cobertura.xml": root,
		"/tmp/cov/b.cobertura.xml": other,
	})
	if two.Duplicates != 0 || two.Parsed != 2 {
		t.Errorf("two distinct projects must stay two readings, got parsed=%d dupes=%d",
			two.Parsed, two.Duplicates)
	}

	// A document carrying no timestamp at all is untouched, so every leg that
	// works today keeps the figure it has.
	plain := `<?xml version="1.0"?><coverage line-rate="0.5" lines-valid="100" lines-covered="50"/>`
	if coverageIdentity(plain) != plain {
		t.Errorf("a document with no timestamp must pass through unchanged: %q",
			coverageIdentity(plain))
	}

	// The pattern is unanchored and carries no element context, so it strips a
	// timestamp on any element at any depth — not the root's. That is the wanted
	// behaviour (stripping more can only merge more, and no cobertura element
	// carries a timestamp that distinguishes one measurement from another), and it
	// is asserted rather than described because the comment above the pattern used
	// to claim the narrower rule while the pattern never was anchored. The
	// trade-off paragraph in coverageIdentity is licensed by whichever of the two
	// is true, so the true one is the one a test holds.
	nested := `<coverage line-rate="0.5" lines-valid="100" timestamp="1"><packages>` +
		`<package name="A" timestamp="2"/></packages></coverage>`
	if id := coverageIdentity(nested); strings.Contains(id, "timestamp") {
		t.Errorf("a nested timestamp is stripped too; the pattern is not root-only: %q", id)
	}
}

func TestParseCoberturaSetSharesTheIdentityRule(t *testing.T) {
	// cicd's own .NET leg harvests the same MTP layout through a different
	// function, so the rule has to hold in both or the busier path keeps the
	// defect. Same fixture shape as above.
	root := `<?xml version="1.0"?><coverage line-rate="0.5" lines-valid="100" ` +
		`lines-covered="50" timestamp="1700000000"><packages><package name="A"/></packages></coverage>`
	attach := strings.Replace(root, `timestamp="1700000000"`, `timestamp="1700000007"`, 1)
	got := parseCoberturaSet(root + coberturaSeparator + attach)
	if len(got) != 1 {
		t.Fatalf("parseCoberturaSet returned %d readings, want 1: %v", len(got), got)
	}
	if got[0].Lines != 100 {
		t.Errorf("lines = %d, want 100 — a deduped document must not be re-weighted", got[0].Lines)
	}
}

// TestCoverageSetErrorsRefuseAHarvestThatReadNothing pins the fail-open this
// package shipped: a pattern that found documents, read none of them, and came
// back passed=true.
//
// A leg whose every document is unreadable yields no reading, so haveCoverage is
// false and the ratchet records skipped:no-coverage-output — a verdict that is
// fail-open by design (ADR-003) and right for the consumer who configured no
// coverage at all. Reused for an unreadable harvest it says "there was nothing
// to measure" about documents cicd could not read. The synthetic counts below
// exercise that distinction. Coverage can be wrong in a direction a ratchet
// cannot catch, so this must be an error, which gates because Test pins its
// threshold to HIGH.
func TestCoverageSetErrorsRefuseAHarvestThatReadNothing(t *testing.T) {
	dead := coverageSetErrors("/tmp/cov/*.cobertura.xml", coverageSet{
		Matched: 10, Parsed: 0, Duplicates: 5,
		Unparsed: []string{"/tmp/cov/a.cobertura.xml", "/tmp/cov/b.cobertura.xml"},
	})
	if len(dead) != 1 {
		t.Fatalf("a harvest that read nothing must error, got %v", dead)
	}
	for _, want := range []string{"/tmp/cov/*.cobertura.xml", "matched 10", "failed measurement"} {
		if !strings.Contains(dead[0], want) {
			t.Errorf("error missing %q: %s", want, dead[0])
		}
	}

	// One reading is enough to make it a measurement rather than a failure. The
	// documents nothing could read still get their own warning, which is where
	// a partial harvest is reported.
	if got := coverageSetErrors("p", coverageSet{
		Matched: 4, Parsed: 1, Unparsed: []string{"/tmp/a.xml"},
	}); got != nil {
		t.Errorf("a partial harvest is reported by warning, not error: %v", got)
	}

	// Deliberately narrow: an empty harvest is a command that wrote no report,
	// which a leg may legitimately do, and is not cicd failing to read anything.
	// coverageSetWarnings owns that case.
	if got := coverageSetErrors("p", coverageSet{}); got != nil {
		t.Errorf("an empty harvest is not a failed read: %v", got)
	}

	// Same two constraints as every other message here: the caller owns the leg
	// label, and notify renders these as markdown code spans.
	for _, e := range dead {
		if strings.Contains(e, "test-leg") {
			t.Errorf("the caller owns the leg label; self-labelling doubles it: %s", e)
		}
		if strings.Contains(e, "`") {
			t.Errorf("error carries a backtick, which notify renders as a code span: %s", e)
		}
	}
}

// TestBuildCoverageSetReadsBOMdDocuments generates BOM-prefixed reports in
// root/attachment pairs. It exercises the BYO harvest's parsing and deduplication
// together, without relying on a captured coverage document.
func TestBuildCoverageSetReadsBOMdDocuments(t *testing.T) {
	const bom = "\uFEFF"
	doc := func(rate, covered, valid string) string {
		return bom + `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<coverage line-rate="` + rate + `" lines-covered="` + covered + `" lines-valid="` + valid + `">
  <sources><source>/src</source></sources><packages></packages>
</coverage>`
	}
	set := buildCoverageSet(map[string]string{
		"/tmp/cov/aaa.cobertura.xml":                     doc("0.25", "360", "1440"),
		"/tmp/cov/_dagger_1/In/dagger/aaa.cobertura.xml": doc("0.25", "360", "1440"),
		"/tmp/cov/bbb.cobertura.xml":                     doc("0.50", "100", "200"),
		"/tmp/cov/_dagger_1/In/dagger/bbb.cobertura.xml": doc("0.50", "100", "200"),
	})
	if set.Matched != 4 || set.Parsed != 2 || set.Duplicates != 2 {
		t.Fatalf("matched=%d parsed=%d dups=%d, want 4/2/2", set.Matched, set.Parsed, set.Duplicates)
	}
	if len(set.Unparsed) != 0 {
		t.Errorf("a BOM must not make a readable report unreadable: %v", set.Unparsed)
	}
	// And the harvest that reads its documents is not an error.
	if got := coverageSetErrors("/tmp/cov/*.cobertura.xml", set); got != nil {
		t.Errorf("a harvest that read its documents must not error: %v", got)
	}
}

// TestDuplicateNoteClaimsOnlyWhatTheKeyCompared pins a warning that was false in
// an evidence envelope on a shipped tag.
//
// duplicateNote said the dropped documents were "reporting the same measurement"
// while the count beside it said zero documents were merged. The dedup runs
// before sniffCoverageReport, so on a harvest where every document was
// unreadable nothing had reported any measurement at all — the clause asserted
// parsed content on a path with no parse behind it. The synthetic harvest below
// isolates this state: duplicates can be dropped before any document parses.
//
// The note may assert only what coverageIdentity compared: text with any
// timestamp attribute removed, which is a fact whether the later parse succeeds
// or fails. Guarding the clause behind Parsed > 0 was rejected — it silences the
// falsehood on the harvest that produced it, leaves it wherever a parse fails
// for another reason, and drops the count on the path a reviewer most needs it.
func TestDuplicateNoteClaimsOnlyWhatTheKeyCompared(t *testing.T) {
	const backable = "identical apart from any timestamp attribute"

	dead := coverageSetWarnings("/tmp/cov/*.cobertura.xml", coverageSet{
		Matched: 10, Parsed: 0, Duplicates: 5,
		Unparsed: []string{"/tmp/cov/a.cobertura.xml"},
	})
	if len(dead) == 0 {
		t.Fatalf("a harvest that read nothing still reports its counts")
	}
	if !strings.Contains(dead[0], "merged 0 document(s)") ||
		!strings.Contains(dead[0], "dropped 5 duplicate document(s)") {
		t.Fatalf("both counts belong in the line: %s", dead[0])
	}
	if !strings.Contains(dead[0], backable) {
		t.Errorf("the note must say what the key compared: %s", dead[0])
	}
	// Any wording claiming the dropped documents measured something is unbackable
	// here, because Parsed is 0; "byte-identical" is the opposite error, narrower
	// than the key coverageIdentity actually applies.
	for _, forbidden := range []string{"same measurement", "byte-identical"} {
		if strings.Contains(dead[0], forbidden) {
			t.Errorf("merged 0 document(s) and %q cannot both be true: %s",
				forbidden, dead[0])
		}
	}

	// One claim, every path: the wording does not change with the parse outcome,
	// so there is no state in which the reader has to work out which rule ran.
	live := coverageSetWarnings("p", coverageSet{Matched: 4, Parsed: 2, Duplicates: 2})
	if !strings.Contains(live[0], backable) {
		t.Errorf("the success path states the same compared fact: %s", live[0])
	}
}
