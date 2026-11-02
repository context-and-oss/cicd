package main

// coverageglob.go holds the pure logic behind a witnessed leg whose coverage
// report cannot be named by a literal path.
//
// Untagged, and deliberately so: byotest.go is //go:build !unit_test, and the
// last thing to live only in that file — a switch with no default arm — is how
// --include golang came to resolve to an empty language set. include.go and
// noartifact.go carry the same split for the same reason. Everything a reader
// has to trust here (which patterns are refused, how many documents were
// merged, what happens to a matched file nothing can parse) is driven by tests.
//
// Why this exists. A leg's coveragePath is read with ctr.File(path), i.e. one
// literal path, and Microsoft.Testing.Platform names each test application's
// report <guid>.cobertura.xml — the guid is load-bearing, it is what stops two
// applications overwriting each other's numbers, which is why cicd's own leg
// refuses to pass --coverage-output. So a BYO .NET leg on MTP had no way to
// name what it had just written. The remedies available to a consumer were to
// force a filename (safe for one test application, and silently wrong for two:
// the surviving document holds whichever finished last) or to merge by hand.
// A well-formed cobertura holding half a repository's numbers is worse than no
// document at all, because it reads as a successful measurement — and coverage
// is the one figure here that is wrong in the direction that survives a
// ratchet.
//
// The multi-document machinery already existed for cicd's own .NET leg
// (parseCoberturaSet, which dedups on coverageIdentity because MTP writes every
// report a second time into the .trx attachment directory). The BYO path simply
// could not reach it. This file lets it, for any format sniffCoverageReport knows,
// not cobertura alone.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// coverageGlobMeta are the characters that make a coveragePath a pattern rather
// than a path. A path holding none of them takes the original single-file code
// path byte-for-byte: the evidence for every leg that works today must not move
// because this file exists.
const coverageGlobMeta = `*?[`

// coveragePathIsGlob reports whether a leg's coveragePath is a pattern.
func coveragePathIsGlob(p string) bool {
	return strings.ContainsAny(p, coverageGlobMeta)
}

// splitCoverageGlob splits a pattern into the directory to search and the
// filename pattern to match inside it.
//
// A metacharacter in the directory portion is refused rather than approximated.
// `find` takes one starting point, so /tmp/*/cover.xml cannot be expressed as
// given, and the two ways to paper over it are both worse than an error: search
// the parent of the pattern and the match set silently widens, or drop the
// segment and it silently narrows. A consumer who gets an error rewrites the
// pattern; a consumer who gets a quietly wrong match set gets a coverage figure
// measured over the wrong files, and no way to tell.
func splitCoverageGlob(pattern string) (dir, name string, err error) {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return "", "", fmt.Errorf("coverage glob is empty")
	}
	dir, name = path.Split(trimmed)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "."
	}
	if strings.ContainsAny(dir, coverageGlobMeta) {
		return "", "", fmt.Errorf(
			"coverage path %q puts a pattern in a directory segment (%q), which cannot be "+
				"expanded from a single starting point — put the pattern in the filename "+
				"(the search already descends into subdirectories, so %s covers a report "+
				"written into a nested results directory)",
			trimmed, dir, path.Join(shallowestLiteralDir(dir), name))
	}
	if name == "" {
		return "", "", fmt.Errorf(
			"coverage path %q names a directory, not a report — append a filename pattern "+
				"such as %q", trimmed, path.Join(trimmed, "*.cobertura.xml"))
	}
	return dir, name, nil
}

// shallowestLiteralDir returns the leading segments of a directory that hold no
// pattern, so the error above can suggest a starting point that exists rather
// than one the consumer would have to work out.
func shallowestLiteralDir(dir string) string {
	parts := strings.Split(dir, "/")
	keep := []string{}
	for _, p := range parts {
		if strings.ContainsAny(p, coverageGlobMeta) {
			break
		}
		keep = append(keep, p)
	}
	out := strings.Join(keep, "/")
	if out == "" {
		return "."
	}
	return out
}

// coverageSet is the outcome of reading every document a pattern matched.
//
// The three counts are separate on purpose, and none of them is derivable from
// the others. Matched is what the pattern found; Parsed is how many of those
// yielded a measurement; Duplicates is how many were the same document as one
// already read — coverageIdentity's sense of the same, which is not byte
// identity and is decided before anything is parsed. A single figure cannot
// distinguish "the pattern found one report" from "the pattern found four, three
// of which nothing could read" — and the second is a coverage figure measured
// over a quarter of a repository while looking exactly as authoritative as the
// first.
type coverageSet struct {
	Matched    int
	Parsed     int
	Duplicates int
	Unparsed   []string
	Readings   []nodeCoverage
}

// buildCoverageSet reads a pattern's matches into per-document readings.
//
// docs maps path to contents; the caller supplies it because reading a file out
// of a container needs Dagger and this file must not.
//
// Documents that are the same measurement are counted and dropped — see
// coverageIdentity for what "the same" means and why it is not byte-identity.
// That is not tidiness: MTP
// writes each report twice — once into the results directory and once into the
// .trx attachment tree beneath it — and the search descends, so a pattern that
// matches the real report matches its copy too. Merging both double-weights
// that project against every other one in the same leg, which moves the figure
// without anything failing. Measured on cicd's own .NET leg: 4 files, 2 distinct
// reports.
func buildCoverageSet(docs map[string]string) coverageSet {
	set := coverageSet{Matched: len(docs)}
	seen := map[string]bool{}
	for _, p := range sortedKeysOf(docs) {
		raw := docs[p]
		key := coverageIdentity(raw)
		if seen[key] {
			set.Duplicates++
			continue
		}
		seen[key] = true
		rep, ok := sniffCoverageReport(raw)
		if !ok {
			set.Unparsed = append(set.Unparsed, p)
			continue
		}
		set.Parsed++
		set.Readings = append(set.Readings, nodeCoverage{Percent: rep.Pct, Lines: rep.Lines})
	}
	return set
}

// coberturaTimestampRE matches a timestamp attribute on any element at any
// depth, not the root's. It is unanchored and carries no element context
// deliberately: stripping more can only merge more, and there is no cobertura
// element whose timestamp distinguishes one measurement from another.
//
// Said this precisely because the comment here used to say "the root element's"
// while the regex never was anchored, and the trade-off argument below is
// licensed by whichever of the two is true. A reader widening the pattern later
// would have checked it against a paragraph that already agreed with the wider
// behaviour.
var coberturaTimestampRE = regexp.MustCompile(`\stimestamp="[^"]*"`)

// coverageIdentity is the key two coverage documents are the same measurement
// under. It is the document with its timestamp attribute removed, not the raw
// bytes.
//
// Why not raw bytes. Microsoft.Testing.Platform writes each test application's
// cobertura once at the results-directory root and again under the trx
// attachment directory, and those pairs have been observed to be byte-identical.
// But they are byte-identical because the second member is a file *copy*, which
// is a property of how MTP happens to publish attachments rather than anything
// about the measurement. Timestamps can differ across projects, so the field is
// live, and a release that serialised the attachment a second time instead of
// copying it could produce pairs differing in exactly one attribute.
//
// The consequence of missing such a pair is silent and wrong in the direction
// that survives review: every project's reading enters mergeNodeCoverage twice,
// the coverable-line weighting stays internally consistent, and the percentage
// remains entirely plausible. Nothing errors and no count looks wrong — the
// Duplicates figure would simply read 0. So the identity test must not depend on
// copy semantics cicd does not control.
//
// The trade-off, stated because it is real: two *different* projects whose
// coverage documents are identical once every timestamp attribute is gone —
// every one, at any depth, which is what the pattern strips — would now merge
// into one reading. For a non-empty cobertura that requires identical <sources>
// and identical per-class line data, which two distinct projects do not have,
// and none of the bytes carrying that data is a timestamp. MTP puts a timestamp
// on <coverage> and nowhere else, so today the wider strip and a root-only one
// remove the same bytes; the argument is stated over the wider one because that
// is the one that runs. The
// case where it is plausible is the empty document, and an empty cobertura
// contributes no reading at all (sniffCoverageReport rejects it — see
// TestBuildCoverageSetCountsWhatItCouldNotRead), so merging two of them changes
// nothing a figure is derived from.
func coverageIdentity(raw string) string {
	return coberturaTimestampRE.ReplaceAllString(raw, "")
}

// sortedKeysOf keeps the read order deterministic, so a leg's coverage figure
// does not depend on map iteration order. It matters for more than tidiness:
// foldCoverage short-circuits on a single reading, and which document survives
// dedup decides which path is named in a warning.
func sortedKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// coverageSetWarnings reports what the harvest did, in the evidence, for every
// outcome that is not "every matched document was read".
//
// The count is stated even on the clean path. cicd cannot know how many reports
// a consumer's own command should have written — that is the whole nature of a
// BYO leg — so it cannot tell a complete harvest from a partial one, and the
// only honest thing it can do is say how many it merged and let a reviewer who
// knows the repository judge it. A figure with no count beside it is a claim
// about a number of projects nobody stated.
//
// It does not name the leg. The leg label has exactly one owner — legPrefix, in
// the caller — because two owners is how the evidence came to read "test-leg
// dotnet: test-leg dotnet: coverage pattern ...". Everything returned from a leg
// is labelled by the caller; only a message the caller appends directly, outside
// that path, labels itself.
//
// No backticks: notify renders every warnings[] entry as a markdown code span.
func coverageSetWarnings(pattern string, set coverageSet) []string {
	if set.Matched == 0 {
		return []string{fmt.Sprintf(
			"coverage pattern %s matched no file, so this leg contributed no "+
				"coverage figure — the command may not have written a report, or it wrote "+
				"one somewhere the pattern does not reach",
			pattern)}
	}
	var out []string
	out = append(out, fmt.Sprintf(
		"coverage pattern %s matched %d file(s), merged %d document(s)%s",
		pattern, set.Matched, set.Parsed, duplicateNote(set.Duplicates)))
	if len(set.Unparsed) > 0 {
		// Never silent. A pattern matching four reports where three are
		// unreadable yields a figure measured over one of them, and a figure
		// measured over less than it appears to be is the inflation direction a
		// ratchet cannot catch.
		out = append(out, fmt.Sprintf(
			"%d matched file(s) are in no recognized coverage format (v8 "+
				"json-summary, go coverprofile, pytest-cov JSON, cobertura XML) or report no "+
				"coverable lines, so they contributed nothing to this leg's figure: %s",
			len(set.Unparsed), strings.Join(set.Unparsed, ", ")))
	}
	return out
}

// duplicateNote states the dedup only when it fired, because a note that
// appears on every run is a note a reader stops seeing.
//
// It describes what the key compares and nothing more: the document text with
// any timestamp attribute removed. Two narrower phrasings were both wrong, in
// opposite directions, and both shipped.
//
// "byte-identical" was narrower than the rule is run — coverageIdentity does not
// key on bytes, so a reader chasing the note would look for a byte difference
// that need not exist. Replacing it with "reporting the same measurement" then
// overshot the other way: the drop happens before sniffCoverageReport, so the
// clause claims something about parsed content on a path where nothing has been
// parsed yet. A failed MTP harvest reported duplicate documents as "reporting
// the same measurement" even though none yielded a parsed reading — asserting
// a measurement beside a count stating that none was obtained. The duplicate
// count alone cannot support that claim about the document set.
//
// Guarding the clause behind Parsed > 0 is not the fix. It would silence the
// falsehood on the harvest that produced it and leave it wherever a parse fails
// for some other reason, and it would drop the count on exactly the path a
// reviewer most needs it. The dedup is a textual test with a textual answer, so
// the note states the textual fact, which holds on every path.
func duplicateNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" and dropped %d duplicate document(s), identical apart"+
		" from any timestamp attribute", n)
}

// coverageSetErrors reports the one harvest outcome that is a failed
// measurement rather than an absent one: the pattern found documents and not a
// single one of them yielded a reading.
//
// It has to be an error, not a warning, because the alternative is fail-open and
// was measured as such. A leg whose every document was unreadable produces no
// reading, so mergeLegCoverage sees nothing, haveCoverage is false, and the
// ratchet records skipped:no-coverage-output — a verdict that is fail-open by
// design (ADR-003) and correct for the case it was written for, a consumer who
// configured no coverage at all. Reused here it says "there was nothing to
// measure" about a run where documents existed but cicd could not parse any
// of them, and the envelope comes back passed=true. This was observed on an
// MTP harvest: no measurement, a green envelope and the ratchet silently off.
// Coverage is the one figure here that is wrong in the direction a ratchet
// cannot catch, so a ratchet that is not running must not be reported by its
// absence.
//
// Deliberately narrow. Matched==0 stays a warning: that is a command which wrote
// no report, which a leg may legitimately do, and it is not cicd failing to read
// anything. This condition is unambiguous — the documents are there, they were
// read off the filesystem, and every parser refused them.
//
// Unlabelled and backtick-free, for the reasons on coverageSetWarnings.
func coverageSetErrors(pattern string, set coverageSet) []string {
	if set.Matched == 0 || set.Parsed > 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"coverage pattern %s matched %d file(s) and none of them yielded a measurement, "+
			"so this leg measured no coverage and the ratchet had nothing to compare — a "+
			"pattern that finds documents cicd cannot read is a failed measurement, not "+
			"an absent one",
		pattern, set.Matched)}
}

// coverageFindArgs builds the search argv. The pattern reaches find as an argv
// element, never as text inside a script body — the rule the ADO templates are
// held to, applied to cicd's own generated shell. A consumer-supplied pattern
// spliced into `sh -c` would be a shell injection with a coverage report's name
// as its vector.
//
// -print0 rather than -print: a newline in a filename is pathological, and
// splitting on it would silently split one path into two unreadable ones.
//
// Not depth-limited, matching cicd's own .NET harvest: the reports of a pooled
// MTP run sit at the top of the results directory, and a per-project run writes
// them into each project's build tree. A depth limit would be right for one
// layout and quietly wrong for the other, which is the shape of bug this file
// exists to remove. The duplicates recursion picks up are counted and dropped
// by buildCoverageSet.
func coverageFindArgs(dir, name string) []string {
	return []string{"find", dir, "-name", name, "-type", "f", "-print0"}
}

// splitFindOutput turns find -print0 output into paths.
func splitFindOutput(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, "\x00") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
