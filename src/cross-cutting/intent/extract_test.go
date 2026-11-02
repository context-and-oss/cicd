package main

import (
	"strings"
	"testing"
)

// A synthetic capsule exercises folded and literal block scalars with colons
// in their prose: //go:build and a hypothetical document count. The unchanged
// props path is invented too.
const capsuleShape = `capsule: CAPS-024
title: name the dotnet denominator
decisions:
  - id: d01
    decision: >
      The denominator comes from enumeration, not from the harvest. It lives in
      dotnetreport.go which is untagged. test.go is //go:build !unit_test, so
      nothing in it is reachable from the only suite that runs without a Dagger
      session.

      A second paragraph, after a blank line, which is a paragraph break and not
      the end of the block.
  - id: d02
    decision: |
      Illustration: 10 documents, 5 distinct. The fixture's checks/Directory.Build.props
      is deliberately named here and is not part of this change.
impact: low
`

// TestExtractYAMLTextKeepsProseHoldingColons pins the defect this extractor
// shipped: a block-scalar body line containing a colon was destroyed, and every
// rule in rules.go then graded what survived.
//
// Two ways it went wrong, both silent. A line containing a colon but no ": " was
// dropped entirely, because the only continuation branch was guarded by
// !strings.Contains(":"). A line containing ": " anywhere was truncated to
// whatever followed the first one, because the key/value branch matched prose.
//
// Losing the line naming dotnetreport.go and test.go at the colon in
// //go:build can make refs-infer-coupling reject prose about those very files.
func TestExtractYAMLTextKeepsProseHoldingColons(t *testing.T) {
	got := extractYAMLText(capsuleShape)

	// The two filenames the artifact named, which the extractor deleted.
	for _, want := range []string{"dotnetreport.go", "test.go", "//go:build !unit_test"} {
		if !strings.Contains(got, want) {
			t.Errorf("extraction dropped %q, which the artifact named:\n%s", want, got)
		}
	}
	// Truncation at the first ": " would lose the prefix that marks these
	// invented counts as an illustration rather than a measurement.
	if !strings.Contains(got, "Illustration: 10 documents") {
		t.Errorf("prose was truncated at a colon: %s", got)
	}
	// The path a capsule cites as deliberately unchanged. Losing it is the
	// see-the-file-the-artifact-named failure, whose cheapest remedy is deleting
	// exactly this kind of sentence.
	if !strings.Contains(got, "checks/Directory.Build.props") {
		t.Errorf("extraction dropped a deliberately-cited unchanged path: %s", got)
	}
	// A blank line inside a block scalar is a paragraph break. Closing the block
	// there would drop every paragraph after the first, which is most of a
	// capsule.
	if !strings.Contains(got, "A second paragraph, after a blank line") {
		t.Errorf("a paragraph after a blank line was dropped: %s", got)
	}
}

// TestExtractYAMLTextDropsStructureNotProse holds the other side. The fix can
// only add text to what rules see, so it must not start feeding them YAML
// structure — a min-length credited for structural tokens is a different lie.
func TestExtractYAMLTextDropsStructureNotProse(t *testing.T) {
	got := extractYAMLText(capsuleShape)

	// The folding indicator is not prose. It used to be emitted as a bare ">"
	// token, because Index(": ") on "decision: >" yielded ">" as the value.
	if strings.Contains(got, " > ") || strings.Contains(got, " | ") {
		t.Errorf("a block-scalar indicator leaked into the graded text: %s", got)
	}
	// Structural keys contribute nothing and must not inflate the text.
	for _, key := range []string{"decisions:", "impact:", "capsule:"} {
		if strings.Contains(got, key) {
			t.Errorf("structural key %q leaked into the graded text: %s", key, got)
		}
	}
	// Values still come through.
	for _, want := range []string{"CAPS-024", "name the dotnet denominator", "low"} {
		if !strings.Contains(got, want) {
			t.Errorf("extraction dropped the value %q: %s", want, got)
		}
	}
}

// TestExtractYAMLTextClosesABlockOnDedent proves the block ends where YAML says
// it ends. A block that never closes would swallow every later key's value, and
// the loss would look exactly like the loss this change repairs.
func TestExtractYAMLTextClosesABlockOnDedent(t *testing.T) {
	got := extractYAMLText(`a:
  body: >
    inside the block
  after: outside the block
b: last value
`)
	for _, want := range []string{"inside the block", "outside the block", "last value"} {
		if !strings.Contains(got, want) {
			t.Errorf("dropped %q: %s", want, got)
		}
	}
	// "after: outside the block" is a key/value line, so only its value survives.
	if strings.Contains(got, "after:") {
		t.Errorf("a key after a block scalar leaked: %s", got)
	}
}

// TestIsBlockScalarHeader keeps the header test exact. Matching a leading ">"
// loosely would treat a prose line beginning with a quotation marker as a block
// header and swallow the paragraph under it — the same silent loss, arriving
// through the fix.
func TestIsBlockScalarHeader(t *testing.T) {
	for _, v := range []string{">", "|", ">-", "|-", ">+", "|+", ">2", "|-2", "> # why folded"} {
		if !isBlockScalarHeader(v) {
			t.Errorf("%q is a block scalar header", v)
		}
	}
	for _, v := range []string{
		"", " ",
		"> quoted prose that begins with a marker",
		"|| not an indicator",
		">>",
		"a value",
		"#comment",
	} {
		if isBlockScalarHeader(v) {
			t.Errorf("%q is not a block scalar header", v)
		}
	}
}

// TestOpensBlockScalar covers the "key:>" shape Index(": ") cannot see, and
// refuses to read a line of prose ending in a colon as a key.
func TestOpensBlockScalar(t *testing.T) {
	for _, line := range []string{"intent:>", "intent: >", "intent:|-", "intent: > # why"} {
		if !opensBlockScalar(line) {
			t.Errorf("%q opens a block scalar", line)
		}
	}
	for _, line := range []string{
		"no colon here",
		"and then this happened: >", // the key is prose, not a token
		"intent: a plain value",
		":>",
	} {
		if opensBlockScalar(line) {
			t.Errorf("%q does not open a block scalar", line)
		}
	}
}

// TestExtractYAMLTextIgnoresComments keeps a commented-out weasel word from
// being graded, in either direction.
func TestExtractYAMLTextIgnoresComments(t *testing.T) {
	got := extractYAMLText("# TBD: decide later\nkey: real value\n")
	if strings.Contains(got, "TBD") {
		t.Errorf("a comment was graded as prose: %s", got)
	}
	if !strings.Contains(got, "real value") {
		t.Errorf("the value was dropped: %s", got)
	}
}
