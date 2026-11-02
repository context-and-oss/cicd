package main

// Unit tests for codeSpan — the one helper every backtick in a rendered comment
// now goes through. Run with:
//
//	go test -tags unit_test -run CodeSpan ./...
//
// The assertion is not "the output looks safe". Each case decodes the emitted
// span with decodeCodeSpan below, which applies CommonMark §6.1's own rules, and
// requires the recovered content to equal the input byte for byte. That proves
// both halves at once: the content could not terminate the span, and the fix did
// not quietly edit the content to make it fit.

import (
	"strings"
	"testing"
)

// decodeCodeSpan reads a code span the way a CommonMark parser does and returns
// the content it yields. It reports ok=false when what it was given is not a
// single well-formed span — which is the interesting failure, because a string
// that closes its own span early decodes to the part before the break, not to
// the whole of itself.
//
// Rules implemented, in CommonMark's order:
//   - the opening and closing runs must be the same length,
//   - no run inside may be that long or longer, or the span ends there,
//   - one space is stripped from each end of the content, and only when it both
//     begins and ends with a space and is not all spaces.
func decodeCodeSpan(s string) (string, bool) {
	open := 0
	for open < len(s) && s[open] == '`' {
		open++
	}
	if open == 0 || open*2 >= len(s)+1 {
		return "", false
	}
	closeRun := 0
	for closeRun < len(s) && s[len(s)-1-closeRun] == '`' {
		closeRun++
	}
	if closeRun != open {
		return "", false
	}
	body := s[open : len(s)-closeRun]
	// A run inside the body as long as the fence would have closed the span
	// early, so the string is not one span.
	if longestBacktickRun(body) >= open {
		return "", false
	}
	if strings.TrimSpace(body) != "" &&
		strings.HasPrefix(body, " ") && strings.HasSuffix(body, " ") {
		body = body[1 : len(body)-1]
	}
	return body, true
}

// TestCodeSpanRoundTripsHostileContent is the whole point of the change: every
// string here used to break out of its span and have its tail parsed as markdown
// inside a comment carrying cicd's name.
func TestCodeSpanRoundTripsHostileContent(t *testing.T) {
	cases := map[string]string{
		"plain":                              "feature/x",
		"a refname with a backtick":          "feat/x`whoami`",
		"closes the span and injects a link": "main` [click me](https://example.invalid/) `",
		"a lone backtick":                    "`",
		"two backticks":                      "``",
		"a fenced block marker":              "```",
		"backticks either side":              "`x`",
		"already flanked by spaces":          " x ",
		"a run in the middle":                "a``b```c`d",
		"a path a scanner reported":          "src/`odd`/name.go:42",
		"an image digest":                    "mcr.microsoft.com/dotnet/sdk:10.0@sha256:abc",
		"pipes and backticks":                "a|b`c",
		"unicode either side":                "→`x`←",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := codeSpan(in)
			got, ok := decodeCodeSpan(out)
			if !ok {
				t.Fatalf("emitted %q, which is not a single code span — the content escaped it", out)
			}
			if got != in {
				t.Errorf("content was altered: rendered %q, decodes to %q, want %q", out, got, in)
			}
		})
	}
}

// TestCodeSpanPadsBothEndsOrNeither pins the rule that makes the round trip
// above possible. CommonMark strips one space from each end of a code span's
// content only when it begins *and* ends with a space, so a pad on one end
// survives into the output — and a path rendered with a leading space is a
// reviewer clicking a location that is not the location.
func TestCodeSpanPadsBothEndsOrNeither(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantPads bool
		why      string
	}{
		{"x", false, "nothing at either end needs keeping apart from the fence"},
		{"`x", true, "a leading backtick would fuse with the opening fence"},
		{"x`", true, "a trailing backtick would fuse with the closing fence"},
		{" x ", true, "flanking spaces would be eaten by the strip rule"},
		{" x", false, "one leading space is not stripped, so padding would add one"},
		{"x ", false, "one trailing space is not stripped, so padding would add one"},
		{"   ", false, "all-space content is exempt from the strip rule"},
	} {
		out := codeSpan(tc.in)
		fence := out[:longestBacktickRun(tc.in)+1]
		body := out[len(fence) : len(out)-len(fence)]
		padded := body == " "+tc.in+" "
		if padded != tc.wantPads {
			t.Errorf("codeSpan(%q) = %q: padded=%v, want %v — %s",
				tc.in, out, padded, tc.wantPads, tc.why)
		}
		// Whatever the pad decision, the content must survive it.
		if got, ok := decodeCodeSpan(out); !ok || got != tc.in {
			t.Errorf("codeSpan(%q) = %q decodes to (%q, %v), want (%q, true)",
				tc.in, out, got, ok, tc.in)
		}
	}
}

// TestCodeSpanFlattensLineTerminators — a newline inside a list item ends the
// item, so the tail of a multi-line warning became a second bullet rendered as
// raw markdown. The warning and error loops previously did no flattening at all.
func TestCodeSpanFlattensLineTerminators(t *testing.T) {
	for _, in := range []string{"a\nb", "a\r\nb", "a\rb"} {
		out := codeSpan(in)
		if strings.ContainsAny(out, "\n\r") {
			t.Errorf("codeSpan(%q) = %q still carries a line terminator", in, out)
		}
	}
	if got := codeSpan("a\r\nb"); got != "`a b`" {
		t.Errorf("CRLF must collapse to one space, got %q", got)
	}
}

// TestRenderedCommentContainsNoEscapableSpan walks the real rendered comment for
// an envelope whose every untrusted field is hostile, and requires that every
// code span in it decodes cleanly. This is the integration end: it fails if a
// new sink is added that formats backticks itself instead of calling codeSpan.
func TestRenderedCommentContainsNoEscapableSpan(t *testing.T) {
	e := baseEnv()
	e.Repo.Branch = "feat/x` [click](https://example.invalid/) `"
	e.Repo.CommitSHA = "abc`def"
	e.Warnings = []string{
		"artifact: NOT ATTESTED — ```three``` and a\nnewline",
		"   ",
		"",
	}
	e.Errors = []string{"semgrepRunError: exit 2 at `/src/a|b.go`"}
	e.Findings = []Finding{
		{Severity: SeverityHigh, Tool: "trufflehog", ArtifactPath: "src/`odd`/x.go", Line: 7,
			Message: "credential"},
	}
	out := buildMarkdown("precommit", "https://example.invalid/run", e)

	if strings.Contains(out, "[click](") && !strings.Contains(out, "`") {
		t.Fatal("the injected link is outside any span")
	}
	for _, span := range spansIn(out) {
		if _, ok := decodeCodeSpan(span); !ok {
			t.Errorf("comment contains a span that does not decode: %q", span)
		}
	}
	// The hostile branch name must be present in full — proof the fix did not
	// sanitise it away, which would hide which branch was actually built.
	if !strings.Contains(out, e.Repo.Branch) {
		t.Errorf("branch name was altered; comment:\n%s", out)
	}
	// The path must be byte-exact, including its line, or path:line is a
	// location a reviewer cannot follow.
	if !strings.Contains(out, "src/`odd`/x.go:7") {
		t.Errorf("finding location was altered; comment:\n%s", out)
	}
	// An empty or all-space warning must not render as a bare pair of
	// backticks, which is a literal, not a span.
	if strings.Contains(out, "- ``\n") {
		t.Errorf("an empty entry rendered as a literal backtick pair; comment:\n%s", out)
	}
}

// spansIn extracts the code spans from rendered markdown by scanning backtick
// runs pairwise. Deliberately simple: it is looking for spans this package
// emitted, all of which sit on one line.
func spansIn(md string) []string {
	var spans []string
	for _, line := range strings.Split(md, "\n") {
		i := 0
		for i < len(line) {
			if line[i] != '`' {
				i++
				continue
			}
			n := 0
			for i+n < len(line) && line[i+n] == '`' {
				n++
			}
			rest := line[i+n:]
			// Find a closing run of exactly n.
			j, closed := 0, -1
			for j < len(rest) {
				if rest[j] != '`' {
					j++
					continue
				}
				m := 0
				for j+m < len(rest) && rest[j+m] == '`' {
					m++
				}
				if m == n {
					closed = j
					break
				}
				j += m
			}
			if closed < 0 {
				i += n
				continue
			}
			spans = append(spans, line[i:i+n+closed+n])
			i += n + closed + n
		}
	}
	return spans
}

// TestBranchAndCommitCellsCannotBreakTheTable covers the third defect the same
// two lines carried. The Commit and Branch rows were formatted with a bare %s
// inside backticks and never passed through escapeCell at all — so an unescaped
// pipe in the value opened a new column and shifted every cell after it, and a
// newline ended the row.
//
// A pipe is legal in a git refname; measured with check-ref-format, which
// accepts feat/a|b and also a backtick, '<', '>' and '&', while rejecting '[',
// '*', '~', '^', ':', '?' and a space.
func TestBranchAndCommitCellsCannotBreakTheTable(t *testing.T) {
	e := baseEnv()
	e.Repo.Branch = "feat/a|b"
	e.Repo.CommitSHA = "abc\ndef"
	out := buildMarkdown("precommit", "", e)

	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| **Branch**") && !strings.HasPrefix(line, "| **Commit**") {
			continue
		}
		// A two-column row is "| a | b |": three unescaped pipes, no more.
		bare := 0
		for i := 0; i < len(line); i++ {
			if line[i] == '|' && (i == 0 || line[i-1] != '\\') {
				bare++
			}
		}
		if bare != 3 {
			t.Errorf("row has %d unescaped pipe(s), want 3 — the value opened a column: %q", bare, line)
		}
	}
	// The value is still readable, not deleted: the escape renders as a pipe.
	if !strings.Contains(out, `feat/a\|b`) {
		t.Errorf("the branch name must survive as an escaped pipe; comment:\n%s", out)
	}
	// A newline in the value must not produce a second line.
	if strings.Contains(out, "| **Commit** | `abc`") {
		t.Errorf("the commit value was cut at the newline; comment:\n%s", out)
	}
}
