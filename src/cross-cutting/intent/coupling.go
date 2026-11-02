package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// runArtifactRules is the production boundary: all prose rules see the entire
// current artifact. Only coupling distinguishes a new rationale from an edit
// to an existing one. See specs/couple-the-edit-not-the-artifacts-history.md.
func runArtifactRules(path, content, diff string) ([]IntentFinding, bool, error) {
	text := extractText(content, path)
	findings := runRules(path, text, "")
	if strings.TrimSpace(diff) == "" {
		return findings, false, nil
	}
	paths, _, err := parseDiffPaths(diff)
	if err != nil {
		return nil, false, err
	}
	var section *diffFilePaths
	for i := range paths.files {
		if paths.files[i].newPath == path {
			if section != nil {
				return nil, false, fmt.Errorf("%s: duplicate diff sections", path)
			}
			section = &paths.files[i]
		}
	}
	if section == nil {
		return nil, false, fmt.Errorf("%s: artifact is not in the supplied diff", path)
	}
	// New/copied/renamed artifacts must stand on their own. A header-only or
	// binary patch likewise provides no prior text: retain the full check.
	narrowed := false
	if section.oldPath == section.newPath && !section.copied {
		before, textual, err := previousArtifact(content, section.lines)
		if err != nil {
			return nil, false, fmt.Errorf("%s: cannot read artifact edit: %w", path, err)
		}
		if textual {
			text = introducedReferences(extractText(before, path), text, paths.touched)
			narrowed = true
		}
	}
	findings = append(findings, checkRefsCoupling(path, text, diff)...)
	return findings, narrowed, nil
}

func couplingScopeWarning(modified int) string {
	return fmt.Sprintf("intent-gate: refs-infer-coupling judged newly introduced file references in %d modified artifact(s); other prose rules judged whole artifacts", modified)
}

// introducedReferences keeps only newly introduced path tokens and literal
// changed names. A replacement line may repeat an old reference, so comparing
// + lines alone would still misjudge numerical redactions and reflow. Literal
// witnesses are differenced too: a historical Makefile mention must not clear
// a newly added unrelated.go. Extraction happens on both complete documents,
// preserving YAML block-scalar and Markdown frontmatter context.
func introducedReferences(before, after string, changed []string) string {
	old, now := map[string]bool{}, map[string]bool{}
	for _, tok := range pathToken.FindAllString(before, -1) {
		old[tok] = true
	}
	for _, tok := range pathToken.FindAllString(after, -1) {
		now[tok] = true
	}
	var removed []string
	for _, tok := range uniqueStrings(pathToken.FindAllString(before, -1)) {
		if !now[tok] {
			removed = append(removed, tok)
		}
	}
	var refs []string
	for _, tok := range uniqueStrings(pathToken.FindAllString(after, -1)) {
		if old[tok] {
			continue
		}
		if i := renamedFrom(tok, removed); i >= 0 {
			removed = append(removed[:i], removed[i+1:]...)
			continue
		}
		refs = append(refs, tok)
	}
	for _, p := range changed {
		candidates := []string{p}
		if i := strings.LastIndex(p, "/"); i >= 0 {
			candidates = append(candidates, p[i+1:])
		}
		for _, name := range candidates {
			if !strings.Contains(name, "/") && len(name) < minLiteralBasename {
				continue
			}
			if mentionsLiterally(after, name) && !mentionsLiterally(before, name) {
				refs = append(refs, name)
			}
		}
	}
	return strings.Join(uniqueStrings(refs), "\n")
}

// renamedFrom returns the index of a removed reference that tok renames, or
// -1. A rename keeps the segment count and the file it names (the last
// segment) and replaces exactly one other segment: an org slug or directory
// in a URL or path. It is still the reference the rationale made, so an
// in-place scrub of it introduces nothing. Swapping the named file, or more
// than one segment, is a new reference. Each removed reference explains at
// most one introduced token, so one removal cannot launder several additions.
func renamedFrom(tok string, removed []string) int {
	segs := strings.Split(tok, "/")
	if len(segs) < 2 {
		return -1
	}
	for i, r := range removed {
		old := strings.Split(r, "/")
		if len(old) != len(segs) || old[len(old)-1] != segs[len(segs)-1] {
			continue
		}
		diff := 0
		for j := range segs {
			if segs[j] != old[j] {
				diff++
			}
		}
		if diff == 1 {
			return i
		}
	}
	return -1
}

var artifactHunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$`)

type artifactHunk struct {
	oldStart, newStart int // zero-based insertion points (including zero-count ranges)
	oldLines, newLines []string
}

// previousArtifact reverses a textual patch against the actual current file.
// Counts, positions, context and added bytes must agree before coupling may
// narrow. A failed read never means "no new references". File paths have
// already been resolved by the shared parseDiffPaths; this reads hunks only.
func previousArtifact(content string, patch []string) (string, bool, error) {
	var hunks []artifactHunk
	for i := 0; i < len(patch); i++ {
		line := patch[i]
		if !strings.HasPrefix(line, "@@") {
			if len(hunks) > 0 && (i != len(patch)-1 || line != "") {
				return "", false, fmt.Errorf("unexpected line after a hunk")
			}
			continue
		}
		m := artifactHunkHeader.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if m == nil {
			return "", false, fmt.Errorf("invalid hunk header")
		}
		oldStart, oldCount, err := artifactRange(m[1], m[2])
		if err != nil {
			return "", false, err
		}
		newStart, newCount, err := artifactRange(m[3], m[4])
		if err != nil {
			return "", false, err
		}
		h := artifactHunk{oldStart: oldStart, newStart: newStart}
		lastKind := byte(0)
		for i+1 < len(patch) && !strings.HasPrefix(patch[i+1], "@@") {
			i++
			raw := patch[i]
			if i == len(patch)-1 && raw == "" {
				break
			}
			if raw == `\ No newline at end of file` {
				if lastKind == 0 {
					return "", false, fmt.Errorf("misplaced no-newline marker")
				}
				if lastKind != '+' {
					h.oldLines[len(h.oldLines)-1] = strings.TrimSuffix(h.oldLines[len(h.oldLines)-1], "\n")
				}
				if lastKind != '-' {
					h.newLines[len(h.newLines)-1] = strings.TrimSuffix(h.newLines[len(h.newLines)-1], "\n")
				}
				lastKind = 0
				continue
			}
			if raw == "" || (raw[0] != ' ' && raw[0] != '+' && raw[0] != '-') {
				return "", false, fmt.Errorf("invalid hunk payload")
			}
			lastKind = raw[0]
			if lastKind != '+' {
				h.oldLines = append(h.oldLines, raw[1:]+"\n")
			}
			if lastKind != '-' {
				h.newLines = append(h.newLines, raw[1:]+"\n")
			}
			if len(h.oldLines) > oldCount || len(h.newLines) > newCount {
				return "", false, fmt.Errorf("hunk payload exceeds declared counts")
			}
		}
		if len(h.oldLines) != oldCount || len(h.newLines) != newCount {
			return "", false, fmt.Errorf("truncated hunk payload")
		}
		if strings.Join(h.oldLines, "") == strings.Join(h.newLines, "") {
			return "", false, fmt.Errorf("hunk states no textual change")
		}
		hunks = append(hunks, h)
	}
	if len(hunks) == 0 {
		return "", false, nil
	}
	current := documentLines(content)
	var previous []string
	cursor := 0
	for _, h := range hunks {
		if h.newStart < cursor || h.newStart > len(current) || len(h.newLines) > len(current)-h.newStart {
			return "", false, fmt.Errorf("hunk range is outside or overlaps the current artifact")
		}
		gap := h.newStart - cursor
		if h.oldStart != len(previous)+gap {
			return "", false, fmt.Errorf("old and new hunk positions disagree")
		}
		previous = append(previous, current[cursor:h.newStart]...)
		for j, line := range h.newLines {
			if line != current[h.newStart+j] {
				return "", false, fmt.Errorf("hunk context or additions do not match the current artifact")
			}
		}
		previous = append(previous, h.oldLines...)
		cursor = h.newStart + len(h.newLines)
	}
	previous = append(previous, current[cursor:]...)
	for i, line := range previous {
		if i < len(previous)-1 && !strings.HasSuffix(line, "\n") {
			return "", false, fmt.Errorf("old artifact has content after a no-newline marker")
		}
	}
	return strings.Join(previous, ""), true, nil
}

func artifactRange(startText, countText string) (int, int, error) {
	start, err := strconv.Atoi(startText)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hunk range")
	}
	count := 1
	if countText != "" {
		count, err = strconv.Atoi(countText)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid hunk count")
		}
	}
	if count > 0 {
		if start == 0 {
			return 0, 0, fmt.Errorf("non-empty hunk range starts at zero")
		}
		start--
	}
	return start, count, nil
}

func documentLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
