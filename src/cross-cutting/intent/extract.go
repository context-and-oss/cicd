package main

import "strings"

// extractText returns the prose content of an artifact, stripping structural
// noise so that semantic rules operate on meaningful text regardless of format.
func extractText(content, path string) string {
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return extractYAMLText(content)
	}
	if strings.HasSuffix(path, ".md") {
		return extractMarkdownText(content)
	}
	return content
}

// extractYAMLText pulls string values out of YAML, ignoring keys and
// structural tokens. Handles scalars (key: value), list items (- item) and
// block scalars (key: > / key: | / - >), whose bodies are prose and are kept
// verbatim.
//
// The block-scalar body is tracked by indentation rather than sniffed line by
// line, and that is the whole point of this function. It previously decided per
// line, with two rules that both silently destroyed prose:
//
//   - a line containing a colon but no ": " was dropped **entirely**, because
//     the only continuation branch was guarded by !strings.Contains(":");
//   - a line containing ": " anywhere was truncated to whatever followed the
//     first one, because the key/value branch matched prose.
//
// Every rule in rules.go then graded what survived. Measured on a capsule:
// the single line reading
// "it lives in dotnetreport.go which is untagged. test.go is //go:build
// !unit_test" was discarded over the colon in //go:build, so the artifact named
// the two files it changed, the extractor deleted both, and
// refs-infer-coupling reported that the artifact "may describe a different
// change" — about an artifact describing exactly that change. 1026 of 7875
// bytes never reached a rule.
//
// It fails in both directions, which is why the fix is the extractor and not a
// rule. A false failure here is the see-the-file-the-artifact-named spec one
// layer earlier, and its cheapest remedy is to delete the mention of an
// *unchanged* file — a rejected option, a call site left alone — which that
// spec names as the most valuable sentence in a capsule. The other direction is
// a false pass: checkNoTBD and checkNoWeaselWords never saw a dropped line
// either, so "TBD: decide later" or a weasel word sitting next to a colon was
// graded as absent. A gate that reads part of a document and reports on all of
// it is this repository's founding doctrine applied to prose.
//
// Colons in prose are not exotic and not avoidable here: //go:build, a URL, a
// Go map literal, "Measured: 16 documents", every ERE with [[:space:]]. The
// previous behaviour effectively required a capsule to be written around the
// extractor.
func extractYAMLText(content string) string {
	var sb strings.Builder
	// Indentation of the key that opened the current block scalar, or -1 when no
	// block is open. A line indented deeper than that key belongs to the body,
	// which is YAML's own rule for where a block scalar ends.
	blockIndent := -1
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		// A blank line inside a block scalar is a paragraph break, not the end of
		// the block — YAML only closes it on a line indented no deeper than the
		// key. Treating a blank line as the end would drop every paragraph after
		// the first, which is most of a capsule.
		if blockIndent >= 0 && (trimmed == "" || indent > blockIndent) {
			if trimmed != "" {
				sb.WriteString(trimmed)
				sb.WriteByte(' ')
			}
			continue
		}
		blockIndent = -1
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, ": "); idx >= 0 {
			val := strings.TrimSpace(trimmed[idx+2:])
			if isBlockScalarHeader(val) {
				blockIndent = indent
				continue
			}
			if val != "" {
				sb.WriteString(val)
				sb.WriteByte(' ')
			}
			continue
		}
		// A key with a block scalar and nothing else on the line: "intent: >".
		// Index(": ") misses it because there is no space after the colon.
		if opensBlockScalar(trimmed) {
			blockIndent = indent
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(trimmed[2:])
			// A list item that is itself a block scalar: "- >".
			if isBlockScalarHeader(item) {
				blockIndent = indent
				continue
			}
			sb.WriteString(item)
			sb.WriteByte(' ')
			continue
		}
		// Anything else with no colon is prose outside a block scalar (a plain
		// multi-line flow scalar). Kept as before; a line with a colon at this
		// point is a structural key such as "impact:" and contributes nothing.
		if !strings.Contains(trimmed, ":") {
			sb.WriteString(trimmed)
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}

// isBlockScalarHeader reports whether a value opens a block scalar rather than
// being prose. It accepts the folded and literal indicators with YAML's chomping
// and explicit-indentation modifiers (>, |, >-, |-, >+, |+, >2, |-2), and a
// trailing comment, because "intent: > # why" is legal and its body is still
// prose.
//
// It must stay exact. Matching a leading > loosely would treat a prose line
// beginning with a quotation marker as a block header and swallow the paragraph
// under it, which is the same class of silent loss this file exists to remove.
func isBlockScalarHeader(v string) bool {
	if v == "" {
		return false
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" || (v[0] != '>' && v[0] != '|') {
		return false
	}
	for _, c := range v[1:] {
		if c != '-' && c != '+' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// opensBlockScalar reports whether a line is a key whose value is a block
// scalar indicator with nothing between them, e.g. "intent:>" — a shape
// Index(": ") cannot see because no space separates the colon from the
// indicator.
//
// The text before the colon must be a single token. A line of prose that
// happens to end in a colon followed by an indicator-like character is not a
// key, and treating it as one would open a block that swallows the paragraph
// beneath it.
func opensBlockScalar(trimmed string) bool {
	idx := strings.Index(trimmed, ":")
	if idx < 0 {
		return false
	}
	key := trimmed[:idx]
	if key == "" || strings.ContainsAny(key, " \t") {
		return false
	}
	return isBlockScalarHeader(strings.TrimSpace(trimmed[idx+1:]))
}

// extractMarkdownText returns body prose plus frontmatter values.
// Frontmatter keys are excluded; only their values contribute to analysis.
func extractMarkdownText(content string) string {
	if !strings.HasPrefix(content, "---") {
		return content
	}
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	return extractYAMLText(parts[1]) + " " + parts[2]
}

// changeScope reads the change set out of a supplied diff: the paths that
// still exist after it, which is what the gate scopes its artifacts to.
//
// known is whether the diff states a change set at all. An empty diff does
// not, and the gate falls back to auditing every artifact. A git diff does,
// even when it names no surviving file: a change that only deletes files is
// still a change the presence rule judges. Before this, such a diff produced
// no paths and was read exactly like an empty one, so the gate audited the
// tree's existing artifacts and passed a change that carried none.
//
// A diff that cannot be read is an error, never an empty change set; see
// parseDiffPaths (diffpaths.go, shared with src/risk) for what that means.
func changeScope(diff string) (changed map[string]bool, known bool, err error) {
	paths, known, err := parseDiffPaths(diff)
	if err != nil || !known {
		return nil, known, err
	}
	return paths.surviving, true, nil
}

// extractDiffPaths returns every path the diff touched, deleted files and
// rename sources included, because the coupling rule asks "is this artifact
// about this change?" and a deleted file is part of the change. A diff that
// cannot be read touches nothing here; Check has already refused it through
// changeScope before any rule runs.
func extractDiffPaths(diff string) []string {
	paths, _, err := parseDiffPaths(diff)
	if err != nil {
		return nil
	}
	return paths.touched
}
