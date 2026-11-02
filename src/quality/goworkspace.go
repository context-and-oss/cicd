package main

import "strings"

// goTestArgs picks the package selector for `go test`.
//
// Single-module layout (no go.work at root): "./..." — the default.
//
// Workspace layout (go.work present): expand to "./<member>/..." for every
// `use` directive. `./...` from a workspace root that has no go.mod of its
// own does NOT auto-expand to workspace member packages — Go errors with
// "directory prefix . does not contain modules listed in go.work". Naming
// each member explicitly is the documented workaround.
//
// goWorkContents is the raw contents of go.work, or "" if the file is
// absent. An empty / unparseable workspace falls back to "./...".
//
// Every member is single-quoted, because the result is spliced into a
// `sh -c` command line (test.go) and a `use` directive is consumer-authored
// text: a member named `a b`, `x;rm -rf /` or `$(id)` used to be parsed by the
// shell, not by `go test`. The default `./...` is cicd's own literal and
// stays bare.
func goTestArgs(goWorkContents string) string {
	if strings.TrimSpace(goWorkContents) == "" {
		return "./..."
	}
	members := parseGoWorkUse(goWorkContents)
	if len(members) == 0 {
		return "./..."
	}
	parts := make([]string, 0, len(members))
	for _, m := range members {
		m = strings.TrimPrefix(m, "./")
		m = strings.TrimSuffix(m, "/")
		if m == "" || m == "." {
			parts = append(parts, shellQuote("./..."))
			continue
		}
		parts = append(parts, shellQuote("./"+m+"/..."))
	}
	return strings.Join(parts, " ")
}

// shellQuote wraps s in single quotes for a POSIX shell, where nothing inside
// them is interpreted. An embedded single quote ends the quoted span, is
// written as an escaped literal, and reopens it: `it's` becomes `'it'\”s'`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// parseGoWorkUse extracts module paths from `use` directives in a go.work
// file. Handles both single-line `use ./mod` and block `use ( ... )` forms,
// strips inline `// comments`, and ignores blank lines.
func parseGoWorkUse(contents string) []string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			out = append(out, trimQuotes(line))
			continue
		}
		if line == "use (" || strings.HasPrefix(line, "use (") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(line, "use ") {
			out = append(out, trimQuotes(strings.TrimSpace(strings.TrimPrefix(line, "use "))))
		}
	}
	return out
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
