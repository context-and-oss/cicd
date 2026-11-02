// Which files a git diff changes, read from its file headers.
//
// Byte-identical in src/cross-cutting/intent and src/risk, enforced by a
// synced_files group in scripts/repo-inventory.json. The two modules carried a
// parser each, wrong in different ways, and both errors were silent:
//
//   - risk read only `+++ b/` and `rename to`, so a --no-prefix diff produced
//     no paths, and an empty set fell back to "the change touched nothing":
//     a Dockerfile edit read as NOTHING IN SCOPE, SKIPPED, passed.
//   - intent refused a C-quoted `+++ "b/x y.md"` as a no-prefix diff, missed a
//     binary artifact (no +++ line at all), and read an added content line
//     `++ b/specs/old.md` as a header, so a PR could satisfy presence with an
//     artifact it never touched.
//
// Untagged so `go test -tags unit_test` reaches it in both modules.
package main

import (
	"fmt"
	"strconv"
	"strings"
)

// diffPaths is the change set a git diff states.
type diffPaths struct {
	// surviving holds every path that exists after the change: added,
	// modified, mode-only and binary changes, and the target of a rename or
	// copy. A deleted file is not in it, so it is never read as in scope.
	surviving map[string]bool
	// touched lists every path the change touched, in the order the diff
	// names them: surviving paths plus deleted files and rename sources. A
	// copy's source is not touched; the copy left it as it was.
	touched []string
	// files retains the resolved file sections for callers that also read
	// hunks. Paths are still interpreted in exactly one place.
	files []diffFilePaths
}

// diffFilePaths is a resolved file header plus its original patch lines.
// Empty oldPath/newPath means creation/deletion. copied distinguishes a copy
// from an in-place edit even when a caller supplies equal source/target paths.
type diffFilePaths struct {
	oldPath, newPath string
	copied           bool
	lines            []string
}

// diffBlock is one `diff --git` block's headers, resolved when the next block
// starts or the diff ends.
type diffBlock struct {
	header             string // the `diff --git` line, for error messages
	gitOld, gitNew     string // from the `diff --git` line; empty when it cannot be split
	oldPath, newPath   string // from `--- a/` and `+++ b/`
	renameFrom, moveTo string // from `rename from`, and `rename to` or `copy to`
	created, deleted   bool
	copied             bool
	lines              []string
}

// parseDiffPaths reads the change set out of a git diff's file headers.
//
// known is whether the diff states a change set at all. An empty diff does
// not. A git diff does, even when it names no surviving file: a change that
// only deletes files is still a change, and the caller judges it rather than
// treating it as an absent diff.
//
// Headers are read only between a `diff --git` line and the block's first
// hunk (`@@`) or binary payload, so a content line that happens to start with
// `+++ ` or `rename to ` is never read as one. Quoted paths (git's C-style
// quoting for spaces, tabs, quotes and non-ASCII bytes) are unquoted.
//
// A diff this function cannot read is an error, never an empty change set:
// text with no `diff --git` header is not a git diff, and headers without the
// a/ and b/ prefixes (--no-prefix, diff.noprefix, diff.mnemonicPrefix) name
// paths that would match nothing in the tree. Either used to read as a change
// that touched nothing.
func parseDiffPaths(diff string) (paths diffPaths, known bool, err error) {
	if strings.TrimSpace(diff) == "" {
		return diffPaths{}, false, nil
	}
	paths.surviving = map[string]bool{}
	seen := map[string]bool{}
	touch := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			paths.touched = append(paths.touched, p)
		}
	}

	var block *diffBlock
	finish := func() error {
		if block == nil {
			return nil
		}
		b := block
		block = nil
		oldPath := firstNonEmpty(b.oldPath, b.renameFrom, b.gitOld)
		newPath := firstNonEmpty(b.newPath, b.moveTo, b.gitNew)
		if b.created {
			oldPath = ""
		}
		if b.deleted {
			newPath = ""
		}
		if oldPath == "" && newPath == "" {
			return fmt.Errorf("the supplied diff's file header %q names no path that can be read, so its change set is unknown", b.header)
		}
		if newPath != "" {
			paths.surviving[newPath] = true
			touch(newPath)
		}
		if !b.copied {
			touch(oldPath)
		}
		paths.files = append(paths.files, diffFilePaths{
			oldPath: oldPath, newPath: newPath, copied: b.copied, lines: b.lines,
		})
		return nil
	}

	inHeader := false
	for _, raw := range strings.Split(diff, "\n") {
		if strings.HasPrefix(raw, "diff --git ") {
			if err := finish(); err != nil {
				return diffPaths{}, false, err
			}
			line := strings.TrimSuffix(raw, "\r")
			block = &diffBlock{header: line, lines: []string{raw}}
			inHeader = true
			gitOld, gitNew, split, err := splitGitHeader(strings.TrimPrefix(line, "diff --git "))
			if err != nil {
				return diffPaths{}, false, fmt.Errorf("the supplied diff's file header %q cannot be read: %v", line, err)
			}
			if split {
				// The b/ side first: its message is the one the smoke matrix
				// and every consumer report already quote.
				if block.gitNew, err = stripDiffPrefix(gitNew, "b/", line); err != nil {
					return diffPaths{}, false, err
				}
				if block.gitOld, err = stripDiffPrefix(gitOld, "a/", line); err != nil {
					return diffPaths{}, false, err
				}
			}
			continue
		}
		if block != nil {
			block.lines = append(block.lines, raw)
		}
		if !inHeader {
			continue
		}
		line := strings.TrimSuffix(raw, "\r")
		switch {
		case strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "Binary files "), line == "GIT binary patch":
			// What follows is content, not headers.
			inHeader = false
		case strings.HasPrefix(line, "new file mode "):
			block.created = true
		case strings.HasPrefix(line, "deleted file mode "):
			block.deleted = true
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			// Git appends a tab delimiter to these headers for paths with
			// whitespace, including C-quoted names. It is not part of the
			// path (a filename's own tab is escaped inside the quotes).
			p, err := unquoteDiffPath(strings.TrimSuffix(line[4:], "\t"))
			if err != nil {
				return diffPaths{}, false, fmt.Errorf("the supplied diff's file header %q cannot be read: %v", line, err)
			}
			old := strings.HasPrefix(line, "--- ")
			if p == "/dev/null" {
				if old {
					block.created = true
				} else {
					block.deleted = true
				}
				continue
			}
			prefix := "b/"
			if old {
				prefix = "a/"
			}
			if p, err = stripDiffPrefix(p, prefix, line); err != nil {
				return diffPaths{}, false, err
			}
			if old {
				block.oldPath = p
			} else {
				block.newPath = p
			}
		case strings.HasPrefix(line, "rename from "), strings.HasPrefix(line, "copy from "):
			// rename and copy lines carry no a/ or b/ prefix by design.
			p, err := unquoteDiffPath(line[strings.Index(line, " from ")+len(" from "):])
			if err != nil {
				return diffPaths{}, false, fmt.Errorf("the supplied diff's file header %q cannot be read: %v", line, err)
			}
			block.copied = strings.HasPrefix(line, "copy ")
			if !block.copied {
				block.renameFrom = p
			}
		case strings.HasPrefix(line, "rename to "), strings.HasPrefix(line, "copy to "):
			p, err := unquoteDiffPath(line[strings.Index(line, " to ")+len(" to "):])
			if err != nil {
				return diffPaths{}, false, fmt.Errorf("the supplied diff's file header %q cannot be read: %v", line, err)
			}
			block.moveTo = p
			block.copied = strings.HasPrefix(line, "copy ")
		}
	}
	if block == nil {
		return diffPaths{}, false, fmt.Errorf("the supplied diff carries no `diff --git` header, so it is not a git diff and its change set is unknown")
	}
	if err := finish(); err != nil {
		return diffPaths{}, false, err
	}
	return paths, true, nil
}

// splitGitHeader splits the two paths of a `diff --git` line.
//
// Either side may be C-quoted. Unquoted, the line is ambiguous whenever a path
// holds a space, and git resolves it the way this does: the two sides of an
// unrenamed file are the same path behind different prefixes, so the split is
// at the middle. A rename whose unquoted names hold spaces cannot be split, and
// needs no split: its `rename from` and `rename to` lines name both paths.
// split is false then, never a guess.
func splitGitHeader(rest string) (oldSide, newSide string, split bool, err error) {
	if strings.HasPrefix(rest, `"`) {
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return "", "", false, err
		}
		if oldSide, err = strconv.Unquote(q); err != nil {
			return "", "", false, err
		}
		if !strings.HasPrefix(rest[len(q):], " ") {
			return "", "", false, fmt.Errorf("no second path after %s", q)
		}
		newSide, err = unquoteDiffPath(rest[len(q)+1:])
		return oldSide, newSide, err == nil, err
	}
	if strings.HasSuffix(rest, `"`) {
		for i := strings.LastIndex(rest, ` "`); i >= 0; i = strings.LastIndex(rest[:i], ` "`) {
			if q, err := strconv.QuotedPrefix(rest[i+1:]); err == nil && len(q) == len(rest)-i-1 {
				newSide, _ = strconv.Unquote(q)
				return rest[:i], newSide, true, nil
			}
		}
		return "", "", false, fmt.Errorf("unterminated quoted path")
	}
	if strings.Count(rest, " ") == 1 {
		i := strings.Index(rest, " ")
		return rest[:i], rest[i+1:], true, nil
	}
	if mid := len(rest) / 2; len(rest)%2 == 1 && rest[mid] == ' ' && len(rest) > 5 &&
		rest[2:mid] == rest[mid+3:] {
		return rest[:mid], rest[mid+1:], true, nil
	}
	return "", "", false, nil
}

// unquoteDiffPath undoes git's C-style path quoting; an unquoted path is
// returned as it is. strconv.Unquote reads the same escapes git writes
// (octal bytes, \t, \n, \", \\).
func unquoteDiffPath(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return s, nil
	}
	return strconv.Unquote(s)
}

// stripDiffPrefix removes the a/ or b/ prefix a git diff puts on every header
// path, and refuses a path without it: without the prefix the path cannot be
// told apart from one that begins with a directory of that name, and before
// this was refused such a diff matched nothing in the tree.
func stripDiffPrefix(p, prefix, line string) (string, error) {
	if !strings.HasPrefix(p, prefix) {
		return "", fmt.Errorf("the supplied diff's file header %q carries no %s prefix (generated with --no-prefix, diff.noprefix or diff.mnemonicPrefix), so its change set cannot be matched to any path in the tree", line, prefix)
	}
	return strings.TrimPrefix(p, prefix), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
