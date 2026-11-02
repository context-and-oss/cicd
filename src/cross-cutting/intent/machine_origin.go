package main

import (
	"fmt"
	"regexp"
	"strings"
)

// workflowPathPattern matches the only paths the approved machine-origin mode
// may touch: top-level files directly under .github/workflows/.
var workflowPathPattern = regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`)

// usesLinePattern matches a GitHub Actions step `uses:` reference line,
// capturing everything up to (but not including) the `@<ref>` pin and an
// optional trailing version comment. Two uses: lines are the "same action,
// different pin" only when this captured prefix is identical.
var usesLinePattern = regexp.MustCompile(`^(\s*-?\s*uses:\s*[^@\s]+)@(\S+)(\s*#.*)?\s*$`)

// MachineOriginDecision is the outcome of validating a diff against the
// approved Dependabot GitHub Actions pin-bump shape
// (specs/harden-workflow-supply-chain.md). Accepted means the diff is
// exclusively `uses:` SHA and adjacent version-comment changes across .github/workflows/*.yml|yaml
// files — the only shape allowed to satisfy intent presence without a
// human-authored artifact.
type MachineOriginDecision struct {
	Accepted bool
	Reason   string
}

// validateMachineOriginDiff independently re-validates a diff before it may
// substitute for a human intent artifact. It never trusts the caller's actor
// assertion alone: every changed path must be an existing workflow file, no
// file may be added/deleted/renamed, and every added/removed payload line
// must be a `uses:` line whose only semantic change is the pin (commit SHA)
// and/or its adjacent version comment. Any mixed, structural, non-workflow,
// or unparsable diff is rejected so the caller falls back to normal intent
// presence behavior.
func validateMachineOriginDiff(diff string) MachineOriginDecision {
	files := splitDiffFiles(diff)
	if len(files) == 0 {
		return MachineOriginDecision{Reason: "diff contains no parseable file sections"}
	}
	for _, f := range files {
		if reason, ok := f.validateActionsPinOnly(); !ok {
			return MachineOriginDecision{Reason: reason}
		}
	}
	return MachineOriginDecision{
		Accepted: true,
		Reason:   fmt.Sprintf("%d workflow file(s) contain only actions uses: sha/version-comment changes", len(files)),
	}
}

// diffFileSection is one `diff --git a/X b/Y` section of a unified diff.
type diffFileSection struct {
	oldPath, newPath       string
	isRename, isAdd, isDel bool
	removed, added         []string
}

// splitDiffFiles parses a unified diff into per-file sections. It only
// recognises headers produced by `git diff` (`diff --git`, `--- a/`, `+++
// b/`, `rename from/to`, `new/deleted file mode`); anything else it can't
// make sense of is left for validateActionsPinOnly to reject via its path/
// line checks rather than causing a parse failure here.
func splitDiffFiles(diff string) []diffFileSection {
	var sections []diffFileSection
	var cur *diffFileSection
	flush := func() {
		if cur != nil {
			sections = append(sections, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			cur = &diffFileSection{}
			continue
		case cur == nil:
			continue
		}
		switch {
		case strings.HasPrefix(line, "rename from "), strings.HasPrefix(line, "rename to "):
			cur.isRename = true
		case strings.HasPrefix(line, "new file mode"):
			cur.isAdd = true
		case strings.HasPrefix(line, "deleted file mode"):
			cur.isDel = true
		case strings.HasPrefix(line, "--- "):
			cur.oldPath = strings.TrimSpace(strings.TrimPrefix(line, "--- "))
		case strings.HasPrefix(line, "+++ "):
			cur.newPath = strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "@@"):
			// Hunk header — carries no payload of its own.
		case strings.HasPrefix(line, "+"):
			cur.added = append(cur.added, strings.TrimPrefix(line, "+"))
		case strings.HasPrefix(line, "-"):
			cur.removed = append(cur.removed, strings.TrimPrefix(line, "-"))
		}
	}
	flush()
	return sections
}

// validateActionsPinOnly reports why (if at all) this file section falls
// outside the approved actions-pin-bump shape.
func (f diffFileSection) validateActionsPinOnly() (reason string, ok bool) {
	if f.isRename {
		return "file was renamed", false
	}
	if f.isAdd || f.oldPath == "/dev/null" {
		return "file was added", false
	}
	if f.isDel || f.newPath == "/dev/null" {
		return "file was deleted", false
	}
	oldRel := strings.TrimPrefix(f.oldPath, "a/")
	newRel := strings.TrimPrefix(f.newPath, "b/")
	if oldRel == "" || newRel == "" {
		return "diff section has no recognisable file path", false
	}
	if oldRel != newRel {
		return fmt.Sprintf("%s: path changed", newRel), false
	}
	if !workflowPathPattern.MatchString(newRel) {
		return fmt.Sprintf("%s: not a .github/workflows/*.yml|yaml file", newRel), false
	}
	if len(f.removed) != len(f.added) {
		return fmt.Sprintf("%s: structural change (unequal added/removed line counts)", newRel), false
	}
	for i := range f.removed {
		oldPrefix, oldOK := usesActionPrefix(f.removed[i])
		newPrefix, newOK := usesActionPrefix(f.added[i])
		if !oldOK || !newOK {
			return fmt.Sprintf("%s: a changed line is not a uses: reference", newRel), false
		}
		if oldPrefix != newPrefix {
			return fmt.Sprintf("%s: action reference changed, not just its pin", newRel), false
		}
	}
	return "", true
}

// usesActionPrefix returns the `uses:` line with its pin (and any trailing
// comment) stripped off, so two lines compare equal exactly when the only
// difference between them is the SHA pin and/or its version comment.
func usesActionPrefix(line string) (string, bool) {
	m := usesLinePattern.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}
