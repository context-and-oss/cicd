#!/usr/bin/env bash
# ============================================================
# commit-diff.sh — resolve the incremental change range for the commit stage.
#
# Prints a git revision range to stdout for the caller to feed the diff-scoped
# risk/intent gates (`git diff <range>` → --diff). ADR-005 Option-B fallback:
#
#   1. normal push          before..after   (before is a real ancestor SHA)
#   2. first / force push    HEAD~1..HEAD    (before is all-zeros, or unresolvable)
#   3. no base resolves      <empty>         (no before AND no HEAD~1 — full-repo scan)
#
# NEVER emits `origin/main...HEAD`: on `main` after a merge that three-dot range
# is empty (merge-base == HEAD), which would silently unscope every gate.
#
# Usage:
#   scripts/commit-diff.sh <before-sha> <after-sha>
# In GitHub Actions:
#   scripts/commit-diff.sh "${{ github.event.before }}" "${{ github.event.after }}"
#
# An empty range means "no incremental base". Callers then pass no --diff at
# all, and the composite audits the whole tree because nothing was scoped. A
# range that resolves and then fails to diff is the caller's to fail: an empty
# diff file would read as a change touching nothing
# (specs/a-diff-the-workflow-could-not-compute-is-not-an-empty-diff.md).
# ============================================================
set -uo pipefail

before="${1:-}"
after="${2:-HEAD}"

# All-zeros before is GitHub's sentinel for a first push / branch creation /
# force push with no known prior tip. Empty string is NOT all-zeros.
is_all_zeros() {
  case "$1" in
    "") return 1 ;;
    *[!0]*) return 1 ;;
    *) return 0 ;;
  esac
}

# A resolvable, non-sentinel `before` is a normal push — diff before..after.
if [ -n "$before" ] && ! is_all_zeros "$before" \
  && git rev-parse --verify --quiet "${before}^{commit}" >/dev/null 2>&1; then
  printf '%s..%s\n' "$before" "$after"
# Otherwise fall back to the previous commit if one exists (first/force push).
elif git rev-parse --verify --quiet 'HEAD~1^{commit}' >/dev/null 2>&1; then
  printf 'HEAD~1..HEAD\n'
# No base resolves — emit nothing; the gates fall back to a full-repo scan.
else
  printf '\n'
fi
