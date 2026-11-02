#!/usr/bin/env bash
# ============================================================
# commit-diff-test.sh — unit test for scripts/commit-diff.sh (ADR-005 Option-B).
#
# Exercises the three range-resolution cases, each in its own throwaway git
# repo so the ambient checkout never influences the result:
#
#   1. normal push       distinct before/after SHAs      -> before..after
#   2. all-zeros before  first / force push sentinel      -> HEAD~1..HEAD
#   3. no base resolves   single-commit repo, no HEAD~1   -> <empty>
#
# Exits non-zero on the first mismatch.
# ============================================================
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "not in a git repository" >&2
  exit 1
}
script="$repo_root/scripts/commit-diff.sh"
[ -x "$script" ] || [ -f "$script" ] || {
  echo "missing $script" >&2
  exit 1
}

ZEROS="0000000000000000000000000000000000000000"
tmproot=$(mktemp -d)
trap 'rm -rf "$tmproot"' EXIT

fail=0
pass=0

check() {
  # check <label> <expected> <actual>
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "ok   — $label"
    pass=$((pass + 1))
  else
    echo "FAIL — $label: expected [$expected], got [$actual]" >&2
    fail=$((fail + 1))
  fi
}

# A fresh git repo with N sequential commits; prints the repo path.
make_repo() {
  local dir="$1" n="$2" i
  git init -q "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "test"
  for i in $(seq 1 "$n"); do
    echo "commit $i" > "$dir/file-$i.txt"
    git -C "$dir" add -A
    git -C "$dir" commit -q -m "commit $i"
  done
  printf '%s' "$dir"
}

# ── Case 1: normal push — distinct before/after SHAs -> before..after ────────
repo1=$(make_repo "$tmproot/normal" 2)
before=$(git -C "$repo1" rev-parse HEAD~1)
after=$(git -C "$repo1" rev-parse HEAD)
out=$(cd "$repo1" && bash "$script" "$before" "$after")
check "normal push -> before..after" "$before..$after" "$out"

# ── Case 2: all-zeros before -> HEAD~1..HEAD ─────────────────────────────────
repo2=$(make_repo "$tmproot/zero" 2)
after=$(git -C "$repo2" rev-parse HEAD)
out=$(cd "$repo2" && bash "$script" "$ZEROS" "$after")
check "all-zeros before -> HEAD~1..HEAD" "HEAD~1..HEAD" "$out"

# ── Case 3: no base resolves — single commit, no HEAD~1 -> empty ─────────────
repo3=$(make_repo "$tmproot/nobase" 1)
after=$(git -C "$repo3" rev-parse HEAD)
out=$(cd "$repo3" && bash "$script" "$ZEROS" "$after")
check "no base resolves -> empty" "" "$out"

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
