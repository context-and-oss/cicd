#!/usr/bin/env bash
# check-doc-commands.sh — doc-command parity check.
#
# Convention: fenced ```sh blocks in the given markdown file whose FIRST line
# is exactly "# doc-test" are executable documentation. This script extracts
# each such block to a temp file and runs it from the repo root with bash -e,
# exiting non-zero on the first failure — or if the file contains no marked
# blocks at all (a guide with zero executable examples fails the parity
# check by definition). Blocks without the marker (consumer-repo examples,
# YAML snippets) are never executed.
#
# Usage: bash scripts/check-doc-commands.sh docs/how-to-guides/<guide>.md
set -u

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root"

doc="${1:?"usage: check-doc-commands.sh <markdown-file>"}"
[ -f "$doc" ] || { echo "no such file: $doc" >&2; exit 1; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Write each marked block to $tmpdir/block-N.sh (no NULs — bash command
# substitution cannot carry them).
awk -v dir="$tmpdir" '
  /^```sh[[:space:]]*$/ { fence=1; first=1; marked=0; buf=""; next }
  /^```[[:space:]]*$/ && fence {
    fence=0
    if (marked) { n++; printf "%s", buf > (dir "/block-" n ".sh") }
    next
  }
  fence {
    if (first) { if ($0 == "# doc-test") marked=1; first=0 }
    buf = buf $0 "\n"
  }
' "$doc"

total=0
for f in "$tmpdir"/block-*.sh; do
  [ -e "$f" ] || break
  total=$((total + 1))
  echo "==> doc-test block $total"
  sed 's/^/    /' "$f"
  if ! bash -e "$f"; then
    echo "FAIL: doc-test block $total in $doc" >&2
    exit 1
  fi
  echo "PASS: block $total"
done

if [ "$total" -eq 0 ]; then
  echo "FAIL: no '# doc-test' blocks found in $doc" >&2
  exit 1
fi

echo "OK: $total doc-test block(s) passed in $doc"
