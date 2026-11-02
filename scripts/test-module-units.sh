#!/usr/bin/env bash
# Canonical clean-checkout module-unit runner.
#
# Runs the COMPLETE `-tags unit_test` suite for every module in the defended
# inventory (scripts/repo-inventory.json, via inventory-query.py) that ships
# one — no `-run TestXxx` subsetting, no Dagger session required. A module's
# production Dagger-entrypoint files are tagged `//go:build !unit_test` (see
# root CLAUDE.md's "Go build-tag pattern"), so `-tags unit_test` excludes them
# and leaves only pure-Go production helpers plus the test files themselves —
# discovered per-module by trying it, not by a hand-maintained module list.
#
# Fails loudly, not silently, on:
#   - any failing test (forwarded exit code)
#   - a module with *_test.go files that executes zero tests (setup-only or
#     build-constraint-filtered false pass — Go's default reports this as a
#     harmless "ok")
#   - an empty overall run (inventory unusable, or every module's tests got
#     skipped)
# TEST_MODULE_UNITS_MODULES lets scripts/tests/test_module_units.py point this
# runner at a throwaway fixture tree instead of the live inventory, so the
# zero-test and failing-test detection paths have real fixture-driven proof
# (mirrors check-repo-surface.py's --root/--inventory test seam).
set -uo pipefail

# GOWORK=off is load-bearing, not a convenience. "No shared Go module" (root
# CLAUDE.md): each Dagger module is isolated with its own go.mod, and the
# repo-root go.work deliberately lists only ./src/internal. Without this,
# `cd src/risk && go test ./...` resolves the *root* workspace, which does not
# contain src/risk, and Go refuses before compiling anything:
#
#   pattern ./...: directory prefix . does not contain modules listed in
#   go.work or their selected dependencies
#   FAIL ./... [setup failed]
#
# Some modules carry a module-local `go.work` with `use .` that masks this and
# some do not, so leaving workspace resolution to the ambient environment makes
# the result depend on which module and which shell you happen to be in. Pinning
# it off makes every module resolve against its own go.mod — the isolation the
# repository actually declares — identically in CI and in a clean local
# checkout.
export GOWORK=off

DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$DEFAULT_ROOT"

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    *) echo "usage: $0 [--root DIR]" >&2; exit 2 ;;
  esac
done

cd "$ROOT"

if [ -n "${TEST_MODULE_UNITS_MODULES+x}" ]; then
  MODULES="$TEST_MODULE_UNITS_MODULES"
else
  MODULES=$(python3 "$DEFAULT_ROOT/scripts/inventory-query.py" modules)
  if [ -z "$MODULES" ]; then
    echo "ERROR: scripts/inventory-query.py produced an empty module list" >&2
    exit 1
  fi
fi

FAILED=0
TOTAL_RAN=0
TESTED_MODULES=0

for MODULE in $MODULES; do
  # Tests may live in any package within the module. Discover recursively to
  # match the ./... execution boundary; a root-only probe would silently omit
  # a module whose suites all live in nested packages.
  test_files=$(find "$MODULE" -type f -name '*_test.go' 2>/dev/null)
  if [ -z "$test_files" ]; then
    continue
  fi

  echo "==> go test -race -tags unit_test -v ./... ($MODULE)"
  output=$(cd "$MODULE" && go test -race -tags unit_test -v ./... 2>&1)
  status=$?
  echo "$output"

  if [ $status -ne 0 ]; then
    echo "FAIL: $MODULE unit tests failed (exit $status)" >&2
    FAILED=1
    continue
  fi

  ran_count=$(printf '%s\n' "$output" | grep -c '^=== RUN')
  if [ "$ran_count" -eq 0 ]; then
    echo "FAIL: $MODULE has $(printf '%s\n' "$test_files" | wc -l) test file(s) but executed zero tests (setup-only false pass)" >&2
    FAILED=1
    continue
  fi

  echo "$MODULE: $ran_count test(s) executed"
  TESTED_MODULES=$((TESTED_MODULES + 1))
  TOTAL_RAN=$((TOTAL_RAN + ran_count))
done

if [ "$TESTED_MODULES" -eq 0 ] || [ "$TOTAL_RAN" -eq 0 ]; then
  echo "FAIL: canonical runner discovered no executable unit tests across the module inventory" >&2
  exit 1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "FAIL: one or more modules failed unit tests or executed zero tests" >&2
  exit 1
fi

echo "OK: $TOTAL_RAN unit test(s) executed across $TESTED_MODULES module(s)"
