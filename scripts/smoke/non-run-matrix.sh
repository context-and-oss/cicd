#!/usr/bin/env bash
# non-run-matrix.sh — the founding rule, end to end: a tool that could not
# produce a usable result must fail the gate at every threshold, `--fail-on
# NONE` included, or be refused before an envelope exists.
#
# Every module carries a `nonrun_matrix_test.go` holding the same rule over its
# folds. Those prove the fold; they cannot prove the entry function feeds the
# fold what the container actually produced. The one defect this script was
# written against lived exactly in that gap: quality.Check on a tree with no
# Python test, under `--include python`, came back measured as
#
#   passed   true          <-- at --fail-on NONE
#   outcome  ERROR
#   errors   ["test python: pytest failed (exit 5)"]
#
# because the fold read the leg's ran flag and pytest's exit 5 ("no tests
# collected") leaves ran true with a green accounting. Each fold's unit matrix
# was green the whole time. pytest's no-result exits (2-5) are now non-runs
# at the leg itself, named "pytest: did not run (exit N: ...)".
#
# So each case below injects a real non-run through the real module and asserts
# the verdict, and each is paired with a positive control that runs the same
# module on an input it can read and requires it to pass: without the control a
# module that refused everything would satisfy the matrix.
#
# A refusal counts only with its own reason in the output. A call that failed
# because the module did not load, or Docker went away, is not a refusal of the
# injected input and must not read as one.
#
# Usage: bash scripts/smoke/non-run-matrix.sh
#
# Env (optional): SHA, BRANCH, REPO.
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root" || exit 1

for tool in dagger jq git; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required command: $tool" >&2; exit 127; }
done

SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

rc=0
fail() { echo "FAIL: $*" >&2; rc=1; }

# The invariant every envelope must hold whatever the case: an outcome that says
# the tool produced no usable result never sits beside a passing verdict.
invariant() {
  local name=$1 file=$2
  if ! jq -e '(.outcome != "ERROR") or (.passed == false)' "$file" >/dev/null; then
    fail "$name: outcome ERROR beside passed:true"
  fi
}

# expect_verdict NAME WANT FILE -- dagger args...
# Runs the call, exports the envelope to FILE, and requires .passed == WANT.
expect_verdict() {
  local name=$1 want=$2 file=$3
  shift 4
  echo "== $name (want passed:$want) =="
  if ! dagger --progress=plain "$@" export --path "$file" >"$work/log" 2>&1; then
    tail -40 "$work/log" >&2
    fail "$name: the call itself failed, so there is no verdict to read"
    return
  fi
  local got
  got=$(jq -r '.passed' "$file")
  if [ "$got" != "$want" ]; then
    jq -c '{passed, outcome, errors}' "$file" >&2
    fail "$name: passed=$got"
  fi
  invariant "$name" "$file"
}

# expect_refusal NAME REASON -- dagger args...
# Requires the call to fail AND to name REASON (a fixed string) in its output.
expect_refusal() {
  local name=$1 reason=$2
  shift 3
  echo "== $name (want refusal) =="
  if dagger --progress=plain "$@" >"$work/log" 2>&1; then
    fail "$name: the call succeeded on an input it must refuse"
    return
  fi
  if ! grep -qF -- "$reason" "$work/log"; then
    tail -40 "$work/log" >&2
    fail "$name: the call failed, but not with the refusal it owes ($reason)"
  fi
}

ctx=(--commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO")

# ---------------------------------------------------------------------------
# quality.Check — a test runner that exited non-zero with a green accounting.
# go-app carries no Python, so pytest collects nothing and exits 5.
# ---------------------------------------------------------------------------
expect_verdict "quality: pytest collected nothing" false "$work/q-fault.json" -- \
  -m ./src/quality call check --src ./testdata/go-app --include python --fail-on NONE "${ctx[@]}"
if ! jq -e '.outcome == "ERROR" and ((.errors // []) | any(test("pytest: did not run \\(exit 5:")))' "$work/q-fault.json" >/dev/null 2>&1; then
  fail "quality: the non-run is not named as pytest's exit 5"
fi
expect_verdict "quality: control" true "$work/q-control.json" -- \
  -m ./src/quality call check --src ./testdata/python-app --include python --fail-on NONE "${ctx[@]}"

# ---------------------------------------------------------------------------
# quality.Check — a Go package that does not compile beside one that passes.
# go test exits 1 for both a failing test and a package it could not build, and
# the build failure used to read as a failing suite that NONE passes: the
# module's tests ran on part of it and reported as all of it.
# ---------------------------------------------------------------------------
gobroken="$work/go-broken"
cp -R ./testdata/go-app "$gobroken"
mkdir -p "$gobroken/broken"
printf 'package broken\n\nfunc B() int { return 1\n' >"$gobroken/broken/broken.go"
printf 'package broken\n\nimport "testing"\n\nfunc TestB(t *testing.T) { _ = B() }\n' >"$gobroken/broken/broken_test.go"
expect_verdict "quality: a Go package did not build" false "$work/q-go-fault.json" -- \
  -m ./src/quality call check --src "$gobroken" --include go --fail-on NONE "${ctx[@]}"
if ! jq -e '.outcome == "ERROR" and ((.errors // []) | any(test("go test: did not run on the whole module \\(exit 1\\): 1 package\\(s\\) could not be built or set up, so their tests never ran: [^ ]*/broken \\(build failed\\)")))' "$work/q-go-fault.json" >/dev/null 2>&1; then
  jq -c '.errors' "$work/q-go-fault.json" >&2
  fail "quality: the unbuilt Go package is not named as a partial run"
fi
expect_verdict "quality: Go control" true "$work/q-go-control.json" -- \
  -m ./src/quality call check --src ./testdata/go-app --include go --fail-on NONE "${ctx[@]}"

# ---------------------------------------------------------------------------
# risk.Validate — a findings.json that is not a scan's output. `null` used to
# pass as a review that found nothing.
# ---------------------------------------------------------------------------
mkdir -p "$work/risk-null"
printf 'null\n' >"$work/risk-null/findings.json"
printf '{}\n' >"$work/risk-null/decisions.json"
expect_refusal "risk: findings.json is null" "parse findings.json:" -- \
  -m ./src/risk call validate --source "$work/risk-null" --fail-on NONE "${ctx[@]}"

mkdir -p "$work/risk-ok"
printf '{"schema_version":"1.0","findings":[]}\n' >"$work/risk-ok/findings.json"
printf '{}\n' >"$work/risk-ok/decisions.json"
expect_verdict "risk: control" true "$work/r-control.json" -- \
  -m ./src/risk call validate --source "$work/risk-ok" --fail-on NONE "${ctx[@]}"

# ---------------------------------------------------------------------------
# intent.Check — a diff whose change set cannot be read. It used to fall back
# to auditing the whole tree, which passes whenever any artifact anywhere is
# well written. Refused at `--fail-on never`, the loosest the gate has. A change
# that touches no artifact is deliberately not a case: that is the gate's
# finding, not a non-run, and `never` is entitled to let it through.
# ---------------------------------------------------------------------------
tree="$work/intent-src"
mkdir -p "$tree/specs"
cat >"$tree/specs/refuse-an-unreadable-diff.md" <<'MD'
# Refuse a diff the gate cannot read

The intent gate scopes its judgement to the artifacts a change touches, so it
must read the change set from the supplied diff. A diff generated with
--no-prefix carries no b/ prefixes, which means no path in it can be matched to
an artifact. Falling back to a full audit would pass because some other artifact
is well written, so the gate refuses the diff instead and names why.
MD
printf 'package main\n' >"$tree/main.go"
( cd "$tree" && git init -q && git add . && git -c user.email=smoke@example.com -c user.name=smoke commit -qm base )

printf '// changed\n' >>"$tree/main.go"
( cd "$tree" && git diff --no-prefix ) >"$work/noprefix.diff"
( cd "$tree" && git checkout -q -- main.go )

printf '\nThe refusal names the header it could not read.\n' >>"$tree/specs/refuse-an-unreadable-diff.md"
( cd "$tree" && git diff ) >"$work/spec.diff"
# The edit stays in the tree: coupling reconstructs the previous artifact from
# the current file and the diff's hunks, and refuses a tree that does not hold
# the diff's post-image. Reverting it here was a fixture lie, not a gate defect.
if ! ( cd "$tree" && git apply --reverse --check "$work/spec.diff" ); then
  fail "intent: control diff does not match its source tree"
fi
rm -rf "$tree/.git"

expect_refusal "intent: no-prefix diff" "carries no b/ prefix" -- \
  -m ./src/cross-cutting/intent call check --src "$tree" --diff "$work/noprefix.diff" --fail-on never "${ctx[@]}"
# The control runs at the default threshold, so it proves the spec was judged
# and found sound, not merely that `never` let it through.
expect_verdict "intent: control" true "$work/i-control.json" -- \
  -m ./src/cross-cutting/intent call check --src "$tree" --diff "$work/spec.diff" "${ctx[@]}"

if [ "$rc" -ne 0 ]; then
  echo "non-run-matrix: FAILED" >&2
  exit 1
fi
echo "non-run-matrix: OK — every injected non-run failed or was refused at --fail-on NONE, every control passed"
