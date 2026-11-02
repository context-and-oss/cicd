#!/usr/bin/env bash
# smoke-all.sh — run the behavioural fixture smokes the way CI runs them.
#
# The smokes in scripts/smoke/ call the real composites through Dagger and
# assert on the evidence produced, which makes them the only checks that can
# catch a pipeline that still compiles and still loads but has stopped doing
# something. Until this script existed, nothing but .github/workflows/ci.yml
# ran them: `make check-surface check-pins check-capsules check-go-format lint
# test-module-units` could all be green over a broken fixture assertion, so the
# stage-2/stage-4 break once reached CI instead of the author's terminal.
#
# Usage:
#   bash scripts/smoke-all.sh                      # every smoke, as CI runs them
#   bash scripts/smoke-all.sh stage-orchestrators  # one, by script name
#
# This is slow and needs a Docker daemon — each entry below starts a real
# Dagger session and runs a real pipeline over a fixture. It is not part of the
# local check-* sweep for that reason, and `make prepush` does not call it.
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not in a git repository" >&2; exit 1; }
cd "$repo_root" || exit 1

# Every invocation, named literally rather than discovered from the directory.
# Discovery would run a newly added script with no arguments and no decision
# about what it needs — and would silently skip one that needs some.
# check_smoke_scripts_are_wired in scripts/repo_surface.py proves this list and
# scripts/smoke/ still agree, so the explicitness cannot go stale.
#
# commit-shapes.sh runs once per artifact shape. `archive-identity` is
# deliberately absent, for the same reason ci.yml omits it: assert_unique_identity
# already runs inside the `archive` shape, so the standalone shape would buy a
# fourth full pipeline execution and no new fact.
SMOKES=(
  "stage-orchestrators.sh"
  "dotnet-runner-shapes.sh"
  "mtp-byo-coverage.sh"
  "test-leg-services.sh"
  "semgrep-redaction.sh"
  "semgrep-inline.sh"
  "gitleaks-identity.sh"
  "commit-shapes.sh container"
  "commit-shapes.sh archive"
  "commit-shapes.sh none"
  "commit-apps.sh"
  "dast-shapes.sh guardrails"
  "dast-shapes.sh service"
  "dast-shapes.sh container"
  "non-run-matrix.sh"
)

filter="${1:-}"

# A missing Dagger or Docker makes every script below fail deep inside a
# pipeline invocation with an error about something else. Say so up front
# instead: an unrunnable suite must not look like a failing one.
missing=""
command -v dagger >/dev/null 2>&1 || missing="dagger"
if [ -z "$missing" ] && ! docker info >/dev/null 2>&1; then
  missing="a running Docker daemon"
fi
if [ -n "$missing" ]; then
  echo "cannot run the behavioural smokes: $missing is not available." >&2
  echo "These call the real composites through Dagger; there is no offline mode." >&2
  exit 2
fi

selected=()
for entry in "${SMOKES[@]}"; do
  script="${entry%% *}"
  if [ -n "$filter" ] && [ "$script" != "$filter" ] && [ "$script" != "${filter}.sh" ]; then
    continue
  fi
  selected+=("$entry")
done

if [ "${#selected[@]}" -eq 0 ]; then
  echo "no smoke matches '${filter}'. Known scripts:" >&2
  printf '%s\n' "${SMOKES[@]%% *}" | sort -u | sed 's/^/  /' >&2
  exit 2
fi

# Run every selected smoke even after one fails. Each is minutes long, so
# stopping at the first failure would hide the rest behind another full run —
# the cost of these scripts is exactly why the whole picture has to come back
# from one invocation.
declare -a failed=()
for entry in "${selected[@]}"; do
  echo
  echo "──────── scripts/smoke/${entry}"
  # shellcheck disable=SC2086
  if bash "scripts/smoke/${entry%% *}" ${entry#"${entry%% *}"}; then
    echo "── ok: ${entry}"
  else
    echo "── FAILED: ${entry}" >&2
    failed+=("$entry")
  fi
done

echo
echo "════════ smoke summary"
for entry in "${selected[@]}"; do
  status="ok"
  for f in "${failed[@]-}"; do [ "$f" = "$entry" ] && status="FAILED"; done
  printf '  %-7s %s\n' "$status" "$entry"
done

if [ "${#failed[@]}" -gt 0 ]; then
  echo
  echo "${#failed[@]} of ${#selected[@]} smoke(s) failed." >&2
  exit 1
fi
echo
echo "all ${#selected[@]} smoke(s) passed."
