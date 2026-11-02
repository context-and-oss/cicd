#!/usr/bin/env bash
# Wait for a release pin-bump pull request to merge, then let the caller tag.
#
# Only `release.yml` uses this. `cd.yml` deliberately does not: it runs on every
# push to main, so the merge of the bump pull request starts a fresh run that
# finds the pins already at the target and tags there — no runner sits waiting.
#
# `release.yml` is the manual override, the path a human takes when CD itself is
# broken. It has to produce a tag in the run the operator started, because "come
# back later and hope another workflow finishes the job" is not an override. So
# this one blocks, and pays for it with an idle runner. See
# specs/deliver-release-pins-by-pull-request.md.
#
# Usage:  wait-for-release-merge.sh <branch> [--timeout-seconds N] [--interval-seconds N]
#
# Requires GH_TOKEN. Exit codes are distinct because the caller must not treat
# these alike — only 0 may lead to a tag:
#   0  merged
#   1  still open when the budget ran out
#   2  closed without merging, or unmergeable in a way waiting cannot fix
#   3  the pull request could not be read at all — an unknown state, never
#      "merged" and never "still waiting"
set -euo pipefail

BRANCH="${1:?"usage: wait-for-release-merge.sh <branch> [--timeout-seconds N] [--interval-seconds N]"}"
shift

TIMEOUT=2400
INTERVAL=20
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout-seconds) TIMEOUT="${2:?--timeout-seconds needs a value}"; shift 2 ;;
    --interval-seconds) INTERVAL="${2:?--interval-seconds needs a value}"; shift 2 ;;
    *) echo "::error::unknown argument '$1'" >&2; exit 3 ;;
  esac
done

for value in "$TIMEOUT" "$INTERVAL"; do
  if ! printf '%s' "$value" | grep -qE '^[0-9]+$' || [ "$value" -lt 1 ]; then
    echo "::error::timeout and interval must be positive integers (got '$value')" >&2
    exit 3
  fi
done

# Consecutive read failures, not total: one transient API blip during a release
# must not abandon a pull request that is about to merge, and a token that has
# stopped working must not look like a pull request that never merges. Both
# answers are wrong in different directions, so the run distinguishes them.
MAX_CONSECUTIVE_FAILURES=5
failures=0
elapsed=0

echo "Waiting for ${BRANCH} to merge (budget ${TIMEOUT}s, polling every ${INTERVAL}s)."

while :; do
  if ! snapshot=$(gh pr view "$BRANCH" \
    --json state,mergedAt,mergeStateStatus \
    --jq '[.state, (.mergedAt // "-"), (.mergeStateStatus // "UNKNOWN")] | @tsv' 2>&1); then
    failures=$((failures + 1))
    echo "::warning::could not read ${BRANCH} (${failures}/${MAX_CONSECUTIVE_FAILURES}): ${snapshot}"
    if [ "$failures" -ge "$MAX_CONSECUTIVE_FAILURES" ]; then
      echo "::error::gave up reading pull request ${BRANCH} after ${MAX_CONSECUTIVE_FAILURES} consecutive failures. The merge state is unknown, which is not the same as unmerged — check the pull request before re-running, because a tag cut against an unknown state could tag the wrong tree." >&2
      exit 3
    fi
    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
      # Deliberately not the timeout exit below. Falling through to it would
      # report "not merged, auto-merge still armed" — a verdict about a pull
      # request this run never managed to read. The budget expiring during a read
      # failure leaves the state unknown, and unknown is its own answer.
      echo "::error::the ${TIMEOUT}s budget expired while pull request ${BRANCH} was unreadable (last error: ${snapshot}). Its merge state is unknown, not unmerged." >&2
      exit 3
    fi
    continue
  fi
  failures=0

  state=$(printf '%s' "$snapshot" | cut -f1)
  merged_at=$(printf '%s' "$snapshot" | cut -f2)
  merge_state=$(printf '%s' "$snapshot" | cut -f3)

  case "$state" in
    MERGED)
      echo "::notice::${BRANCH} merged at ${merged_at}."
      exit 0
      ;;
    CLOSED)
      echo "::error::pull request for ${BRANCH} was closed without merging, so there is nothing to tag. Reopen it or re-run the release." >&2
      exit 2
      ;;
    OPEN) ;;
    *)
      # An unrecognised state is not a licence to keep waiting: the states are a
      # closed set, so a new one means this script's assumptions are stale.
      echo "::error::pull request for ${BRANCH} reports state '${state}', which this script does not know how to interpret." >&2
      exit 3
      ;;
  esac

  # DIRTY is a merge conflict. Nothing about waiting resolves one, and burning
  # the whole budget on it buries the real reason under a timeout message.
  if [ "$merge_state" = "DIRTY" ]; then
    echo "::error::pull request for ${BRANCH} conflicts with main and cannot merge. Something landed on main that touches the same pins. Re-run the release: the delivery script re-derives the bump against the live tip." >&2
    exit 2
  fi

  if [ "$elapsed" -ge "$TIMEOUT" ]; then break; fi
  echo "  ${elapsed}s: state=${state} merge_state=${merge_state}"
  sleep "$INTERVAL"
  elapsed=$((elapsed + INTERVAL))
done

# Not a failure of the release so much as the end of this run's patience. The
# pull request is real and auto-merge is armed, so it may still merge on its own;
# say that rather than implying the bump was lost.
echo "::error::pull request for ${BRANCH} had not merged after ${TIMEOUT}s (last merge state: ${merge_state:-unknown}). Auto-merge is still armed, so it may merge without help — but no tag was cut by this run. Check the 'ci' check on the pull request, then either re-run this workflow after it merges or let cd.yml tag it." >&2
exit 1
