#!/usr/bin/env bash
# Decide whether a rejected `git push` is worth retrying.
#
# Exit 0 ("retryable") ONLY for the three rejections that mean the remote ref
# moved under us. Everything else — a ruleset refusal (GH006/GH013), a revoked
# or under-scoped PAT, a transport failure — exits 1 so the caller reports the
# remote's own message instead of burning its retry budget on a refusal no
# retry can satisfy.
#
# Deliberately a separate script rather than a shell function inside cd.yml:
# this is a regex against git's exact wording, which is precisely the kind of
# thing that rots silently on a git upgrade. As a script it is driven by real
# captured stderr in scripts/tests/test_push_rejection.py, so a wording change
# fails a test instead of misclassifying a release.
#
# Usage: classify-push-rejection.sh <file containing git push stderr>
set -euo pipefail

if [ $# -ne 1 ]; then
	echo "usage: $0 <push-stderr-file>" >&2
	exit 2
fi

if [ ! -f "$1" ]; then
	echo "$0: no such file: $1" >&2
	exit 2
fi

# git prints the reason in parentheses on the `! [rejected]` line:
#   ! [rejected]        HEAD -> main (fetch first)
#   ! [rejected]        HEAD -> main (non-fast-forward)
#   ! [rejected]        HEAD -> main (stale info)
# A ruleset refusal is `! [remote rejected] ... (push declined due to
# repository rule violations)`, which matches none of them — as intended.
#
# The reason must appear on the `[rejected]` line itself, not merely somewhere
# in the output: a violated-rule name or a quoted commit message is remote text
# we do not control, and it must not be able to talk this script into a retry.
# `[remote rejected]` deliberately does not match — the substring "[rejected]"
# is not present in it.
grep -qE '\[rejected\][^)]*\((fetch first|non-fast-forward|stale info)\)' "$1"
