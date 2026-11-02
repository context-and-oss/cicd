#!/usr/bin/env bash
# Decide whether a failed `dagger develop` is worth retrying.
#
# Exit 0 ("retryable") ONLY when the failure is the Go module chain failing to
# fetch or verify — the checksum database, the module proxy, or the transport
# under them. Everything else exits 1: a codegen failure, a compile error in
# the module, a missing dependency in dagger.json. Those do not get better on
# the second attempt, and retrying them turns a ten-second red into a
# five-minute one that says the same thing.
#
# Neither answer can produce a green. A fault misread as retryable is retried
# and then reported; a fault misread as permanent is reported at once. The
# classification chooses the message and the budget, never the verdict — which
# is what lets this file be a regex against wording we do not own.
#
# Deliberately a separate script rather than a shell condition inside ci.yml,
# for the reason classify-push-rejection.sh gives: it is a regex against the Go
# toolchain's exact phrasing, so it is driven by real captured output in
# scripts/tests/test_dagger_develop.py and a rewording fails a test instead of
# misclassifying a run.
#
# Usage: classify-dagger-develop-failure.sh <file containing the failed output>
set -euo pipefail

if [ $# -ne 1 ]; then
	echo "usage: $0 <develop-output-file>" >&2
	exit 2
fi

if [ ! -f "$1" ]; then
	echo "$0: no such file: $1" >&2
	exit 2
fi

# Every pattern below is the module chain, not the module. `go mod download`
# and `go mod verify` run inside the generated container, so their failures
# surface through Dagger as a bare "exit code: 1" at the top level with the
# real sentence buried in the step output — which is the whole reason this
# reads the captured log rather than an exit status.
#
# sum.golang.org / proxy.golang.org: named explicitly because a fault there is
#   the common case and says nothing about the code.
# stream error ... INTERNAL_ERROR: HTTP/2 peer reset. This is the one that
#   failed CI on 2026-09-14; see the test fixture.
# dial tcp / i.o timeout / TLS handshake / connection reset / unexpected EOF:
#   the transport under all of the above.
# 5xx: the proxy admitting it, rather than the transport guessing.
grep -qE \
	'(sum\.golang\.org|proxy\.golang\.org|stream error:.*INTERNAL_ERROR|dial tcp|i/o timeout|TLS handshake timeout|connection reset by peer|unexpected EOF|50[0234] (Bad Gateway|Service Unavailable|Gateway Time-?out|Internal Server Error))' \
	"$1"
