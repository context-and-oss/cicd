#!/usr/bin/env bash
# Run `dagger develop`, retrying only the failures a retry can fix, and saying
# which kind of failure it was when it gives up.
#
# Why this exists. `dagger develop` generates a module's SDK by fetching Go
# modules, so it fails for two unrelated reasons that look identical from
# outside: the code is wrong, or the network is. On 2026-09-14 the second one
# took CI red with
#
#	Error: failed to apply generated code: exit code: 1
#
# at the top level, while the actual sentence —
#
#	reading https://sum.golang.org/tile/8/0/x205/155: stream error:
#	stream ID 23; INTERNAL_ERROR; received from peer
#
# sat about eight hundred lines down inside a Dagger TUI dump. The step read as
# "your module does not compile" and meant "the checksum database hung up".
#
# What this does NOT do is make the failure softer. A develop that could not
# generate an SDK must stay red: every `dagger call` after it would otherwise
# run against a stale or absent SDK, which is the founding doctrine's exact
# failure — a step that could not do its work reading as a step that did it.
# The retry narrows *which* reds are real; it never turns one green.
#
# Usage: dagger-develop.sh [module-directory]   (default: the working directory)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
classify="$here/classify-dagger-develop-failure.sh"
dir="${1:-.}"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# 0 5 15 30: the same shape as the engine pre-pull in ci.yml, one attempt
# shorter because this one is behind a cache that the pre-pull has already
# warmed. Four attempts spans roughly a minute, which is longer than every
# sum.golang.org blip observed so far and short enough that a genuinely down
# proxy does not hold a matrix cell open.
attempt=0
for delay in 0 5 15 30; do
	attempt=$((attempt + 1))
	[ "$delay" = 0 ] || sleep "$delay"

	# PIPESTATUS, not the pipeline's status. The output has to reach both the
	# log and the job console, so it goes through tee — and tee succeeds
	# whatever it is piped. `set -o pipefail` above would in fact carry the
	# failure through, but a develop that reports success because the tee
	# worked is the founding doctrine's own failure mode, and it must not
	# depend on one shell option staying set.
	(cd "$dir" && dagger develop) 2>&1 | tee "$log"
	rc=${PIPESTATUS[0]}
	if [ "$rc" -eq 0 ]; then
		[ "$attempt" -eq 1 ] || echo "dagger develop succeeded on attempt $attempt"
		exit 0
	fi

	if ! "$classify" "$log"; then
		# Not a fetch fault. Report it now rather than spending three more
		# attempts proving that a compile error is still a compile error.
		echo "::error title=dagger develop failed::Could not generate the SDK in ${dir}. This is not a transient fetch fault — no module-proxy, checksum-database or transport error appears in the output — so the cause is in the module or its dagger.json. Full output above."
		exit 1
	fi

	echo "dagger develop hit a module-fetch fault in ${dir} (attempt ${attempt}); retrying"
done

# Still failing, and every failure was a fetch fault. Name that, because the
# thing to do about it is not to read the module's Go code.
echo "::error title=dagger develop could not fetch its modules::Could not generate the SDK in ${dir} after ${attempt} attempts. Every attempt failed fetching or verifying Go modules — the checksum database, the module proxy, or the transport under them — not building the module. Re-run the job; if it keeps failing, check the Go module proxy's status rather than the code."
exit 1
