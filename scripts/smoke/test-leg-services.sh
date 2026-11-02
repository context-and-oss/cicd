#!/usr/bin/env bash
# test-leg-services.sh — proves a test leg's declared service is actually bound
# and reachable, and that one which never becomes usable is a NON-RUN.
#
# Every other proof for test-leg services is a unit test over the rules in
# src/quality/services.go. None of them binds a container: the fold from probe
# result to evidence row is tested with a hand-built serviceProbe, so a wiring
# mistake in byotest.go — a binding attached to the wrong container, an env var
# injected after the exec, a probe whose result is never read — passes the
# entire unit suite. This script is the only thing here that runs the engine.
#
# CASE 1 — the service is reachable, and the leg can find it.
#
# The assertion is deliberately made by the CONSUMER'S OWN COMMAND, not by
# reading evidence: the leg reads CICD_SERVICE_CACHE_HOST and
# CICD_SERVICE_CACHE_PORT and speaks Redis to them. If the binding is absent the
# alias does not resolve; if the variables are missing `set -u` fails the line
# before redis-cli is called; if either is wrong the ping never answers PONG. An
# evidence field reading `ready: true` distinguishes none of those from a
# working bind, because cicd writes that field itself.
#
# The leg runs in the redis image so that redis-cli is present without an
# install step — the leg's toolchainImage is ADR-004 level 1, the consumer's own
# choice, and nothing about this case needs a Node toolchain.
#
# `readyCmd` runs in the SERVICE'S image, which is where redis-cli lives. So
# this leg must report readyVia "ready-cmd", and the engine-port-gate floor
# disclosure must be ABSENT — a disclosure on a run that made the stronger claim
# is the noise that gets it ignored on the run that mattered.
#
# CASE 2 — the service never listens.
#
# alpine's default command is /bin/sh, which exits immediately with no terminal,
# so nothing ever binds port 5432. The engine then fails the dependent exec with
# "service exited before healthcheck". The assertions are `passed == false` and
# an errors[] entry naming the alias — never a warnings[] line, which gates
# nothing at any threshold and would have been a dependency that silently was
# not there under a green tick. quality.Test itself has no --fail-on knob (the
# threshold is fixed HIGH, ADR-003), so what the errors[] entry buys is the
# non-run: gatedPassed refuses one at every threshold, including the NONE a
# consumer sets on the composite that reads this envelope. The leg's cmd would
# echo if it ran, and its absence from the envelope is the second half of the
# claim.
#
# This case waits out the engine's healthcheck budget before it reddens. That
# budget belongs to Dagger, is not configurable from here, and is disclosed in
# the spec rather than worked around.
#
# CASE 3 — two legs at --parallelism 2 each get their own service.
#
# The engine dedupes identical service definitions, so two legs declaring the
# same redis as `cache` were handed ONE instance once they ran side by side:
# measured, leg b's INCR read 2. Each leg here INCRs one key, sleeping either
# side so the two overlap, and its own command fails unless it read 1, so a
# shared instance reddens the run through the consumer's command, not through a
# field cicd writes. Each command also requires CICD_TEST_LEG to be its own
# label, which is what keeps two legs with the same command two executions.
# See specs/run-test-legs-under-the-parallelism-bound.md.
#
# Both cases also assert that a service env VALUE never reaches the envelope,
# on the serialised document rather than a parsed field — the field that leaks
# is the one nobody thought to parse (the dotnetKeepOutput rule).
#
# Usage: bash scripts/smoke/test-leg-services.sh
# Env (supplied by the module-test job): MODULE, SHA, BRANCH, REPO.
#
# It lives in a script rather than inline in .github/workflows/ci.yml because a
# `run:` body over roughly 24 KB makes GitHub refuse the workflow at STARTUP —
# no job, no check run. See docs/reference/workflow-step-size.md.
set -euo pipefail

MODULE="${MODULE:-src/quality}"
SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

REACHED=/tmp/qt-services-reached.json
DEAD=/tmp/qt-services-dead.json
SECRET=hunter2-never-in-evidence

# The leg command is quoted shell inside a JSON string inside a shell variable.
# Built with jq rather than concatenation: the first version of this script
# spliced it by hand, the inner double quotes closed the JSON string, and the
# module refused the document before a single container started.
PROBE='set -eu; '
PROBE+='echo "reaching $CICD_SERVICE_CACHE_HOST:$CICD_SERVICE_CACHE_PORT"; '
PROBE+='redis-cli -h "$CICD_SERVICE_CACHE_HOST" -p "$CICD_SERVICE_CACHE_PORT" ping | grep -q PONG'

OK_LEG=$(jq -nc --arg cmd "$PROBE" --arg secret "$SECRET" '
  [{label:"reach", language:"node", toolchainImage:"redis:7-alpine", cmd:$cmd,
    services:[{alias:"cache", image:"redis:7-alpine", port:6379,
               readyCmd:"redis-cli -h cache ping", readyTimeout:60,
               env:{SMOKE_TOKEN:$secret}}]}]')

dagger -m "./$MODULE" call test \
  --src ./testdata/node-app \
  --test-legs "$OK_LEG" \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$REACHED"

jq -e '.passed == true
  and ((.errors // []) | length == 0)
  and (.genericReport.legs | length == 1)
  and (.genericReport.legs[0].services | length == 1)
  and .genericReport.legs[0].services[0].alias == "cache"
  and .genericReport.legs[0].services[0].port == 6379
  and .genericReport.legs[0].services[0].ready == true
  and .genericReport.legs[0].services[0].readyVia == "ready-cmd"
  and (.genericReport.legs[0].services[0].envKeys == ["SMOKE_TOKEN"])
  and ((.warnings // []) | map(select(test("answered on the declared port"))) | length == 0)' \
  "$REACHED" > /dev/null

if grep -q "$SECRET" "$REACHED"; then
  echo "test-leg-services: FAIL — a service env value reached the envelope" >&2
  exit 1
fi

DEAD_LEG=$(jq -nc --arg secret "$SECRET" '
  [{label:"dead", language:"node", toolchainImage:"alpine:3.20",
    cmd:"echo THE-DEAD-LEG-COMMAND-RAN",
    services:[{alias:"db", image:"alpine:3.20", port:5432,
               env:{POSTGRES_PASSWORD:$secret}}]}]')

dagger -m "./$MODULE" call test \
  --src ./testdata/node-app \
  --test-legs "$DEAD_LEG" \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$DEAD"

jq -e '.passed == false
  and ((.errors // []) | map(select(test("service db"))) | length >= 1)
  and (.genericReport.legs[0].services[0].ready == false)
  and (.genericReport.legs[0].services[0].envKeys == ["POSTGRES_PASSWORD"])' \
  "$DEAD" > /dev/null

if grep -q "THE-DEAD-LEG-COMMAND-RAN" "$DEAD"; then
  echo "test-leg-services: FAIL — the leg's command ran although its service never bound" >&2
  exit 1
fi

if grep -q "$SECRET" "$DEAD"; then
  echo "test-leg-services: FAIL — a service env value reached the envelope" >&2
  exit 1
fi

PAIR=/tmp/qt-services-pair.json
COUNT='set -eu; test "$CICD_TEST_LEG" = "$1"; sleep 3; '
COUNT+='n=$(redis-cli -h "$CICD_SERVICE_CACHE_HOST" -p "$CICD_SERVICE_CACHE_PORT" INCR hits); '
COUNT+='echo "n=$n"; sleep 3; test "$n" = 1'

PAIR_LEGS=$(jq -nc --arg count "$COUNT" '
  [ "a", "b" | {label:., language:"node", toolchainImage:"redis:7-alpine",
    cmd:("set -- " + . + "; " + $count),
    services:[{alias:"cache", image:"redis:7-alpine", port:6379,
               readyCmd:"redis-cli -h cache ping", readyTimeout:60}]} ]')

dagger -m "./$MODULE" call test \
  --src ./testdata/node-app \
  --test-legs "$PAIR_LEGS" \
  --parallelism 2 \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$PAIR"

jq -e '.passed == true
  and ((.errors // []) | length == 0)
  and ([.genericReport.legs[].label] == ["a", "b"])
  and ([.genericReport.legs[] | select(.exitCode == 0 and (.durationMs | type) == "number")] | length == 2)' \
  "$PAIR" > /dev/null

echo "test-leg-services: OK — a declared service is bound and reachable, and one that never binds is a non-run, and concurrent legs never share one"
