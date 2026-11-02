#!/usr/bin/env bash
# mtp-byo-coverage.sh — proves that `quality.Test` can READ the coverage document
# a Microsoft.Testing.Platform run actually wrote.
#
# A BYO test leg is the only path that reaches `sniffCoverageReport` for a
# cobertura document: cicd's own .NET leg calls `parseCobertura` directly through
# `parseCoberturaSet`, so it never went through the sniffer and never hit this.
#
# MTP writes every cobertura with a UTF-8 BOM, and `strings.TrimSpace` does not
# remove one — U+FEFF left Unicode's `White_Space` property in 4.0.1, so
# `unicode.IsSpace` reports false for it. `sniffCoverageReport` picked its parser
# from the first character of the trimmed text, so a BOM'd document began U+FEFF
# rather than `<`, no arm of the format switch fired, and the harvest matched the
# document and merged none.
#
# Measured on this fixture immediately before `stripBOM` landed:
#
#   passed              true                          <-- green
#   coverageRatchet     skipped:no-coverage-output
#   coverageMeasured    false
#   errors[]            (none)
#   warnings[]          "matched 1 file(s), merged 0 document(s)"
#
# So `passed` is worthless as an assertion here — it is `true` on both revisions
# — and the merge count is the whole test. The ratchet under it is fail-open by
# ADR-003 design, which is right for a consumer who configured no coverage and
# wrong as a description of a run that produced a report cicd could not read.
#
# The ratchet verdict is asserted for its own sake: it moves from
# `skipped:no-coverage-output` to `skipped:no-baseline`. Before the fix the
# ratchet misdescribed its own reason for skipping, claiming the command produced
# no report about a command that produced one. That is a second honesty defect
# closed by the same change, and it is invisible if only the merge count is read.
#
# WHY `toolchainImage` IS PASSED, AND WHY IT IS NOT A DIGEST
#
# The BYO path resolves a .NET image through `ResolveToolchain`, which reads
# `global.json`'s `sdk.version` and nothing else. This fixture deliberately
# carries only the runner opt-in and no `sdk.version`, so resolution falls through
# to `defaultToolchain[Dotnet]` = `mcr.microsoft.com/dotnet/sdk:8.0` — an SDK with
# no MTP CLI at all, since `"test": {"runner": …}` did not exist before .NET 10.
# It silently ignores the opt-in, routes the command through `-target:VSTest`, and
# MSBuild rejects `--coverage` with MSB1001 "Unknown switch". Measured; the same
# command on 10.0 exits 0. That gap between `quality.Check` (which reads the TFM
# from `*.csproj` and `Directory.Build.props` and names the band it chose in
# `warnings[]`) and `quality.Test` (which does neither) is tracked as an open issue.
#
# The tag is deliberately not a digest. A leg's `toolchainImage` is ADR-004's
# consumer-resolved toolchain, the one image class this repository does not pin;
# `check-runtime-image-pins.py` discovers `From(...)` in `src/` and does not scan
# workflows or scripts, so a digest here would be a second copy of `images.go`
# that no gate can hold in step with the first. A stale pin in a test case proves
# the fix against an SDK nobody ships any more, while reading as current.
#
# WHY THE COMMAND NAMES THE TEST PROJECT
#
# `dotnet test` at the source root resolves the single project in the working
# directory and does not recurse, so it exits 1 with "No test projects were
# found." — measured on 10.0 against this fixture. A BYO leg runs the consumer's
# own command, so that is the consumer's to get right; `quality.Check` discovers
# targets explicitly because there the command is cicd's.
#
# Usage: bash scripts/smoke/mtp-byo-coverage.sh
#
# Env (supplied by the module-test job): MODULE, SHA, BRANCH, REPO.
#
# This lives in a script rather than inline in .github/workflows/ci.yml because
# the quality arm of that job is the repository's largest `run:` body and a body
# over roughly 24 KB makes GitHub refuse the workflow at STARTUP — no job, no
# check run, an absence from the PR check list rather than a red tick. Inlining
# this block measured 14704 of the 16384-byte budget, and most of it is comment,
# which is exactly the payload that difference is made of. See
# docs/reference/workflow-step-size.md.
set -euo pipefail

MODULE="${MODULE:-src/quality}"
SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

OUT=/tmp/qt-mtp.json

LEG='[{"label":"dotnet","language":"dotnet",'
LEG+='"toolchainImage":"mcr.microsoft.com/dotnet/sdk:10.0",'
LEG+='"cmd":"dotnet test tests/dotnet-mtp-app.Tests.csproj --coverage --coverage-output-format cobertura",'
LEG+='"coveragePath":"*.cobertura.xml"}]'

dagger -m "./$MODULE" call test \
  --src ./testdata/dotnet-mtp-app \
  --test-legs "$LEG" \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$OUT"

jq -e '.passed == true
  and ((.errors // []) | length == 0)
  and .coverageByLanguage.dotnet > 0
  and .coverageLinesByLanguage.dotnet > 0
  and .coverageRatchet == "skipped:no-baseline"
  and .genericReport.legs[0].coverageMeasured == true
  and ((.warnings // []) | map(select(test("matched 1 file\\(s\\), merged 1 document\\(s\\)"))) | length == 1)
  and ((.warnings // []) | map(select(test("test-leg.*test-leg"))) | length == 0)' \
  "$OUT"

echo "mtp-byo-coverage: OK — MTP cobertura read, merged and measured"
