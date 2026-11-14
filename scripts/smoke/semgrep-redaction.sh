#!/usr/bin/env bash
# semgrep-redaction.sh — proves the matched source semgrep copies into its
# SARIF never reaches the evidence envelope.
#
# semgrep writes the whole matched line into region.snippet.text, and
# p/security-audit's generic.secrets rules match exactly the line holding a
# credential. So the raw key reached the envelope through SAST while gitleaks'
# --redact kept it out of the secrets leg. src/security/semgrepredact.go
# withholds it; semgrepredact_test.go drives that function on a hand-written
# report, and this script is the proof that the real semgrep's output passes
# through it.
#
# No committed fixture can do this. The rule refuses any match containing
# example, sample, test or fake, and every credential under testdata/ carries
# one of those words — which is why no CI cell ever saw the leak. A key the
# rule does match would be a credential-shaped string in the repository, so the
# probe key is assembled here, at run time, and never exists as one string in
# any committed file.
#
# Two assertions. The first is the positive control: semgrep reported the AWS
# rule on the probe file, so the second cannot pass by matching nothing. The
# second reads the serialised envelope, not a parsed field — the field that
# leaks is the one nobody thought to parse.
#
# Usage: bash scripts/smoke/semgrep-redaction.sh
# Env (supplied by the module-test job): MODULE, SHA, BRANCH, REPO.
#
# It lives in a script rather than inline in .github/workflows/ci.yml because a
# `run:` body over the step budget makes GitHub refuse the workflow at STARTUP —
# no job, no check run. See docs/reference/workflow-step-size.md.
set -euo pipefail

MODULE="${MODULE:-src/security}"
SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

OUT=/tmp/evidence-semgrep-redact.json
probe=$(mktemp -d)
trap 'rm -rf "${probe:?}"' EXIT

key="AKIA""CICDREDACTPROBE0"
printf 'AWS_ACCESS_KEY_ID=%s\n' "$key" > "$probe/deploy.env"

dagger -m "./$MODULE" call scan-source --src "$probe" --fail-on NONE \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$OUT"

if ! jq -e '[.sarifReport.runs[]?
      | select(.tool.driver.name | test("opengrep"; "i"))
      | .results[]?
      | select(.ruleId | endswith("detected-aws-access-key-id-value"))] | length > 0' "$OUT" >/dev/null; then
  echo "FAIL: opengrep did not report the probe key, so the redaction check below would prove nothing" >&2
  exit 1
fi
if ! jq -e --arg key "$key" 'tostring | contains($key) | not' "$OUT" >/dev/null; then
  echo "FAIL: the probe key survives into the evidence envelope" >&2
  exit 1
fi
echo "PASS: opengrep matched the probe key and it appears nowhere in the envelope"
