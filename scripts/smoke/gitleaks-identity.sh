#!/usr/bin/env bash
# gitleaks-identity.sh — proves the commit author gitleaks' history leg writes
# into its SARIF never reaches the evidence envelope.
#
# --redact keeps the secret out of gitleaks' report and nothing kept the
# person out: every history result carries partialFingerprints.author, .email
# and .commitMessage. src/security/gitleaksidentity.go keeps only commitSha and
# date; gitleaksidentity_test.go drives it on a hand-written report, and this
# script is the proof that a real history leg passes through it.
#
# The history result survives into the envelope only where the tree leg did not
# already report the same location (mergeGitleaksSARIF), so the probe commits
# a credential and then deletes it: the tree is clean and history is the only
# leg that sees it. The identity is fictitious and set per command, so no
# git config is read or written. The key is assembled at run time, as in
# semgrep-redaction.sh, so no credential-shaped string is committed here.
#
# Two assertions. The positive control: a gitleaks result names the probe's
# first commit, so the second cannot pass by the history leg not running. The
# second reads the serialised envelope, not a parsed field.
#
# Usage: bash scripts/smoke/gitleaks-identity.sh
# Env (supplied by the module-test job): MODULE, SHA, BRANCH, REPO.
set -euo pipefail

MODULE="${MODULE:-src/security}"
SHA="${SHA:-local}"
BRANCH="${BRANCH:-main}"
REPO="${REPO:-https://example.com}"

OUT=/tmp/evidence-gitleaks-identity.json
probe=$(mktemp -d)
trap 'rm -rf "${probe:?}"' EXIT

name="Cicd Identity Probe"
email="cicd.identity.probe@example.invalid"
subject="cicdidentityprobe subject"
commit() {
  GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" \
    GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email" \
    git -C "$probe" -c commit.gpgsign=false commit -q -m "$1"
}

git -C "$probe" init -q
printf 'TOKEN=%s\n' "ghp_""Zq8Lm3Vt7Rk2Wp9Xs4Nb6Hc1Jd5Fg0Ya8Ue" > "$probe/cfg.env"
git -C "$probe" add cfg.env
commit "$subject"
leaked=$(git -C "$probe" rev-parse HEAD)
git -C "$probe" rm -q cfg.env
commit "remove cfg"

dagger -m "./$MODULE" call scan-source --src "$probe" --fail-on NONE \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path "$OUT"

if ! jq -e --arg sha "$leaked" '[.sarifReport.runs[]?
      | select(.tool.driver.name == "gitleaks")
      | .results[]?
      | select(.partialFingerprints.commitSha == $sha)] | length > 0' "$OUT" >/dev/null; then
  echo "FAIL: no gitleaks history result names the probe commit, so the check below would prove nothing" >&2
  exit 1
fi
for leak in "$name" "$email" "$subject"; do
  if ! jq -e --arg v "$leak" 'tostring | contains($v) | not' "$OUT" >/dev/null; then
    echo "FAIL: the probe commit's identity ($leak) survives into the evidence envelope" >&2
    exit 1
  fi
done
echo "PASS: gitleaks history reported the probe commit and its author, email and subject appear nowhere in the envelope"
