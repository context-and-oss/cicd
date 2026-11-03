#!/usr/bin/env bash
# Deliver a release's version-pin bump to main by pull request.
#
# Deliver pins on a branch and pull request so the destination's effective
# review and required-CI rules apply. Auto-merge supplies no human approval.
# Both release workflows share this implementation to avoid divergent bump,
# validation and delivery mechanics. See specs/release-by-pull-request.md.
#
# Usage:  deliver-release-pins.sh <version> <source-workflow>
#           version          semver without a leading v, e.g. 1.12.0
#           source-workflow  cd.yml | release.yml — recorded in the artifact
#
# Requires: cwd at the repository root; `origin` already carrying a credential
# with Contents + Workflows write (every release rewrites .github/workflows/
# pins, which no `permissions:` key can authorise); GH_TOKEN set to that write
# identity for `gh`; RELEASE_VERIFY_TOKEN set to the workflow's GitHub App token
# with Pull requests and Checks read for delivered-PR verification; and
# the check named `ci` actually required on main — asserted rather than assumed
# by scripts/release_gate.py.
#
# Result, on the last stdout line and appended to $GITHUB_OUTPUT when set:
#   result=released    pins on main are already at the target — the caller tags
#   result=pr-open     a pull request is open with auto-merge armed; the tag is
#                      cut by the release run that follows the merge
#   result=superseded  main already carries a tag >= the target; do nothing
#   result=stale       main moved past the commit this version was computed for;
#                      do NOT tag -- the run for the new tip releases instead.
#                      Main is left pinned to an uncut version by construction,
#                      so this path exits NON-ZERO when nothing is going to cut
#                      it (scripts/check-release-handoff.py decides); the result
#                      is emitted either way.
# Any other outcome exits non-zero. There is no fifth, quieter answer: a
# release that could not be delivered must never read as a release that was.
set -euo pipefail

VERSION="${1:?"usage: deliver-release-pins.sh <version> <source-workflow>"}"
SOURCE="${2:?"usage: deliver-release-pins.sh <version> <source-workflow>"}"

if ! printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "::error::'$VERSION' is not semver X.Y.Z" >&2
  exit 2
fi

# Use a delivery branch outside a potentially protected release/** namespace.
# A new branch carries no prior check, so a creation rule can reject it even
# though the intended final merge is a pull request. Read effective rules and
# refusals rather than assuming a branch prefix is exempt.
BRANCH="chore/release-v${VERSION}"
TITLE="chore(release): bump version pins to v${VERSION}"

emit() {
  echo "result=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "result=$1" >> "$GITHUB_OUTPUT"
  fi
}

# Never let a push credential reach the log through a message that echoes the
# remote URL. Actions masks registered secrets and git anonymises URLs in most
# diagnostics; this belt costs one sed.
redact() {
  sed -E 's#(x-access-token:)[^@]*@#\1***@#g' "$1" >&2
}

bump_and_validate() {
  python3 scripts/bump-version.py "$VERSION"
  python3 scripts/bump-version.py "$VERSION" --scope workflows
  # The release-blocking coherence gate: every managed pin must agree on one
  # version and every command a workflow or template calls must still exist in
  # its module source. Run against live main below so a merge landing during
  # delivery cannot leave new pinned content or a removed command unchecked.
  python3 scripts/check-workflow-pins.py
}

push_log=$(mktemp)
changed_list=$(mktemp)
pr_body=$(mktemp)
preflight_log=$(mktemp)
trap 'rm -f "$push_log" "$changed_list" "$pr_body" "$preflight_log"' EXIT

# The Checks API's fine-grained auth contract supports App tokens, not
# fine-grained personal access tokens. Require a verifier before writes; never fall back
# to the writer if it is missing. Only the delivered-PR readback uses it, so the
# branch preflight still asks about the actual release identity's capabilities.
if [ -z "${RELEASE_VERIFY_TOKEN:-}" ]; then
  echo "::error::RELEASE_VERIFY_TOKEN is required for delivered-PR verification. Pass the workflow GITHUB_TOKEN with Pull requests and Checks read. Nothing was pushed." >&2
  exit 1
fi

# Probe pull-request access before a branch can be written. Contents/Workflows
# write alone does not grant Pull requests access; discovering that only after
# push would leave a release branch without a delivery PR. This read probe does
# not prove that later mutating API calls or verifier requests will succeed.
#
# This asks the cheapest question needing the same permission. It proves READ
# only: a fine-grained PAT grants Pull requests as read-only or read-and-write,
# so a token stuck on read-only still fails later at `gh pr create`. Catching the
# common case before anything is pushed is worth one API call anyway.
if ! gh pr list --limit 1 --json number >"$preflight_log" 2>&1; then
  detail=$(sed -E 's#(x-access-token:)[^@]*@#\1***@#g' "$preflight_log" | tr '\n' ' ')
  echo "::error::the release credential cannot read this repository's pull requests, so a bump could be pushed but never delivered. GitHub said: ${detail}Grant CICD_RELEASE_TOKEN 'Pull requests: Read and write' (fine-grained PAT) or the 'repo' scope (classic PAT); it already needs Contents and Workflows write. Nothing was pushed." >&2
  exit 1
fi

# The second preflight, and it asks whether this script's central claim is even
# true. Everything below is built on `ci` being a required status check on main:
# the pull request body says so, auto-merge depends on it, and the tag cut
# afterwards inherits whatever trust it confers. Without a required check,
# auto-merge can merge immediately and CI can become green only afterward.
# That later success is not evidence that the merge was gated.
#
# This runs on every path, including the `released` path that only tags: a tag
# cut from an ungated main is the same false pass one step further along. There
# is deliberately no override flag — an escape hatch here is how the claim rots
# again, quietly.
python3 scripts/check-release-gate.py --branch main

# Re-derive the bump against the LIVE tip of main on each attempt, rather than
# rebasing a commit built on a stale tree: that way any newly merged pinned
# content is bumped too, so the coherence gate sees the real set before the push
# rather than after.
# The commit this run's version was computed for. cd.yml checks the job out at
# `workflow_run.head_sha` -- the commit whose CI completed -- and next-version
# ran git-cliff against exactly that tree. The reset below moves HEAD to the live
# tip, which is right for re-deriving pins and wrong for deciding what to tag, so
# the original has to be remembered before it is lost.
COMPUTED_SHA=$(git rev-parse HEAD)

for attempt in 1 2 3 4 5; do
  git fetch --quiet origin main
  git reset --hard FETCH_HEAD

  # Two merges landing seconds apart spawn two release runs that can compute
  # different targets (a fix bumps patch, a feat bumps minor). They serialize on
  # the workflow's concurrency group, so by the time this run reaches the tip
  # another may already have released a newer tag. Without this guard, the
  # superseded run would rewrite every pin downward and tag a lower version.
  # The same refusal cd.yml makes before computing a version: a clone with no
  # reachable tag is an unbootstrapped copy. A fallback attached to a pipeline's
  # final command can hide an earlier failure and leave latest empty; refuse
  # instead of comparing against an unknown baseline.
  if ! tag=$(git describe --tags --abbrev=0 2>/dev/null) || [ -z "$tag" ]; then
    echo "::error::no v* tag is reachable from HEAD. A copy carrying pins must be bootstrapped with the tag those pins name before a release can be delivered (CONTRIBUTING.md, 'Bootstrapping a fresh copy')." >&2
    exit 1
  fi
  latest=${tag#v}
  greater=$(printf '%s\n%s\n' "$latest" "$VERSION" | sort -V | tail -1)
  if [ "$VERSION" = "$latest" ] || [ "$greater" = "$latest" ]; then
    echo "::notice::main is already at v${latest} (>= target v${VERSION}) — superseded by another release run."
    emit superseded
    exit 0
  fi

  bump_and_validate

  if git diff --quiet; then
    # Pins on main already carry the target. Either the bump PR from an earlier
    # run has merged (the normal path — this is the run that tags), or a re-run
    # whose pin delivery landed and whose tag push failed. Both want the tag.
    #
    # The caller tags HEAD, now reset to live main. That must equal the commit
    # whose changes determined this version; otherwise a later breaking change
    # could be swallowed by a patch tag and disappear from unreleased history.
    #
    # Refusing the moved tip is necessary but leaves main pinned to an uncut
    # version: this branch has no remaining pin diff and no tag at the target.
    # A successor release run must repair that handoff. Verify it instead of
    # assuming CI on the new tip can run. See specs/verify-the-release-handoff.md.
    tip=$(git rev-parse HEAD)
    if [ "$tip" != "$COMPUTED_SHA" ]; then
      echo "::warning::main moved from ${COMPUTED_SHA} to ${tip} while v${VERSION} was being delivered, so this run's version no longer accounts for everything on main. Nothing was tagged, and main is pinned to v${VERSION} until some later run cuts it."
      # Emitted before the check so the caller learns the tagging verdict either
      # way. `stale` is correct whatever the handoff turns out to be -- the two
      # are different questions, and conflating them would let a broken handoff
      # argue this run into tagging the wrong commit.
      emit stale
      # $GITHUB_RUN_ID is this CD run. Without excluding it the check finds its
      # own in-flight run and reports that the successor it is looking for has
      # already arrived.
      # `if cmd; then` would swallow the exit code -- an if-statement whose
      # condition failed and that has no else reports 0 itself, so `$?` after
      # `fi` is the if's status, not the script's. Three answers have to be
      # told apart here, so the code is captured directly.
      rc=0
      python3 scripts/check-release-handoff.py \
        --exclude-run-id "${GITHUB_RUN_ID:-}" || rc=$?
      if [ "$rc" = "0" ]; then
        exit 0
      fi
      if [ "$rc" = "2" ]; then
        echo "::warning::could not establish whether anything is going to cut v${VERSION}; release-drift.yml asks again on its schedule." >&2
        exit 0
      fi
      # Nothing is coming to repair the unresolved pins. The check names the
      # stranded run and remedy; fail now rather than waiting for a scheduled
      # sweep while this delivery appears healthy.
      exit 1
    fi
    echo "Pins already at v${VERSION}; nothing to deliver — the caller tags."
    emit released
    exit 0
  fi

  git diff --name-only > "$changed_list"
  # Every change to main must carry an intent artifact; the gate rejects a diff
  # that touches none. Generated rather than exempted — widening the gate's
  # machine-origin exemption to cover the release identity would hand the
  # identity that writes .github/workflows/ a way past the gate.
  artifact=$(python3 scripts/ci/write-release-intent.py "$VERSION" \
    --changed-from "$changed_list" --source "$SOURCE")

  # Stage tracked modifications and the artifact by name. `git add -A` could
  # sweep untracked build output into the release commit.
  git add -u
  git add "$artifact"
  git commit -q -m "$TITLE"

  # Learn the remote branch's current value, if any, so the push below can take
  # a lease rather than clobbering blind. Absent on a first delivery, which is
  # why this may fail.
  git fetch --quiet origin "refs/heads/${BRANCH}:refs/remotes/origin/${BRANCH}" 2>/dev/null || true

  if git push --force-with-lease --quiet origin "HEAD:refs/heads/${BRANCH}" 2>"$push_log"; then
    redact "$push_log"
  else
    redact "$push_log"
    if bash scripts/ci/classify-push-rejection.sh "$push_log"; then
      # A retryable rejection: the branch moved under us. Re-derive against the
      # tip and try again rather than force past whatever landed.
      echo "::warning::push of ${BRANCH} rejected on attempt ${attempt} — re-deriving against the new tip."
      continue
    fi
    reason=$(awk '/^remote: - /{sub(/^remote: - /,""); gsub(/[[:space:]]+$/,""); if ($0 != "") { printf "%s%s", sep, $0; sep="; " }}' "$push_log")
    echo "::error::push of ${BRANCH} was refused for a reason no retry can satisfy.${reason:+ Remote says: $reason} Check, in this order: (1) inspect effective branch-creation rules — a prefix such as refs/heads/release/** may be protected; do not assume a branch-name change waives policy; (2) CICD_RELEASE_TOKEN still grants Contents + Workflows write, since every release rewrites .github/workflows/ pins." >&2
    exit 1
  fi

  # Reuse an open pull request for this branch rather than opening a second one.
  # A re-run after a failed release would otherwise leave two PRs racing to
  # merge the same bump.
  existing=$(gh pr list --head "$BRANCH" --state open --json number --jq '.[0].number // empty')
  if [ -n "$existing" ]; then
    echo "Reusing open pull request #${existing} for ${BRANCH}."
  else
    {
      echo "Bumps every managed version pin to \`v${VERSION}\`, delivered by \`${SOURCE}\`."
      echo
      echo "Pins are delivered by pull request so effective branch and review"
      echo "policy applies. The preflight verified that \`ci\` is required. See"
      echo "\`specs/release-by-pull-request.md\`."
      echo
      echo "The rationale artifact for this bump is \`${artifact}\`. The coherence gate"
      echo "(\`scripts/check-workflow-pins.py\`) passed against the live tip of \`main\`"
      echo "before this branch was pushed. That is automated evidence, not a human review."
      echo
      echo "Auto-merge is requested; it supplies no approval. This request still needs"
      echo "\`ci\` and every applicable check and review requirement to be satisfied."
      echo "After the merge, successful CI/CD must verify the pins before tagging."
    } > "$pr_body"
    gh pr create --base main --head "$BRANCH" --title "$TITLE" --body-file "$pr_body"
    existing=$(gh pr list --head "$BRANCH" --state open --json number --jq '.[0].number // empty')
  fi

  # A pull request opened by the Actions default token triggers no workflow runs,
  # so `ci` would never run, auto-merge would never fire, and the release would
  # sit as an open pull request forever — silent, which is the failure mode this
  # whole change exists to remove. The release PAT is what makes the checks run,
  # so refuse rather than arm auto-merge on a request nothing will ever check.
  author=$(gh pr view "$existing" --json author --jq '.author.login')
  case "$author" in
    github-actions*)
      echo "::error::pull request #${existing} was opened by '${author}', the Actions default token. A pull request it creates triggers no workflow runs, so the check named 'ci' will never run and auto-merge will never fire. Pass CICD_RELEASE_TOKEN as GH_TOKEN for this step." >&2
      exit 1
      ;;
  esac

  # GitHub can wait for applicable CI and review requirements without an idle
  # runner. Capability to bypass a rule is not approval to do so; requesting
  # auto-merge neither supplies a review nor proves the merge will complete.
  # Re-requesting auto-merge on an already-armed PR is a no-op.
  gh pr merge --auto --merge "$BRANCH"

  # Now prove what the body above asserts, because this command does not.
  # `gh pr merge --auto` cannot arm auto-merge on a request that is already
  # mergeable: it merges it on the spot, exits 0, and reports which of the two
  # happened nowhere. Both outcomes are legitimate — armed and waiting, or merged
  # on a head commit `ci` had already passed — and exactly one third outcome is
  # not: merged with nothing having examined it. That third one is what the
  # branch preflight above now prevents, and this is the assertion that catches
  # it if it is ever reachable by some other route.
  # Scope the App credential to this read-only verifier. All subsequent PR
  # writes still use the release identity; a failed readback remains a failure.
  GH_TOKEN="$RELEASE_VERIFY_TOKEN" \
    python3 scripts/check-release-gate.py --delivered-pr "$existing"

  # Close release pull requests for LOWER versions. The branch name carries the
  # version, so a target that moves (a `feat:` landing while a patch release is
  # waiting) opens a second branch and leaves the first one open forever — and it
  # can never merge, because `strict_required_status_checks_policy` requires the
  # branch to be up to date with main and main has moved past it. Left alone these
  # accumulate as open pull requests proposing to downgrade every pin.
  #
  # Only ever a branch matching the exact shape this script creates, and only a
  # strictly lower version. A higher one is reported and left alone: this run
  # would be the superseded one, and the tag guard above is what decides that, not
  # a branch name.
  #
  # Housekeeping, so a failure here warns rather than failing a release that has
  # already been delivered — but it says what it could not clean up, because a
  # silent leak is how the accumulation starts.
  stale=$(gh pr list --state open --json number,headRefName,title \
    --jq '.[] | select(.headRefName | test("^chore/release-v[0-9]+\\.[0-9]+\\.[0-9]+$")) | [.number, .headRefName, .title] | @tsv' \
    || echo "")
  while IFS=$'\t' read -r number head title; do
    [ -n "${number:-}" ] || continue
    [ "$head" != "$BRANCH" ] || continue
    other="${head#chore/release-v}"
    if [ "$title" != "chore(release): bump version pins to v${other}" ]; then
      echo "::warning::left open pull request #${number} (${head}) alone — its title is not the shape this script creates, so it may be a human's branch."
      continue
    fi
    highest=$(printf '%s\n%s\n' "$other" "$VERSION" | sort -V | tail -1)
    if [ "$other" = "$VERSION" ] || [ "$highest" = "$other" ]; then
      echo "::warning::open pull request #${number} proposes v${other}, at or above this run's v${VERSION}. Left alone — that is the tag guard's decision, not this cleanup's."
      continue
    fi
    if gh pr close "$number" --comment "Superseded by the v${VERSION} release. This branch proposes v${other}, which is now behind, and it cannot merge anyway: main requires the branch to be up to date and has moved past it." >/dev/null; then
      echo "::notice::closed superseded release pull request #${number} (v${other})."
    else
      echo "::warning::could not close superseded release pull request #${number} (v${other}) — close it by hand, or it will sit open proposing a pin downgrade."
    fi
  done <<< "$stale"

  emit pr-open
  exit 0
done

echo "::error::could not deliver the v${VERSION} pin bump in 5 attempts — every push of ${BRANCH} was rejected as out of date. Re-run this release." >&2
exit 1
