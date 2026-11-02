# Intent: cut a release by pull request, because the release job cannot push to main

Written for v1.11.0, the release that found the problem; every release since
follows the same path.

## Why

`cd.yml` has not produced a release since v1.10.0. Every run reaches the tag step
and dies one line earlier, at `git push origin HEAD:main` in the `Commit and push
bumped pins` step:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Required status check "ci" is expected.
remote: ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
```

Two active rulesets govern `main`, and each one alone is fatal to that push:

- a branch-protection ruleset (rules `pull_request`,
  `non_fast_forward`, `deletion`) requires every
  change to arrive through a pull request.
- The required-CI ruleset (rule `required_status_checks`) requires the check named `ci` on the commit being pushed.

The release commit is created and pushed in one motion, so it can never carry a
passing check — there is no window in which CI could have run on it. This is not a
misconfiguration to repair inside the job and it is not a missing bypass grant: a
direct-push release is structurally incompatible with a required status check on
the target branch. Waiting for the automation to be redesigned would leave 46
commits of merged, CI-witnessed work unreleased, so the pin bump arrives here the
way every other change to `main` arrives.

## What changed

Nothing but version pins, and only in the files the release bumper owns:

- `python3 scripts/bump-version.py 1.11.0` — 26 files, the consumer-facing
  surfaces the default token may push (module READMEs, `templates/github-actions/`,
  `templates/azure-devops/`, `templates/local/scripts/cicd-prepush`).
- `python3 scripts/bump-version.py 1.11.0 --scope workflows` — 2 files,
  `.github/workflows/commit.yml` and `.github/workflows/precommit.yml`. These are
  scoped separately because GitHub refuses a push touching `.github/workflows/`
  unless the credential carries the `workflow` scope, which the default token
  cannot be granted through any `permissions:` key.

28 files, 90 insertions, 90 deletions, every one a `v1.10.0` → `v1.11.0` pin. No
source file, module contract or workflow logic is touched.

## Proof

- `python3 scripts/check-workflow-pins.py` reports `OK (managed paths present,
  pins consistent, all called commands exist)`. This is the release-blocking
  coherence gate — the guard that caught the historical `commit-archive@v1.0.0`
  command skew, where a pin advanced past a command that no longer existed.
- The diff was filtered for any line that is not a version pin, and it is empty.
- `git cliff --bumped-version` (2.13.1, the version `.github/actions/install-git-cliff`
  pins, run locally against a checksum-verified binary) computes `v1.11.0`
  independently. The number is not chosen by hand.
- The same bump was rehearsed in a throwaway worktree off `origin/main` before this
  branch existed, so the numbers above were measured rather than predicted.

## Decisions

**The pins land by PR; the tag still comes from CD.** The alternative was to push the
tag and create the release from a workstation, which would work — neither ruleset
targets `refs/tags`. It was rejected because a hand-cut tag is a release no pipeline
witnessed. `cd.yml` already handles this case on purpose: when `bump_and_validate`
finds the pins already at the target version, `git diff --quiet` succeeds and the
step sets `released=true` with the comment "Pins already at target … fall through so
the tag is cut". That branch exists for a re-run whose pin push landed and whose tag
push failed; a pin bump that arrived by PR is the same state reached a different way.
So after this merges, CI runs on `main`, CD fires on CI success, finds nothing to
bump, and tags `v1.11.0` with git-cliff notes generated in CI. Cutting the tag by
hand stays the fallback if that run fails for an unrelated reason.

**This change does not repair the automation.** `cd.yml` and `release.yml` both still
end in a push to `main` and will both still fail on the next release for exactly the
reason above. Making automated releases work again means having those workflows open
a pull request and merge it — viable, because `required_approving_review_count` is 0
on the required-CI ruleset, so a bot's own PR can self-merge. That is a change to
release mechanics with its own failure modes (a self-merging bot that can reach
`main`, a PR that goes stale mid-release, a partial release leaving a merged pin bump
with no tag), so it needs its own change, its own spec and its own proof. Doing it in
the same breath as a release that is already 46 commits overdue would mean shipping
untested release machinery as part of the release it is meant to perform.

**No intent-gate escape hatch was added for release commits.** The gate correctly
rejects a diff carrying no intent artifact, and a release is a decision, so it gets a
document like anything else. The module has one machine-origin exemption
(`dependabotActionsPin`) and widening it to cover release bumps would hand the
release identity a way past the gate — a larger trust decision than this change
warrants, and one that would be made while nobody is looking for it.

## Known residue

**`release/**` is a protected namespace, so a release branch must not be named that.**
Both rulesets above condition on `["refs/heads/main", "refs/heads/release/**"]`, not on
`main` alone. The first attempt at this change pushed a branch called
`release/v1.11.0` and was refused with the same `GH013 … Required status check "ci" is
expected` that blocks the release job — a new branch has no checks either, so a branch
under that prefix cannot be created by push at all. The name here is deliberately
outside the pattern. Nothing announces this: the rejection names the rule but not the
fact that the branch name is what put the ref in scope.

**A release still takes a human at two points**: opening this PR, and confirming the
CD run that follows actually tagged. Until the workflows are redesigned, a release
that is not watched is a release that silently does not happen — which is precisely
how the gap since v1.10.0 opened. Nothing currently alerts on "CI passed on main and
CD failed", so the failure mode that produced this backlog can recur unobserved.

**The rejected-push classifier does not cover this case yet.** The work merged in
`specs/classify-a-refused-release-push.md` explains a push refused because `main`
advanced. A push refused by a repository rule is a different cause with a different
remedy, and the retry loop treats them alike: it burns all five attempts
re-deriving a bump against a tip that was never the problem, then reports "failed to
push version pins after 5 attempts" — accurate, and silent about the rule that
actually declined it.
