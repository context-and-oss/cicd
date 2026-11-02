# Intent: deliver a release's pin bump by pull request, because it cannot be pushed

## Why

`cd.yml` and `release.yml` both ended in `git push origin HEAD:main`. Two branch
rulesets on this repository refuse that, and not by accident of configuration:

- a branch-protection ruleset carries a `pull_request` rule
- The required-CI ruleset requires the status check named `ci` on the commit
  being pushed

A commit created and pushed in one motion can satisfy neither. There is no window
in which `ci` could have run against it, so no retry, no re-run and no permissions
change makes the push succeed. `cd.yml` therefore failed on every release from
2026-07-30 onward, 64 commits of merged work accumulated behind it, and `v1.11.0`
had to be tagged by hand. `release.yml` had never been used, so its identical dead
line had simply never been discovered.

So the bump arrives the way every other change to `main` arrives: on a branch, as
a pull request, merged by GitHub's auto-merge once `ci` passes.

## What changed

**One delivery, two callers.** `scripts/ci/deliver-release-pins.sh` holds the
mechanics — re-derive the bump against the live tip, run both bump scopes and the
coherence gate, generate the intent artifact, push a branch, open or reuse the
pull request, arm auto-merge. `cd.yml` and `release.yml` each call it. Two copies
of release mechanics is a drift this repository has already been bitten by:
`release.yml`'s hand-maintained module list went stale by its own comment, and the
version this change replaces still bumped only consumer-facing pins, so a manual
release would have left every `.github/workflows/` pin behind and never run the
gate that catches it.

The script reports one of four results and nothing quieter:

| result | meaning | caller |
|---|---|---|
| `pr-open` | branch pushed, pull request open, auto-merge armed | `cd.yml` stops; `release.yml` waits |
| `released` | pins on `main` already carry the target, and the tip is still the commit the version was computed for | tag and release |
| `superseded` | `main` already carries a tag at or above the target | `cd.yml` stops; `release.yml` fails |
| `stale` | pins carry the target but `main` moved past the commit the version was computed for | `cd.yml` stops; `release.yml` fails |

`stale` exists because the delivery resets to the live tip and the caller tags
whatever `HEAD` is. While the tip is the commit the version was computed for those
are the same commit; when `main` moved in between they are not, and the tag lands
on work no one weighed. That is not hypothetical: v2.2.3 was computed for a pins
merge and cut on a `refactor!` that landed fourteen seconds later, so a breaking
change shipped inside a patch — and the major it deserved could never be computed
again, because `git-cliff` saw nothing unreleased once the tag had swallowed it.
Refusing costs that version its number and nothing else: the run for the new tip
re-derives the bump over the full history and releases a version that accounts for
all of it. A tag on the wrong commit is not recoverable that way.

`released` is the seam that keeps the tag in the pipeline. The merge of the bump
pull request is a push to `main`, which runs CI, which runs CD, which finds the
pins already at the target and tags there. So `cd.yml` never waits and no runner
sits idle.

- `.github/workflows/cd.yml` — the 5.6 KB push step becomes a 793-byte caller.
  The tag and release steps now gate on `result == 'released'`. Release notes are
  generated *after* the delivery rather than before it, because the delivery
  resets to the live tip of `main` and `--unreleased` means "since the newest
  tag" — generated first, the notes described the checked-out `head_sha` while the
  tag pointed at the tip, so a commit landing in between was tagged but missing
  from its own release notes.
- `.github/workflows/release.yml` — rewritten as a real independent override. It
  shares the delivery but owns its tagging path, because an override that depended
  on `cd.yml` finishing the job would be useless in the situation it exists for.
  It also gains what it was missing: `persist-credentials: false` (it had the
  latent PAT-shadowing bug that failed the v1.2.0 release from `cd.yml`, and had
  only never hit it), the workflow bump scope, the coherence gate, `git-cliff`
  notes instead of `--generate-notes`, and `git add -A` is gone.
- `scripts/ci/wait-for-release-merge.sh` — `release.yml`'s bounded poll.
- `scripts/ci/write-release-intent.py` — generates the pull request's intent
  artifact.
- `scripts/tests/test_deliver_release_pins.py` (32),
  `scripts/tests/test_wait_for_release_merge.py` (15),
  `scripts/tests/test_release_intent.py` (21).

**The release generates a real intent artifact.** Every change to `main` must
carry one. The alternative was to widen the intent gate's one machine-origin
exemption to cover the release identity; rejected, because it would hand the
identity that can write `.github/workflows/` a documented way past the gate, and
that trust decision would be made where nobody is looking for it.

**The branch is `chore/release-v<version>`, not `release/v<version>`.** Both
rulesets condition on `["refs/heads/main", "refs/heads/release/**"]`, so a branch
under that prefix cannot be *created* by push either — a new branch carries no
check, so the attempt is refused with the same `GH013`. Nothing announces this:
the rejection names the violated rule and never says the branch name is what
pulled the ref into scope.

## Proof

Measured against the real repository, not reasoned about.

**The defect, captured from production while this change was being written.**
Merging the drift detector started a CD run on the old code, targeting the
same v1.12.0 this change rehearses. That run failed
with:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Required status check "ci" is expected.
 ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
```

and then advised the remedy this change deletes as wrong — "needs the release
identity on the ruleset bypass list". There is no bypass to add: the rule cannot
be satisfied from a push at all, by any identity that does not bypass it entirely.
So the diagnosis is not inference from the rulesets, it is the current behaviour of
the pipeline.

**The fix, in production, on the first run.** The next run — the
first execution of this code — bumped 26 consumer pins and 2 workflow pins,
passed the coherence gate, generated `specs/release-v1-12-0.md`, and **pushed
`chore/release-v1.12.0`**:

```
Bumped pins to v1.12.0 (scope=default, 26 file(s) changed, 86 already correct …)
Bumped pins to v1.12.0 (scope=workflows, 2 file(s) changed, 0 already correct …)
workflow/template pin check: OK
remote: Create a pull request for 'chore/release-v1.12.0' on GitHub by visiting:
```

The push that had been structurally impossible for four days succeeded,
carrying 29 files. That is the defect closed, measured on the real
repository.

The same run then failed, on something this change had not anticipated:

```
GraphQL: Resource not accessible by personal access token (repository.pullRequests)
```

`CICD_RELEASE_TOKEN` is a fine-grained PAT with Contents and Workflows write and
**no `pull_requests` permission at all**. So the delivery pushed a release branch
and could not open a pull request against it — and the diagnostic was GitHub's
sentence above, which names no remedy and does not mention the token's
permissions. Two things came out of it, both in this document's own doctrine: a
credential the API will refuse is knowable before anything is written, so it is
now probed first and the error names the permission to grant (`gh pr list --limit
1`, six tests in `TestCredentialPreflight`); and the probe proves *read* only,
because a fine-grained PAT grants Pull requests as read-only or read-and-write,
so a token stuck on read-only still fails later at `gh pr create` — stated here
rather than left for the next person to discover.

**The branch namespace, both directions.** A commit which has never had
a CI run, pushed to two refs:

```
$ git push origin HEAD:refs/heads/chore/release-v0.0.0-probe
 * [new branch]      HEAD -> chore/release-v0.0.0-probe          # accepted

$ git push origin HEAD:refs/heads/release/v0.0.0-probe
remote: error: GH013: Repository rule violations found for refs/heads/release/v0.0.0-probe.
remote: - Required status check "ci" is expected.
 ! [remote rejected] HEAD -> release/v0.0.0-probe               # refused
```

So the namespace trap is real and the chosen name clears it. Both probe refs were
deleted; `git ls-remote origin 'refs/heads/*probe*'` returns nothing.

**The classifier, against that real capture.** The stderr from the refused push
was fed to `scripts/ci/classify-push-rejection.sh`, which returned permanent (exit
1) rather than retryable, and the annotation builder lifted the remote's own words:
`Required status check "ci" is expected.` A ruleset refusal therefore fails once
with the cause, instead of being answered by five re-derives and a message naming
the retry.

**Auto-merge can actually fire.** Read from the live rulesets rather than assumed:
`required_approving_review_count: 0`, and the only required check is `ci`. Two
repository settings were flipped to make the design work — `allow_auto_merge`
false → true (without it `gh pr merge --auto` fails, which the delivery treats as
a failed release rather than a delivered one) and `allow_update_branch` false →
true, which matters because `strict_required_status_checks_policy` is `true`; see
Known residue.

**The intent artifact satisfies the real gate.** A genuine v1.12.0 bump was
rehearsed in a worktree: both bump scopes rewrote **28 files**, the coherence gate
passed, the generator produced `specs/release-v1-12-0.md`, and the resulting
37-file diff was run through the real `intent.Check` module:

```
passed=true  findingsCount=0
warnings: ["intent-gate: 1 artifact(s) checked, no violations"]
```

The gate scoped to exactly the generated artifact and judged it. The negative
control matters more: the identical bump with the artifact removed reports

```
passed=false  findingsCount=1
error presence | this change touches no intent artifact; every change must carry one
```

So the generator is load-bearing and proven, not passing because the gate was
asleep.

**The workflows are still inside the defended surface.** A throwaway
`uses: some-random-owner/evil-action@v1` inserted into the rewritten `release.yml`
makes `check-repo-surface.py` fail at `.github/workflows/release.yml:108` with the
startup-death explanation. Restored, all four gates pass:
`repository surface check: OK (126 active surfaces, 15 modules, 9 checks)`,
`workflow/template pin check: OK`, runtime image pins OK, ADO templates OK.

**Suites.** 352 script tests OK (68 new). 619 module unit tests across 9 modules.
Every `run:` body in both workflows is under 1.1 KB, well inside the 16 KiB
step-size budget — the largest step in either file shrank.

**One bug the tests caught before it shipped.** `wait-for-release-merge.sh` fell
through to its timeout exit when the budget expired while the pull request was
*unreadable*, reporting "not merged, auto-merge still armed" — a verdict about a
pull request the run had never managed to read. Unknown now has its own exit code.
That is the same class as the false passes this codebase already has doctrine for:
a check that could not look must never report a result as though it had.

## Decisions

**Auto-merge, not a waiting runner, for `cd.yml`.** GitHub does the waiting, the
merge happens the moment `ci` passes, and the only new state is one reversible
repository setting. The alternative — poll in the workflow — burns a runner for
the length of a CI run on every release and has to reimplement give-up
semantics.

**`release.yml` does wait, and owns its tag.** It is the path a human takes when
`cd.yml` is broken, so "come back later and hope another workflow finishes the
job" is not an override. The idle runner is the price of that, paid only on a
manual dispatch. The two tagging paths are kept from drifting by sharing the
delivery script and the notes generator; what is duplicated is the thin wiring,
not the mechanics.

**Refuse rather than arm auto-merge on a pull request nothing will check.** A pull
request opened by `GITHUB_TOKEN` triggers no workflow runs, so `ci` would never
report, auto-merge would never fire, and the release would sit open forever —
silent, which is the failure mode this whole change exists to remove. The delivery
reads the pull request's author back and exits non-zero if it is
`github-actions*`.

**Close superseded release pull requests, but only ones this script could have
created.** The branch name carries the version, so a target that moves opens a
second branch and orphans the first — and the orphan can never merge, because
`main` requires the branch to be up to date and has moved past it. Left alone,
every superseded release accumulates an open pull request proposing to downgrade
every pin. Closing is restricted to a branch matching the exact shape this script
creates *and* a title matching the exact string it writes *and* a strictly lower
version; anything else is reported and left alone, because a human working on a
similarly-named branch must not have their pull request closed by a bot
pattern-matching a name. A higher version is never closed either: whether this run
is the superseded one is the tag guard's decision, made against a real tag.

**Housekeeping warns; delivery fails.** A failure to close a stale pull request
must not fail a release that was already delivered — but it says what it left
behind, because a silent leak is how accumulation starts.

## Known residue

**A release cannot ship while `ci` is red on `main`, and that includes the
override.** The bump merges on `ci` and nothing else, so if CI itself is broken,
neither `cd.yml` nor `release.yml` can release — `release.yml` will deliver the
pull request and then time out waiting. This is deliberate (a release should not
ship past a broken CI) but it is a real limit on what "manual override" means: the
only remaining path is a human with a ruleset bypass. Before this change the
release identity was assumed to have such a bypass; it does not, which is what the
old remedy text in `cd.yml` wrongly advised adding.

**Strict required checks can stall a release pull request.**
`strict_required_status_checks_policy` is `true`, so a branch that falls behind
`main` cannot merge until it is updated, and GitHub's auto-merge is not guaranteed
to update it. Three things reduce the exposure and none of them closes it: the
delivery force-pushes a re-derived bump to the *same* branch name when the target
is unchanged, so a same-target advance heals itself; a moved target closes the
orphan; and `allow_update_branch` is now enabled. If this bites in practice the
real fix is a merge queue, not more retry logic. A stall is at least no longer
silent — the drift detector from `specs/report-release-drift.md` reports it.

**`cd.yml` tags the live tip of `main`, not the `workflow_run` head SHA.** The
delivery resets to the tip, so a commit that lands mid-release is included in the
tag. Pre-existing, and each such commit passed CI on its own; the notes-ordering
fix above at least makes the release notes describe the tree that was tagged.

**Nothing proves the end-to-end path on this pull request.** The delivery is
driven by stub `git` and `gh` across every branch, and the pieces that touch the
real repository (the ruleset probes, the bump, the intent gate) were run for real
— but no CI job opens a release pull request, and none should. The first genuine
proof is the next release, and the drift detector is already watching for it not
happening.

**A re-run whose tag already exists fails loudly rather than being handled.** Both
workflows will fail at `git tag` if the version is already tagged. That is the
correct answer to "release a version that exists", but it reads as a broken
pipeline rather than as a rejected request.
