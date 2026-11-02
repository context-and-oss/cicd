# Intent: notice that releases have stopped, from outside the release pipeline

## Why

`cd.yml` failed on every run from 2026-07-30 to 2026-08-04 and nothing said so.
Sixty-four commits of merged, CI-witnessed work accumulated behind it, `v1.10.0`
stayed the newest tag for five days, and every signal a human actually looks at
stayed green: CI passed on `main`, every PR check list was green, and the only
evidence was a red run in a tab nobody had reason to open. The gap was found by
asking "so release up?", not by anything in this repository.

That is the same failure class this codebase already has doctrine for, one level
up. `src/quality` and `src/security` distinguish "the tool ran and found nothing"
from "the tool never ran", because a scanner that could not execute reports zero
findings exactly like a clean tree. A release pipeline that could not run reports
no new tag exactly like a repository with nothing to release. **A release pipeline
that could not run must never read as "nothing to release."**

The obvious fix — a notification step inside `cd.yml` on failure — does not work
here, and the reason is on the record. Under this repository's `selected` Actions
policy a disallowed action does not fail its step: GitHub refuses the workflow at
*startup*, so no job is created and no check run is published. `ci.yml` and
`cd.yml` sat dead that way for four days while PRs merged on a check list that
never mentioned them. A step inside CD cannot report that CD never started. The
detector has to be a separate workflow that assumes nothing about CD having run.

## What changed

A scheduled workflow that measures one thing: is `main` ahead of the newest tag,
and for how long?

- `.github/workflows/release-drift.yml` — new. `schedule` at 06:10 UTC daily plus
  `workflow_dispatch` with `threshold-days` and `dry-run` inputs. Checks out with
  `fetch-depth: 0`, installs git-cliff through the existing local
  `.github/actions/install-git-cliff` (a third-party action here would kill the
  run at startup, which is the failure this workflow exists to catch), and runs
  the script. `permissions: contents: read, issues: write, actions: read`.
- `scripts/release_drift.py` — new. The logic: `measure()`, the pure predicates
  `is_drifting`/`drift_age_days`/`decide_action`, the title and body renderers,
  and `check()`, which ties them together. Every command goes through an injected
  `runner` callable, which is what makes the failure modes testable.
- `scripts/check-release-drift.py` — new. The thin dashed CLI over that module,
  the same split `check-repo-surface.py` has over `repo_surface.py`.
- `scripts/tests/test_release_drift.py` — new, 51 cases.
- `scripts/repo-inventory.json` — the new workflow declared under
  `active_surfaces.internal_workflows`, which is what puts it inside the
  step-size, local-link and action-trust checks.

Drift requires *both* a version difference and commits after the tag, and neither
implies the other: a backlog of `chore:` commits bumps no version and would
otherwise open an issue no release could ever close, while git-cliff computing a
version on an empty range would flag a released tree. Past the threshold the run
opens one issue labelled `release-drift`, keeps it accurate while drift persists,
and **closes it when a release lands** — the issue closing itself is the signal.

## Proof

Measured, not predicted. Both real states were driven against this repository's
actual history with git-cliff 2.13.1, the version `install-git-cliff` pins:

- before the `v1.11.0` tag was fetched, exactly the state that went unnoticed:
  `tag=v1.10.0 next=v1.11.0 ahead=64 age=4.8d drifting=True action=open`
- with the tag present: `tag=v1.11.0 next=v1.11.0 ahead=0 age=0.0d
  drifting=False action=none`

Every command whose answer feeds the verdict was driven in its failing form, and
each one exits 1 rather than reporting clean — two of them against real tooling
rather than a fake:

- a genuine `git clone --depth 1` → `shallow clone: tags and commit counts are
  truncated … Check out with fetch-depth: 0`, exit 1. A shallow clone gets every
  number wrong in the direction that hides drift, so it is refused rather than
  under-reported.
- `git-cliff` off `PATH` → `command failed (exit 1): git cliff --bumped-version`,
  exit 1.
- git-cliff exiting 0 with empty output, an unparseable commit count, a commit
  stamp that is not an epoch, a counted range git log lists as empty, and an
  unreadable issue list all raise rather than return a report, because every
  report reads as a verdict.

`gh run list` is the one command allowed to degrade to a note: the CD-run summary
is context printed into the issue body, never an input to the verdict.

The new workflow is genuinely inside the defended surface, not merely listed in
it: a throwaway `uses: some-random-owner/evil-action@v1` inserted into it makes
`check-repo-surface.py` fail with the startup-death explanation and name the line.
All four surface gates pass (`repository surface check: OK (126 active surfaces,
15 modules, 9 checks)`), and the full script suite is 284 tests OK.

## Decisions

**Report by issue, not by red run, and exit 0 either way.** A scheduled workflow
that is permanently red while a backlog persists becomes furniture within a week,
and the thing being reported is not a build failure — it is a state of the
repository. An issue is durable, has one home, accumulates the history of how long
the drift lasted, and closes itself. The alternative considered was a Teams card
through the `notify` module; rejected because no webhook secret exists in this
repository and `notify` is aimed at consumer pipelines, so it would mean adding a
credential to serve one internal alert.

**Two days before reporting.** Below the threshold, drift is just the normal
window between a merge and the release that picks it up, and an issue opened
there is noise. An issue that is already open is updated regardless of age,
though: the threshold exists to avoid opening one, not to let one that exists go
stale and under-report the backlog.

**One issue, lowest number wins, duplicates named.** If somebody opens a second
issue under the label, the script keeps maintaining the older one and prints which
others it left alone, rather than picking silently or fanning out.

## Known residue

**A scheduled workflow is disabled after 60 days of repository inactivity.** That
is GitHub behaviour, not something this workflow can defend against, and it is the
one way this detector can go quiet the way `cd.yml` did. It is a low risk while the
repository is active — and an inactive repository has no drift to report — but the
detector is not self-witnessing: nothing checks that it ran.

**Nothing proves this in CI on this pull request.** A `schedule` trigger only ever
runs from the default branch, so the workflow itself cannot execute until it is on
`main`; the proof above is local plus the unit suite. Confirming the wiring means
one `workflow_dispatch` with `dry-run: true` after merge.

**There is no snooze.** A deliberately held release will have its issue reopened by
the next run, because the drift is real and the script has no way to distinguish
"held on purpose" from "nobody noticed". Raising `--threshold-days` only affects a
manual dispatch, not the schedule.

**This detects the symptom, not the cause.** `cd.yml` and `release.yml` both still
end in a `git push origin HEAD:main` that the branch rulesets refuse — see
`specs/release-v1-11-0-by-pull-request.md`. This change is deliberately first, so
the detector is live before release mechanics change, and it will report the same
drift again if the repair to those workflows regresses.
