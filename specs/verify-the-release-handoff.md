# Verify the release handoff

## Why

On 2026-09-10 `main` carried thirteen dangling `@v3.2.2` pins for roughly forty
minutes. Every signal in the repository was green while it did, including the
run that created the state.

The chain: a release pull request merged, bumping every pin to
`v3.2.2`. Sixteen minutes later the merge drain landed a feature, so
`main` moved. The CD run for the release merge reached
`scripts/ci/deliver-release-pins.sh`, found the tip had moved past the commit
its version was computed for, and declined to tag.

Declining was right. `v2.2.3` was computed for a pins merge and cut on a
`refactor!` that landed fourteen seconds later, so a breaking change shipped
inside a patch and the major it deserved could never be computed again, because
git-cliff saw nothing unreleased once the tag had swallowed it. A tag on the
wrong commit is wrong in the published record and cannot be taken back.

Two things around the refusal were wrong.

**The code said the refusal was free.** Its comment read: *"nothing is lost but
the gap in the sequence"*. That is false, and not occasionally — the stale
branch is only reachable when `git diff --quiet` is true, which means `main`'s
pins already carry the target version, and the guard above it has already
established that no tag at or above the target exists. So every stale emission
leaves `main` pinned to a version nothing named. A consumer following `main`
resolves that pin against a ref that was never created.

**The repair was asserted, not checked.** The warning claimed *"the release run
for the feature commit re-derives the bump over the full history and tags that"*. No
such run existed. CI on the feature commit died in `Install Dagger CLI` on
`curl … exit 35` — an SSL connect error with no relation to the code — so CD's
gate (`if: conclusion == 'success'`) skipped every job. Nothing tagged
anything, and the assertion sat inside a CD run reporting **success**.

Nothing else would have caught it either. `.github/workflows/release-drift.yml`
measures a different quantity — commits ahead of the newest tag — and reports
it through an issue only after a two-day threshold, on a daily schedule. The
break was two days from being mentioned by any part of the system.

This is the failure class the whole workstream targets, one level up from the
scanners: an absent signal read as a verdict. Here the absent signal was a
release run that never started, and the verdict was `success`.

## What changed

`scripts/release_handoff.py` asks two questions instead of one.

The first is a standing invariant: **does every managed pin on `main` name a tag
that exists?** It takes its scope from the defended inventory, since a second
hand-maintained list of managed files is what froze `.github/workflows/` at
`v0.2.0` while every other pin moved on. It does not care how the state was
reached, which is the point — a stranded handoff, a deleted tag and a
hand-edited pin all land in the same place, and the routes nobody has thought
of yet land there too.

The second runs only when a pin dangles: **is anything still going to cut the
missing tag?** Abandonment is claimed on positive evidence alone — a CI or CD
run for `main`'s tip that has concluded unsuccessfully, or a CD run for the tip
that concluded at all while no tag appeared, since CD is triggered by CI
completing and that trigger is then spent. Everything else, in flight or not
yet observed, is `pending`. In-flight beats concluded because `gh run rerun`
leaves the failed attempt visible beside the new one, and checking conclusions
first would call a handoff abandoned at the moment someone is discharging it.

That asymmetry is deliberate. `main` is momentarily pinned to an uncut version
on every ordinary release, in the window between a pins merge and the run that
tags it, so a check that went red there would be red on every release — and a
red run on a state that heals itself in one CI cycle is the false alarm that
teaches people to ignore the signal, which is worse than no signal.

`scripts/check-release-handoff.py` is the entry point, and three callers run
it, each covering a case the others cannot:

- `.github/workflows/cd.yml` gains a `handoff` job on the CI-failed path. That
  is the exact event that strands a release, and until now the gate skipped
  silently on it. This is the caller that would have caught the incident within
  one CI cycle instead of two days.
- `scripts/ci/deliver-release-pins.sh` runs it on the stale branch, at the
  moment the obligation is created. The result `stale` is still emitted first,
  because whether to tag and whether a repair is coming are separate questions
  and conflating them would let a broken handoff argue a run into tagging the
  wrong commit. The run exits non-zero when nothing is coming.
- `.github/workflows/release-drift.yml` runs it on its schedule. This is the
  only caller that keeps asking when CD never starts at all, which is a real
  state here: under the `selected` Actions policy a disallowed action makes
  GitHub refuse a workflow at startup, publishing no job and no check run.

Exit 2 — a command the verdict depends on could not run — never fails a
release. A rate-limited API must not turn concurrent releases red. It is not
read as a pass either: the caller warns and says the scheduled sweep asks
again.

`scripts/tests/test_release_handoff.py` drives the whole decision path through
injected fakes, and `scripts/tests/test_deliver_release_pins.py` covers the
wiring — that the check is consulted, that it is told to exclude the run it is
running inside, and that all three of its answers reach the caller intact.

## What this does not do

It is not part of `ci.yml`. A release pull request rewrites every pin to the
next version before that tag exists, so the check would be red by construction
on every release branch; `scripts/check-workflow-pins.py` says the same thing
about why it compares pins to each other rather than to the newest tag.

It does not re-run anything. A robot that restarts a failed build can mask a
real failure, so the check names the run that stranded the release and the
command that restarts it, and leaves the decision to a person.

It does not change what gets tagged. The refusal that produced the incident
stays exactly as it was, because it is correct; only the claim made about its
cost has changed.
