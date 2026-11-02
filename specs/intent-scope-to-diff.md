# Intent: scope the intent gate to the files a change touches

## Why

The intent gate globbed every artifact in the repo and ran its prose rules on
all of them. Because of that, a pull request that touched a single capsule
inherited every pre-existing finding across the whole tree — the gate punished
the author for debt they did not write. We change it so the gate judges only
the artifacts a change actually touches, since the point of an intent gate is
to prove *this* change was deliberate, not to re-audit the repo's back
catalogue on every run.

## What changed

The `diff` argument already threaded from the intent module's `main.go` up
through the precommit composite, but no caller ever produced it — so the
coupling rule was dead and nothing was ever scoped. We now generate
`git diff <base>...HEAD` in the workflows and pass it as `--diff`. A new parser
in `extract.go` returns the added and modified paths, and the gate intersects
those with the discovered artifacts so the rules run only on that set.

## Decisions

We chose file-level scoping rather than line-level, because the prose rules
(causal language, minimum length) are properties of a whole artifact and not of
individual lines — a half-edited rationale is still the author's to own.

We scope the presence check too: a change that touches no intent artifact now
fails, instead of passing just because some unrelated artifact happens to exist
elsewhere in the repo. That is what gives the gate teeth. When no diff is
supplied — a standalone call or a default-branch audit — the gate falls back to
scanning every discovered artifact, so those paths keep working unchanged.

We dogfood the gate here with a spec under `specs/` rather than a capsule,
because the gate is format-agnostic and consumer repos carry capsules instead.
Running both formats through one gate is the proof that the format-agnostic
claim actually holds.
