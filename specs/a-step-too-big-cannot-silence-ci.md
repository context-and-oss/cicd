# Intent: a workflow step must stay small enough for the workflow to start

## Why

Same failure as [keep-pipelines-startable.md](./keep-pipelines-startable.md),
reached without any policy being involved, and found the same way — by noticing
an absence rather than a failure.

Two pull requests sat merge-ready showing four green checks
each, with *all* of `ci.yml` — `lint-repo`, `verify-contracts`, `module-test`,
both composite smokes and the aggregate `ci` — missing from the check list.
Nothing was red. Nothing was pending. The jobs simply were not there, and a
short green list reads as "everything passed".

The signature of a startup refusal is worth writing down, because it is the only
thing that distinguishes this from a workflow that legitimately did not apply:
the run's `name` equals its `path` (`.github/workflows/ci.yml`, not `CI`), the
event is `push`, there are zero jobs, no check runs are published, and **no
`pull_request` run is created at all**.

The cause is a size ceiling on a single step's `run:` body. `ci.yml`'s
`module-test` job held one `run:` step containing the whole per-module `case`
statement, and my change pushed it over.

Measured, not assumed. `ci.yml` triggers only on `push`/`pull_request` to
`main`, so pushing a feature branch yields **no run** when the file loads and a
**startup-failure record** when it does not — a validity oracle needing no pull
request. Pushing the same file at increasing step sizes:

| `run:` body, as written | Lines | Run created |
|---|---|---|
| 22,395 B (main) | 342 | yes |
| 24,035 B | 365 | yes |
| 24,519 B | 371 | **no** |
| 25,410 B | 387 | **no** |

Three properties matter more than the number:

- **Size, not content.** The 24,519 B case differs from the 24,035 B one by six
  lines of shell *comment*. `main` plus 45 harmless comment lines breaks too.
- **Per step, not per file or per job.** 60 filler lines (+3.4 KB) added to a
  *different* job in the same file starts fine.
- **Nothing static catches it.** Valid YAML, `actionlint` exit 0, every existing
  guard in `scripts/` green. The workflow is well-formed and simply too big in
  one place to run.

`main` was sitting at 19,126 B of script — starting fine, and about twenty lines
from silently dying. Anyone adding a module test case would have tripped it,
and would have seen a green check list while doing so.

## What changed

**`ci.yml`'s `module-test` job splits that step into three**, one per `case` arm
group: quality, security, and everything else. Largest is now 7,501 B. The arm
bodies are byte-identical to before; only their grouping into steps changed.

`MODULE`, `SHA`, `BRANCH` and `REPO` move to the job's `env:` block so they are
declared once rather than three times. That has a consequence worth naming:
losing the in-script `MODULE="${{ matrix.module }}"` assignment also loses
ShellCheck's proof that the value is a safe literal, so all 22 `./$MODULE`
references started tripping SC2086. They are now `"./$MODULE"`. Quoting was the
right resolution rather than re-splicing `${{ }}` into a bash body — the same
rule the ADO template check already enforces.

**The ceiling is now guarded in the tree.** Splitting one step fixes today; the
next person to grow one would land in exactly the same silence. So
`scripts/repo_surface.py` gains `check_workflow_step_sizes` — the ninth surface
check — which measures every `run:` block scalar in the declared workflows,
dedented (GitHub runs the script, not the indentation), against
`STEP_RUN_BUDGET_BYTES = 16384`. It runs inside `check-repo-surface.py` in
`lint-repo`, and a shipped-file test asserts `ci.yml` itself stays under.

The block-scalar extractor is hand-rolled rather than PyYAML: the shipped
scripts deliberately carry no third-party dependency, and the shape needed is
narrow.

## Decisions

**16 KiB, well below the measured cliff.** The real ceiling is undocumented and
could move, so the budget is deliberately not set just under it. 16 KiB is "the
largest step we are willing to ship" — 2.6× headroom under the lowest size ever
observed to fail, and 2.2× the largest step now in the tree. The doc says
explicitly not to raise it to make a step fit; the headroom *is* the guard,
because the real ceiling arrives with no error message.

**Split the step rather than extract a script — this time.** Moving the `case`
body into `scripts/ci/module-test.sh` removes the class of problem outright, and
makes the body shellcheck-able and unit-testable. No size budget applies to a
script at all, so that end state needs no guard; the doc records it as the
preferred second option. Not done here because it
changes how every module's integration test is invoked — the job that validates
all fifteen modules — and doing that inside the change that unblocks two other
pull requests compounds two risks that are easier to judge apart. The guard is
what makes deferring it safe rather than merely convenient.

**An empty `run:` body is reported, not measured as 0 B.** If the extractor
cannot find a body — indentation level with the `run:` key, say — the step would
measure as the smallest possible one and pass. A guard that reports OK over
nothing is the exact failure being fixed, so it is named instead.

**Its own pull request, ahead of the two it unblocks.** The two blocked pull requests both edit
this step, so either could have carried the fix. Landing it separately means the
fix is reviewable on its own terms and proves itself with a real `ci.yml` run
before anything else rebases onto it — rather than arriving inside a change
whose own CI could not run.

## Known residue

The guard covers the declared workflows only. The `templates/` starters a
consumer owns are not checked; their workflow files are theirs, and none is
close to the ceiling. `actionlint` is still not run in CI — it would not have
caught this anyway, and adding it is a separate call.

The exact ceiling remains unknown, and the values above are one repository's
measurements on one day. If a step under 16 KiB ever startup-fails, the budget
was optimistic and the measurement table in
[docs/reference/workflow-step-size.md](../docs/reference/workflow-step-size.md)
is where the new datapoint belongs.
