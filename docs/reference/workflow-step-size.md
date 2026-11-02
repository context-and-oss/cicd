# Workflow `run:` step size ceiling

A GitHub Actions step whose `run:` body is large enough makes GitHub **refuse
the workflow at startup**. The workflow does not fail — it never starts. No job
is created, no check run is published, and the workflow simply is not in the
pull request's check list. Every other check on the PR is green, so the absence
reads as "nothing to report".

This is the same failure mode as an action the repository's `selected` Actions
policy does not permit (see [the Actions policy note in
`CLAUDE.md`](../../CLAUDE.md)), reached by a completely different route. That
one cost this repository four days of dead `ci.yml` and `cd.yml`. This one hid
`ci.yml` from two pull requests that were otherwise ready to merge.

## What we measured

Measured on this repository in 2026-08 by pushing `ci.yml` to a branch at
increasing step sizes and reading back whether a run record appeared at all.
`ci.yml` triggers only on `push`/`pull_request` to `main`, so a feature-branch
push produces **no run** when the file loads and a **startup-failure record**
when it does not — a free validity oracle needing no pull request.

| `run:` body, as written | Lines | Run created |
|---|---|---|
| 22,395 B | 342 | yes |
| 24,035 B | 365 | yes |
| 24,519 B | 371 | **no** |
| 25,410 B | 387 | **no** |

The ceiling sits between 24,035 B and 24,519 B as written — roughly 20.5 KB of
script after dedenting. Three properties matter more than the exact number:

- **It is size, not content.** The 24,519 B case differs from the 24,035 B one
  by six lines of shell *comment*. Adding 45 harmless comment lines to the
  otherwise untouched file breaks it too.
- **It is per step, not per file or per job.** Adding 60 filler lines (+3.4 KB)
  to a *different* job in the same file starts fine. Splitting the offending
  step in two made the file and the job *larger* and it started fine.
- **Nothing else catches it.** The file is valid YAML, `actionlint` exits 0, and
  every other guard in `scripts/` passes. The workflow is well-formed; it is
  just too big in one place to run.

The exact ceiling is undocumented by GitHub and could move, so it is not
encoded anywhere as a limit to sit just below.

## The budget

`scripts/repo_surface.py` defines `STEP_RUN_BUDGET_BYTES = 16384` and
`check_workflow_step_sizes` fails any declared workflow with a `run:` body over
it, measured **dedented** — GitHub runs the script, not the indentation. It runs
as part of `scripts/check-repo-surface.py` (`make check-surface`) in `ci.yml`'s
`lint-repo` job.

16 KiB is not the ceiling. It is the largest step we are willing to ship, chosen
to leave several KB of headroom under the lowest size ever observed to fail. At
the time the guard landed, `ci.yml`'s `module-test` job held a single 19,126 B
step — starting fine, and about twenty lines from silently dying. That step is
now three: one per `case` arm group.

An empty `run:` block body is reported too. A body the extractor cannot find —
because its indentation is level with the `run:` key, say — would otherwise
measure 0 B and make an unreadable step the smallest possible one. A guard that
passes over nothing is the failure this repository refuses everywhere else.

## When you hit it

Two fixes, in order of preference:

1. **Split the step.** Cheapest, and what `module-test` does. Shared setup moves
   to the job's `env:` block so it is declared once rather than per step.
2. **Move the body into a script under `scripts/` and call that.** No ceiling
   applies, and the body becomes shellcheck-able and unit-testable. Worth doing
   when a step is long because it holds real logic rather than a long list of
   independent commands. Note that `check-repo-surface.py` resolves documented
   `dagger` commands out of workflow bodies, so a body moved into a script must
   stay in a path that check still reads.

Do not raise `STEP_RUN_BUDGET_BYTES` to make a step fit. The headroom is the
point: the guard exists because the real ceiling gives no warning and no error
message, only an absence.
