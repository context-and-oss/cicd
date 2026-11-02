# A diff the workflow could not compute is not an empty diff

## Intent

Every surface that scopes the intent (and, in precommit, risk) gate to a change
set computed the diff the same way:

```sh
git diff … "origin/$base"...HEAD > "$out" 2>/dev/null || : > "$out"
```

behind a step marked `continue-on-error: true` (GitHub) or `continueOnError:
true` (Azure DevOps), and then passed `--diff "$out"` on every run. A shallow
checkout, a base the runner never fetched, or a merge base that does not exist
made `git diff` fail; the `|| : >` turned that into an empty file, and the
step-level tolerance hid it a second time. Intent reads an empty diff as a
change that touched nothing in scope and answers with a whole-tree audit, so a
pull request carrying no intent artifact passed on the artifacts already on
main and reported "N artifact(s) checked".

Seven surfaces carried the shape: `.github/workflows/precommit.yml`,
`commit.yml` and `dogfood-precommit.yml`, the four Azure DevOps templates
(`templates/azure-devops/{precommit,commit}.yml` and their `shared/` copies),
and the local pre-push helper (`scripts/cicd-prepush`, with its template copy).

## Chosen approach

Two states that used to share one empty file are now told apart at the step
that knows which one it is in:

- **Nothing to scope** (a push with no resolvable base commit, a build that is
  not a pull request, or a diff that is genuinely empty): the step logs why and
  writes no file, and the call passes **no `--diff` at all**. The composite then
  audits the whole tree because it was asked to, not because it was misled.
- **Scope asked for and lost** (a pull request whose base cannot be fetched or
  diffed; a push whose resolved range cannot be diffed): the step fails with
  `::error title=Change scope unavailable::` (GitHub) or
  `##vso[task.logissue type=error]` (Azure DevOps) naming the base and the
  remedy (`fetch-depth: 0` / `fetchDepth: 0`). `continue-on-error` is gone from
  every diff step. A non-PR precommit build that cannot reach its default
  branch warns instead and passes no `--diff`, since nothing was asked of it.
- **`cicd-prepush`** exits 2 when it resolved a base and could not diff
  against it, naming the three ways out: `git fetch --unshallow`,
  `CICD_DIFF_BASE=<ref>`, or `CICD_DIFF_BASE=none` to ask for the full audit
  by name. Its `origin/HEAD` lookup gained `|| true`, which also fixes a latent
  `set -e`/`pipefail` exit on a clone with no `origin/HEAD`.

The base ref reaches each log line through `tr -c` into a fixed character set,
so a branch name cannot inject a workflow command.

Two checks in `scripts/repo_surface.py` (`make check-surface`) keep it closed,
over the same surface groups:

- `--diff` is a `guarded_flags` entry (`CHANGE_DIFF_FILE`): it may only be
  appended to the argument array from inside a conditional testing that
  variable, never passed on the command line.
- `check_change_diff_not_swallowed` refuses `|| :` / `|| true` on any logical
  line that runs `git diff`.

Both were run against the pre-fix `precommit.yml` and both reported it.

## Rejected

- **Put the swallowed-diff check in `check-workflow-pins.py` and
  `check-ado-templates.py`**, as first planned. `check-workflow-pins` is the
  deliberately narrow release-blocking gate, and two checkers answering one
  question across two surface families is the "two resolvers for one question"
  doctrine breach. check-surface already reads both families through one
  inventory.
- **Keep passing an empty file and teach intent to distrust it.** Intent cannot
  tell "the workflow had nothing to diff" from "the workflow failed to diff":
  both arrive as zero bytes. Only the step knows.
- **Fail every build whose diff cannot be computed.** A push to main with no
  resolvable base, or a first commit, has nothing to scope; failing it would be
  a gate the consumer cannot clear.

## Blast radius

A consumer whose pull-request pipeline checks out shallowly, or whose base
branch shares no history with the head, now goes red at the diff step where it
used to pass with a whole-tree audit. Every template cicd ships already checks
out with full history, so a consumer on an unmodified template is unaffected.
A local pre-push in a shallow clone exits 2 until the base is fetched or the
full audit is requested by name.

## Expected result

`SwallowedChangeDiffTests` and `GuardedFlagTests` in
`scripts/tests/test_repo_surface.py`: the exact shipped line is reported, a
`|| true` split across a continuation is reported, a handler that exits is
accepted, a comment quoting the old shape and `|| true` on `git fetch` are not
commands that feed the diff. `make check-surface` is green on the tree and red
on the pre-fix `precommit.yml`.
