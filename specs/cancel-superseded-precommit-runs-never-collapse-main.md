# Cancel superseded pre-commit runs; never collapse main

## Problem

No pre-commit or commit surface declared what happens when a second run starts
before the first finishes.

- Pre-commit: every push to a pull request started a full run, and the run for
  the commit the PR had just left kept going to the end. Its verdict is for a
  commit nobody will merge, and it holds a runner and a Dagger engine while the
  run that matters waits.
- Commit: the obvious fix — the same `concurrency:` block — is wrong there.
  GitHub keeps at most one *pending* run per concurrency group and cancels the
  one already waiting when another arrives, with or without
  `cancel-in-progress`. Three merges to main in quick succession run the first
  and the last; the middle commit never gets commit-stage evidence, and nothing
  says so. ADO's `trigger: batch: true` does the same thing under another name.

## Decision

- **GitHub pre-commit callers** (`templates/github-actions/precommit.yml`,
  `.github/workflows/dogfood-precommit.yml`) carry:

  ```yaml
  concurrency:
    group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

  A pull-request run shares a group with the PR's other runs and cancels the
  one in flight. Every other run is grouped by its own run id, so it is never
  cancelled and never queued. Keying the fallback on `github.ref` instead would
  put every push to a branch (main, for the dogfood workflow) into one group,
  and GitHub would cancel the pending one. The group starts with the workflow
  name because groups are shared across the repository: a bare `pr-12` would
  cancel another workflow's run for the same PR.
- The block lives in the **caller**, not in the reusable `precommit.yml`: the
  caller is the workflow the event started, and its run is the one to cancel.
- **GitHub commit templates and workflows** declare no `concurrency:`, with a
  comment saying why.
- **ADO**: `templates/azure-devops/precommit.yml` states `pr: autoCancel: true`
  and `templates/azure-devops/commit.yml` states `trigger: batch: false`. Both
  are ADO's defaults, so the templates behaved correctly already; stated, a copy
  that flips one is a diff a reviewer sees and a check that fails. The `shared/`
  templates carry no trigger and say which setting the application repository
  should state.

## Guards

- `scripts/repo_surface.py` `check_superseded_runs`: both pre-commit callers
  exist and carry that block (workflow-name prefix, PR-number group, run-id
  fallback, PR-only cancel); no file matching
  `templates/github-actions/commit*.yml` or `.github/workflows/commit*.yml`
  declares `concurrency:` at any level; an empty match is itself a problem.
- `scripts/ado_templates.py` `check_run_collapsing`: a precommit template that
  declares `pr:` states `autoCancel: true`; a commit template that declares
  `trigger:` states `batch: false`.

Both were proven to bite on the live tree: `|| github.ref` in the GitHub
caller plus a `concurrency:` block on `.github/workflows/commit.yml` fails
`check-repo-surface.py` with both named; `batch: true` and a deleted
`autoCancel` fail `check-ado-templates.py` with both named.

## Blast radius

- A consumer who copies the new pre-commit template sees superseded PR runs
  end as **cancelled**. A required status check on the old head commit reads
  cancelled, which is correct: that commit is not the one being merged.
- Feature-branch `push` runs of the pre-commit template (it triggers on both
  `push` and `pull_request`) are not cancelled; each has its own group. Only
  the decision the user took — cancel PR runs, queue nothing else — is
  implemented.
- Consumers who already copied the templates get nothing until they copy again;
  the reusable workflows did not change.

## Still open

- A branch push and a pull-request run for the same commit both run the full
  pre-commit pipeline. Dropping one is a trigger decision for the consumer, not
  something a concurrency group can express.
