# Intent: a pipeline that cannot start must not read as a pipeline with nothing to say

## Why

CI on this repository was dead for four days and nothing noticed.

`.github/workflows/ci.yml` used `golangci/golangci-lint-action` and
`.github/workflows/cd.yml` used `taiki-e/install-action` twice. This
repository's GitHub Actions policy is `selected` with `github_owned_allowed`
and `verified_allowed` true and `patterns_allowed` empty — measured, not
assumed:

```
gh api repos/context-and-oss/cicd/actions/permissions
gh api repos/context-and-oss/cicd/actions/permissions/selected-actions
```

Under that policy a disallowed action does **not** fail its step. GitHub
refuses the whole run at *startup*: no job is created, no check run is
published, and the workflow simply does not appear in the pull request's check
list. A reviewer sees a short, fully green list and merges. That is how
two pull requests merged from 2026-07-30 17:20 onward with `lint-repo`,
`verify-contracts`, `module-test`, `composite-smoke` and
`composite-smoke-commit` never having run at all, and how CD's last successful
run stayed at 2026-07-30 09:16. Diagnosis took a probe PR carrying a
last-known-good `ci.yml` that *also* startup-failed, which is what finally
pointed away from the file and at the environment.

This is the same failure class the repo already legislates against for
scanners — "a tool that could not run must never read as clean" — arriving one
level up, at the harness. A gate that reports nothing is indistinguishable from
a gate that reports success, and here the absence was the *entire* gate.

## What changed

The two third-party actions are gone, replaced by steps the policy cannot
refuse:

- `ci.yml`'s lint step runs golangci-lint via
  `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2`
  with `GOWORK: "off"`. Integrity is not weaker than a digest pin — the Go
  checksum database verifies the module — and the version must stay in step
  with `src/internal/.golangci.yml` (`version: "2"`), which the comment says.
- `cd.yml`'s two git-cliff installs use a new local composite action,
  `.github/actions/install-git-cliff`, pinning version 2.13.1 and verifying
  the release tarball against its published sha512 before installing. Local
  actions (`uses: ./...`) are always permitted. The install asserts
  `git-cliff --version` afterwards so a silent no-op install fails the step
  rather than resurfacing later as a confusing "git cliff failed".

Fixing the two workflows is not enough: the next third-party action anyone adds
would silence the pipeline exactly the same way, and again invisibly. So the
trust set is now declared and enforced in the tree. `repo-inventory.json` gains
a `workflow_actions` block (`trusted_owners`, `third_party_allowed`,
`workflow_groups`), and `scripts/repo_surface.py` gains
`check_workflow_actions_trusted` — the eighth surface check — which reads every
`uses:` in the declared reusable workflows, internal workflows and local
actions — a composite action can itself call another action, and a third-party
one there kills startup identically — and fails on an owner
that is neither trusted nor explicitly admitted with a reason. Local and
`docker://` references are skipped; a commented call-site example is not read
as a step. The loader refuses a `third_party_allowed` entry with no reason, and
refuses `trusted_owners` with an empty `workflow_groups`, because a guard whose
scope is empty passes vacuously — reporting OK over nothing is the bug being
fixed, not a way to fix it.

## The second org control, found on the way out

Trying to merge this change surfaced a companion problem from the same rollout
window. The required-CI ruleset (active on `refs/heads/main` and `refs/heads/release/**`) requires a status
check with the context **`ci`**, with `strict_required_status_checks_policy`.
Nothing in this repository ever published a check run by that name — the jobs
are `Lint Go source`, `Test src/<module>`, `Verify module contracts` and the two
composite smokes. So the rule was unsatisfiable, and every merge to `main` was
blocked for anyone outside the bypass team from the moment it landed. The two
pull requests merged at 09:19 and 09:20 that morning, before it existed; this is the
first pull request to hit it.

`ci.yml` therefore gains an aggregate job literally named `ci` that `needs:`
every other job and fails unless all of them succeeded. That satisfies the rule
honestly instead of bypassing it, and it keeps coverage exact: the org names one
required context, and an aggregate that `needs:` every job cannot drift as jobs
are added or renamed, whereas naming an individual job in the ruleset would
quietly stop covering the rest the moment a job is added.

`if: always()` on that job is load-bearing. Without it a failed dependency skips
the aggregate, GitHub reports the required `ci` context as *pending* forever, and
the PR sits in a state that reads as "still running" rather than "failed" — the
same absence-reads-as-nothing shape as the bug this change exists to fix.
`skipped` and `cancelled` are treated as failures for the same reason: a gate
that did not run is not a gate that passed. The four outcomes (all success, one
failure, one skipped, one cancelled) were exercised against the extracted script
before pushing, which is how a real bug in it was caught — the first draft
formatted the `needs` metadata dict instead of its `result` field and crashed.

## Decisions

**In-repo fix, not a settings change.** Adding two `patterns_allowed` entries
would have restored both workflows with no code change. Rejected as the primary
fix for three reasons: the policy may be org-enforced (the org-level API 403s
without `admin:org`, so we cannot even confirm we could change it), a repo
settings change is invisible in git and unreviewable, and the repo's own
doctrine already prefers explicit pinning to trusting a third party's tag. The
allow-list remains available if the maintainer prefers it — that is a call to
report, not one to make silently.

**Guard scope is the workflows, not the templates' consumers.** The check reads
`reusable_workflows` and `internal_workflows`. It deliberately does not police
what a *consumer's* repository puts in its own workflows; the templates under
`templates/` are starters a consumer owns, and their Actions policy is theirs.
A shipped-inventory test asserts `ci.yml` and `cd.yml` stay inside the checked
scope, so the two files this incident killed cannot quietly leave it.

**Owner-level trust, not action-level.** `actions/*` and `github/*` are trusted
wholesale because that is precisely what `github_owned_allowed` grants — a
narrower per-action list here would encode a stricter rule than the policy it
models and would break on an unrelated `actions/*` step for no safety gain.

## Known residue

Nothing in CI notices a newer git-cliff or golangci-lint; both versions are
maintained by hand, and the action comment names that. And this change only
restores the gate — CI's seventeen jobs are about to run for the first time in
four days, so real failures accumulated behind the dead gate may surface, and
they are fixes for this change to make, not to defer.
