# Intent: run CD only for a push to this repository, and scan only this repository's code

## Why

Pinning the default SAST packs (`specs/pin-the-default-sast-rules.md`) froze
`p/security-audit` at the 725 rules the registry served when it was captured,
instead of the 225 it serves now. The first dogfood run under the pin reported
unsuppressed results that the live pack had never shown. They split
three ways, and each way gets a different answer, because treating them alike
would either hide a real hole or "fix" test data.

**One is a real hole.** `.github/workflows/cd.yml` runs on `workflow_run` of CI
with `branches: [main]`, and three of its jobs check out
`github.event.workflow_run.head_sha` and run scripts from it — `tag-and-release`
with `contents: write` and `CICD_RELEASE_TOKEN`. The branch filter matches the
*head* branch name, which a fork chooses. A pull request from a fork's branch
called `main` runs CI as `pull_request`, CI on a fork pull request runs the
fork's own `ci.yml` and can therefore conclude success at will, and CD then
fires with the fork's commit as `head_sha`. While the repository is private no
fork can open one; the moment it is public, anyone could.

**Two are a configuration gap.** `.github/dependabot.yml` sets no cooldown, so a
compromised action release would be proposed as a SHA bump on the day it is
published.

**The rest are fixtures.** The DAST target's cookies and raw HTML, the
curl-pipe-shell workflow that exists to prove `gha-curl-pipe-shell`, and the
unhardened pnpm workspace are all under `testdata/`, insecure on purpose so the
integration tests have something to find — the same reason `trivy.yaml` already
skips that directory.

## What changed

- `cd.yml`'s `gate` now also requires `workflow_run.event == 'push'` and
  `head_repository.full_name == github.repository`. Every job that checks out
  `head_sha` needs the gate, so the checkout only ever sees a commit already on
  `main`. `handoff` carries the same two conditions, since a fork's failed run
  says nothing about this repository's `main`. The concurrency key gains the
  repository and the event as well, because GitHub keeps one pending run per
  group and cancels the older: without it a fork's run could displace a pending
  release before the gate skipped it.
- The three `head_sha` checkouts keep their rule match, suppressed with a
  rule-specific `nosemgrep` that points at the gate. The rule matches the
  checkout's shape and cannot see a job-level condition, so no edit to the
  condition can clear it; moving the sha through a job output instead would
  clear the rule while changing nothing it is about, which is gaming the
  scanner. A suppression is disclosed in the evidence and counted, so a reader
  still sees three reviewed matches.
- `dependabot.yml`'s `github-actions` entry gains `cooldown: default-days: 7`.
  The `gomod` entry gets a `nosemgrep` instead of a cooldown, because Dependabot
  applies cooldown to version updates only and that entry raises none: a
  cooldown there would read as protection while governing nothing, the same
  argument the file already makes against `open-pull-requests-limit`.
- A root `.semgrepignore` excludes `/testdata/`, anchored so the `testdata/`
  directories under `src/` (recorded tool output for unit tests) stay in scope.
  Consumers are untouched: semgrep reads the file from the scanned root, and
  every module-test and smoke cell scans a fixture directory as its root.

## The trap the ignore file sets

A `.semgrepignore` *replaces* semgrep's built-in ignore list rather than adding
to it. Measured against semgrep 1.162.0 on this tree: with no ignore file it
scanned 827 files and no `*_test.go`; with an ignore file naming only
`/testdata/` it would also scan every `*_test.go` and the whole `.git`
directory. So the file restates the built-in defaults and names `.git`
explicitly (without a slash, since a worktree's `.git` is a file). With it the
scan reads 759 files: the 827 minus the root `testdata/`, plus the ignore file
itself, and nothing outside `testdata/` left the scan.

## Proof

The two pinned rules, staged in the registry layout so their ids match, against
`dependabot.yml` and `cd.yml` before the change report the five unsuppressed
results CI did. After it, one rule result is gone (the cooldown) and the other
four carry an `inSource` suppression in the SARIF.

## Trade-offs

An action's own security fix now also reaches this repository a week late; a
fix that cannot wait is a manual bump. And `/testdata/` is no longer scanned by
the dogfood run, so insecure code added there by mistake would not be reported
by it — accepted, because everything there is deliberately insecure, and each
fixture is still scanned whenever a test points cicd at it.

## And the entry the cooldown suppression sits on was never valid

Touching `.github/dependabot.yml` made GitHub run Dependabot's own config check
on the pull request, and it refused the file: the `gomod` entry carried
`applies-to: security-updates`, a key Dependabot accepts only inside
`groups.<name>`. The entry's comment said the key was what made `ignore` reach
security updates, but `ignore` is one of the options Dependabot's options
reference marks as changing security update pull requests too, so the key did
nothing a valid file could not. The key is removed, the comment now says why the
ignore alone holds, and CAPS-059 records that its chosen option was first
written with it. Nothing checked the file locally because no local tool runs
Dependabot's schema; the check that caught it is GitHub's, and it only runs when
a pull request changes the file.
