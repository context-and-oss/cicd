# Intent: a release push that was refused must say why, not say "main advanced" five times

## Why

The release job re-derives the version bump against the live tip of main and
retries the push, because two merges landing seconds apart can produce two CD runs
racing for the same tip. The loop assumed **every** rejection was that race:

```bash
if git push origin HEAD:main; then …; fi
echo "::warning::push rejected on attempt ${attempt} — main advanced; re-deriving against the new tip."
```

The CD run of the v1.11.0 attempt (2026-08-03) shows what that costs when
the rejection is permanent. Five times, verbatim:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Required status check "ci" is expected.
 ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
##[warning]push rejected on attempt 1 — main advanced; re-deriving against the new tip.
```

then `::error::failed to push version pins after 5 attempts.`

Three separate harms:

- **The diagnosis was wrong and stated confidently.** Main had not advanced. The
  remote said exactly what was wrong on the first attempt, and the workflow
  overwrote that with its own guess — four more times.
- **The final error named the retry, not the cause.** "failed after 5 attempts"
  sends a reader looking for a race that never happened; the real cause is eleven
  lines further up, repeated five times so that neither instance looks decisive.
- **Every attempt re-ran the whole bump.** `bump-version.py` twice plus the
  coherence gate, five times, for a refusal no retry could ever satisfy.

## What changed

- **`scripts/ci/classify-push-rejection.sh`** decides retryability. Exit 0 only for
  the three rejections that actually mean the remote ref moved — `(fetch first)`,
  `(non-fast-forward)`, `(stale info)` — and only when the reason sits on git's own
  `[rejected]` line. Everything else exits 1 and the job fails on attempt 1 with the
  remote's message.
- **The violated rules reach the annotation.** GitHub states them as
  `remote: - <rule>` lines; those are lifted into the `::error::` so the cause lands
  in the run summary instead of only in a step log. The v1.11.0 refusal now reads
  `Remote says: Required status check "ci" is expected.`
- **The exhausted-retries message tells the truth**: all five rejections were
  fast-forward conflicts, re-run the release.
- **Push stderr is redacted before printing.** git anonymises credentials out of the
  URLs in its own diagnostics (confirmed in that run's log) and Actions masks
  registered secrets, but this step deliberately echoes remote output, so
  `x-access-token:…@` is rewritten before it reaches the log regardless.

## Proof

`scripts/tests/test_push_rejection.py` — 13 tests, in `lint-repo` via the existing
`unittest discover`. Every fixture is **real captured stderr**, not a paraphrase: the
GH013 block comes from that run, the non-fast-forward block was produced
locally by pushing a diverged branch at a bare repo. Retryable: `fetch first`,
`non-fast-forward`, `stale info`. Terminal: GH013 ruleset, GH006 protected branch,
403 permission denied, missing `workflow` scope, transport failure, empty stderr.

The step's own lines were then run against those fixtures — extracted verbatim from
`cd.yml`, fed the GH013 log with a fake PAT embedded in the remote URL:

```
To https://x-access-token:***@github.com/context-and-oss/cicd.git
::error::push to main was refused for a reason no retry can satisfy. Remote says: Required status check "ci" is expected. A release commit is pushed direct to main, …
```

exit 1 on attempt 1, PAT redacted, rule named. The `(fetch first)` log through the
same lines falls through to the retry warning. The whole step body also passes
`bash -n` and is 5.6 KB, inside the 16 KiB step budget.

## Decisions

**A transport failure is classified terminal, deliberately.** It is genuinely
transient, so retrying it is defensible — but each attempt opens with
`git fetch --quiet origin main` under `set -e`, which has never tolerated a network
flake either. Making only the push network-resilient would be a half measure that
reads as more robustness than it has. Both now fail loudly with the real message, and
a re-run is one click. If release runs ever start losing to flakes, the honest fix is
retrying *the whole attempt* including the fetch, not widening this regex.

**The classifier is a script, not a shell function in the workflow.** It is a regex
against git's exact wording — the class of thing that rots silently on a git upgrade.
As a script, real captured stderr can drive it in CI; inline, it could only be
reviewed by eye. It also keeps the step body small (`workflow-step-size.md`).

**Anchored on the `[rejected]` line.** Violated-rule names and echoed commit subjects
are remote text nobody here controls. A rule literally containing
`(non-fast-forward)` must not talk a permanent refusal into a retry; there is a test
for exactly that. `[remote rejected]` does not contain the substring `[rejected]`, so
a remote-side refusal cannot match by accident.

## Known residue

**This makes the v1.11.0 failure legible; it does not unblock it.** The blocking rule
is a required status check named `ci` on `refs/heads/main`, and a release commit is
pushed *direct* to main by the bot, so no PR check run can ever satisfy it. That needs
a repository decision — the release identity on the ruleset bypass list, or the rule
scoped so it does not apply to that actor. Everything merged since 2026-08-03 is
unreleased until then.

**The tag push is not classified.** `git push origin "v…"` in the `Tag release` step
fails with git's own message and no retry loop, so nothing misattributes it — but a
tag ruleset would fail it after the pins commit has already landed on main, leaving
main bumped and untagged. The re-run path documented at the `git diff --quiet` branch
covers that case; it has not been exercised.
