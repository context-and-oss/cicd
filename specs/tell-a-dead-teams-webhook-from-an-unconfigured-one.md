# Tell a dead Teams webhook from an unconfigured one

A pipeline that notifies nobody must not report the same success as one that
notified a channel. cicd's Teams leg reported success in three distinct
situations — card delivered, no webhook configured, card attempted and lost —
and distinguished none of them, in either direction.

## What was measured

Three composites carried the same block:

```go
if teamsWebhook != nil {
    if err := dag.Notify().Teams(ctx, teamsWebhook, summary, "commit", opts); err != nil {
        fmt.Fprintf(os.Stderr, "teams notification failed: %v\n", err)
    }
}
```

Two independent defects sit in those four lines.

**`!= nil` is not "configured".** Under GitHub Actions `secrets: inherit`, a
secret the calling repository never defines still arrives as a non-nil, empty
`*dagger.Secret`. `.github/workflows/commit.yml`, `precommit.yml` and
`dogfood-precommit.yml` passed `--teams-webhook env:TEAMS_WEBHOOK`
unconditionally, so every consumer who had never set Teams up POSTed a card to
the empty string on every run. The result was
`Post "": unsupported protocol scheme ""` on stderr, inside a job log that is
twenty minutes long on a real repository, and an exit status of zero.
`.github/workflows/dast.yml` had carried the guard from the day it was written;
the other three drifted without it, and so did all four Azure DevOps templates.

**A failed POST was written to stderr and nowhere else.** The pipeline's whole
premise is that a tool which could not run must not read as clean, and the
notification leg was the one step exempt from it. A webhook that has been
rotated, revoked or re-pointed — the case that actually matters, because the
team is relying on the channel — produced one line on stderr and a green run.
The card before it may have been the last that arrived, and nothing said so.

## What changed

`notify.Teams` returns `(*dagger.File, error)` — an evidence envelope — instead
of `error`. It classifies three states and states which one happened:

| state | outcome | evidence |
|---|---|---|
| card delivered | `CLEAN` | no warning; a line on every run is noise |
| no webhook to post to | `SKIPPED` | `teams: NOT CONFIGURED — …` |
| attempted and lost | `ERROR` | `teams: NOT DELIVERED — …` |

`passed` is `true` in all three. A notification is not a gate: the scan's
verdict is what it was before the POST, and turning a webhook outage into a red
pipeline teaches a team to stop passing the webhook, which is this same defect
arrived at from the other side.

The classification lives in `src/notify/teamsdelivery.go`, an **untagged** file.
The Dagger entry function is `//go:build !unit_test`, and the rule that a blank
webhook is not a webhook was unreachable from any test while it lived inside
that entry function — which is how it came to be `!= nil` in three composites
and nothing else. `moduleName` and `moduleStage` moved out of `main.go` for the
same reason.

### The second Wrap

`notify` consumes `combined-evidence.json`, which is `cross-cutting/evidence`'s
output, so notify's own envelope cannot be inside the aggregate produced by the
call that fed it. The composites therefore aggregate twice when a webhook is
supplied: once to build the summary the card reports on, and again with the
delivery envelope appended. The pull request comment is rendered after both, so
it can carry the delivery record; the card cannot, because it was built before
the POST it would have to report on.

**That second `Wrap` is also what performs the notification.** A module function
returning an Object type gets a generated client method with no `ctx` and no
`error`, and returns a lazy reference — the body does not run until something
reads the file. Skipping the merge to save an aggregation pass, on the grounds
that delivery succeeded, would silently stop sending cards.

A non-merged `notify-evidence.json` beside the bundle was the alternative, and
has precedent in `cross-cutting/dependency-track`. It was rejected: `warnings[]`
is the one field `cross-cutting/evidence` propagates into
`combined-evidence.json` and thence into the pull request comment, and the
comment is the channel a human reads *when Teams is dead*. A record only in a
file nobody downloads is the stderr line with extra steps. The price is one
extra in-engine JSON merge on notifying runs — no containers, no network.

### Two non-configurations, named separately

`teamsUnconfiguredReason` returns the empty string for a value that must be
attempted, and otherwise the clause the warning quotes:

- **empty or whitespace.** A secret file with a trailing newline, or a variable
  holding one, is the same non-configuration as an unset one, and `Post "\n"`
  fails with the same unreadable transport error.
- **an unexpanded Azure DevOps macro.** ADO expands `$(TEAMS_WEBHOOK)` before
  the shell parses the line, and an *undefined* variable expands to its own
  literal text — so a pipeline that never declared the variable hands cicd a
  sixteen-character string that is not empty. The --include work recorded the same fault
  for `--include`, where `quality.Check` failed a run naming an unexpanded macro
  as an unknown language. Classified as a broken webhook it would tell a team
  their channel had died when they never had one, which is a worse answer than
  the silence it replaces.

The match is anchored at both ends. A real incoming-webhook URL may legally
carry a `$(` in a query value, and treating that as unconfigured would silence a
channel that works.

Everything else is attempted. **A malformed URL is a broken configuration, not
an absent one**, and the difference between the two is the point of the file, so
a value that is present and wrong must reach `NOT DELIVERED` rather than be
quietly reclassified as "you never set it up".

### A new leak, closed by the test that found it

Routing delivery errors into `warnings[]` publishes them one channel wider than
the stderr line they replace: into `combined-evidence.json` and the pull request
comment. The Teams webhook URL **is** its credential — the token is in the path
— and the thing that answers a failed POST is often not Teams. A proxy, a WAF or
a 404 page quotes the request *target* rather than the URL cicd sent
(`The requested URL /webhookb2/<token>/… was not found on this server`).

`scrubSecrets` had only the full URL registered, so a fixture whose 500 body
echoed the path put that path straight into the serialised envelope. The test
caught it before the change shipped. `teamsScrubValues` now registers the URL,
its escaped path, its path and its raw query, each only when it is at least 16
characters: below that, `ReplaceAll` would splice `***` through unrelated text —
a path of `/` would hit every slash in the message — while protecting nothing a
token-bearing webhook path could ever look like. Production and the tests both
build the seam through `newTeamsDelivery`, so a leak a test cannot see is a leak
production does not have either.

## The guard, and the check that keeps it

The module now tells the three states apart, so an unguarded flag no longer
lies. It is still wrong: passed unconditionally, it puts a `NOT CONFIGURED`
warning into the pull request comment of every consumer who never asked for the
channel, and a disclosure on every run is noise. The guard is what keeps the leg
from running at all.

All seven drifted surfaces now carry it — three GitHub workflows with the
`if [ -n "${TEAMS_WEBHOOK:-}" ]; then extra+=(…); fi` one-liner, four Azure
DevOps templates with the `case` form that excludes the unexpanded macro too,
which is the shape `templates/azure-devops/dast.yml` already used.

`check_guarded_flags` (`scripts/repo_surface.py`, check 20) refuses the next
drift. Each entry in `guarded_flags.flags` names a flag, the variable behind it
and a reason; every occurrence in a declared starter surface must be an append
to a shell argument array from inside a conditional testing that same variable.
Traps, each one mutation-tested:

- **the array alone is not the guard.** An unconditional
  `extra+=(--teams-webhook env:TEAMS_WEBHOOK)` is the same defect one line over,
  and is the shape a repair would most plausibly regress into.
- **the condition is read without its body.** The GitHub one-liner names
  `TEAMS_WEBHOOK` twice — once in the test and once in the append — so a
  substring search over the whole line accepts a guard testing
  `NPM_FEED_TOKEN`, which is exactly the copy-paste this check exists to catch.
  `_guard_condition` returns the part before `; then`, or the subject of a
  `case … in`, and never the body.
- **the lookback is finite** (12 lines). A conditional further away than that is
  not one a reader of the append would see either.
- **a declared flag no surface passes at all is reported**, the same
  stale-exemption rule `composite_reach` carries: a declaration nothing
  exercises is a check that proves nothing.
- **the comment must not spell the macro.** `check-ado-templates.py` refuses any
  `$(WORD)` in a bash body, comments included, because a commented-out line is
  one edit from a live one. The rationale beside the guard therefore describes
  the literal macro text without writing it.

## Residue

- `build.BuildArchive` still returns a `*dagger.Directory` and so has no
  `warnings[]` of its own; unrelated, and already documented in
  [name-the-version-file-cicd-could-not-use.md](name-the-version-file-cicd-could-not-use.md).
- `--dependency-track-api-key` is still passed unconditionally by
  `.github/workflows/commit.yml`. That leg has its own partial-configuration
  disclosure and is not declared in `guarded_flags`; if it grows one, the
  declaration is one manifest entry.
- Nothing in cicd asserts that a consumer's `TEAMS_WEBHOOK` is a Teams URL
  rather than any other endpoint. It is a secret, and cicd does not read it.
