# Intent: harden the repo's own CI workflows the way the risk gate demands

## Why

We ship a risk module that flags GitHub Actions workflows for two supply-chain
weaknesses — `PIPE-003` (an action referenced by a floating tag instead of a
commit SHA) and `PIPE-001` (a workflow with no top-level `permissions:` block,
so every job inherits a write-scoped `GITHUB_TOKEN`). The dogfood pipeline ran
that gate against `.github/workflows/` and surfaced 37 of these on our own
files. Leaving them unfixed is indefensible for a security tool: we cannot tell
consumers to pin and scope their tokens while our own pipelines float tags and
run write-all. So this change removes the debt at the source rather than hiding
it.

## What changed

Every third-party step action in `.github/workflows/` — `ci.yml`, `cd.yml`,
`commit.yml`, `commit-archive.yml`, `precommit.yml`, `release.yml`, and
`dogfood-precommit.yml` — is now pinned to a full 40-character commit SHA with
a trailing `# vX` comment that records the human-readable version. Each of the
six workflows that lacked one gains a top-level `permissions: contents: read`
block; the jobs that genuinely need to write (SARIF upload, PR comments, Pages
deploy, the release push) keep their wider grants at the job level, because
job-level permissions override the top-level default. A new
`.github/dependabot.yml` raises weekly PRs to advance the frozen SHAs, since a
pin with no update path rots and misses upstream security fixes.

## Decisions

We chose to remediate the workflows rather than only scope the scanner. The
companion change already diff-scopes `risk.Validate` so a pull request is
no longer blocked by debt in files it never touched — but scoping alone would
leave our pipelines unpinned and over-permissioned, with the findings merely
hidden from per-PR runs. Doing both is the honest position: the scanner stops
punishing unrelated PRs, and the actual weakness is gone.

We left the `context-and-oss/cicd/.github/workflows/*.yml@v1.5.0` reusable-workflow
references as version tags instead of SHAs, because they are job-level `uses`
that `PIPE-003` does not inspect, and the release automation rewrites those pins
on every tag — a SHA there would break the version-coherence guard. We set the
top-level default to `contents: read` rather than an empty map so that ordinary
checkout steps keep working without a redundant per-job grant.
