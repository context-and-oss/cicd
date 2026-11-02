# Reclaim runner disk before the commit composite smoke

## Why

The `Composite smoke test (commit)` job runs the application, container,
archive, and none artifact shapes serially against one Dagger engine. Two runs
lost a live module-codegen snapshot late in that sequence with `snapshot ...
does not exist`. The hosted runner also carries large Android, .NET, GHC,
ghcup, and Swift installations that this Go smoke job never uses.

The reusable commit and precommit workflows already reclaim those directories
before starting Dagger. Applying the same preparation to this heavier smoke job
gives BuildKit enough working space for all four shapes and keeps the engine
alive for the assertions the job is meant to exercise.

## What changed

Before Dagger is installed or its engine starts, the job removes the unused
host SDK directories and prunes unused Docker images. It records disk space
before and after the cleanup and reports the reclaimed GiB in the log.

We chose to scope the cleanup to this job because it is the only workflow that
runs all four shapes serially in one Dagger engine. It does not change the
commit module, consumer workflows, test fixtures, or release artifacts.

## Verification

The workflow YAML parses successfully and `git diff --check` passes. The pull
request's own `Composite smoke test (commit)` job is the end-to-end check: it
must complete every artifact shape after reporting the reclaimed space.
