# Opt-in coverage ratchet for the commit workflow

## Why

`commit.yml` can measure BYO coverage (`coverage-path`, `test-legs`), but it
never fetched a baseline, so every run reported `coverageRatchet:
skipped:no-baseline`. A consumer that releases from the commit stage could not
have a coverage drop between runs caught, even though the commit composite
already accepts `--baseline`,
`--tolerance` and `--coverage-gate` (ADR-003), and `precommit.yml` already
fetches a baseline the same way.

## Change

- New `commit.yml` inputs `coverage-gate` (default empty) and
  `coverage-tolerance` (default `1.0`).
- Empty `coverage-gate` keeps today's behaviour exactly: no fetch, no ratchet
  flags. Existing `test-legs` consumers that already measure coverage are not
  newly gated.
- `warn` or `gate` runs a fail-open fetch step mirroring precommit's: the newest
  unexpired `commit-evidence-*` artifact of a successful default-branch run of
  the same top-level caller workflow. The composite then receives
  `--coverage-gate`, `--tolerance` and, only when a file was downloaded,
  `--baseline`.
- Any other `coverage-gate` value fails the step instead of being guessed.
- `scripts/repo-inventory.json` no longer excuses `--baseline`, `--tolerance` or
  `--coverage-gate` as unreachable from `.github/workflows/commit.yml`.
  `docs/reference/index.md` documents the inputs.

No permission change: the commit job already has `actions: read`.
`commit-monorepo.yml` and the Azure DevOps templates are unchanged and keep
their documented exemptions.

## Checks

`scripts/tests/test_commit_coverage_workflow.py` executes the actual step
bodies. The mode `case` is tested for empty, `warn`, `gate`, missing and present
baselines, and refused values. The fetch step runs against a stubbed `gh`: it
selects the caller workflow's default-branch evidence, and with no baseline it
exits 0 in bootstrap mode. A consumer run with the ratchet enabled is the live
proof; structural tests alone are not.
