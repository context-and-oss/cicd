# Reach the BYO coverage report from the commit workflow

## Problem and decision

A consumer can run its own tests through `test-cmd` in `commit.yml`, but cannot
name the coverage report they wrote. The engine supports `coverage-path`; the
wrapper omitted it. A successful test command consequently leaves the coverage
source SKIPPED, even if that command enforces its own thresholds.

Expose an optional empty-default string `coverage-path` because the test command
and its report must both be reachable through the wrapper. Pass it through a step
environment variable and a quoted shell-array element to the existing composite.
Do not guess a filename, parse output in the wrapper, or introduce another runner.
A consumer can name a relative or container-absolute JSON summary report.

## Compatibility and limits

Omission keeps the existing behavior. The engine still refuses a run-wide path
with `test-legs`, whose reports belong in each leg's `coveragePath`. Existing
missing/unreadable report outcomes remain unchanged. Measurement is distinct from
a coverage regression ratchet: this workflow does not retrieve a baseline.
Consumer-owned thresholds remain the consumer's responsibility.

## Checks

`scripts/tests/test_commit_coverage_workflow.py` exercises the actual shell
forwarding with absent, ordinary, whitespace and shell-metacharacter paths, checks
the optional input/environment binding and rejects the obsolete reachability
exemption. Existing quality coverage and test-leg unit tests own report parsing,
missing output and incompatible inputs. `scripts/check-repo-surface.py` verifies
the live composite parameter is reachable. Workflow syntax is checked by
actionlint. The reference documents the distinction between harvesting and gating.
