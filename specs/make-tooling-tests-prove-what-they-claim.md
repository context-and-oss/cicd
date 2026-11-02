# Make three tooling tests prove what they claim

## Why

A review of `scripts/tests/` found three tests whose passing did not
establish their stated behaviour. Each was reproduced before changing it.

- **The clean DAST fixture could never pass.** In
  `scripts/tests/test_ado_templates.py`, `CLEAN_DAST` exported its evidence to
  `./dast-evidence` but gated on `./audit-evidence/combined-evidence.json`. The
  gate fails closed on a missing file, so the "clean" positive fixture modelled
  a pipeline that is red on every run. The shipped template's paste-ready gate
  already uses `./dast-evidence`; only the fixture was wrong. The checker
  validates that a verdict is read, not where from, so nothing noticed.
- **The traversal test passed for the wrong reason.** In
  `scripts/tests/test_build_artifact.py`, the `../application.tar.gz` case had
  no checksum and no file behind it, so any `ValueError` (missing file) satisfied
  it. Removing the transport-path allowlist from `verify-build-artifact.py` left
  the test green.
- **The release harness leaked a repository per test.** `harness()` in
  `scripts/tests/test_deliver_release_pins.py` used `tempfile.mkdtemp()` with no
  cleanup: 72 directories per run of the module.

## Change

- `gate_step(directory)` derives a fixture gate for a given evidence directory;
  `CLEAN_DAST` gates on `./dast-evidence`. `FixtureGatePathTests` requires every
  clean fixture to gate on a directory it exports.
- The traversal test builds an existing external payload with a matching
  checksum, then requires the specific `transport path` refusal for both a
  relative escape and an absolute path. The empty-artifact case is its own test
  asserting `exactly one`.
- Harness roots are recorded and removed in `tearDownModule`, which runs after
  failures too.

No production script, template, workflow or module changes.

## Checks

Regression-first: the gate-path test fails on the old DAST fixture; the
strengthened traversal test fails when the allowlist is deliberately removed,
which the old test did not; the release module now leaves 0 temporary
directories instead of 72. The complete Python tooling suite passes.
