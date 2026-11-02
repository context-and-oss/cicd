# Check the smoke's own fixture

The intent positive control in `scripts/smoke/non-run-matrix.sh` must pass the
source tree that its diff describes. Restoring the old spec after generating
the diff made the control fail because the gate now validates the patch against
the supplied current artifact. Keeping the edit fixes that failure; a regression
check keeps the fixture from drifting back into a mismatched pair.

Before discarding Git metadata, check reverse application of the control diff.
`scripts/tests/test_nonrun_fixture.py` executes the actual fixture-producing
block from the smoke script, checks that the exported tree still matches the
diff, and checks that the negative fixture retains its missing-prefix fault.
It starts no Dagger engine and replaces no gate logic. The real smoke remains
the end-to-end proof that each injected failure is refused and each control
passes, rather than a gate that rejects every input satisfying the tests.

The publication checklist in `CONTRIBUTING.md` and the diagram review in
`THIRD_PARTY_NOTICES.md` also record the maintainer's clearance for including
the two embedded raster images. That is a maintainer decision, not a new claim
about an author or upstream licence. The runtime Semgrep rules terms and the
separate destination-bootstrap checks remain unchanged.

Verification: the canonical script and module suites, repository-surface
checks, and the real non-run smoke must pass. Restoring the old spec before
the control is generated for consumption must fail the new fixture test.
