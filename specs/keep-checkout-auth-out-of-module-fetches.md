# Keep checkout authentication out of module fetches

## Why

A reusable workflow checks out a caller repository and then fetches pipeline
modules from another repository. Checkout's persisted Authorization header is
host-scoped. It can override the identity intended for the later fetch, so a
repository-not-found response need not mean the module repository is missing.
The source checkout's token is unnecessary after its own fetch because the commit
diff reads full local history without contacting the remote again.

## Change

Set `persist-credentials: false` on the source Checkout in
`.github/workflows/commit.yml`, retaining `fetch-depth: 0`. Do not introduce an
identity for the public module fetch or restore removed private-module access
configuration. Only the source checkout uses its existing checkout credential.

## Checks

`scripts/tests/test_commit_coverage_workflow.py` guards the nonpersisting checkout,
full history and local-only diff contract. A read-only consumer probe confirmed
that clearing a persisted checkout header restores a cross-repository git fetch;
with a nonpersisting checkout, no source-token header remains. No credential value
is retained in the probe output. A same-repository self-test alone cannot prove
that distinction. Workflows that explicitly fetch additional refs retain their
own authentication contract and are not changed by this patch.
