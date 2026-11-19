# Remove Pages publishing from the reusable commit workflow

A caller without Pages and OIDC permissions cannot start the reusable commit
workflow because GitHub validates the permissions of every nested job before
checking its condition. This happens even when the caller leaves Pages
publishing disabled. The default commit workflow must not require publishing
permissions it does not use.

Remove the publishing job from `.github/workflows/commit.yml` instead of
widening caller permissions. Leave `deploy-pages` as a deprecated boolean input
so existing callers still start. If they pass `true`, warn that the input is
ignored. The commit evidence artifact is still uploaded for callers that want
to publish reports separately. The standalone dashboard builder stays available.

Remove the Pages setup from `templates/github-actions/commit.yml` and the
optional input reference from `docs/how-to-guides/use-without-dockerfile.md`.
The regression tests in `scripts/tests/test_commit_workflow.py` compare the
caller's permissions to the reusable workflow's requests, forbid Pages and OIDC
scopes, and verify the compatibility input and evidence upload remain.
