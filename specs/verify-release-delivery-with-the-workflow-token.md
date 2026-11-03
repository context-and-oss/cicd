# Intent: verify release delivery with the workflow token

## Why

A fine-grained release PAT can push workflow pins and deliver a pull request,
but the [Checks API](https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference)
requires GitHub App authentication for its fine-grained access contract. Because
arming auto-merge can merge an already-eligible pull request immediately, the
release checker must be able to prove that the required CI check passed on that
exact head before the merge. Using the writer PAT for that readback can leave a
delivery unverifiable even though its write permissions are correct. This is an
authentication-contract correction, not a claimed observed production failure.

## What changes

`scripts/ci/deliver-release-pins.sh` now requires a separate
`RELEASE_VERIFY_TOKEN` before any API or Git write. Its ordinary `GH_TOKEN`
continues to represent the release identity for branch-rule/capability preflight,
branch and PR delivery, auto-merge requests and superseded-PR cleanup. Only the
read-only `--delivered-pr` invocation of `scripts/check-release-gate.py` overrides
`GH_TOKEN` with the verifier. Missing or denied verification does not fall back
to the writer or report successful delivery.

`.github/workflows/cd.yml` and `.github/workflows/release.yml` pass the workflow's
`github.token` as the verifier and add only pull-requests/checks read permissions
to the release jobs, retaining their existing contents-write permission. The
fine-grained PAT remains responsible for workflow-file writes and creating PRs
whose checks actually run. The verifier's `gh` authentication is environment-based,
not a token-valued command argument. The existing writer setup still passes a
credential-bearing URL to `git remote set-url`; that mechanism is not changed or
exercised by the delivery harness. `CONTRIBUTING.md` describes the separate
credentials and direct-caller requirement; the checker diagnostic distinguishes
release-identity preflight from App-token readback. Historical incident commentary
in the changed workflows/script is generalised without changing their guards.
Generated PR text calls coherence validation automated evidence, not human review,
and no longer claims that bypass capability makes CI alone sufficient to merge.

## Proof and boundaries

`scripts/tests/test_deliver_release_pins.py` drives the real shell and checker
against invented, role-aware Git/API fixtures. It verifies writer preflight and
cleanup, App-only PR/check-run readback, open/armed and immediate-merge paths,
missing/empty verifier before mutations, denied verifier without retry under the
writer, and absence of credential values from the delivery harness output or
arguments. It also checks the generated PR's review-policy wording. Workflow
contract tests cover both callers and their job-local read permissions. Existing
negative timing, failed/missing CI, truncated response and exit-code cases remain
in force; the pure merge-order logic is unchanged.

Local synthetic execution and source review do not prove that a saved hosted
secret works or that a reviewed release cycle completed. Human approvals,
strict required CI, exact-head/timestamp proof and failures on unreadable evidence
remain required. This change does not request a broader PAT, bypass reviews,
change branch protections, dispatch a release, move an existing tag or publish a
repository.
