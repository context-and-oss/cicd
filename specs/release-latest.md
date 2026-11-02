# Intent: reconcile the reviewed source candidate

## Why

A clean import must retain intended fixes and dependency updates rather than
silently omit pending work or overwrite sanitised source with an older release
snapshot. Because source reconciliation and release delivery are different
operations, this record describes a proposed v5.1.2 candidate, not a tag,
published version, completed review or completed destination bootstrap.
A version already published for different source must not be reassigned,
because consumers and caches can retain the earlier immutable tag contents.

## What is retained and changed

Allocation-safe SBOM collection growth and its regression tests are already in
the reviewed source. They are retained rather than reapplied or reimplemented.
The runtime-only workflow-rule adaptation and previous privacy curation also
remain intact.

The SARIF uploader in `.github/workflows/commit.yml`,
`.github/workflows/dast.yml`, `.github/workflows/dogfood-precommit.yml` and
`.github/workflows/precommit.yml` now uses the upstream v4.39.1 commit. This is
an action dependency pin change, not removal of CodeQL or a change to workflow
permissions, conditions or required checks.

`scripts/bump-version.py` is deliberately unchanged. Its canonical all-scope
operation rebuilds every managed module/workflow/template pin at proposed
v5.1.2 on the current sanitised files. Reconstructing the proposal here, rather
than copying an earlier release artifact, preserves the current provenance,
privacy and review-policy corrections. `CHANGELOG.md` remains unreleased;
`CONTRIBUTING.md` distinguishes proposed pins from a real bootstrap.

## Verification and delivery boundary

Pin/command coherence and repository gates must pass alongside the allocation
regressions. The upload action's commit is checked against its upstream version
ref. Existing source execution behaviour is retained; local checks do not prove
a hosted upload, destination protections, release availability or tag handoff.

No old Git objects, issue/review history, Actions content, credentials or source
archives belong to this reconciliation. No source push, tag, release, human
approval, protected-branch bypass, repository rename or publication is asserted.
The matching bootstrap version and destination execution still need explicit
acceptance under the destination's effective policy. A successful CI check is
not a required approving review, and an approved source proposal is not evidence
that a release was delivered.
