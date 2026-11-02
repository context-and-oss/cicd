# Skip dependency assessment when no dependency scope exists

## Problem

`security.ScanSource` treats every native Trivy report with `Results: null` as a
tool error. That is correct when the repository declares a dependency ecosystem
that Trivy failed to resolve, but wrong for a repository containing no supported
dependency manifests or lockfiles. A dependency-free static site consequently
gets permanent ERROR rows for dependency vulnerabilities and its source SBOM,
even though neither concern is applicable.

Adding an empty package manifest only to manufacture a Trivy target would make
the repository describe a dependency ecosystem it does not have. Allowing a
consumer to disable Trivy would be broader than the fact being expressed and
could hide a real non-run later.

## Decision

We chose automatic applicability detection instead of a consumer-controlled off
switch because applicability is a fact about the scanned tree, while an off
switch could keep hiding a dependency scan after dependencies are added.

Use the existing independent dependency-input probe to distinguish the two
states behind a resultless Trivy report:

- `Results: null` and no supported dependency marker or input: dependency
  vulnerabilities and source SBOM are passing `SKIPPED` concerns;
- `Results: null` with a supported marker or input: keep the scan as an error,
  unless a rescan with development dependencies proves the input holds only
  development packages (see `specs/clear-a-development-only-lockfile.md`);
- a failed probe, empty report, malformed report, or any other scanner error:
  keep the scan as an error.

Each skipped concern carries its own NOT APPLICABLE warning. Neither row claims
an examined count, and no CycloneDX inventory is attached. `SKIPPED` is not
rewritten to `CLEAN`: the report must continue to distinguish an assessment that
ran and found nothing from one that had no applicable scope.

## Verification

Unit tests pin the typed no-targets condition, the independent-probe decision,
the two separate warnings, the passing `SKIPPED` tool rows, and the absence of a
fabricated examined count or inventory. Existing unresolved-ecosystem tests keep
declared-but-unresolved Node, Python and .NET trees red. The repository-wide
module unit suite, formatting check and defended-surface check cover integration
with the shared evidence model.
