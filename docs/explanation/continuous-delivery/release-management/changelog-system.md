# Release Versioning and Changelog

## Overview

This repository uses conventional commits and git-cliff to compute release
versions and notes; a manually added changelog version is not the release input.
`cd.yml` follows successful CI on a push to the repository's `main`.
`release.yml` is the manually requested version path. Both use
`scripts/ci/deliver-release-pins.sh` to deliver managed pin changes by pull request.

This describes the source-defined mechanism, not proof that hosted protections,
credentials, human review or the complete release loop have been verified.

---

## How It Works

1. **Write parseable conventional commits.** The `commit-subjects` CI job
   checks parseability; a subject git-cliff cannot parse can otherwise disappear
   from release computation.
2. **Compute the version from unreleased history.** CD runs
   `git cliff --unreleased --bumped-version` and separately checks the bump
   against reachable history, including the no-release path. The manual release
   workflow takes an explicit version instead.
3. **Validate and deliver pins.** The shared delivery script updates managed
   pins, runs the workflow-pin gate, generates a release intent artifact and
   opens or reuses a `chore/release-v<version>` pull request. It checks effective
   required `ci` policy and uses a separate read credential for delivered-PR
   verification, never a writer fallback.
4. **Review and merge normally.** Required CI and actual human review remain
   separate obligations. Arming auto-merge supplies no human approval and must
   not be treated as review evidence.
5. **Tag only the matching delivered state.** Normal CD can tag on a later run
   once pins match; the manual workflow waits for delivery and verifies the
   merged state before its own tagging path. Superseded versions are skipped; a moved `main` is not
   tagged using a version computed for an earlier tip. The handoff checks and
   scheduled drift monitor report unresolved delivery rather than making a
   changelog edit stand in for a release.

```text
Conventional commits → successful CI → version computation + bump check
    → validated pin/intent PR → required CI + human review → merge
    → matching-state release run → tag and generated release notes
```

---

## Why Keep the Changelog as Output?

Release notes describe the version selected from history; they do not select it.
Using the same unreleased partition for version computation and notes avoids
filing newly merged changes under an already shipped release.

The pin PR keeps release changes on the normal review path instead of pushing
release edits directly to `main`. Source code can check CI and delivery state,
but it cannot by itself establish that an authorized human reviewed a release.
Effective destination policy and an observed, human-reviewed source-to-release
loop still need verification. Do not infer that proof from generated notes or a
successful automation status.

---

## Related Documentation

- [Release Notes](./release-notes.md) - How to write effective release notes
- [Release Evidence](./release-evidence.md) - What evidence is required for approval
- [Commit Messages](../workflow/commit-messages.md) - Conventional commit format
