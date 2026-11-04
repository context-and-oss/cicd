# Changelog

## Unreleased — consumer documentation and publication readiness

- Correct consumer commands, evidence-gate examples, scope and authentication
  guidance against the implemented interfaces.
- Distinguish current source availability from anonymous access, fork CI,
  reporting delivery and a completed human-reviewed release cycle.

These notes describe pending source changes, not a new tag or a claim that
publication or release approval has happened.

## v5.1.3 — clean-source bootstrap

The canonical repository has independent clean history and a matching
`v5.1.3` bootstrap tag/release. Managed module references name that baseline.
It includes the Stage 2 source gate, the commit composite's explicit
`container|archive|none` artifact paths, and running-app DAST on its own cadence.
See [README.md](README.md#module-reference) for the implemented modules.

The bootstrap establishes source availability for authorized readers; it does
not prove public visibility, anonymous fetching, public-fork CI, private-report
delivery or an ordinary required-human-review-compliant release cycle. Those
checks remain separate. Retired Git history and GitHub state were not imported.

## Source preparation history

The initial source proposal used coherent `v5.1.2` pins before the separately
approved bootstrap. That proposal was not a matching destination release.
The preparation work:

- Generalised private operational narratives and replaced captured diagnostics
  with invented ordering/classifier fixtures while retaining regression cases.
- Described release checks without private organisation-specific names;
  retained runtime endpoints, guards and policy checks.
- Distinguished auto-merge arming, bypass permission and required human approval;
  permission to bypass is not an approving review.
- Retained Trivy attribution and added ZAP excerpt provenance/source notices.
  Default Semgrep rules remain under restrictive runtime terms. The workflow
  compatibility adapter obtains upstream content at runtime and retains its
  notices rather than distributing an upstream rule body in this tree.
- Retained allocation hardening and regression tests. Local validation alone
  did not establish destination release behaviour.
- Updated the SARIF upload action to its verified pinned revision without
  changing workflow permissions or findings thresholds.
