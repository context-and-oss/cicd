# ADR-006: The consumer publishes release reports

## Status
Accepted

## Context
Consumers ship per-release SBOM, SCA and SAST reports to their customers from a
CDN. The commit pipeline already produces all three — `sbom.cdx.json`
(CycloneDX + Trivy vulnerability data), `findings.sarif` (SAST/lint/secrets),
`combined-evidence.json` (the audit record) plus `comment.md` (the rendered
human summary) — uploaded together as one workflow artifact. But nothing made
external consumption contractual: the artifact name and file names were
implementation details a consumer had to read cicd's workflow source to learn,
and a rename here would break every downstream publisher silently. Two further
facts shape the contract. Workflow artifacts expire (90-day retention), so the
artifact is a hand-off point, not an archive. And a vulnerability verdict
decays: the SBOM is frozen at release time while CVE knowledge moves, so
"vulnerabilities in release X" is a different question on the day of release
than a month later.

## Decision
cicd builds the reports; the consumer publishes them. The ownership split of
ADR-001 extends to reports: publishing, CDN targets and their credentials live
in the consumer repository, and cicd exposes a contract instead:

- **Stable file names** inside the evidence directory: `combined-evidence.json`,
  `findings.sarif`, `sbom.cdx.json`, `comment.md`. Renaming any of these is a
  breaking change.
- **Stable artifact names**: `commit-evidence-<sha>` and
  `precommit-evidence-<sha>`, now declared as the `evidence-artifact` workflow
  output rather than left for the consumer to reconstruct. Retention caveat:
  publish at release time — after 90 days the artifact is gone.
- **`workflow_call: outputs:`** on both reusable workflows are the consumption
  seam: `evidence-artifact`, `passed`, `findings-count`, `findings-by-severity`,
  `coverage-ratchet`, and `gates` (the per-source verdicts behind the combined
  `passed`, from the envelope's `sources[]`). A caller gates, notifies or
  publishes from `needs.<job>.outputs.*` without parsing cicd's internals.
- **Frozen record vs living verdict**: per release the consumer's CDN holds the
  four files above, frozen — they attest what was known at release time. The
  current vulnerability posture is a separate, mutable document
  (`vuln-current.json` by convention) the consumer regenerates on a schedule by
  rescanning the frozen SBOM against today's vulnerability database. The rescan
  entry point is a function on the security module (delivered separately);
  overwriting the frozen files with rescan output is exactly the
  audit-record-that-lies-over-time this split exists to prevent.

## Amendment: Azure DevOps verdict gates

The Azure DevOps commit and precommit starters now have an active
`Gate on the evidence verdict` step that reads `combined-evidence.json` and
fails on a missing/unreadable verdict or `passed != true`. The former claim
that these templates have no gate is superseded. That gate is distinct from
GitHub's reusable-workflow outputs contract; ADO callers consume the evidence
artifact rather than `workflow_call` outputs. Template source alone does not
prove an adopted pipeline ran successfully or produced fresh evidence.

## Consequences
Easier: consumers publish from a named contract instead of source-diving;
a caller can gate on `passed` and per-gate `gates` without downloading the
artifact; the frozen/living split keeps the release-time audit record honest.
Harder: the artifact and file names are now API — renames need a major version;
the outputs chain is three links GitHub never validates, so
`check_workflow_output_chain` in `scripts/repo_surface.py` verifies every
declared output resolves end to end.
Committed to: cicd never publishes (no CDN credentials, no upload step in this
repository); frozen release files are never regenerated in place.

## Alternatives rejected
- cicd publishing to the CDN itself: puts customer-distribution credentials in
  every consumer's CI path through cicd and violates the ADR-001 split — the
  deploy side of the pipeline stays consumer-owned.
- Longer artifact retention instead of a publish step: an artifact is a
  hand-off, not a distribution channel; customers cannot read workflow
  artifacts, and retention limits are GitHub's to change.
- Refreshing vulnerability data by re-running the full pipeline on the release
  tag: a rebuild produces a new artifact, and scanning it attests something
  other than what shipped. The frozen SBOM is the only input that still
  describes the shipped release.
