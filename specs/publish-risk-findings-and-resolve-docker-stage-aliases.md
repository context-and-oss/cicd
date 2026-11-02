# Publish infrastructure findings and recognise Docker stage aliases

Two reports exposed two separate ways the infrastructure-policy gate
could disagree with the surface a consumer reads. The fixes travel together
because both start in `risk.Validate`, but each keeps its own regression boundary.

## Findings must reach the standard report channel

`src/risk/opa.go` put every Conftest violation in `genericReport` and never set
`sarifReport`. The evidence bundle therefore retained the verdict and rows, but
`src/cross-cutting/evidence/main.go` had no risk run to merge into
`findings.sarif`. GitHub Code Scanning received every other SARIF-producing tool
and none of the infrastructure findings that had actually failed the gate.

`src/risk/sarif.go` now builds one `risk-validate` SARIF run from the same
post-override violation list used for the counts and verdict. A policy id becomes
`ruleId`, a repository-relative file becomes the physical artifact location, and
the canonical severities map to SARIF error, warning, and note levels. The
canonical value also remains in a result property because SARIF has no distinct
CRITICAL level; the bundle reader uses that property in order to keep its detail
row aligned with `findingsBySeverity`.

The run exists with empty result and rule arrays when Conftest completed cleanly.
When an infrastructure group did not run, `invocations.executionSuccessful` is
false and the existing bounded errors become tool execution notifications. This
was chosen because an absent run and a clean run answer different questions, and
a scanner failure must not acquire a clean-looking report while crossing into
SARIF.

New risk envelopes still carry `genericReport` for compatibility. The aggregator
now treats SARIF as the finding-detail source when both are present, since reading
both would show every policy violation twice. It retains the generic reader for
older evidence artifacts and now preserves their policy id and file fields.

`src/risk/schema.go`, `src/risk/README.md`,
`src/composites/commit/CLAUDE.md`,
`docs/how-to-guides/run-pipeline-locally.md`, and
`docs/explanation/continuous-delivery/security/risk-analysis.md` now state that
infrastructure-policy findings participate in the SARIF and Code Scanning path.

`src/risk/sarif_test.go`, `src/cross-cutting/evidence/findings_test.go`, and
`src/cross-cutting/evidence/sarifruns_test.go` cover the clean, finding, non-run,
legacy, deduplication, and final-merge paths.

## A previous Docker stage is not a registry image

`src/risk/policy/infra/docker.rego` applied the unpinned-image test to the first
token of every `FROM`. That is correct for registry references, but Docker also
allows a later stage to use an earlier named stage as its base. In `FROM base AS
final`, `base` carries no independent tag because it names the stage whose source
was already judged.

The policy now checks for a case-insensitive alias declared by an earlier `FROM`
before applying DOCKER-002. The instruction index is part of the predicate because
a future `AS base` cannot change the meaning of an earlier `FROM base`; Docker
would try to pull the earlier token as an image. The originating image is still
checked, so an unpinned image reused through an alias produces one finding rather
than zero or two.

`src/risk/policy/infra/docker_test.rego` covers pinned and unpinned origins,
case-insensitive lookup, alias chains, future declarations, and unrelated
untagged images. These cases run with the repository's pinned Conftest v0.58.0.
