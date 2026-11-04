# Intent: make adoption documentation match the shipped interfaces

## Why

A consumer can run a documented command and still have no working gate because
an option was removed, an example grades an old output, or a shared template
names a tag absent from the clean repository. Link and function-name checks do
not establish command arguments, source scope, credential boundaries or verdict
enforcement. Describing a planned publication as already public also sends a
new adopter down an unavailable fetch path.

## Change

Align the consumer guides and module documentation with implemented entry
points, explicit evidence grading, artifact identity, supported access and
coverage limits. Keep conceptual delivery stages separate from available APIs.
Retain source-owned regression examples and explain consumer mechanisms without
distinctive integration measurements.

Update `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
`CHANGELOG.md`, `CLAUDE.md`, `ROADMAP.md` and `scripts/README.md` so current
bootstrap status, tool prerequisites, reporting availability and release
outcomes do not imply unperformed public or human-approval checks.

Extend `scripts/repo_surface.py` and its regressions in
`scripts/tests/test_repo_surface.py` to read and rewrite the named cicd Azure
DevOps repository-resource tag form as well as module, action and workflow
pins. Share the multiline version reader with `scripts/release_handoff.py`
and cover its reference-line reporting in `scripts/tests/test_release_handoff.py`. The resource matcher must not rewrite another repository's tag or cross
into another mapping. The shared-template examples need this because a release
bumper that ignores their pin would leave them stale immediately afterward.

Validation also found that removing the fake CLI let the proxy loopback test
search the host PATH. Isolate `src/risk/claude-proxy.test.js` to its fixture bin
and the selected Node executable. A second controlled fake must prove that a
missing fixture returns an error rather than falling through to another CLI;
no production proxy behaviour changes.

## Verification and boundary

Require the new stale-resource regression to fail before the guard change and
pass afterward; run the script suite and repository surface/pin/template/image
checks. Review the actual documentation changes against source and check the
revised command paths without contacting live notification or deployment
services. Preserve runtime modules, released tags, severity thresholds and
repository protections. A normal checked pull request still needs a genuine
human review. Neither this artifact nor automated/model review grants approval,
public visibility, private-report delivery or legal clearance.
