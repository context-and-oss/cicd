# Intent: scope the intent gate automatically when validating locally

## Why

The local pre-push runner never produced a diff, so the intent gate fell back
to auditing every artifact in the tree. Because of that, a developer validating
one change was shown the whole repository's intent backlog, which buried the
signal for the change they were actually pushing. We generate the diff inside
the runner instead, since the Dagger module has no access to Git and cannot know
what a change touched.

## What changed

`scripts/cicd-prepush` now resolves a base ref from local Git state, builds the
diff, and passes it to the precommit composite. The same block lands in
`templates/local/scripts/cicd-prepush` so consumer repositories inherit the
behaviour rather than re-deriving it. The scope reason is logged so a full audit
is never silent.

## Decisions

We scope to committed work first and fall back to the working tree only when no
commits exist yet, because a pre-push check should judge what is about to be
pushed rather than half-saved edits. When no base resolves we keep the full
audit, so the runner never hides a genuine presence failure just to stay quiet.
