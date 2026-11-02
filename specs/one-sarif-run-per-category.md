# Intent: one SARIF run per Code Scanning identity, and a refused upload is never silent

## Why

A consumer's commit run surfaced this annotation on 2026-08-11:

> The CodeQL Action does not support uploading multiple SARIF runs with the same
> category. Please update your workflow to upload a single run per category.

Since 2025-07-22, GitHub Code Scanning identifies a SARIF run by the pair
**(tool driver name, category)** and rejects an upload whose runs collide on it —
it used to combine such runs silently
([changelog](https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/)).
This repository produces that collision by design, in three places:

- a multi-project Node tree is one `eslint` run per project (`nodeProjectDirs`,
  ties at the shallowest depth kept);
- a multi-module Go tree is one `golangci-lint` run per module (`goModuleDirs`,
  every module kept — Go's semantics);
- a solution-less .NET tree is one `dotnet-format` run per project.

`evidence.Wrap` concatenates every envelope's runs into one `findings.sarif`,
and the workflows upload it under a single `category:` (`cicd-commit`,
`cicd-precommit`, `cicd-precommit-dogfood`). Two same-tool runs in that file are
one identity, so the whole upload is refused. Single-project repositories are
unaffected — this repository's own dogfood evidence carries
three runs with three distinct driver names, which is why the defect only
surfaced in a consumer.

The quiet half is worse. The upload step ran with `continue-on-error: true` so
that repositories without GitHub Advanced Security would not fail, and that
setting cannot tell "this repo cannot receive SARIF" from "GitHub refused this
file". A consumer whose upload was rejected kept a green run and silently lost
their Code Scanning coverage — the standing failure class, at the upload seam: a
tool that could not run reading exactly like a tool with nothing to report.

## What changed

**`stampSARIFAutomationID` (`src/quality/sarifdoc.go`)** writes
`automationDetails.id = cicd/<tool>/<dir>` onto each run when a leg produced
more than one (`runGolangciLint`, `runEslint`, `runDotnetFormat`). The id is
built from the project directory, not an ordinal, so adding a project does not
shift the identity of the ones already there. Single-run legs are deliberately
not stamped: they keep the workflow category they have always had, and
restamping would re-key every existing alert for no gain. Same tolerance
contract as `stampSARIFDriverVersion` — any parse or marshal failure returns
the original bytes, because run identity must never cost a finding.

This works because `upload-sarif`'s `category` input fills `automationDetails`
**only where it is absent** — verified against codeql-action's
`populateRunAutomationDetails`, which guards on
`run.automationDetails === undefined`. A stamped run's id becomes its category;
unstamped runs keep the workflow's.

**`uniqueRunIdentities` (`src/cross-cutting/evidence/main.go`)** is the backstop
at the one seam every run passes through: any two runs in the merged document
colliding on (driver name, automation id) keep the first untouched and suffix a
deterministic ordinal onto the rest, bumping past ids a producer already owns.
A producer added tomorrow cannot reintroduce the silent loss. Unparseable runs
pass through byte-identical.

**The upload steps ask which failure they have** (`commit.yml`,
`precommit.yml`, `dogfood-precommit.yml`). A probe hits
`GET /repos/{repo}/code-scanning/analyses?per_page=1` first: 403 is "Advanced
Security not enabled" — skip the upload with a notice, findings remain in the
summary, comment and artifact; 200/404 mean the API is there, so the upload
runs **without** `continue-on-error` and a rejection fails the job. Any other
status is a third answer that fails loud, same shape as `commit-subjects`'
exit 2.

## Also in this change

`actions/create-github-app-token` v3 deprecates the `app-id` input (two
warnings per commit run, one per token mint). All three sites now pass
`client-id: ${{ secrets.CICD_APP_CLIENT_ID || secrets.CICD_APP_ID }}` — the
numeric app ID remains a valid JWT issuer, so orgs that have only the legacy
secret keep working; setting `CICD_APP_CLIENT_ID` at the org completes the
migration. Templates and how-to guides updated (the guides also pinned the
action at `@v1`, which predates the deprecation by two majors).

## Proof

- `src/quality/sarifdoc_test.go` — stamp writes the id, preserves sibling
  `automationDetails` properties and the results array, tolerates malformed
  documents, names the root.
- `src/cross-cutting/evidence/sarifruns_test.go` — collisions disambiguated
  (absent ids and explicit ids), first run byte-untouched, distinct identities
  never rewritten, unparseable runs pass through, and the property holds on the
  real `mergeSARIF` path.
- Measured end-to-end (2026-08-11): `quality.check` over a scratch Go workspace
  holding two modules (`mod-a`, `mod-b`) produced one envelope whose
  `sarifReport` carries two `golangci-lint` runs stamped
  `cicd/golangci-lint/mod-a` and `cicd/golangci-lint/mod-b` — the exact
  multi-module shape that previously collided into one refused identity.
- `scripts/smoke/commit-shapes.sh` (`unique_run_identity_expr`, in
  `assert_unique_identity`) — every shape's `composite-smoke-commit` run asserts
  no two runs in the uploaded `findings.sarif` share (driver name,
  `automationDetails.id`), so the invariant is guarded on real pipeline output,
  not only in unit suites.
