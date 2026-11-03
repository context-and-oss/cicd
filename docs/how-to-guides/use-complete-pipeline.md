# Use the complete pipeline

Use the complete path when you want the standard Stage 2 and Stage 4 delivery
flow with evidence, comments, artifacts, and optional Teams notifications.

## Choose the entry points

| CI moment | Module | What it runs |
|-----------|--------|--------------|
| Pull requests and non-main branches | `composites/precommit` | `quality`, `security scan-source`, `risk validate`, evidence wrapping, PR/summary output |
| Main branch commits | `composites/commit` | `build`, `sbom`, `security scan-image`, evidence wrapping, summary output |

Both pipelines run Semgrep with default rules fetched at run time from
`semgrep/semgrep-rules`, which are under the **Semgrep Rules License v1.0**,
not Apache-2.0 — internal business use only, no redistribution, no offering
them as a service. If that does not fit your use, pass your own suitably
licensed rules with the `sast-rulesets` input (`./your-config.yml`); see
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

Use one released tag consistently in the files you adopt. The starter templates
show their current pins; update those pins during rollout if your module tag is
newer.

## GitHub Actions

Copy the starter workflows into the application repository:

```bash
mkdir -p .github/workflows
cp templates/github-actions/precommit.yml .github/workflows/precommit.yml
cp templates/github-actions/commit.yml .github/workflows/commit.yml
```

The cicd modules are fetched from the public repository, so no secret is
required to run either workflow. The optional secrets:

| Secret | Purpose |
|--------|---------|
| `TEAMS_WEBHOOK` | Posts Teams notifications |
| `NPM_FEED_TOKEN` | Authenticates private npm feeds |
| `NUGET_FEED_TOKEN` | Authenticates private NuGet feeds |

The commit workflow builds and scans the image but never publishes it — each
consumer repo owns its own deployment, so no registry credentials are needed.
The copied `.github/workflows/commit.yml` works as-is:

```yaml
jobs:
  commit:
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.3
    secrets:
      TEAMS_WEBHOOK: ${{ secrets.TEAMS_WEBHOOK }}
      NPM_FEED_TOKEN: ${{ secrets.NPM_FEED_TOKEN }}
      NUGET_FEED_TOKEN: ${{ secrets.NUGET_FEED_TOKEN }}
```

### Why the secrets are mapped by name

`secrets: inherit` would hand the reusable workflow every secret the caller
can see. The map above passes **only the keys it names**, and only keys the
reusable workflow declares can be listed at all. Delete a line to withhold
that secret; the smallest caller names only what it uses:

```yaml
jobs:
  commit:
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.3
    secrets:
      TEAMS_WEBHOOK: ${{ secrets.TEAMS_WEBHOOK }}
```

An optional secret left out of the map resolves empty inside the reusable
workflow, and the Teams leg then reports `SKIPPED` rather than failing.

## Azure DevOps

Azure DevOps can consume this pipeline in two ways:

- copy the starter YAML into each application repository
- keep shared Azure Pipelines templates in a central GitHub repository and let
  each application repository reference them through a GitHub service connection

Use the copy-based setup when you want the fastest adoption path. Use the
shared-template setup when many Azure DevOps projects should consume the same
pipeline definition.

### Copy the starter pipelines

Copy the starter pipelines into the application repository:

```bash
mkdir -p .pipelines
cp templates/azure-devops/precommit.yml .pipelines/precommit.yml
cp templates/azure-devops/commit.yml .pipelines/commit.yml
```

Create the variables described at the top of each template. At minimum:

| Variable | Required for | Purpose |
|----------|--------------|---------|
| `ADO_ORG` | precommit PR comments | Azure DevOps organization name |

Enable "Allow scripts to access the OAuth token" if you want Azure DevOps PR
comments.

### Use shared templates from GitHub

If Azure DevOps should use centrally managed templates from GitHub, create a
GitHub service connection in the Azure DevOps project:

1. Open **Project settings**.
2. Open **Pipelines > Service connections**.
3. Create a **GitHub** service connection.
4. Authorize the GitHub organization or repository that stores the shared
   pipeline templates.
5. Name the connection consistently, for example `github-shared-pipelines`.

Then keep only a small pipeline file in each application repository. The
application repository owns triggers; the shared template owns jobs, steps, and
pipeline behavior.

```yaml
trigger:
  branches:
    exclude:
      - main

pr:
  branches:
    include:
      - '*'

resources:
  repositories:
    - repository: cicdTemplates
      type: github
      name: context-and-oss/cicd
      endpoint: github-shared-pipelines
      ref: refs/tags/v0.1.0

extends:
  template: templates/azure-devops/shared/precommit.yml@cicdTemplates
```

For the commit pipeline, use the same service connection and point at the commit
template:

```yaml
trigger:
  branches:
    include:
      - main

resources:
  repositories:
    - repository: cicdTemplates
      type: github
      name: context-and-oss/cicd
      endpoint: github-shared-pipelines
      ref: refs/tags/v0.1.0

extends:
  template: templates/azure-devops/shared/commit.yml@cicdTemplates
```

Keep template refs pinned to a released tag. Move projects to a newer tag
deliberately instead of tracking `main`.

The GitHub service connection gives Azure DevOps permission to fetch the YAML
template repository. The Dagger modules themselves are fetched from the public
cicd repository inside the run and need no credential.

When the service connection is not granted to all pipelines, the first run may
pause and ask an Azure DevOps admin to permit that pipeline to use the
connection.

## Run the complete pre-commit pipeline locally

From this repo, use local module paths while developing or testing the pipeline:

```bash
dagger -m ./src/composites/precommit call run \
  --src ./testdata/go-app \
  --fail-on NONE \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  export --path ./out/precommit-evidence
```

From an application repo, use the released module address:

```bash
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.3 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./audit-evidence
```

## Run the complete commit pipeline locally

Use this when the source has a Dockerfile. The image is built and scanned but
never published — each consumer repo owns its own deployment:

```bash
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.3 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./audit-evidence
```

Add `--dockerfile` when the Dockerfile does not sit at the source root, and
`--platform` to build for something other than `linux/amd64`. Both default to
the module's values (`Dockerfile`, `linux/amd64`) when omitted, and both are
reachable from the harnesses as well — `dockerfile` / `platform` inputs on the
reusable workflow, `DOCKERFILE` / `PLATFORM` variables in the Azure DevOps
templates — so a repository whose Dockerfile lives under `docker/` does not have
to move it to be scanned.

The exported audit directory contains:

| File | Meaning |
|------|---------|
| `combined-evidence.json` | Combined pass/fail state and finding counts |
| `findings.sarif` | SARIF findings suitable for code scanning |
| `sbom.cdx.json` | CycloneDX SBOM when a module produced one |
| `comment.md` | Markdown summary for CI job summaries or PR comments |

## Tune the gate

Use `--fail-on` to decide which severities fail the pipeline:

| Value | Behavior |
|-------|----------|
| `CRITICAL` | Fail only on critical findings |
| `HIGH` | Fail on high or critical findings |
| `MEDIUM` | Fail on medium, high, or critical findings |
| `LOW` | Fail on any finding |
| `NONE` | Never fail on findings; useful for first rollout |

`NONE` suppresses **findings**, not non-runs: a step that could not execute still
reports `passed: false` at every threshold, with the reason in `errors[]`. A green
`NONE` run therefore means the pipeline did the work and you chose not to gate on
what it found — not merely that nothing came back.

## Related

- [Run the pipeline locally](run-pipeline-locally.md)
- [Mix and match modules](mix-and-match-modules.md)
- [Use individual modules](use-individual-modules.md)
