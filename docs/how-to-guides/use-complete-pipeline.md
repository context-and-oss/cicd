# Use the complete pipeline

Use the complete path when you want the standard Stage 2 and Stage 4 delivery
flow with evidence, comments, artifacts, and optional Teams notifications.

## Choose the entry points

| CI moment | Module | What it runs |
|-----------|--------|--------------|
| Pull requests and non-main branches | `composites/precommit` | `quality`, `security scan-source`, `risk validate`, evidence wrapping, PR/summary output |
| Main branch commits | `composites/commit` | Repository source gate (`quality`, source security, risk validation), then explicit `container`, `archive` or `none` artifact tail, evidence wrapping and summary output |

See [archive/none shapes](use-without-dockerfile.md) for non-container repositories.
[Application mode](../../templates/github-actions/commit-monorepo.yml) uses explicit
app boundaries and check legs rather than repository-wide discovery; its dependency
vulnerability, dependency licence and SBOM assessments are currently deferred.
Do not interpret its passing result as repository-wide or dependency assurance.

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

Verify that the referenced release exists and platform policy permits these
reusable workflows and actions. Public modules support anonymous fetching;
private copies require read-only source access. See
[availability and source access](../../README.md#availability-and-source-access)
for separate source-checkout/local-module use. Package-feed and notification
credentials do not grant module-source access.

Optional secrets (omit them unless needed):

| Secret | Purpose |
|--------|---------|
| `TEAMS_WEBHOOK` | Posts Teams notifications |
| `NPM_FEED_TOKEN` | Authenticates private npm feeds |
| `NUGET_FEED_TOKEN` | Authenticates private NuGet feeds |

The commit workflow builds and scans the image but never publishes it — each
consumer repo owns its own deployment, so no registry credentials are needed.
Once workflow access is established, a minimal caller is:

```yaml
jobs:
  commit:
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.4
    # No optional secrets by default.
```

### Why the secrets are mapped by name

`secrets: inherit` would hand the reusable workflow every secret the caller
can see. When a feature needs a secret, map **only the keys it needs**; only keys
the reusable workflow declares can be listed. For example, opting into Teams:

```yaml
jobs:
  commit:
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.4
    secrets:
      TEAMS_WEBHOOK: ${{ secrets.TEAMS_WEBHOOK }}
```

An optional secret left out of the map resolves empty inside the reusable
workflow, and the Teams leg then reports `SKIPPED` rather than failing.

### Coverage baseline and enforcement

The precommit caller excludes main pushes. Its baseline fetch looks for
`precommit-evidence-*` in successful default-branch runs of that **same caller
workflow**; commit workflow artifacts do not seed it. Configure a default-branch
push path in that same precommit caller, with the same coverage-producing inputs,
before relying on its ratchet. Verify a successful seed artifact, the next PR's
baseline selection, and a controlled regression failure. The shipped starter pair
does not establish this automatically. Commit coverage measurement is supported
with `test-cmd` plus `coverage-path` or per-leg `coveragePath`; its ratchet is
separately opt-in through `coverage-gate`.

Retain minimum-coverage, blocking licence, full-history secrets and live-verification
protections until equivalent scope and enforcement are configured and verified.
A relative ratchet is not a minimum; default licence warn mode is not blocking.

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

For **Azure Repos**, an owner must configure a required target-branch
**Build validation** policy selecting the precommit pipeline. YAML `pr:` does not
establish Azure Repos PR validation. Verify an actual PR-triggered run, the required
policy's blocking behavior, and comment delivery separately. For GitHub-hosted
source in Azure Pipelines, YAML PR triggers apply subject to platform settings.

For comments, expose `System.AccessToken` and grant the build service permission
to contribute to pull requests; see [authentication](set-up-azure-devops-auth.md).

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
      ref: refs/tags/v5.1.4

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
      ref: refs/tags/v5.1.4

extends:
  template: templates/azure-devops/shared/commit.yml@cicdTemplates
```

Keep template refs pinned to a released tag. Move projects to a newer tag
deliberately instead of tracking `main`.

The GitHub service connection authorizes fetching the YAML template repository.
It does not automatically authorize Dagger's separate module fetch inside the run.
Establish separately authorized read-only module-source access, or use local module
paths from an authorized separate checkout; never substitute a writer credential.
Verify the pinned shared-template files and their module dependencies before use.

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

The fixture command above is inspection only. From an application repo, once
module-source access is established, export and grade a fresh bundle:

```bash
rm -rf ./audit-evidence &&
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.4 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./audit-evidence &&
jq -e '.passed == true' ./audit-evidence/combined-evidence.json > /dev/null
```

## Run the complete commit pipeline locally

Use this when the source has a Dockerfile. The image is built and scanned but
never published — each consumer repo owns its own deployment:

```bash
rm -rf ./audit-evidence &&
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.4 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./audit-evidence &&
jq -e '.passed == true' ./audit-evidence/combined-evidence.json > /dev/null
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
`NONE` run therefore does not mean clean or complete examination. Inspect warnings,
suppressions and per-source scope, examined and rules metadata even when `passed`
is true; partial or unrequested checks may not fail the verdict.

## Related

- [Run the pipeline locally](run-pipeline-locally.md)
- [Mix and match modules](mix-and-match-modules.md)
- [Use individual modules](use-individual-modules.md)
