# Use individual modules

Use individual modules when you want one capability without adopting the full
pre-commit or commit pipeline.

## Quality

Run linting and unit tests:

```bash
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.2 call check \
  --src . \
  --include go \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-quality.json
```

Repeat `--include` for the languages you want, or omit it to let the module
detect supported languages. Supported values are `go`, `node`, `python`, and
`dotnet`.

## Source security

Run SAST, secrets detection, and filesystem vulnerability scanning:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-security.json
```

Scope a scan when a repository has generated or vendored content:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
  --src . \
  --path services/api \
  --exclude vendor \
  --exclude generated \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-security.json
```

## Image security

Scan a built container image:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-image \
  --image alpine:3.19 \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-image-security.json
```

## Web security

Run a passive OWASP ZAP baseline scan against a live target:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-web \
  --target https://staging.example.com \
  --full=false \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-web-security.json
```

Only use `--full=true` against environments you own and control.

## Risk

Validate committed `findings.json` and `decisions.json` in CI:

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.2 call validate \
  --source . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-risk.json
```

Generate those files during a local review:

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.2 call scan \
  --source . \
  export --path .
```

Then review `decisions.json`, commit both risk files, and let `validate` enforce
the decisions in CI.

## Build and SBOM

Build an OCI image and generate a CycloneDX SBOM:

```bash
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.2 call build \
  --src . \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo"

dagger -m github.com/context-and-oss/cicd/src/build@v5.1.2 call sbom \
  --image alpine:3.19 \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-sbom.json
```

Use a custom Dockerfile path or platform with `--dockerfile` and `--platform`
when calling `build`.

## Notifications

Build a PR or build-summary comment from an evidence file:

```bash
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.2 call github-build-comment \
  --summary ./evidence-security.json \
  --pipeline-name security \
  export --path ./comment.md
```

Post to Teams when you have an incoming webhook. `teams` returns an evidence
envelope of its own, so export it — that document is the only place that says
whether the card arrived:

```bash
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.2 call teams \
  --summary ./evidence-security.json \
  --pipeline-name security \
  --webhook-url env:TEAMS_WEBHOOK \
  export --path ./evidence-teams.json
```

Its `outcome` is `CLEAN` when the card was delivered, `SKIPPED` when
`TEAMS_WEBHOOK` held nothing to post to, and `ERROR` when the card was
attempted and lost — a rotated or revoked webhook looks exactly like the last
case. `passed` stays `true` in all three: a notification is not a gate. Pass
`--webhook-url` only when the value exists; the composites' starter workflows
guard it for the same reason.

## GitHub Actions example

This job runs only the source security module and uploads its evidence:

```yaml
name: Source security

on:
  pull_request:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Dagger
        # Checksum-verified download, no `curl install.sh | sh`.
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.1.2
        with:
          version: 0.20.8

      - name: Run source security scan
        run: |
          dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
            --src . \
            --fail-on HIGH \
            --commit-sha "$GITHUB_SHA" \
            --branch "$GITHUB_REF_NAME" \
            --repo-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
            export --path ./evidence-security.json

      - name: Gate on the verdict
        # dagger call exits 0 whatever the verdict; it is in the file. A
        # missing file or a missing `passed` fails here too.
        run: jq -e '.passed == true' ./evidence-security.json > /dev/null

      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-evidence-${{ github.sha }}
          path: ./evidence-security.json
```

If you use `quality`, `risk`, `build`, or `notify` instead, keep the auth and
install steps and replace only the `dagger -m ... call ...` command.

Keep the gate step whichever module you call. `dagger call` exits 0 whatever
the verdict — a run with HIGH findings and a run whose scanner never started
both export a file and succeed — so the verdict lives only in the envelope's
`passed` field. A scanner that could not run is named in `errors[]` and sets
`passed: false` at every `--fail-on`, `NONE` included; the gate is what turns
that into a red job.

To upload SARIF to GitHub code scanning, wrap one or more evidence files with
`cross-cutting/evidence` first and upload the generated `findings.sarif`.

## Azure DevOps example

This pipeline runs the same source security module:

```yaml
trigger: none

pr:
  branches:
    include:
      - '*'

pool:
  vmImage: ubuntu-latest

variables:
  DAGGER_VERSION: "0.20.8"

steps:
  - checkout: self
    fetchDepth: 0

  # Install Dagger: copy the "Install Dagger CLI" step from
  # templates/azure-devops/commit.yml. It verifies the download against its
  # checksum and needs no sudo, where piping install.sh into sh runs a script
  # nobody read.

  - bash: |
      mkdir -p ./out
      dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
        --src . \
        --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./out/evidence-security.json
    displayName: Run source security scan

  - bash: jq -e '.passed == true' ./out/evidence-security.json > /dev/null
    displayName: Gate on the verdict

  - publish: ./out/evidence-security.json
    artifact: security-evidence-$(Build.SourceVersion)
    displayName: Upload evidence
    condition: always()
```

The modules are fetched from the public cicd repository, so no GitHub
credential is needed on either platform.

## Related

- [Use the complete pipeline](use-complete-pipeline.md)
- [Build your own pipeline](build-your-own-pipeline.md)
- [Mix and match modules](mix-and-match-modules.md)
