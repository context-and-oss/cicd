# Mix and match modules

Use these combinations when the complete pipeline is too much for a repository,
or when different stages need different gates.

## Pick by outcome

| You want | Use |
|----------|-----|
| Fast feedback on a pull request | `quality` + `security scan-source` |
| A governance gate with human review | `risk scan` locally, `risk validate` in CI |
| Image assurance before publish | `build sbom` + `security scan-image` |
| Runtime web assurance | `security scan-web` against staging |
| Standard pre-commit behavior without notification | `stage-2` |
| Standard commit behavior without notification | `stage-4` |
| Full CI entry point with audit output | `composites/precommit` or `composites/commit` |

## Combine quality and source security

This is the smallest useful PR gate:

```bash
SHA="$(git rev-parse HEAD)"
BRANCH="$(git branch --show-current)"
REPO_URL="https://github.com/your-org/your-repo"

dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.2 call check \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-quality.json

dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-security.json
```

Use this when a repo does not build a container image, or when you want to roll
out scanning before adopting the complete composite.

## Add risk without slowing every PR

Run AI risk discovery on demand or on a schedule:

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.2 call scan \
  --source . \
  export --path .
```

Review and commit `findings.json` and `decisions.json`, then make CI enforce the
reviewed decisions:

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.1.2 call validate \
  --source . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-risk.json
```

## Split source and image security

Run source scanning before merge:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-source-security.json
```

Run image scanning after the image exists:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-image \
  --image "$IMAGE_REF" \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-image-security.json
```

## Use stages when you want standard grouping

`stage-2` returns evidence files for quality and source security:

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.1.2 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL"
```

`stage-4` returns evidence files for build/SBOM and image security:

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.1.2 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL"
```

Use the composite modules instead when you want wrapped audit output, generated
comments, and optional Teams notifications.

## Roll out gradually

Start permissive, then tighten:

| Rollout phase | Suggested gate |
|---------------|----------------|
| First visibility | `--fail-on NONE` |
| Stop the worst issues | `--fail-on CRITICAL` |
| Normal production gate | `--fail-on HIGH` |
| Strict regulated repo | `--fail-on MEDIUM` or `LOW` |

Keep the same evidence output path across phases so dashboards, artifacts, and
comments do not need to change.

## GitHub Actions mix-and-match example

This workflow uses the standard precommit composite on PRs, but adds a separate
passive web scan only for changes to the default branch:

```yaml
name: Mixed CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write
  actions: read

jobs:
  precommit:
    if: github.event_name == 'pull_request'
    uses: context-and-oss/cicd/.github/workflows/precommit.yml@v5.1.2
    secrets:
      TEAMS_WEBHOOK: ${{ secrets.TEAMS_WEBHOOK }}
      NPM_FEED_TOKEN: ${{ secrets.NPM_FEED_TOKEN }}
      NUGET_FEED_TOKEN: ${{ secrets.NUGET_FEED_TOKEN }}

  web-security:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Dagger
        # Checksum-verified download, no `curl install.sh | sh`.
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.1.2
        with:
          version: 0.20.8

      - name: Passive web scan
        run: |
          dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-web \
            --target https://staging.example.com \
            --full=false \
            --fail-on HIGH \
            --commit-sha "$GITHUB_SHA" \
            --branch "$GITHUB_REF_NAME" \
            --repo-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
            export --path ./evidence-web-security.json

      - name: Gate on the verdict
        # dagger call exits 0 whatever the verdict; it is in the file. A
        # missing file or a missing `passed` fails here too.
        run: jq -e '.passed == true' ./evidence-web-security.json > /dev/null

      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: web-security-${{ github.sha }}
          path: ./evidence-web-security.json
```

## Azure DevOps mix-and-match example

This pipeline runs quality and source security as separate module calls, then
uploads both evidence files:

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
      dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.2 call check \
        --src . \
        --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./out/evidence-quality.json

      dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
        --src . \
        --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./out/evidence-security.json
    displayName: Run selected modules

  - bash: |
      # One verdict per file: `jq -e` over several files reports only the last.
      fail=0
      for f in ./out/evidence-quality.json ./out/evidence-security.json; do
        jq -e '.passed == true' "$f" > /dev/null || { echo "$f did not pass"; fail=1; }
      done
      exit "$fail"
    displayName: Gate on the verdicts

  - publish: ./out
    artifact: selected-module-evidence-$(Build.SourceVersion)
    displayName: Upload evidence
    condition: always()
```

## Related

- [Use the complete pipeline](use-complete-pipeline.md)
- [Use individual modules](use-individual-modules.md)
- [Build your own pipeline](build-your-own-pipeline.md)
