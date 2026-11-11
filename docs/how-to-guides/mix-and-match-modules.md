# Mix and match modules

Use these combinations when the complete pipeline is too much for a repository,
or when different stages need different gates.

Read [availability and source access](../../README.md#availability-and-source-access)
first: public modules support anonymous fetching; private copies require read-only
access, and platform policy controls workflow/action access. Default SAST rules have [Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
Keep existing minimum-coverage, licence, history-secrets and live-verification
protections until equivalent scope and blocking policy are configured and verified.

## Pick by outcome

| You want | Use |
|----------|-----|
| Fast feedback on a pull request | `quality` + `security scan-source` |
| A governance gate with human review | `risk scan` locally, `risk validate` in CI |
| Image assurance before publish | `build sbom` + `security scan-image` |
| Runtime web assurance | `security scan-web` against staging |
| Standard pre-commit behavior without notification | `stage-2` |
| Container artifact tail without notification (no source gate) | `stage-4` |
| Full CI entry point with audit output | `composites/precommit` or `composites/commit` |

## Combine quality and source security

This is the smallest useful PR gate:

```bash
set -euo pipefail
mkdir -p ./out
rm -f ./out/evidence-quality.json ./out/evidence-security.json
SHA="$(git rev-parse HEAD)"
BRANCH="$(git branch --show-current)"
REPO_URL="https://github.com/your-org/your-repo"

dagger -m github.com/context-and-oss/cicd/src/quality@v5.2.0 call check \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-quality.json

dagger -m github.com/context-and-oss/cicd/src/security@v5.2.0 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-security.json

for f in ./out/evidence-quality.json ./out/evidence-security.json; do
  jq -e '.passed == true' "$f" > /dev/null
done
```

Successful export is not a passing verdict. The script stops on either export
failure, removes previous outputs, and grades each required fresh envelope.
Inspect warnings, suppressions and per-source scope/examined metadata as well;
`passed` does not establish full examination.

Use this when a repo does not build a container image, or when you want to roll
out scanning before adopting the complete composite.

## Add risk without slowing every PR

AI risk discovery is opt-in. It requires configured LLM access (native
`ANTHROPIC_API_KEY` or an explicitly configured proxy) and submits selected source
files in full up to the prompt budget. `scan-manifest.json` records the selection.
Read [authentication and data scope](run-pipeline-locally.md#ai-risk-scan-risk-module-only)
and [what reaches the model](../../src/risk/README.md#what-the-scan-sends-to-the-model)
before authorizing a scan. Policy-only `validate` does not invoke AI discovery.

Run discovery on demand or on an authorized schedule:

```bash
dagger -m github.com/context-and-oss/cicd/src/risk@v5.2.0 call scan \
  --source . \
  export --path .
```

Review and commit `findings.json` and `decisions.json`, then make CI enforce the
reviewed decisions:

```bash
set -euo pipefail
mkdir -p ./out
rm -f ./out/evidence-risk.json
dagger -m github.com/context-and-oss/cicd/src/risk@v5.2.0 call validate \
  --source . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-risk.json
jq -e '.passed == true' ./out/evidence-risk.json > /dev/null
```

## Split source and image security

Run source scanning before merge:

```bash
set -euo pipefail
mkdir -p ./out
rm -f ./out/evidence-source-security.json
dagger -m github.com/context-and-oss/cicd/src/security@v5.2.0 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-source-security.json
jq -e '.passed == true' ./out/evidence-source-security.json > /dev/null
```

Run image scanning after the image exists:

```bash
set -euo pipefail
mkdir -p ./out
rm -f ./out/evidence-image-security.json
dagger -m github.com/context-and-oss/cicd/src/security@v5.2.0 call scan-image \
  --image "$IMAGE_REF" \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL" \
  export --path ./out/evidence-image-security.json
jq -e '.passed == true' ./out/evidence-image-security.json > /dev/null
```

## Use stages when you want standard grouping

The following stage calls illustrate grouping only; they do not export or grade
verdicts and are **not gates**. Use a wrapping composite for an executable gate.

`stage-2` groups quality, source security, risk validation and optional intent:

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.2.0 call run \
  --src . \
  --fail-on HIGH \
  --commit-sha "$SHA" \
  --branch "$BRANCH" \
  --repo-url "$REPO_URL"
```

`stage-4` returns evidence files for build/SBOM and image security:

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.2.0 call run \
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
    uses: context-and-oss/cicd/.github/workflows/precommit.yml@v5.2.0
    # Add only explicitly needed optional secrets by name.

  web-security:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Dagger
        # Checksum-verified download, no `curl install.sh | sh`.
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.2.0
        with:
          version: 0.20.8

      - name: Passive web scan
        run: |
          set -euo pipefail
          rm -f ./evidence-web-security.json
          dagger -m github.com/context-and-oss/cicd/src/security@v5.2.0 call scan-web \
            --target https://staging.example.com \
            --mode baseline \
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
uploads both evidence files. For Azure Repos, an owner must configure and verify
required target-branch **Build validation**; YAML `pr:` alone is not PR enforcement.

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
      set -euo pipefail
      mkdir -p ./out
      rm -f ./out/evidence-quality.json ./out/evidence-security.json
      dagger -m github.com/context-and-oss/cicd/src/quality@v5.2.0 call check \
        --src . \
        --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./out/evidence-quality.json

      dagger -m github.com/context-and-oss/cicd/src/security@v5.2.0 call scan-source \
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
