# Build your own pipeline

Build a custom pipeline when the standard composites are close, but your team
needs a different order, a different gate, extra deployment logic, or another
reporting channel.

Read [availability and source access](../../README.md#availability-and-source-access)
first: this repository is currently private. Remote installs and installer actions
require separately authorized access. For private local development, install from
module paths in a separate authorized checkout; do not copy credentials or use a
writer token. Anonymous imports apply only after authorized publication and verified
release availability. Default SAST rules have
[Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

## Start with a local Dagger module

Create a module in the application repository:

```bash
mkdir -p ci
cd ci
dagger init --sdk go --name app-ci
```

Add dependencies on the modules you want:

```bash
dagger install github.com/context-and-oss/cicd/src/quality@v5.1.4
dagger install github.com/context-and-oss/cicd/src/security@v5.1.4
dagger install github.com/context-and-oss/cicd/src/risk@v5.1.4
dagger install github.com/context-and-oss/cicd/src/cross-cutting/evidence@v5.1.4
dagger develop
cd ..  # return to the application root for the ./ci commands below
```

## Compose module calls

Use the generated Go client to call each imported module. This example creates a
custom PR gate that runs quality, source security, risk validation, and evidence
wrapping:

```go
package main

import "dagger/app-ci/internal/dagger"

type AppCi struct{}

func (m *AppCi) PrGate(
	src *dagger.Directory,
	commitSha string,
	branch string,
	repoUrl string,
	failOn string,
) *dagger.Directory {
	qualityEvidence := dag.Quality().Check(
		src,
		commitSha,
		branch,
		repoUrl,
		dagger.QualityCheckOpts{FailOn: failOn},
	)

	securityEvidence := dag.Security().ScanSource(
		src,
		commitSha,
		branch,
		repoUrl,
		dagger.SecurityScanSourceOpts{FailOn: failOn},
	)

	riskEvidence := dag.Risk().Validate(
		src,
		commitSha,
		branch,
		repoUrl,
		dagger.RiskValidateOpts{FailOn: failOn},
	)

	return dag.Evidence().Wrap(
		[]*dagger.File{qualityEvidence, securityEvidence, riskEvidence},
		commitSha,
		branch,
		repoUrl,
	)
}
```

Run it:

```bash
rm -rf ./audit-evidence &&
dagger -m ./ci call pr-gate \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./audit-evidence &&
jq -e '.passed == true' ./audit-evidence/combined-evidence.json > /dev/null
```

Exporting is not grading: the fresh combined envelope must pass. Preserve warnings,
errors and per-source scope/examined/rule metadata; a passing verdict does not mean
complete examination. Retain existing protections until equivalent scope and
blocking policy are configured and verified.

## Decide where the custom logic belongs

| Custom need | Put it in |
|-------------|-----------|
| Reorder checks or skip modules | Your custom Dagger module |
| Add deployment after checks pass | Your custom Dagger module or CI workflow |
| Change branch triggers or permissions | CI workflow |
| Change severity threshold per branch | CI workflow input or custom module argument |
| Add a new scanner | A new domain module that returns an evidence envelope |
| Change notification destination | A custom notification module or CI step |

## Preserve the evidence contract

When adding your own scanner or gate, return an evidence envelope with the same
shape as the existing modules. At minimum, include:

| Field | Why it matters |
|-------|----------------|
| `schemaVersion` | Names the wire shape the file is in. See [the version rule](#the-version-rule) below — a consumer that trusts this field needs to know what it promises |
| `moduleName` | Identifies the producer |
| `repo` | Carries commit, branch, and repo provenance |
| `passed` | **The verdict.** Every cicd surface reads pass/fail from this field alone |
| `findingsCount` | Summaries and trend reporting — never a gate, and it stays 0 on a failure with no findings |
| `findingsBySeverity` | Powers severity thresholds and comments |
| `errors` | Anything that fails the gate without being a finding: a tool that could not run, or a gate verdict such as a coverage-ratchet trip. Nothing derives `passed` from this list — set `passed=false` yourself, or you have written the false pass this contract exists to prevent |

Use `cross-cutting/evidence` to wrap several evidence files into one audit
directory with `combined-evidence.json`, `findings.sarif`, and `sbom.cdx.json`.

### The version rule

`schemaVersion` is semver over the envelope **shape**, not over cicd. A property
appearing anywhere in the envelope is a minor bump; a property disappearing or
changing meaning is a major bump. `src/internal/evidence/schema_version_test.go`
records the exact property set each version describes and fails until a shape
change and a version change arrive in the same commit.

That gate is new. The version stood at `1.0.0` while the envelope grew `sources`,
`tests`, `testsByLanguage` and a `scope` field on each source status, so **no
consumer should treat `1.0.0` as identifying any one shape** — it named several.
`1.1.0` is the first version this repository can prove describes what it ships.

Two consequences for a consumer:

- **Do not gate on equality.** An `==` check against one version string breaks
  on every additive release, which is the pressure that froze the version in the
  first place. Accept the major family and treat unknown properties as absent.
- **Do not read the version out of a contract.** A module contract's
  `outputSchema` names the major family (`evidence-1`, `evidence-1[]`) because a
  static file cannot keep a claim about a minor that moves with the payload. The
  precise version travels in the envelope itself.


## Keep CI thin

After the custom Dagger module exists, CI should mostly install Dagger, pass
secrets, and call your module:

### GitHub Actions

```yaml
name: Custom PR gate

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  pr-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Dagger
        # Checksum-verified download, no `curl install.sh | sh`.
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.1.4
        with:
          version: 0.20.8

      - name: Run custom PR gate
        run: |
          set -euo pipefail
          rm -rf ./audit-evidence
          dagger -m ./ci call pr-gate \
            --src . \
            --fail-on HIGH \
            --commit-sha "$GITHUB_SHA" \
            --branch "$GITHUB_REF_NAME" \
            --repo-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
            export --path ./audit-evidence

      - name: Gate on the verdict
        # dagger call exits 0 whatever the verdict; it is in the file. A
        # missing file or a missing `passed` fails here too.
        run: jq -e '.passed == true' ./audit-evidence/combined-evidence.json > /dev/null

      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: custom-pr-gate-${{ github.sha }}
          path: ./audit-evidence/
```

Once the approved namespace is public and the referenced release exists, these
modules can be imported without a git token. Neither availability nor a release
is established by this import candidate. Private-source access must be separately
authorized and read-only; a feed or comment credential is not module authorization.
If you want PR comments or job-summary markdown, import `notify` and add a
generated comment file to the returned directory, following the composite modules.

### Azure DevOps

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
      rm -rf ./audit-evidence
      dagger -m ./ci call pr-gate \
        --src . \
        --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./audit-evidence
    displayName: Run custom PR gate

  - bash: jq -e '.passed == true' ./audit-evidence/combined-evidence.json > /dev/null
    displayName: Gate on the verdict

  - publish: ./audit-evidence
    artifact: custom-pr-gate-$(Build.SourceVersion)
    displayName: Upload evidence
    condition: always()
```

For Azure Repos, an owner must configure and verify required target-branch
**Build validation** for this pipeline; YAML `pr:` alone does not establish it.
GitHub-hosted source uses YAML PR triggers subject to platform settings.

That keeps the pipeline behavior testable locally and portable between CI
systems.

## Related

- [Use individual modules](use-individual-modules.md)
- [Mix and match modules](mix-and-match-modules.md)
- [Run the pipeline locally](run-pipeline-locally.md)
