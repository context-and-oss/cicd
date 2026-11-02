# Application commit evidence

`commit-monorepo.yml` runs the existing commit composite in application mode.
Each app has its own caller workflow and GitHub run. Inputs live in that caller;
there is no application manifest, automatic discovery or required package manager.
The initial command adapters support Node and .NET, including a client with a
server plugin. Regular callers of `commit.yml` retain repository mode.

SBOM generation, dependency vulnerability scanning and dependency licence
assessment are intentionally disabled in this workflow for now. Evidence marks
them as `SKIPPED` / not assessed, rather than clean or zero dependencies. Source
licence declarations are still checked. A passing run covers only enabled checks.

Independent, self-contained app folders can use the ordinary commit module with
`--src ./app-folder`, retaining normal dependency checks and SBOM generation.
The reusable `commit.yml` currently hardcodes `--src .`; it does not yet expose
an app-folder input. Do not assume four calls to it automatically scope four apps.

Copy the [caller template](../../templates/github-actions/commit-monorepo.yml)
once per app. Use a release containing the new workflow and application inputs;
the repository release process updates template and module pins together.

## Inputs and execution

- `app-id`: stable lowercase ID, 1–64 characters, letters/digits/hyphens/underscores.
- `source-paths`: newline-separated literal repository-relative files/folders.
  Include shared code and plugin sources explicitly. Missing/empty paths, globs,
  traversal and the repository root are refused. Include scanner configuration,
  licence files, relevant pipeline/IaC files and policies when they belong in scope.
- `lint-legs`: JSON array of `label`, `language`, `cmd`, `reportPath`, `format`,
  and optional `toolchainImage`. Native formats: `eslint` and `dotnet-format`.
- `test-legs`: existing `label`, `language`, `cmd`, optional `coveragePath` and
  `toolchainImage`. Application coverage paths are literal relative files. A
  declared report must be freshly produced and readable. Omitting coverage
  explicitly leaves it unmeasured; command exit status witnesses test execution,
  not a discovered test count or proof that every source file was exercised.
- Artifact inputs select `archive` or `none` explicitly. Container mode is not
  supported by this initial application workflow.
  Archive output is a newly produced directory under the checkout. A consumer
  command can assemble several app pieces there in a compatible build image.

Each language declared in the command legs must have lint and test
execution. Up to eight legs of each kind are accepted, with unique labels.
Commands include setup and run from `/src` in independent toolchain containers.
They can access the entire checkout to resolve workspace references and build
configuration. Setup state is not shared between legs. Registry credentials use
Dagger secrets, with the existing npm/NuGet feed settings.

Code scanners receive only the declared sources, at their original paths.
Secrets scanning covers the current source snapshot, not Git history. Risk
validation covers declared source/policy inputs. Lint output naming a file
outside the declared scope is rejected, not trimmed into a clean result.
Commands remain caller declarations: this pipeline cannot prove that a consumer
script selected every intended test. There are no custom SBOM commands or
repository-wide dependency scans standing in for app-scoped dependency evidence.

## Evidence contract

Schema 1.5 adds optional `repo.appId` and `repo.sourcePaths`. Repository mode omits
both. Application aggregation checks repository/commit provenance and stamps the
declared app scope onto each part without discarding unknown native fields.

The bundle contains `combined-evidence.json`, native SARIF and individual evidence
under `parts/`, with machine-readable concern indexes. It does not contain
`sbom.cdx.json` or a placeholder empty inventory. A dedicated evidence part
records `sbomGenerated: false`, `dependencyAssessment: not-assessed`, and scoped
`SKIPPED` rows for SBOM, dependency vulnerabilities and dependency licences.
Source licence evidence remains separate from the skipped dependency licence row.
SARIF identities distinguish apps at the same commit.

`evidence-artifact` names the uploaded bundle. `passed` is true only when the
pipeline executed, evidence uploaded and all configured gates passed. Module
failures are retained as failed evidence while independent checks continue.
Invalid configuration or an unavailable engine can prevent any bundle; the
workflow fails and does not claim one was uploaded.

Application mode has no report renderer, notification, dashboard, SARIF upload or
dependency-tracking publication. Downstream consumers own presentation and delivery.
There is no automatic affected-app selection, baseline lookup, Windows build
orchestration, or cross-app aggregation. Archive scans cover output secrets;
dependency assessments remain deferred regardless of artifact choice.

## Verification

The module unit suite exercises configuration, scope boundaries, native lint
parsing, explicit dependency deferral and evidence identity. The
[application smoke](../../scripts/smoke/commit-apps.sh) exercises the shared
modules against a pnpm workspace with two apps, shared code and a .NET plugin,
including absence of SBOM output and a failing test command. It requires a working
Docker/Dagger engine.
