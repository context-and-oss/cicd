# Reference

Information-oriented technical facts. For task-oriented recipes see
[How-to Guides](../how-to-guides/index.md).

## Adoption

- [Step mapping: existing CI → cicd](./step-mapping.md) — the canonical
  "I run X today, what is it in cicd?" lookup, with a replace / feed-in / keep
  verdict per step.

## Supply chain

- [Runtime tool images](./runtime-images.md) — which container images cicd runs,
  why the repository-selected ones are digest-pinned while consumer toolchains
  are not, and how a pin is added, checked and updated.

## Dynamic analysis

- [Running-app DAST](./dast.md) — the three shapes, every parameter at each of
  the three layers (workflow → composite → module), the `dast/1.0` evidence
  payload, and the disclosure lines that say what a green scan did not cover.

## Pipeline harness

- [Application commit evidence](./commit-monorepo.md) — workflow parameters,
  explicit app scope, shared scanners and separate evidence bundles.
- [Workflow `run:` step size ceiling](./workflow-step-size.md) — a step big
  enough makes GitHub refuse the workflow at startup, so it vanishes from the
  check list instead of going red; what we measured, and the budget that guards
  it.

## Non-container (archive) surface

Added by the non-container-artifacts feature; the image-path functions are
documented in each module's `README.md`.

### Module functions

| Function | Module | Returns | Parameters |
|----------|--------|---------|------------|
| `build-archive` | `src/build` | `Directory` (the built artifact) | `--src`, `--build-cmd`, `--output-path`, `--toolchain-image` (optional), provenance (`--commit-sha`, `--branch`, `--repo-url`) |
| `test` | `src/quality` | evidence `File` | `--src`, exactly one of `--test-cmd` / `--test-legs` (JSON array of legs: `label`, `language`, `cmd`, optional `coveragePath`, `toolchainImage`), `--coverage-path` (optional, `--test-cmd` only), `--baseline` (optional file: prior evidence envelope or bare `{"coverageByLanguage": {...}}`), `--tolerance` (default `1.0`), `--coverage-gate` (`gate`\|`warn`, default `gate`), `--toolchain-image` (optional), `--include` (optional), provenance |
| `check` (extended) | `src/quality` | evidence `File` | existing params + `--lint-only` (optional bool: skip the test loop) |
| `scan-archive` | `src/security` | evidence `File` | `--src` (source tree → lockfile SBOM + dependency vulns), `--output-dir` (built artifact → secrets scan), `--fail-on` (default `HIGH`), provenance |
| `run` | `src/composites/commit` | audit `Directory` | `--src`, provenance (`--commit-sha`, `--branch`, `--repo-url`), `--artifact` (`container`\|`archive`\|`none`, default `container`), `--fail-on` (default `HIGH`); source-gate passthrough (`--include`, `--sast-rulesets` default `p/security-audit`, `--diff`, coverage knobs, `--test-cmd`/`--test-legs`/`--coverage-path`, `--baseline`, `--tolerance`, `--coverage-gate`, `--toolchain-image`, npm/nuget feeds); container shape (`--dockerfile` default `Dockerfile`, `--platform` default `linux/amd64`); archive shape (`--build-cmd`, `--output-path`, both required for `--artifact archive`); `--verify-secrets` (default `false`, container only); `--teams-webhook`/`--run-url` (optional) |
| `run` (extended) | `src/composites/precommit` | audit `Directory` | existing params + the `test`/ratchet params above + `--require-intent` (optional bool, default off — turns on the change-intent gate; `--intent-globs` narrows what counts as an intent artifact) |

### Evidence envelope fields (coverage/ratchet)

| Field | Type | Meaning |
|-------|------|---------|
| `coverageByLanguage` | map lang → pct | measured coverage |
| `coverageBaselineByLanguage` | map lang → pct | baseline the ratchet compared against |
| `coverageRatchet` | string | `pass` \| `fail` \| `skipped:no-baseline` \| `skipped:no-coverage-output` \| `skipped:warn-mode` |

The combined envelope (`combined-evidence.json`) merges all three; ratchet
merge is fail-dominant. SBOMs appear under the envelope key
`cyclonedxReport`; secrets/SAST findings under `sarifReport`.

### Reusable workflow inputs

| Workflow | Input | Default | Notes |
|----------|-------|---------|-------|
| `precommit.yml` | `test-cmd` | — | enables witnessed BYO test execution |
| `precommit.yml` | `test-legs` | — | witnessed BYO test execution, one leg per language (JSON array); excludes `test-cmd` |
| `precommit.yml` | `coverage-path` | — | coverage file the test command writes |
| `precommit.yml` | `toolchain-image` | — | explicit (digest-pinnable) toolchain |
| `precommit.yml` | `coverage-tolerance` | `1.0` | allowed pct-point drop |
| `precommit.yml` | `coverage-gate` | `gate` | `warn` = ratchet never fails the run |
| `precommit.yml` | `require-intent` | `false` | `true` enforces the change-intent gate; off, the audit records that intent was not checked |
| `precommit.yml` | `include` | — | same contract as `commit.yml`: comma-separated languages, empty auto-detects. A name outside `go`\|`node`\|`nodejs`\|`typescript`\|`ts`\|`python`\|`py`\|`dotnet`\|`csharp`\|`c#` fails the step, and `quality.Check` refuses it too rather than dropping it. An excluded language is named in the evidence (`quality: NOT SCANNED — …`) — a disclosed exemption, not a clean run |
| `commit.yml` | `artifact` | `container` | shape selector: `container`\|`archive`\|`none` |
| `commit.yml` | `dockerfile` | — | container shape only: Dockerfile path relative to the repository root. Empty keeps the module default, `Dockerfile` at the root |
| `commit.yml` | `platform` | — | container shape only: OCI platform the image is built for. Empty keeps the module default, `linux/amd64` |
| `commit.yml` | `build-cmd` | — | consumer build command; required when `artifact=archive` |
| `commit.yml` | `output-path` | — | artifact directory relative to src; required when `artifact=archive` |
| `commit.yml` | `sast-rulesets`, `include`, `test-cmd`, `test-legs`, feeds | — | source-gate passthrough (heavy SAST pack by default) |
| `commit.yml` | `coverage-path` | empty | report written by `test-cmd`, e.g. `coverage/coverage-summary.json`; relative to the test working directory or absolute inside its container. With `test-legs`, use each leg's `coveragePath` instead; combining both is refused |
| `commit.yml` | `coverage-gate` | empty | opt-in ratchet: empty fetches no baseline; `warn` or `gate` fetches one (see below). Other values fail the step |
| `commit.yml` | `coverage-tolerance` | `1.0` | allowed pct-point drop; only used with `coverage-gate` |
| `commit.yml` | `toolchain-image`, `fail-on`, DT vars | — | as above |

The commit workflow **measures** BYO coverage; the regression ratchet is opt-in.
With `coverage-gate` empty (the default) it fetches no baseline and the ratchet is
skipped. With `warn` or `gate` it fetches the newest `commit-evidence-*` artifact
from a successful default-branch run of the same top-level caller workflow, as
precommit does; no baseline is a fail-open bootstrap. The ratchet is not a
substitute for consumer-owned thresholds, so keep those in the test command. Use a supported report (for Vitest, enable the `json-summary` reporter),
not terminal output or LCOV. An omitted path leaves coverage unmeasured; a missing
report warns and records skipped coverage rather than inventing a percentage.
Malformed reports retain the engine's error/warning semantics; configuring a path
is not proof that coverage was measured.

The precommit workflow fetches the coverage baseline from the most recent
successful default-branch run's `precommit-evidence-*` artifact; missing
baseline = fail-open bootstrap (ADR-003). Azure DevOps templates expose the
same flags but no baseline fetch yet (TODO, ADR-003).

### Reusable workflow outputs

Both reusable workflows declare the same six `workflow_call` outputs — the
consumption seam for callers (ADR-006): read `needs.<job>.outputs.*` instead of
reconstructing cicd's internals. Jobs reading them need `if: always()`, because
a tripped gate fails the calling job. The gate step writes its outputs before
either of its exit paths, so a tripped or crashed gate still reports
`passed=false` rather than an empty string.

| Output | Value | Notes |
|--------|-------|-------|
| `evidence-artifact` | `commit-evidence-<sha>` / `precommit-evidence-<sha>` | name of the uploaded evidence artifact (`combined-evidence.json`, `findings.sarif`, `sbom.cdx.json`, `comment.md`). 90-day retention — publish elsewhere for anything longer-lived |
| `passed` | `true` \| `false` | combined verdict; `false` also covers a gate that could not run |
| `findings-count` | integer | total findings across all gates |
| `findings-by-severity` | compact JSON object | e.g. `{"HIGH":2,"LOW":5}` |
| `coverage-ratchet` | string | `pass` \| `fail` \| `skipped:<reason>`, empty when no ratchet ran |
| `gates` | compact JSON array | per-gate status from the envelope's `sources[]`: `{moduleName, stage, tool, passed, findingsCount, errorsCount, warningsCount}` per source envelope |

`check_workflow_output_chain` (`scripts/repo_surface.py`) verifies each
declared output resolves through its job output to a step that actually writes
it — GitHub validates none of that chain and resolves a typo to the empty
string at run time.

### Toolchain resolution (ADR-004)

The generic resolver uses `--toolchain-image` → version files (`.nvmrc` →
`node:<major>-alpine`, `global.json`'s `sdk.version` →
`mcr.microsoft.com/dotnet/sdk:<major.minor>`) → configured defaults. Only an
explicit image can carry a consumer-supplied digest; version-derived references
are composed at run time. In this generic chain, a `global.json` with no
`sdk.version` supplies no SDK choice. `build build-archive` returns a directory,
not an envelope, and cannot attach a resolution warning.

`quality test` records `toolchainFrom` / `toolchainNote` per leg and discloses
version files it read but could not use. Its .NET path differs from the generic
chain:

For **BYO .NET tests**, there is a specialized resolver: unless an explicit
image is supplied, `sdk.version`, then the highest readable literal
`TargetFramework`, then the lowest supported SDK band select a readable SDK tag.
The band rounds up to a supported band, or uses the highest supported band with
a warning when the request exceeds it. A runner-only `global.json` therefore
falls through to TargetFramework detection before the default. Per-leg
`toolchainFrom` / `toolchainNote` disclose that resolution. This differs from
`build-archive`'s generic version-file resolver and from native .NET checks'
digest-pinned images.
Every repository-selected **tool** image is digest-pinned; see
[Runtime tool images](./runtime-images.md).

This chain covers only the container a consumer's own `build-cmd` / `test-cmd`
runs in. `quality check`'s auto-detected lint/test legs run cicd's own commands in
pinned images and ignore `--toolchain-image`; for .NET the pinned SDK band is
chosen from the repository (`global.json` `sdk.version`, else the highest literal
`TargetFramework`) — see
[.NET SDK band selection](./runtime-images.md#net-sdk-band-selection).

### Coverage formats recognized by `quality test`

v8/istanbul `coverage-summary.json` · go `coverprofile` · pytest-cov JSON ·
cobertura XML (coverlet). Format is sniffed from the file at
`--coverage-path`, or at each leg's `coveragePath`. Legs sharing a language are
combined by coverable-line weighting, so `coverageByLanguage` keeps one figure
per language and the ratchet baseline stays comparable; the per-leg figures are
in the envelope's `genericReport` (`genericFormat: byo-test-legs`) alongside the
detected / witnessed / unwitnessed language lists.
