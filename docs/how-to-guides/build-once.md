# Build once, assess it, deploy the retained output

The commit composite can share one prepared Node or .NET execution context and
return the deployable alongside its audit evidence. The consumer owns commands,
build properties and deployment. Source checks still see the original checkout;
artifact checks see the output being retained.

This guide describes the implemented inputs at the managed release pins shown
in the starters. Use the same verified revision for the workflow, modules and
artifact verifier; an older pin does not gain new inputs without an upgrade. The repository is
currently private; verify authorized source/workflow access separately from feed
credentials, as described under [availability and source access](../../README.md#availability-and-source-access).
Source checks execute SAST with runtime
[Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
A passing bundle does not imply full-scope or dependency assurance in application
mode; inspect warnings and per-source examined metadata. Retain existing coverage
minima, blocking licence policies, history-secrets scans and live verification
until equivalent scope and enforcement are configured and verified.

## Configure shared preparation

Use `prepare-cmd` for dependency installation and, when needed, compilation.
Specify `prepare-language` (`node` or `dotnet`) and an explicit `toolchain-image`.
Use witnessed `test-cmd`, or select exactly one labelled `test-legs` entry with
`prepare-test-label`. Its language and any explicit image must match preparation.
The command runs once; lint, selected tests and packaging branch from its state.
Their filesystem mutations do not flow into one another.

For a .NET archive, the relevant reusable-workflow inputs look like:

```yaml
artifact: archive
parallelism: 1
toolchain-image: mcr.microsoft.com/dotnet/sdk:10.0
prepare-language: dotnet
prepare-cmd: dotnet restore App.slnx && dotnet build App.slnx -c Release --no-restore
test-cmd: dotnet test App.slnx -c Release --no-build --no-restore
build-cmd: dotnet publish src/App/App.csproj -c Release --no-build --no-restore -o dist/app
output-path: dist/app
```

Use your SDK image, preferably digest-pinned, and your runner/coverage arguments.
Build the test projects too. Match configuration, framework, RID, architecture,
self-contained settings, version and other build properties across commands.
A mismatched publish may require another compilation: cicd cannot infer MSBuild
compatibility from arbitrary shell commands. This is one context per invocation;
multiple independent build groups use separate application invocations or
consumer-owned Dagger orchestration.

For Node, installation usually suffices before tests:

```yaml
artifact: archive
toolchain-image: node:24-bookworm
prepare-language: node
prepare-cmd: npm ci
test-cmd: npm test
build-cmd: npm run build
output-path: dist
```

Build before tests only when the tests need compiled output. If preparation
already builds, package by copying that output into a **different dedicated
output-path**. Packaging clears output-path before running so a no-op cannot
export stale source or prepared files. Never choose an output-path containing
source, installed dependencies or intermediates needed by the package command.
.NET `bin`, `obj` and NuGet packages stay in the shared context for `--no-build`.

Automatic ESLint skips installation when using prepared Node dependencies;
`dotnet format` uses `--no-restore` with prepared .NET state. Application-mode
lint commands receive the same state for the prepared language; remove their
redundant setup yourself. A `test-legs` command that happens to run lint does not
silently replace the lint assessment. Application mode already accepts explicit
lint commands and native reports.

Container builds can use the prepared `/src` as their Dockerfile context. A
multi-stage Dockerfile that compiles again will still compile again: use a
runtime-only Dockerfile that copies the prepared output if you want to avoid
that work. The resulting OCI image is retained for later import/push.

## Project budget and parallelism are different controls

| Input | Default | Meaning |
|---|---:|---|
| `node-project-limit` | 4 | Positive integer: total independent Node project roots auto-discovery may check. Exceeding it fails; roots are never silently truncated. |
| `parallelism` | 1 | Integer 1–4: independent source check groups, and declared BYO test legs, allowed in flight within one commit or precommit invocation. |

For eight independent apps, `node-project-limit: 8` permits all eight without
requiring a workspace migration. It does not run eight installs simultaneously.
`parallelism: 2` can overlap, for example, quality and source security, and runs
up to two declared test legs at once. The same bound applies at both levels, so
the peak is 2p-1 containers (p test legs beside the other p-1 groups), not p².
Automatic per-language/per-project loops stay sequential. The evidence is folded
in declaration order whatever order the legs finish in, so a concurrent run
differs from a sequential one only in each leg's `durationMs`. Each leg gets its
own instance of every service it declares, so two legs declaring the same
database never share one. The existing eight-test-leg limit is unchanged. Compiler/test-runner workers and a caller's
workflow matrix remain separate consumer controls; matrix fan-out multiplies
total resource use. Application mode declares its checks and does not accept a
Node discovery budget. Precommit exposes both controls with the same defaults. Caller-owned Dagger
pipelines can also pass an existing prepared container through precommit; its
workflow starters do not construct preparation state.

The default stays sequential because large repositories have exhausted hosted
runner disk. Raise concurrency after measuring CPU, memory, disk and elapsed
time on the actual runner; 4 is a guardrail, not a recommended setting.

## Deploy the exact assessed bytes

The exported audit directory keeps its existing report paths and adds:

```text
artifact-manifest.json
artifacts/
  artifact-manifest.json
  combined-evidence.json
  application.tar.gz       # archive; or image.tar for container
```

The manifest records source commit, repository, branch, application boundary
when present, producing run URL, verdict, payload SHA-256 and evidence SHA-256.
The OCI tar checksum identifies transport bytes, not a registry manifest digest.
Archive assessment retains the existing scope: output-secret checks plus source
dependency assessment in repository mode. Application mode still explicitly
defers SBOM and dependency assessment. Exporting a payload does not broaden the
claims in the evidence.

GitHub commit workflows upload the deployable separately only after a passing
gate. `build-artifact-id` identifies that immutable workflow artifact;
`build-artifact` gives its name, including commit, run ID and attempt (and app ID
in application mode). Both are empty when no candidate is uploaded. `passed`
also stays false when a required candidate upload fails. Evidence is uploaded
on failure without duplicating the payload. The `none` shape produces no bundle.

The Azure DevOps commit starters now enforce the evidence verdict and upload a
separate candidate only for a passing run. Download the named candidate from the
exact producing Build ID. Candidates follow pipeline retention; GitHub requests
90 days. Promote to durable consumer-owned storage if deployment must remain
possible after expiry.

In a GitHub deployment job, depend on the commit job, require `passed == 'true'`,
and use `actions/download-artifact` with
`artifact-ids: ${{ needs.commit.outputs.build-artifact-id }}` and
`merge-multiple: true` into a dedicated folder. For a separate workflow, explicitly
select the trusted producing repository, run and artifact ID; never use “latest”.
Fetch from a trusted main-branch run, not an untrusted pull request.

Before import or extraction, run the verifier from the same trusted cicd revision
as the producing workflow (checkout cicd separately, or vendor the script):

```bash
python3 cicd/scripts/verify-build-artifact.py downloaded-bundle \
  --repo "$EXPECTED_REPOSITORY_URL" \
  --commit "$EXPECTED_COMMIT_SHA" \
  --branch "$EXPECTED_BRANCH" \
  --run-url "$EXPECTED_PRODUCING_RUN_URL"
# Application mode additionally requires --app-id "$EXPECTED_APP_ID".
```

Supply expected values from the deployment's trusted selection, not by copying
them out of the manifest being verified. The verifier refuses changed payloads,
changed evidence, a failed/missing verdict, and mismatched provenance. Checksums
bind contents; authentication comes from selecting a trusted CI run. Then extract
the archive or import the OCI tar and publish/deploy those bytes using the
consumer's credentials. Do not rerun the build in the deployment job. Build-time
frontend settings must already match the intended target; runtime configuration
is needed to promote one frontend bundle through different environments.

## Cache downloads, retain deliverables

Quality and archive command containers mount repository-scoped npm, pnpm and
NuGet package caches. Source trees, `bin`, `obj` and `node_modules` are shared
through the prepared container, not restored from a broad cross-commit output
cache. The conventional root-user package-cache paths are mounted; a custom
image/user/store configuration may need consumer-managed cache mounts.

These caches live in the Dagger engine. A fresh ephemeral engine on each CI job
does not give persistent downloads simply because a runner has an Actions cache.
Cross-job reuse needs a persistent engine/cache backend. Cache hits are optional:
a cold restore must remain correct. No credentials are intentionally exported;
consumer commands must keep credential files out of their selected output.
