# Use the pipeline without a Dockerfile

Your repo ships a zip or a folder — a Dataverse webresource solution, a .NET
app published to an Azure Web App — not a container image. This guide wires
the **archive** pipeline shape into such a repo: attested build, lockfile
SBOM, secrets scan of the built output, witnessed test coverage with a
ratchet gate. No Dockerfile is needed in your source (Docker still runs Dagger).

Read [availability and source access](../../README.md#availability-and-source-access)
first: public modules support anonymous fetching, while private copies require
read-only access. Local `./src/...` examples require a cicd source checkout.
Default SAST rules have [Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
Keep existing coverage minima, blocking licence policy, history-secrets and live
credential-verification protections until equivalent checks are configured and
verified. A ratchet is relative, licence warn mode is not blocking, and a source
snapshot is not a history or live-verification audit.

Background on *why* the pipeline is shaped this way:
[Artifact shapes](../explanation/artifact-shapes.md),
[ADR-001](../decisions/ADR-001-artifact-shapes.md) and
[ADR-005](../decisions/ADR-005-commit-stage-code-and-artifact.md).

## Archive, image, or none?

There is one commit-stage entry point for every repo shape (ADR-005):
`commit run`, with an explicit `--artifact container|archive|none` selector.
The selector is never auto-detected — you declare the shape.

One question picks yours: **what do you deploy?**

- A container image → `--artifact container` (the default; needs a
  Dockerfile). See [Use the complete pipeline](use-complete-pipeline.md).
- A zip, a folder, a bundle → `--artifact archive`, this guide.
- Nothing deployable — a library, an infra/config repo → `--artifact none`.
  No build runs; the SBOM comes from the source lockfiles.

Do not write a Dockerfile just to satisfy the pipeline. Evidence about an
image you never ship is worse than no evidence.

Whichever shape you pick, the **source gate** — quality, SAST, secrets,
dependency-vuln and risk — runs on your code first. The shape only selects the
artifact tail that follows it. (The change-intent gate is not part of the commit
stage; it belongs to the pre-commit loop, where a missing rationale can still be
written. See the amendment in
[ADR-005](../decisions/ADR-005-commit-stage-code-and-artifact.md).)

## Coming from `commit-archive.yml`

Before `v1.7.0` the archive shape had its own reusable workflow,
`commit-archive.yml`, and its own composite entry point, `RunArchive`. The
ADR-005 cutover removed both: one `commit.yml` and one
`commit run` serve every shape.

<!-- The legacy pin and verb are named in prose, not written as a complete
     `...yml@vX.Y.Z` / `-m ...@vX.Y.Z call <cmd>` reference. Both forms are
     scanned by check-repo-surface.py (pin coherence, documented-command
     resolution), which cannot tell a documented legacy from a live one and
     would fail this page. Do not "restore" the literal syntax. -->

**Historical pins are scoped to the original repository.** There, tags of
`v1.6.0` or earlier retain `.github/workflows/commit-archive.yml` and the
same-tag composite's `RunArchive` entry point. Removing them from `main` did
not change those tagged files. This explains the original repository's migration
path; it does not promise that an independent fresh import has those tags or
workflows. Verify the referenced repository before relying on a legacy pin.

What the pin does cost is everything released since:
the source gate, `test-legs` and the toolchain-resolution warnings documented
on this page all postdate `v1.6.0`.

### GitHub Actions: the input mapping

Every `commit-archive.yml` input exists in `commit.yml` under the same name, so
the migration is the changed path plus one added line:

```yaml
jobs:
  commit: # was: commit-archive
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.8
    with:
      artifact: archive # the added line
      build-cmd: "npm ci && npm run build" # unchanged
      output-path: dist # unchanged
      # unchanged and still optional: toolchain-image, fail-on, deploy-pages
    # Add only explicitly needed optional secrets by name.
```

The workflow `name:` and the job id are yours to keep or change — but a branch
ruleset naming the required check, or a notification filtering on the job name,
has to move in the same change or it stops matching anything.

### Azure DevOps: bump the pin and the verb together

The Azure DevOps templates were unified in a separate change, and their
failure mode is the opposite way round. You copied `commit-archive.yml` into
your own repo, so the file itself is yours and nothing removed it — but its
`dagger` step invokes the `run-archive` verb against the
`src/composites/commit` module at a `v1.6.x` pin, and `RunArchive` does not
exist at `v2.0.1`.

Bumping that pin without changing the verb is the one action here that breaks a
working pipeline. Change both at once:

| In your copied template | Was (`v1.6.x`) | Now (`v2.0.1`) |
|---|---|---|
| module pin | `...commit` at `v1.6.x` | `...commit` at `v2.0.1` |
| verb | `call run-archive` | `call run` |
| shape flag | *(implied by the verb)* | `--artifact archive` |
| `--build-cmd` / `--output-path` | unchanged | unchanged |

Or re-copy `templates/azure-devops/commit.yml` (or the `shared/` variant) and
set `ARTIFACT: "archive"` as described under
[Azure DevOps](#azure-devops) below.

### What changes in the run

The artifact tail is the same code: `build build-archive` followed by
`security scan-archive`, exactly as `RunArchive` called them. What precedes it
is new — the source gate (quality, SAST, secrets, dependency-vuln, risk) runs
for every shape, and `RunArchive` ran none of it.

Coverage is the one thing that needs a deliberate line, and it is a gain rather
than a regression: `commit-archive.yml` had no `test-cmd` input and passed no
test flags to the composite, so it produced no coverage and migrating cannot
take any away. Getting coverage at the commit stage is opt-in, and `test-cmd`
alone does not name a report. `commit.yml` supports `test-cmd` plus
`coverage-path`, or `test-legs` where each leg names `coveragePath`. Measurement
is separate from enforcement: set `coverage-gate: gate` to opt into the commit
workflow's baseline fetch and ratchet (empty by default). See
[A polyglot repository](#a-polyglot-repository-one-leg-per-language) below.

## The commit stage: run --artifact archive

For the archive shape you supply the build command and the output path; the
pipeline runs your command in a resolved toolchain container, treats the output
directory as the artifact, generates a CycloneDX SBOM from your lockfiles,
scans the built output for secrets, and aggregates everything into the audit
directory (`combined-evidence.json`, `findings.sarif`, `sbom.cdx.json`,
`comment.md`).

The standalone fixture and test-leg commands on this page are **inspection
examples**, not CI gates. For a gate, clean the previous output, stop on export
failure, and grade each required fresh envelope with `jq -e '.passed == true'`.

Try it against the bundled fixture (the planted `leaked.env` finding is
deliberate — it exercises the artifact secrets scan):

```sh
# doc-test
dagger -m ./src/composites/commit call run \
  --src ./testdata/node-app \
  --artifact archive \
  --build-cmd "npm install --ignore-scripts && npm run build" \
  --output-path dist \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/ra-audit && test -f /tmp/ra-audit/combined-evidence.json
```

For your own repo: `--build-cmd` is whatever produces your deployable
(`npm run build`, `dotnet publish -c Release -o publish`), `--output-path`
is where it lands (`dist`, `publish`), and `--fail-on` gates on finding
severity (default `HIGH`). Both `--build-cmd` and `--output-path` are required
for `--artifact archive`.

### GitHub Actions caller stub

Copy `templates/github-actions/commit.yml` into your repo's
`.github/workflows/` — one template covers every shape. Set `artifact` to
`archive` and supply the two archive inputs:

```yaml
jobs:
  commit:
    uses: context-and-oss/cicd/.github/workflows/commit.yml@v5.1.8
    with:
      artifact: archive
      build-cmd: "npm ci && npm run build"
      output-path: dist
    # Add only explicitly needed optional secrets by name.
```

Optional inputs: `toolchain-image` and `fail-on`.

### Azure DevOps

Copy `templates/azure-devops/commit.yml` (or the `shared/` variant if your org
uses the shared-template indirection) and set the `ARTIFACT`, `BUILD_CMD` and
`OUTPUT_PATH` variables:

```yaml
variables:
  ARTIFACT: "archive"
  BUILD_CMD: "npm ci && npm run build"
  OUTPUT_PATH: "dist"
```

The template passes `--build-cmd`/`--output-path` only when `ARTIFACT` is
`archive`, so the same file serves the container and none shapes unchanged.

## Witnessed tests and coverage: quality test

Both the pre-commit and the commit stage can execute **your** test command and
attest the result — witnessed evidence, not a self-reported report file. The
coverage ratchet can run at either stage: precommit defaults to `gate` for BYO
tests; the commit workflow opts in via `coverage-gate`. Both need a usable
baseline and measured coverage. Coverage is harvested from the report your test
command writes:

| Language | Coverage output to point `--coverage-path` (or a leg's `coveragePath`) at |
|----------|-----------------------------------------------|
| node     | v8/istanbul `coverage-summary.json` (vitest: `--coverage.reporter=json-summary`) |
| dotnet   | coverlet cobertura XML (`dotnet test --collect:"XPlat Code Coverage"`) |
| go       | `go test -coverprofile` output |
| python   | pytest-cov JSON report |

Fixture demo — runs the fixture's vitest suite and harvests real coverage:

```sh
# doc-test
dagger -m ./src/quality call test \
  --src ./testdata/node-app \
  --test-cmd "npm ci --ignore-scripts && ./node_modules/.bin/vitest run --coverage --coverage.reporter=json-summary --coverage.reportsDirectory=/tmp/cov" \
  --coverage-path /tmp/cov/coverage-summary.json \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/qt.json && jq -e '.coverageByLanguage.node > 0' /tmp/qt.json
```

In CI the reusable workflows can call this through `test-cmd` and `coverage-path`.
For example, in the precommit caller (also configure baseline seeding below):

```yaml
jobs:
  precommit:
    uses: context-and-oss/cicd/.github/workflows/precommit.yml@v5.1.8
    with:
      test-cmd: "npm ci && npm run test:coverage"
      coverage-path: coverage/coverage-summary.json
    # Add only explicitly needed optional secrets by name.
```

With `test-cmd` set, the auto-detected baseline lint still runs (lint-only
mode), but the vanilla test runner is replaced by your command — no double
test run.

### A polyglot repository: one leg per language

`test-cmd` is **one** command in **one** container with **one** coverage
report. On a repository with both a `package.json` and a `.csproj` that
container is chosen by the fixed order `go, node, python, dotnet` — not by
anything about your repository — so the stack that sorts later is simply never
tested, and the evidence used to look exactly like a repository where
everything passed.

Use `test-legs` instead: a JSON array of legs, each with its own command,
language, container and coverage report.

```sh
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.8 call test \
  --src . \
  --test-legs '[
    {"label":"web","language":"node","cmd":"npm ci && npm run test:coverage",
     "coveragePath":"coverage/coverage-summary.json"},
    {"label":"api","language":"dotnet","cmd":"dotnet test \"--collect:XPlat Code Coverage\" --results-directory /tmp/cicd-test-results",
     "coveragePath":"/tmp/cicd-test-results/*.cobertura.xml"}
  ]' \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/qt.json
```

Or through the reusable workflow:

```yaml
jobs:
  precommit:
    uses: context-and-oss/cicd/.github/workflows/precommit.yml@v5.1.8
    with:
      test-legs: |
        [{"label":"web","language":"node","cmd":"npm ci && npm run test:coverage",
          "coveragePath":"coverage/coverage-summary.json"},
         {"label":"api","language":"dotnet","cmd":"dotnet test \"--collect:XPlat Code Coverage\" --results-directory /tmp/cicd-test-results",
          "coveragePath":"/tmp/cicd-test-results/*.cobertura.xml"}]
    # Add only explicitly needed optional secrets by name.
```

These .NET examples assume VSTest with a configured XPlat/coverlet collector.
The explicit absolute results directory pools reports from nested test projects;
without it, each project can write to its own `TestResults` directory. The path
`/tmp/cicd-test-results/*.cobertura.xml` uses cicd's recursive filename-pattern
search beneath that shared directory rather than claiming a fixed file.
For MTP, configure the runner's supported coverage extension/arguments instead.
Verify that your command produces parseable reports and measured .NET coverage in
the evidence before relying on a ratchet; passing tests alone do not prove harvest.

Leg keys: `label` (required, unique, `[A-Za-z0-9._-]`), `language` (required —
exactly `go`, `node`, `python` or `dotnet`; no aliases, because the value is
also the `coverageByLanguage` key the ratchet compares), `cmd` (required),
`coveragePath`, `toolchainImage` and `services` (optional, per leg — see
[Reaching a database from a test leg](#reaching-a-database-from-a-test-leg)).
At most 8 legs; a ninth is an error rather than a truncated run. Legs run one
at a time unless you raise `parallelism` (1–4), which bounds the legs in flight
as well as the check groups; each leg still costs its own container pull and
dependency restore against your pre-commit time budget. The evidence keeps the
declared leg order either way, and each leg reports its `durationMs`. Each leg
sees its own label as `CICD_TEST_LEG`, so two legs with the same command are
still two runs.

Rules worth knowing before you wire it up:

- **`test-cmd` and `test-legs` are mutually exclusive.** Setting both fails the
  run instead of picking one. Same for `coverage-path` beside `test-legs` — a
  leg names its own report, so a run-wide path could not be harvested and the
  coverage it promises would silently never be measured.
- **`toolchain-image` does not apply to a leg.** Each leg resolves its own
  image from its language (or its own `toolchainImage`). Set alongside legs, the
  run-wide one is reported as ignored in the evidence — it is not refused,
  because in the commit stage that same input also selects the archive build's
  image.
- **A language detected in your tree that no leg tests says so.** The envelope's
  `languages` lists what was *witnessed*, the `genericReport` carries the
  detected / witnessed / unwitnessed triple, and a `byo-test: NOT WITNESSED …`
  warning goes into the evidence and verbatim into the PR comment. It is a
  warning and not a failure — nothing failed to run; you never asked for that
  language to be tested — but a partially witnessed repository can no longer
  render like a fully witnessed one. Narrow detection with `include` if the
  marker file is incidental.
- **Legs sharing a language are combined by coverable-line weighting**, so
  `coverageByLanguage` keeps one comparable figure per language for the ratchet;
  the per-leg figures stay in the `genericReport`.

### Reaching a database from a test leg

An integration suite that needs a live PostgreSQL has nothing to talk to inside
a leg container, so it fails at fixture initialisation on every run. A leg can
declare the dependency instead:

```sh
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.8 call test \
  --src . \
  --test-legs '[
    {"label":"api","language":"dotnet","cmd":"dotnet test \"--collect:XPlat Code Coverage\" --results-directory /tmp/cicd-test-results",
     "coveragePath":"/tmp/cicd-test-results/*.cobertura.xml",
     "services":[
       {"alias":"db","image":"postgres:16-alpine","port":5432,
        "env":{"POSTGRES_PASSWORD":"test","POSTGRES_DB":"app"},
        "readyCmd":"pg_isready -h db -U postgres","readyTimeout":60}]}
  ]' \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/qt.json
```

Service keys:

| key | required | meaning |
|---|---|---|
| `alias` | yes | the hostname the leg reaches the service on. Lowercase letters, digits and dashes, starting with a letter — it is a DNS label, and it is also upper-cased into an environment variable name, so `my-db` and `my.db` cannot both exist |
| `image` | yes | the image, verbatim. It is yours, so cicd does not pin it (ADR-004 level 3) — pin a digest yourself if you want the service reproducible |
| `port` | yes | the port the service listens on. There is no default: a guessed port is a binding that looks configured and reaches nothing |
| `env` | no | environment for the service container. Only the **key names** reach the evidence; values never do |
| `readyCmd` | no | a command run against the service until it exits 0. Runs in the *service's own image*, because `pg_isready`, `redis-cli` and `mysqladmin` live there and nowhere else |
| `readyTimeout` | no | seconds allowed for `readyCmd`, default 60, maximum 300. Only meaningful beside `readyCmd`; alone it is an error |

At most 4 services per leg.

Your command finds the service through two environment variables injected per
alias — for `alias: db`, `CICD_SERVICE_DB_HOST` (the alias) and
`CICD_SERVICE_DB_PORT` (the port). Build your connection string from those
rather than hard-coding the alias, and the leg keeps working if the alias
changes:

```csharp
var host = Environment.GetEnvironmentVariable("CICD_SERVICE_DB_HOST");
var port = Environment.GetEnvironmentVariable("CICD_SERVICE_DB_PORT");
```

Rules worth knowing:

- **A declared service that did not become usable is a non-run, not a failed
  test.** It lands in `errors[]`, sets `ran=false`, and therefore fails at
  *every* threshold including `--fail-on NONE`. A suite that could not reach its
  database did not report "no failures"; it reported nothing, and `NONE` is the
  setting where that distinction matters most.
- **`ready` means two different things, and the evidence says which.**
  `readyVia: engine-healthcheck` means the port accepted a connection — a floor,
  not a verdict; the process behind it may still be initialising. `readyVia:
  ready-cmd` means your own check passed. Declaring a `readyCmd` is the only way
  to get a claim cicd did not invent, and when a leg's services all rested on the
  engine gate the evidence says so in `warnings[]`.
- **A declared `readyCmd` that never passes is an error.** There is no fallback
  to the engine's port gate — a readiness check that was asked for and did not
  pass cannot be rounded up to "ready enough".
- **A service that never listens costs about two minutes before the run
  reddens.** That budget belongs to the Dagger engine's healthcheck, not to
  cicd; there is no knob for it here.
- **Lint legs cannot declare services.** A lint command reads the source and
  reaches nothing, so a database beside it is a pull and a wait bought with
  nothing. Declaring one there is an error.
- **No Docker socket is mounted, ever.** The services are engine-managed
  containers on the leg's network. Nothing in a leg gets access to the runner's
  daemon.

## The coverage ratchet

The ratchet compares measured coverage against a **baseline**: an evidence
artifact from a successful default-branch run of the **same caller workflow**.
Precommit selects `precommit-evidence-*`; commit selects `commit-evidence-*`.
The shipped precommit caller excludes main pushes, so the starter pair does not
automatically seed its PR baseline. Configure a default-branch push path in that
same precommit caller, with the same coverage-producing inputs. Verify the seed
artifact, the next PR's selected baseline, and a controlled regression failure
before calling the ratchet enforced. A separate commit workflow does not seed it.
There is no file to commit to your repo — the workflow fetches the artifact
([ADR-003](../decisions/ADR-003-fileless-coverage-ratchet.md)).

Per language: the gate trips when
`measured < baseline − tolerance` (tolerance default `1.0` percentage point,
input `coverage-tolerance`). The verdict lands in `combined-evidence.json` as
`coverageRatchet`:

| Verdict | Meaning |
|---------|---------|
| `pass` | At or above baseline − tolerance |
| `fail` | Below the floor — the envelope fails in gate mode |
| `skipped:no-baseline` | Bootstrap: no prior artifact found (first run, or expired) |
| `skipped:no-coverage-output` | Your test command produced no coverage file at `--coverage-path` (or at any leg's `coveragePath`) |
| `skipped:warn-mode` | A drop occurred but `coverage-gate: warn` was set |

`skipped:no-coverage-output` says the number is absent, not why, and one cause
is not yours. Where cicd runs its own auto-detected vitest leg it needs
`@vitest/coverage-v8`, prefers whatever your repository pins, and installs one
only when you pin none — and that install can fail (a private registry, no
egress, or a provider major that peer-requires a different vitest than yours).
The suite then runs without `--coverage` on purpose, so your tests are
unaffected, but no report is written.

That outcome is now stated rather than inferred. The evidence carries a
`vitest: coverage not measured …` warning naming which of three things
happened — the provider could not be installed, it was installed and produced
nothing parseable, or cicd could not tell — and warnings render in the PR
comment. A run with no coverage evidence and a run measuring zero coverage no
longer look the same. Pinning a provider matching your vitest major removes the
install from the path entirely.

The lifecycle in practice:

1. **Bootstrap** — your first PR has no baseline; the ratchet skips with a
   warning and CI stays green (fail-open by design).
2. **Seed** — the configured default-branch run of that same caller must
   successfully upload compatible measured coverage; inspect the artifact.
3. **Verify** — confirm the next run selects that baseline and a controlled
   coverage regression actually fails in `gate` mode.
4. **Advance** — later successful default-branch runs of that caller provide
   new baselines. Review legitimate drops under your existing coverage policy;
   do not disable unrelated protections to clear a ratchet.

Two operational notes: GitHub artifact retention defaults to 90 days — a repo
dormant longer re-bootstraps silently on its next PR (the warning tells you).
And module warnings (ratchet skips, partial configuration) only appear in CI
logs when dagger runs with `--progress=plain`; the shipped workflows already
do this.

## Toolchain resolution

The container **your own** command runs in is separate from cicd's native
lint/test images. An explicit `--toolchain-image` wins for a single BYO command
or archive build; each test leg instead uses its own `toolchainImage`. This is
the route for a consumer-selected digest pin. It does not change the images
used by auto-detected native checks.

### Archive builds and non-.NET BYO tests

The generic resolver follows [ADR-004](../decisions/ADR-004-toolchain-resolution.md):

1. An explicit image.
2. A usable root version file: `.nvmrc` selects `node:<major>-alpine`;
   for a .NET **archive build**, `global.json`'s `sdk.version` selects
   `mcr.microsoft.com/dotnet/sdk:<major.minor>`.
3. Defaults: `node:22-alpine`, `golang:1.26-alpine`, `python:3.12-slim`,
   or `mcr.microsoft.com/dotnet/sdk:8.0` for that archive path.

`.nvmrc` accepts a bare major such as `22`; `sdk.version` needs at least
`<major>.<minor>`, not just `"10"`. A runner-only `global.json` supplies no SDK
version. The generic archive resolver therefore falls back to 8.0 in that
case, **without** examining target frameworks. This is not the .NET BYO-test
rule below. Use a valid SDK version and runner configuration for your project.

For non-.NET BYO tests, an unusable present version file (for example an nvm
alias such as `lts/iron`) produces a toolchain warning; an absent file does not.
Archive builds return a directory, not an evidence envelope, and do not expose
these resolver warnings. Set an explicit image when the build needs certainty.

### .NET BYO tests

Without an explicit image, `quality test` uses the repository-aware band
selection described in [.NET SDK band selection](../reference/runtime-images.md#net-sdk-band-selection):
usable root `global.json` `sdk.version` first, otherwise the highest literal
`TargetFramework`/`TargetFrameworks` found in project files and
`Directory.Build.props` within the discovery depth. It does not evaluate
MSBuild expressions or conditions.

The requested band maps to the lowest supported band at least as new (currently
8.0 or 10.0). A request above both uses the newest supported band and discloses
that limitation; if the command cannot run, the test fails rather than passing
as clean. No usable SDK request **and** no literal target falls back to 8.0.
A runner-only `global.json` alongside `net10.0` can therefore select 10.0 from
the target, not 8.0. Runner/collector arguments still belong to your BYO command.
A failed repository probe is an error, not permission to use a fallback.

### Inspect the chosen image

Each BYO leg records its image and `toolchainFrom` (`explicit`, `nvmrc`,
`global-json`, `target-framework` or `default`) in `genericReport`, plus
`toolchainNote` when applicable. Review warnings and the actual measured test
and coverage metadata; an image choice is not proof of compatibility.

These consumer toolchain selections use tags unless you supply an explicit
digest. Native scanner/linter images remain separately digest-pinned; for .NET
native checks the repository selects among the supported pinned SDK bands,
not through your `toolchain-image` override.

## The SBOM and your lockfile

Repository-mode archive dependency inventory comes from source dependency
manifests/lockfiles, not a complete inventory of arbitrary output bytes. Commit
lockfiles where supported. Lockfile-free .NET can restore a dependency graph in a
pinned SDK; that restore requires working package access. Inspect inventory warnings
and examined counts instead of assuming an empty inventory is complete.
Application mode currently defers SBOM and dependency assessment.

## What stays yours

Repository-mode quality runs auto-detected baseline lint; retain additional
consumer lint policy until equivalence is verified. cicd never auto-detects your
build command and never deploys — importing
the solution to Dataverse or pushing the zip to Azure remains your repo's
workflow ([ADR-002](../decisions/ADR-002-witnessed-test-execution.md)
covers the ownership split).
