# CLAUDE.md — Codebase Guide

## What this repo is

A monorepo of reusable [Dagger](https://dagger.io) pipeline modules for the source and artifact gates of a 12-stage CD Model, plus independent running-app DAST. The remaining stages are design context, not implemented deployment or approval APIs; see [ROADMAP.md](ROADMAP.md). Each module is a standalone Dagger module written in Go. Modules live under `src/`, are composed into pipelines via `src/composites/`, and consumed through the `templates/` starters.

## Open source: nothing private in the tree

Treat all repository content as public, regardless of current hosting visibility.
No consumer, customer, organisation or person name,
no private issue/PR/SHA/run reference, no unlicensed third-party material — in
code, tests, specs, capsules, docs or commit text. No check enforces it; the
rule and what counts are in [AGENTS.md](AGENTS.md), and reviewers hold it with
[REVIEW.md](REVIEW.md).

@AGENTS.md

## Directory layout

```
src/
  internal/                 Shared Go packages (no Dagger dependency — plain go test)
    detect/                 Language detection by marker file
    evidence/               Evidence envelope schema + merge helpers
    sarif/                  SARIF 2.1.0 document builder

  quality/                  Domain module — multi-language lint + unit test (Check), witnessed BYO test + coverage ratchet (Test)
  security/                 Domain module — SAST, secrets, vuln scan, DAST (ScanSource, ScanImage, ScanArchive, ScanWeb)
  build/                    Domain module — OCI build, CycloneDX SBOM, archive build (Build, Sbom, BuildArchive)
  notify/                   Domain module — Teams, GitHub, ADO notifications (Teams, BuildCard, Github, Ado, etc.)
  risk/                     Domain module — AI risk analysis + OPA policy gate (Scan, Check, Report, Proxy, Validate)

  stage-2/                  Stage orchestrator — the source gate: quality.check (+ quality.test),
                            security.scan-source, risk.validate, and intent.check
                            (gates only with --require-intent) → []*File
  stage-4/                  Stage orchestrator — wires build.build + build.sbom + security.scan-image → []*File

  cross-cutting/
    evidence/               Aggregates []*File evidence into a combined audit *Directory
    contract/               Verifies module Go signatures and pipeline manifests against contracts
    report/                 Extracts native tool report (SARIF/CycloneDX/JSON) from any evidence envelope
    intent/                 Change-intent gate — artifact presence and filename/test coupling checks;
                            opt-in, and says so in the evidence when it was not asked
    pages/                  Builds a static evidence dashboard for GitHub Pages

  composites/
    precommit/              Full pre-commit pipeline: stage-2 + evidence + notify → *Directory
    commit/                 Full commit pipeline (ADR-005): stage-2 source gate + an
                            --artifact container|archive|none tail + evidence + notify → *Directory
    dast/                   Running-app DAST on its own cadence — wired into no other
                            composite and not a merge gate. --app url|service|container
                            selects who starts the application; only `container` builds
                            from this commit and can attest what it scanned. Scan → exported *File,
                            then Package in a fresh call → *Directory

templates/                Copy-paste GitHub Actions and Azure DevOps workflow starters
testdata/                 Language fixture apps used by integration tests
  go-app/                 Go module with tests, a Dockerfile, and a known-vulnerable
                          dependency (jwt-go, a HIGH CVE); its secrets.go is gitleaks:allow
  node-app/               Node.js app with Vitest tests and ESLint
  python-app/             Python app with pytest
  dotnet-app/             C# app with xUnit tests (VSTest runner)
  dotnet-app-nolock/      C# app that commits no NuGet lockfile — the fixture for the
                          lockfile-free dependency-graph restore
  dotnet-mtp-app/         C# app on the Microsoft.Testing.Platform runner (MSTest 4,
                          net10.0, the global.json runner opt-in)
```

`templates/` and `testdata/` stay at the repo root — they are consumed/referenced directly by teams and test fixtures, not part of the Dagger module graph.

## Architecture rules

**Evidence-first.** Evidence-producing checks return `(*dagger.File, error)` — a JSON evidence envelope. Resource and transport functions have different contracts: builds/preparation can return containers or directories, composites aggregate audit directories, artifact helpers return manifests/bundles, and rendering helpers return reports. `build.Build()` returns a container so `Sbom` and `security.ScanImage` can share the same lazy image. The `src/cross-cutting/evidence` module aggregates evidence into `combined-evidence.json`. Do not substitute an unwrapped scanner report for a check's evidence envelope.

**The artifact is never published.** cicd builds and scans the deployable; deploying it — registry push, Dataverse import, Web App publish — stays in the consumer repo (ADR-001). There is no `build.Publish`.

**One entry point for commit shapes.** The commit composite exposes a single `Run` with an explicit `--artifact container|archive|none` selector; the shape is never auto-detected (ADR-005 supersedes ADR-001's per-shape entry points). Do not add a second entry point for a new commit shape. DAST deliberately uses `Scan` → exported file → `Package` in a fresh call: detaching the scan result releases live service bindings before audit packaging. This lifecycle is not an alternative commit shape.

**Schema in every module.** `src/internal/evidence/schema.go` defines the canonical Go types. Each module that produces evidence has a verbatim copy at `src/<module>/schema.go`. Run `make sync-schema` after changing the schema to keep copies in sync.

**No shared Go module.** Dagger modules are isolated — each has its own `go.mod`. Internal packages (`src/internal/`) are in a separate Go workspace (`go.work`) and are shared only via file copy (schema.go, toolchain.go via `make sync-toolchain`) or the Dagger dependency graph (`dagger.json`). Never add Dagger imports to `src/internal/`. Copies are guarded by `check_synced_files` (copies agree with each other) and `check_generated_files` (the generator is re-run and diffed — the drift that actually happens is both copies agreeing while the canonical file moves).

**Language auto-detection.** Modules inspect the source directory for marker files (`go.mod`, `package.json`, `pyproject.toml`/`requirements.txt`, `*.csproj`/`*.sln`/`*.slnx`) within `markerSearchDepth` and run only the relevant tool. Use `--include` to override. The marker set is authored once per module in `markers.go` (`src/quality/`, `src/build/`) and once in `src/internal/detect/detect.go`, and the `find` the modules run is generated from that list — `.slnx` was missing from two of the three copies for exactly as long as nothing tested them together.

**Static tool images are digest-pinned.** Every container image cicd selects on its own behalf — scanner, linter, policy engine, helper, or the language image `quality.Check` picks for an auto-detected language — lives in the owning module's `images.go` as a readable tag plus an immutable multi-arch index digest, is declared in `scripts/runtime-images.json`, and is covered by a `renovate.json` update group. `make check-image-pins` discovers `From(...)` references from source. The one exception is the container a *consumer's* command runs in: ADR-004 resolves it at run time from `--toolchain-image` / `.nvmrc` / `global.json`. Trap: `check-runtime-image-pins.py` treats a `From()` argument it cannot resolve as a consumer toolchain and *exempts* it, so `From(images[band])` passes the gate while going unpinned — keep such selections as a `switch` of literal `From()` calls with no `default:` arm. See [docs/reference/runtime-images.md](docs/reference/runtime-images.md).

## The engineering doctrine

A tool that could not run must never read as "clean": every scanner, linter and
gate here reports zero findings both on a clean tree and when it never executed,
so the two are distinguished explicitly, in the envelope's `errors[]`. The rules,
each with the mechanism that closes its door and the trap that would reopen it,
live in [docs/explanation/doctrine.md](docs/explanation/doctrine.md); the
module-level rules in [doctrine-security.md](docs/explanation/doctrine-security.md)
and [doctrine-quality.md](docs/explanation/doctrine-quality.md). Read the rule,
and the spec it links, before changing the code it names. One line per rule:

- [`--fail-on NONE` never suppresses a non-run](docs/explanation/doctrine.md#--fail-on-none-never-suppresses-a-non-run)
- [Narrowing the scope must be named, and must never narrow to nothing](docs/explanation/doctrine.md#narrowing-the-scope-must-be-named-and-must-never-narrow-to-nothing)
- [A tool that ran on part of the input must not read as having run on all of it](docs/explanation/doctrine.md#a-tool-that-ran-on-part-of-the-input-must-not-read-as-having-run-on-all-of-it)
- [A rule-specific parser failure can be replaced only when cicd has an equivalent](docs/explanation/doctrine.md#a-rule-specific-parser-failure-can-be-replaced-only-when-cicd-has-an-equivalent)
- [A count of what a tool examined is what makes its findings a measurement](docs/explanation/doctrine.md#a-count-of-what-a-tool-examined-is-what-makes-its-findings-a-measurement)
- [A scanner that died must not be described as one that found nothing](docs/explanation/doctrine.md#a-scanner-that-died-must-not-be-described-as-one-that-found-nothing)
- [And a scan that reached nothing must not report the scope it was asked for](docs/explanation/doctrine.md#and-a-scan-that-reached-nothing-must-not-report-the-scope-it-was-asked-for)
- [And a count can never say *which*](docs/explanation/doctrine.md#and-a-count-can-never-say-which)
- [And when a scanner throws the input away, only the scanner knows](docs/explanation/doctrine.md#and-when-a-scanner-throws-the-input-away-only-the-scanner-knows)
- [And a secrets scan must open what the output ships](docs/explanation/doctrine.md#and-a-secrets-scan-must-open-what-the-output-ships)
- [An artifact shape that attests nothing must say which nothing](docs/explanation/doctrine.md#an-artifact-shape-that-attests-nothing-must-say-which-nothing)
- [A gate that is switched off must say so](docs/explanation/doctrine.md#a-gate-that-is-switched-off-must-say-so)
- [A gate that grades prose must not fail on its own blind spot, and cannot grade a document it only partly read](docs/explanation/doctrine.md#a-gate-that-grades-prose-must-not-fail-on-its-own-blind-spot-and-cannot-grade-a-document-it-only-partly-read)
- [A historical rationale is not a new claim about this diff](docs/explanation/doctrine.md#a-historical-rationale-is-not-a-new-claim-about-this-diff)
- [A finding's location is part of its identity](docs/explanation/doctrine.md#a-findings-location-is-part-of-its-identity)
- [And the same door opens one field over](docs/explanation/doctrine.md#and-the-same-door-opens-one-field-over)
- [And a truncated table must keep the rows a reader came for, by a rule it states](docs/explanation/doctrine.md#and-a-truncated-table-must-keep-the-rows-a-reader-came-for-by-a-rule-it-states)
- [The report a gate writes must not be co-authored by the thing it grades](docs/explanation/doctrine.md#the-report-a-gate-writes-must-not-be-co-authored-by-the-thing-it-grades)
- [And a notification nobody received must not report success](docs/explanation/doctrine.md#and-a-notification-nobody-received-must-not-report-success)
- [And a scan scoped to one push must not report the coverage of a gate](docs/explanation/doctrine.md#and-a-scan-scoped-to-one-push-must-not-report-the-coverage-of-a-gate)
- [A gate the consumer cannot clear gets switched off, so cicd clears it](docs/explanation/doctrine.md#a-gate-the-consumer-cannot-clear-gets-switched-off-so-cicd-clears-it)
- [A tool with two command lines must be asked which one it has](docs/explanation/doctrine.md#a-tool-with-two-command-lines-must-be-asked-which-one-it-has)
- [An error naming one line of a long log is a claim, not evidence](docs/explanation/doctrine.md#an-error-naming-one-line-of-a-long-log-is-a-claim-not-evidence)
- [A harvest that read nothing must not report a ratchet it never ran](docs/explanation/doctrine.md#a-harvest-that-read-nothing-must-not-report-a-ratchet-it-never-ran)
- [A witnessed language is not a witnessed repository](docs/explanation/doctrine.md#a-witnessed-language-is-not-a-witnessed-repository)
- [And two resolvers for one question means one of them is wrong](docs/explanation/doctrine.md#and-two-resolvers-for-one-question-means-one-of-them-is-wrong)
- [A file cicd read and could not use must not look like a file that was never there](docs/explanation/doctrine.md#a-file-cicd-read-and-could-not-use-must-not-look-like-a-file-that-was-never-there)
- [A knob nobody can reach and a knob nobody needs look identical from outside](docs/explanation/doctrine.md#a-knob-nobody-can-reach-and-a-knob-nobody-needs-look-identical-from-outside)
- [An acceptance nobody can read is indistinguishable from a bug](docs/explanation/doctrine.md#an-acceptance-nobody-can-read-is-indistinguishable-from-a-bug)

The same doctrine at the harness:

- [Our own workflows use no third-party actions](docs/explanation/doctrine.md#our-own-workflows-use-no-third-party-actions)
- [A workflow step must stay small enough to start](docs/explanation/doctrine.md#a-workflow-step-must-stay-small-enough-to-start)
- [A workflow value reaches the shell as an argument, never as source](docs/explanation/doctrine.md#a-workflow-value-reaches-the-shell-as-an-argument-never-as-source)
- [And a pin nothing can read is not a pin at all](docs/explanation/doctrine.md#and-a-pin-nothing-can-read-is-not-a-pin-at-all)
- [A check nobody wrote is the cheapest version of the same lie](docs/explanation/doctrine.md#a-check-nobody-wrote-is-the-cheapest-version-of-the-same-lie)
- [And a step that could not fetch must not wear a compile error's face](docs/explanation/doctrine.md#and-a-step-that-could-not-fetch-must-not-wear-a-compile-errors-face)
- [And the wrapper only covers the module a job was named for](docs/explanation/doctrine.md#and-the-wrapper-only-covers-the-module-a-job-was-named-for)

## Common tasks

### Run internal tests
```
make test
# or
cd src/internal && go test ./...
```

### Run every module's unit tests (no Dagger session needed)
```
make test-module-units
# or
bash scripts/test-module-units.sh
```
This is the *only* canonical module-unit runner. It walks the defended
inventory (`scripts/repo-inventory.json`), runs the complete
`-tags unit_test` suite for every module that ships one, and fails if a
module with `*_test.go` files executes zero tests. Do not add a second
per-module test list to `Makefile` or `.github/workflows/ci.yml`.

It fails locally in one situation that is not a defect in your change, and
the failure is loud rather than silent, so this is a papercut and not a
doctrine breach. `dagger develop` writes a gitignored `dagger.gen.go` into
the module directory; that file is **untagged** and dispatches to the entry
methods, which `-tags unit_test` excludes — so with the SDK present the
tagged build cannot compile and the suite stops at `undefined: Dast` (or
`Build`, or `Quality`). CI never sees it: `lint-repo` runs the runner on a
clean checkout, and `module-test` runs `dagger develop` in a different job.
Delete the generated SDK from that module directory to run the suite again.
Moving the entry struct into an untagged file is **not** the fix — measured
on `src/composites/dast`, the error simply moves to
`(*Dast).Run undefined`, because the dispatch calls the methods too.

### Lint internal code
```
make lint
```

### Lint every Dagger module (needs Dagger; regenerates each module's SDK)
```
make lint-modules
```

### Check or fix Go formatting
```
make check-go-format   # audit every tracked Go file; exit 2 if gofmt could not run
make fmt               # rewrite the offenders
```

### Sync schema after changes to src/internal/evidence/schema.go
```
make sync-schema
```

### Generate internal SDKs for all modules (needed after dagger.json changes)
```
make develop-all
```

### Test a single module locally
```
dagger develop    # run once in the module dir to generate the SDK

# quality module
dagger -m ./src/quality call check \
  --src ./testdata/node-app \
  --include node \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  export --path /tmp/evidence.json

# security module (source scan)
dagger -m ./src/security call scan-source \
  --src ./testdata/go-app \
  --fail-on NONE \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  export --path /tmp/evidence.json

# build module
dagger -m ./src/build call build \
  --src ./testdata/go-app \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  stdout

# quality module — witnessed BYO test + coverage (archive consumers)
dagger -m ./src/quality call test \
  --src ./testdata/node-app \
  --test-cmd "npm ci --ignore-scripts && ./node_modules/.bin/vitest run --coverage --coverage.reporter=json-summary --coverage.reportsDirectory=/tmp/cov" \
  --coverage-path /tmp/cov/coverage-summary.json \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  export --path /tmp/evidence.json

# commit composite — archive shape (no Dockerfile). One entry point for every
# shape (ADR-005): --artifact container|archive|none selects the artifact tail.
dagger -m ./src/composites/commit call run \
  --src ./testdata/node-app \
  --artifact archive \
  --build-cmd "npm install --ignore-scripts && npm run build" \
  --output-path dist \
  --fail-on NONE \
  --commit-sha local \
  --branch main \
  --repo-url https://example.com \
  export --path /tmp/audit
```

## Adding a new module

1. Create the directory under `src/` (e.g. `src/quality/`, `src/cross-cutting/<name>/`).
2. `cd src/<name> && dagger init --name <name> --sdk go`
3. Copy `src/internal/evidence/schema.go` → `src/<name>/schema.go`
4. Implement `main.go` — evidence-producing checks return `(*dagger.File, error)` containing an envelope. Resource, aggregate, packaging and rendering functions retain their declared container/directory/transport contracts; see the architecture rules above.
5. Add the module to `scripts/repo-inventory.json` — the single defended manifest. `modules` drives the `Makefile`'s `MODULES`/`SYNCED_MODULES`/`CONTRACT_STEPS` and the release module load, and `check-surface` fails on a `dagger.json` on disk that the manifest does not declare. If the module ships a `README.md`/`CLAUDE.md`, declare it under `active_surfaces.module_docs` too, or the undeclared-document check fails.
6. Add the module to the `module-test` matrix in `.github/workflows/ci.yml` and give it a fixture case in that job's case statement (matrix value uses `src/<name>`).
7. Wire it into `src/composites/precommit/main.go` or `src/composites/commit/main.go` as appropriate.
8. If the module exposes a step contract, add it as `src/<module>/contract.json` and list it under `contract_modules` in the inventory.
9. If the module runs a tool container of its own, put the pin in `src/<name>/images.go` (`// renovate-image: <repository>` + version constant + `tag@sha256:<digest>` image constant), declare it in `scripts/runtime-images.json`, and add its `runtime image: <family>` group to `renovate.json`. `make check-image-pins` fails until all three exist.

## CI structure

| Job | Trigger | What it does |
|-----|---------|--------------|
| `lint-repo` | every push/PR | `go test ./...` + golangci-lint on `src/internal/`; `scripts/check-workflow-pins.py` (the release-blocking pin/command gate); `scripts/check-repo-surface.py` (the full defended surface: declared paths exist, local links resolve, cicd pins agree, every documented Dagger command exists, no undeclared active document, every workflow action can start a run); `scripts/check-runtime-image-pins.py`; `scripts/check-ado-templates.py`; `scripts/check-capsules.py` (a capsule whose YAML cannot parse, or a capsule number claimed twice); `scripts/check-go-format.py`; the script unit tests; and `scripts/test-module-units.sh` |
| `lint-modules` | after lint | `scripts/ci/lint-modules.sh` — golangci-lint over every Dagger module in both build-tag sets, developing each module first |
| `verify-contracts` | after lint | Verifies each module's Go signature against its `contract.json` |
| `module-test` | after lint | Runs each module against testdata fixtures via `dagger call` |
| `composite-smoke` | after lint | Runs the full precommit composite against go-app, node-app, dotnet-app |
| `composite-smoke-commit` | after lint | Runs the commit composite in all three shapes (`container`, `archive`, `none`) via `scripts/smoke/commit-shapes.sh` |
| `composite-smoke-dast` | after lint | Runs the DAST composite against `testdata/vuln-app` in both shapes (service, container) |
| `smoke-non-run-matrix` | after lint | `scripts/smoke/non-run-matrix.sh` — injects a real non-run through quality, risk and intent and requires each to fail or be refused at `--fail-on NONE`, beside a positive control per module |
| `commit-subjects` | every push/PR | `scripts/check-commit-subjects.py` — refuses a subject git-cliff cannot parse. Needs `fetch-depth: 0` |

The aggregate `ci` job verifies the suite selected by the change classifier.
Product changes require every product job to succeed; documentation-only changes
require `docs-validation` and expect the product jobs to be skipped. Both paths
require classification and commit-subject validation. Unexpected skips or
cancellations fail. A green documentation path is not execution of module tests,
container smokes or the separate dogfood intent check. `ci` is the required-check
context; destination settings still need independent verification. A new job is
covered only when the aggregate includes its dependency and expected result.

Everything after `lint-repo` runs in parallel, including the composite smokes.
They used to `needs: module-test`, which passed no artifact and granted no
ordering either job relied on — each composite does its own checkout, its own
`dagger develop` and its own engine — so it only made a PR pay module-test's
slowest cell before the first composite container started. `ci` still `needs:`
all of them, so what a green tick means is unchanged; a PR with a red module
cell now burns the composite jobs' compute rather than skipping them, which is
the price of learning about both failures in one run.

### Outbound protocols are proven locally, never against production

No CI job contacts Teams, GitHub's comment API or Azure DevOps. The seam is
proven by a unit suite driving the *production* code against a local `httptest`
server: `src/notify/delivery_test.go` (`TestDeliveryHTTP`). It covers success,
required auth headers, non-2xx, malformed responses, bounded timeout, the
explicit no-retry policy, and proof that a credential never reaches an error
string or the envelope. The `module-test` cell for `notify` is a compile and
rendering check only — do not read `dagger functions` as protocol proof.

### Azure DevOps templates are validated behaviourally

`scripts/check-ado-templates.py` (`make check-ado-templates`) parses every active
ADO template under ADO's YAML subset and checks what it does: the unified `run`
invocation with the flags the pipeline needs, credentials handed to Dagger as
`env:NAME`, any credential written to `~/.git-credentials` cleared again, and **no
consumer-supplied `$(VAR)` macro spliced into a bash body** — ADO expands macros
before the shell parses the line, so `"$(VAR)"` is textual splicing, not quoting.
Pass consumer values through the step's `env:` mapping and reference them as `"$VAR"`.

## The release pipeline

The founding doctrine one level up: a release pipeline that could not run reports
no new tag exactly like a repository with nothing to release. Every check below
asks a question the pipeline's own output cannot answer, and exit 2 (could not ask)
is a third answer that is never a pass. None has an override flag.

**A commit git-cliff cannot parse releases nothing, silently.** `cliff.toml` sets `filter_unconventional = true`, so an unparseable subject is dropped with only a WARN line, and `--bumped-version` prints the version already tagged — a real `fix(quality):` landed as free text and shipped to nobody. `release-drift.yml` cannot see it because it asks the same binary. So `commit-subjects` gates *parseability only* (no type allowlist; `wip:` parses), one notch stricter than cliff, and refuses a shallow clone. Logic in `scripts/commit_subjects.py`. See [specs/refuse-a-commit-git-cliff-cannot-release.md](specs/refuse-a-commit-git-cliff-cannot-release.md).

**A commit it *can* parse can still be filed under a release that shipped.** git-cliff computes the bump by commit *date* and `--unreleased` by *reachability*, so a commit from a branch open across a release lands inside a shipped release (v1.14.2 and v1.14.3 were patches whose notes list a feature). `--unreleased` is passed at both bump sites, and `scripts/check-release-bump.py` derives the required bump from `git log` and refuses when cliff disagrees, on the skip path too. Traps: `chore:` with a `BREAKING CHANGE` footer releases nothing; `Chore:` releases a patch. Not wired into `release.yml`, where the version is a human's override. See [specs/prove-the-bump-matches-its-history.md](specs/prove-the-bump-matches-its-history.md).

**A release that never happens is watched from outside the release pipeline.** `cd.yml` failed for four days while 64 commits accumulated and every human-visible signal stayed green. `.github/workflows/release-drift.yml` compares the newest tag against `git cliff --bumped-version` on a schedule, from outside CD, and past two days of drift opens one deduped issue labelled `release-drift`. Logic in `scripts/release_drift.py`. See [specs/report-release-drift.md](specs/report-release-drift.md).

**A release is delivered by pull request, never pushed to main.** The intended `main` policy requires a PR and the `ci` status **on the commit being pushed**. Effective destination rules must be verified rather than inferred from this guide; ordinary workflow pushes cannot be assumed to satisfy them. Release delivery uses `chore/release-v<version>` branches. `scripts/ci/deliver-release-pins.sh` is the one implementation behind `cd.yml` and `release.yml` and reports `pr-open`, `released`, `superseded` or `stale`. `pr-open` still awaits merge requirements; only `released` permits the caller to tag. `stale` forbids tagging the moved tip and checks the successor handoff; a successful handoff check is not a published release. Traps: a PR opened by `GITHUB_TOKEN` triggers no workflows, so `CICD_RELEASE_TOKEN` is mandatory; and every release is a change to `main`, so `scripts/ci/write-release-intent.py` writes a real intent artifact. See [specs/deliver-release-pins-by-pull-request.md](specs/deliver-release-pins-by-pull-request.md).

**And that pull request's own gate is asked about, never assumed.** The org ruleset once lost its `required_status_checks` rule while still showing as attached; `gh pr merge --auto` on an already-mergeable PR merges on the spot and reports which happened nowhere, so four releases merged before their `ci` run started and read `ci: success` forever. `scripts/check-release-gate.py --branch main` runs as a preflight and fails unless a rule actually names `ci`; `--delivered-pr N` asserts either *open with auto-merge armed* or *merged after `ci` succeeded on the head sha*. While the rule is absent, the pipeline refuses to release at all. See [specs/prove-the-release-merge-was-gated.md](specs/prove-the-release-merge-was-gated.md).

## Severity levels

All scanning modules accept `--fail-on CRITICAL|HIGH|MEDIUM|LOW|NONE`. `NONE` means never fail **over findings** (collect them only) — it does not suppress a non-run, see above. The default is `HIGH`.

## Notifications

`notify` supports Teams, GitHub PR comments, and Azure DevOps PR comments. To test card structure without a real webhook, use the `build-card` function:
```
dagger -m ./src/notify call build-card \
  --summary ./smoke-evidence/combined-evidence.json \
  --pipeline-name precommit \
  export --path /tmp/card.json
```

To preview a GitHub/ADO comment body:
```
dagger -m ./src/notify call github-build-comment \
  --summary ./smoke-evidence/combined-evidence.json \
  --pipeline-name precommit \
  export --path /tmp/comment.md
```
