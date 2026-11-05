# cicd

[![CI](https://github.com/context-and-oss/cicd/actions/workflows/ci.yml/badge.svg)](https://github.com/context-and-oss/cicd/actions/workflows/ci.yml)
[![CD](https://github.com/context-and-oss/cicd/actions/workflows/cd.yml/badge.svg)](https://github.com/context-and-oss/cicd/actions/workflows/cd.yml)
[![Latest release](https://img.shields.io/github/v/release/context-and-oss/cicd?sort=semver)](https://github.com/context-and-oss/cicd/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Reusable [Dagger](https://dagger.io) pipeline modules for a 12-stage continuous-delivery model.
Same modules run **locally**, in **GitHub Actions**, and in **Azure DevOps** — every domain module
returns a JSON **evidence envelope** so pass/fail decisions are auditable wherever they ran.

**Implemented:** stages 2 (source gate) and 4 (commit), plus running-app DAST
on its own cadence. Use the managed release pins below. The other ten stages
are the model, not the code;
[ROADMAP.md](ROADMAP.md) says what is planned and [CHANGELOG.md](CHANGELOG.md) says
exactly what is shipped today, per module.

| Stage | Name | In cicd |
|-------|------|---------|
| 1 | Authoring | human/process stage |
| 2 | Pre-commit | **shipped** — `composites/precommit`: lint, unit test, witnessed BYO test, SAST, secrets, dependency vulns, licences, infra policy, change intent |
| 3 | Pull Request | human/process stage; its automated half is stage 2 running on `pull_request` |
| 4 | Commit | **shipped** — `composites/commit`: the stage 2 source gate plus an explicit `container`, `archive` or `none` artifact tail (build, SBOM, image or archive scan) |
| 5 | Acceptance Testing | planned |
| 6 | Extended Testing | planned; `composites/dast` is the first piece and runs today, outside any merge gate |
| 7 | Exploration | planned |
| 8 | Start Release | planned |
| 9 | Release Approval | planned |
| 10 | Production Deployment | planned — and never a registry push from cicd ([ADR-001](docs/decisions/ADR-001-artifact-shapes.md)) |
| 11 | Live | planned |
| 12 | Release Toggling | planned |

Languages the stage 2 gate auto-detects by marker file, and what runs for each:

| Language | Marker | Lint | Unit tests |
|----------|--------|------|------------|
| Go | `go.mod` | golangci-lint | `go test` |
| Node.js | `package.json` | ESLint | Vitest |
| Python | `pyproject.toml` / `requirements.txt` | Pylint | pytest |
| .NET | `*.csproj` / `*.sln` / `*.slnx` | `dotnet format` | `dotnet test` (VSTest or Microsoft.Testing.Platform, read from `global.json`) |

Anything else is a warned pass that says no language was detected, never a silent green.

📖 **The narrative home** for the continuous-delivery model these modules implement is
[Continuous Delivery](docs/explanation/continuous-delivery/index.md) under `docs/explanation/`.
The modules are the *implementation*; those pages are the *why*.

---

## How do I get started?

You already have a pipeline. cicd doesn't ask you to throw it away — you hand it
**one stage at a time** and grow coverage from there. Pick the path that fits:

| Your situation | Path | Start here |
|----------------|------|------------|
| I want to try one check right now | **Run a single module** | [Run your first check](#run-your-first-check) below |
| I have a pipeline and want to migrate it piece by piece | **Incremental adoption** (agent-drivable) | [Adopt cicd incrementally](docs/how-to-guides/adopt-incrementally.md) |
| I want the whole gate on GitHub Actions / Azure DevOps | **Templates** | [Use the complete pipeline](docs/how-to-guides/use-complete-pipeline.md) |
| I want the pre-wired precommit/commit pipelines in my own Dagger flow | **Composites** | [Build your own pipeline](docs/how-to-guides/build-your-own-pipeline.md) |
| I want to run it before I push | **Local pre-push** | [Run the pipeline locally](docs/how-to-guides/run-pipeline-locally.md) |

New to the whole thing? The [Getting started](docs/tutorials/getting-started.md)
tutorial covers the *why* and walks the first check. Migrating an existing
pipeline? The [migration map](docs/explanation/migrating-to-cicd.md) explains
what maps to what, and the [step-mapping reference](docs/reference/step-mapping.md)
is the exhaustive "I run X today → it's Y in cicd" lookup.

### Availability and source access

Use a published release at the module coordinates below. Public repositories
support anonymous module fetching; private forks or mirrors require authorized
read-only source access. Verify that the referenced release and files exist and
that GitHub Actions sharing/access policy permits any reusable workflows and
installer actions you call. The Renovate preset also needs access to its source.

Package-feed and notification tokens do not grant module-source access. Do not
reuse a writer token or copy credentials into the application repository.

For local use, obtain a source checkout separately, outside the
application tree being scanned, then replace the remote `-m` value with its absolute module path (for example,
`-m "$CICD_SOURCE/src/security"`), keeping `--src .` pointed at your application.
`CICD_SOURCE` is the path to that checkout. Remote dependencies may still require
read access to their own repositories. A local module checkout does not grant
access to remote reusable workflows or actions; verify platform policy separately.

> **On Azure DevOps?** Module-source access and PR-comment access are separate:
> see [Set up Azure DevOps authentication](docs/how-to-guides/set-up-azure-devops-auth.md).

### Run your first check

One command, one envelope — no pipeline changes required. You need the
[Dagger CLI](https://docs.dagger.io/install), a running Docker daemon, and
[jq](https://jqlang.org/) for the verdict check:

```bash
rm -f ./evidence.json &&
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.5 call scan-source \
  --src . --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence.json &&
jq -e '.passed == true' ./evidence.json > /dev/null &&
echo "security scan passed"
```

A successful `dagger call` means the scan **ran and wrote its evidence**, not
that it was clean: a scan that found HIGH findings, or a scanner that could not
run, still exits 0 and records `"passed": false`. The `jq -e` line is the gate —
it exits non-zero unless the envelope says `passed`. A scanner that could not
run fails it at every `--fail-on`, `NONE` included. The `&&` chain (and the
`rm -f` before it) means a failed export can never fall through to grading an
old `evidence.json`.

Open `evidence.json` — pass/fail, findings by severity, embedded SARIF, warnings
and per-source examined/rule metadata. `passed` is a gate decision, not proof of
complete examination or absence of suppressed findings. Source scanning is not a
full-history secrets audit or live credential verification; retain existing
protections until equivalent scope and enforcement are configured and verified.

> **Licence note — default SAST rules.** `scan-source` runs Semgrep with rules
> fetched at run time from `semgrep/semgrep-rules`, which are licensed under the
> **Semgrep Rules License v1.0**, not Apache-2.0: internal business use only, no
> redistribution and no offering them to others as a service. Running cicd as a
> hosted service for others, or redistributing the fetched rules, needs a
> suitable rules licence from Semgrep — or pass your own suitably licensed rules
> with `--sast-rulesets ./your-config.yml`. Details:
> [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

---

## Documentation

Organized using the [Diataxis](https://diataxis.fr/) framework:

| Section | Purpose | Open when… |
|---------|---------|------------|
| [Tutorials](docs/tutorials/index.md) | Learning-oriented | You're new and want to learn by doing |
| [How-to Guides](docs/how-to-guides/index.md) | Task-oriented | You need to get a specific thing done |
| [Reference](docs/reference/index.md) | Information-oriented | You need exact technical facts |
| [Explanation](docs/explanation/index.md) | Understanding-oriented | You want the *why* behind the design |

Highlights worth bookmarking:

- [12-stage CD model](docs/explanation/continuous-delivery/cd-model/overview.md)
- [Migrating from a hand-rolled pipeline](docs/explanation/migrating-to-cicd.md)
- [Pre-commit quality gates](docs/explanation/continuous-delivery/quality-gates/precommit-gates.md)
- [AI risk analysis](docs/explanation/continuous-delivery/security/risk-analysis.md)

---

## Module reference

The building blocks. You rarely call these directly once adopted — the
composites and templates wire them for you — but this is the map of what exists.

| Module | Address | What it does |
|--------|---------|--------------|
| `quality` | `github.com/context-and-oss/cicd/src/quality@v5.1.5` | Multi-language lint + unit tests |
| `security` | `github.com/context-and-oss/cicd/src/security@v5.1.5` | SAST, secrets, vuln scan, image scan, DAST |
| `risk` | `github.com/context-and-oss/cicd/src/risk@v5.1.5` | AI risk analysis + OPA policy gate |
| `build` | `github.com/context-and-oss/cicd/src/build@v5.1.5` | OCI image build, SBOM |
| `notify` | `github.com/context-and-oss/cicd/src/notify@v5.1.5` | Teams / GitHub / Azure DevOps notifications |
| `stage-2` | `github.com/context-and-oss/cicd/src/stage-2@v5.1.5` | Pre-commit orchestrator — quality + security + risk |
| `stage-4` | `github.com/context-and-oss/cicd/src/stage-4@v5.1.5` | Commit orchestrator — build + image scan |
| `composites/precommit` | `github.com/context-and-oss/cicd/src/composites/precommit@v5.1.5` | Full pre-commit pipeline (Stage 2) |
| `composites/commit` | `github.com/context-and-oss/cicd/src/composites/commit@v5.1.5` | Full commit pipeline — source gate + `--artifact container\|archive\|none` tail (Stage 2 + Stage 4, [ADR-005](docs/decisions/ADR-005-commit-stage-code-and-artifact.md)) |
| `composites/dast` | `github.com/context-and-oss/cicd/src/composites/dast@v5.1.5` | Running-app DAST on its own cadence — `--app url\|service\|container`; not a merge gate ([reference](docs/reference/dast.md)) |

Each module has a `README.md` beside its source (for example
[`src/quality/README.md`](src/quality/README.md)). Cross-cutting helpers
(`src/cross-cutting/`: `evidence`, `report`, `contract`, `intent`, `pages`) are
documented in the [reference](docs/reference/index.md).

---

## Repo layout

```text
src/
  quality/  security/  risk/  build/  notify/   ← domain modules
  stage-2/  stage-4/                             ← stage orchestrators
  composites/{precommit,commit,dast}/            ← pre-wired pipelines
  cross-cutting/{evidence,report,contract,      ← shared helpers
                 intent,pages}/
  internal/{detect,evidence,sarif}/             ← shared Go packages (no Dagger)
templates/{github-actions,azure-devops,local}/  ← copy-paste starters
testdata/                                       ← fixture apps the CI smokes run against
  go-app/  node-app/  python-app/               ← one per auto-detected language
  dotnet-app/  dotnet-app-nolock/  dotnet-mtp-app/   ← .NET: VSTest, no lockfile, MTP runner
  app-workspace/                                ← multi-app monorepo
  vuln-app/                                     ← deliberately vulnerable DAST target
  semgrep-github-actions/                       ← workflow files for the SAST parser fixtures
docs/                                           ← Diataxis docs
scripts/                                        ← release + repo-surface tooling
default.json                                    ← the Renovate preset consumers extend
```

`default.json` is the shared [Renovate](https://docs.renovatebot.com/) preset:
`"extends": ["github>context-and-oss/cicd"]` keeps a consumer's cicd pins current
in whichever of the three pin shapes their pipeline uses.

See [CONTRIBUTING.md](CONTRIBUTING.md) to work on the repository,
[docs/explanation/doctrine.md](docs/explanation/doctrine.md) for the engineering
doctrine and [CLAUDE.md](CLAUDE.md) for the codebase guide.

---

## Development

Toolchain: Go 1.26.2, Python 3 (standard library only, for `scripts/`),
Node.js 18 or later (the risk proxy's loopback tests, run by `make
test-scripts` and the risk module's unit tests), git, jq, the
Dagger CLI at the version `DAGGER_VERSION` names in `.github/workflows/ci.yml`,
and a running Docker daemon.

```bash
make test           # internal Go tests
make lint           # golangci-lint on src/internal/
make lint-modules   # golangci-lint on every Dagger module, both tag sets (needs Dagger)
make develop-all    # regenerate every module's Dagger SDK
make sync-schema    # propagate src/internal/evidence/schema.go to module copies
make check-surface  # active docs/templates agree with the shipped implementation
make check-pins     # consumer-facing cicd version pins agree on one version
make test-scripts   # unit tests for the repo-surface + release scripts
make install-hooks  # opt into the local pre-push hook in this repo
make check-hooks    # refuse a clone where git would run no pre-push hook
```

`make check-surface` is the defended repository-surface check: every path the
[inventory](scripts/repo-inventory.json) declares active must exist, its local
links must resolve, its cicd pins must agree, and every Dagger command it
documents must exist in module source. CI runs it on every push and PR.

---

## License

cicd is licensed under the [Apache License, Version 2.0](LICENSE); see
[NOTICE](NOTICE). Third-party material copied into this tree, and third-party
content cicd fetches at run time under its own terms — notably the default
Semgrep rules — is recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
