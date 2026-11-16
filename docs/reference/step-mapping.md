# Step mapping: existing CI → cicd

The canonical lookup for **"I run X today — what is it in cicd?"** Both the
[migration explanation](../explanation/migrating-to-cicd.md) (the before→after
map) and the [incremental adoption how-to](../how-to-guides/adopt-incrementally.md)
(the do-it-now procedure) link here rather than restating this table.

Verdicts:

- **Replace** — a replacement candidate, not permission to delete a control.
  Keep the existing step until equivalent policy, scope, enforcement and delivery
  are configured **and verified**. A passing snapshot is not history coverage;
  a warning-mode check is not a blocking gate.
- **Feed in** — cicd runs *your* command witnessed; you keep the command, cicd
  attests the result.
- **Keep** — cicd does not replace this; it stays in your pipeline.

## Quality

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| `go test`, `pytest`, `dotnet test`, `vitest` | `quality.check` — auto-detects language and runs its supported native test runner; Node requires project-installed Vitest | Replace |
| Jest or another custom test runner | `quality.test` / `test-cmd` or `test-legs` — explicitly run your command; it is not auto-selected | Feed in |
| Your own test command with coverage | `quality.test` / the `test-cmd` + `coverage-path` inputs — runs it witnessed in a toolchain container, harvests coverage, ratchets it (ADR-002/003) | Feed in |
| Several test commands, one per stack, in a polyglot repo | `quality.test` / the `test-legs` input — one command, container and coverage report per language, and any detected language no leg tests is named in the evidence | Feed in |
| A hosted absolute coverage threshold | The coverage ratchet detects regressions, not an absolute minimum; missing baseline/coverage skips fail-open | Keep the minimum in your test command unless equivalent enforcement is configured and verified; feed coverage into the ratchet separately |
| `golangci-lint`, `eslint`, `pylint`, `dotnet format` — **baseline** run | `quality.check` runs its supported language linter; it does not run Ruff | Replace |
| A **project-specific** ESLint/Sonar ruleset you curate | The Node leg uses your installed ESLint and project config; cicd does not reproduce Sonar's engine, dashboard or project gates | Keep additional controls until equivalent policy and execution are verified |

## Security

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| Baseline Semgrep SAST | `security.scan-source` (SAST) — pinned defaults, inline JavaScript support and curatable `--sast-rulesets` | Replace |
| CodeQL / SonarQube SAST | Overlapping, not equivalent analysis. Establish the required language/rule coverage before removing an existing scanner; cicd does not run these engines | Keep until replacement coverage is established |
| CodeQL cross-function dataflow | [`security.scan-taint`](../../src/security/README.md#scan-taint) — Opengrep interfile analysis for Go, Java and JavaScript/TypeScript to a stated call depth; advisory by default, no C# rule. Without GitHub Advanced Security: [run without it](../how-to-guides/run-without-github-advanced-security.md) | Keep until replacement coverage is established |
| .NET security analyzers (`CA3001`–`CA3012`, `CA23xx`, `CA53xx`) in a separate build | `security.scan-source` builds a C# or VB tree with the SDK's Roslyn security analyzers and gates on them | Replace |
| CodeQL for GitHub Actions, zizmor | `security.scan-source` runs zizmor on `.github/workflows`, actions and Dependabot files | Replace |
| Gitleaks source snapshot scanning | `security.scan-source` runs Gitleaks on the uploaded working tree | Replace only after equivalent rules, scope and suppressions are verified |
| Git-history secret scanning | `scan-source` adds history scanning only when the uploaded directory carries usable `.git/` metadata; available history depends on checkout depth. Application mode is snapshot-only | Keep until equivalent history coverage is verified |
| TruffleHog / provider verification / GitHub secret-scanning protections | `scan-image` scans image files with TruffleHog; `--verify-secrets` selects only verified results in the container path. This is not a source/history or platform-protection replacement | Keep provider/platform protections until equivalent behavior is configured and verified |
| `npm audit`, `dotnet list package --vulnerable`, Snyk, Dependabot-as-gate | `security.scan-source` (dependency-vuln) | Replace |
| Trivy/Grype **image** scan action | `security.scan-image` — **container shape only** (needs a built image; see the [boundary](#the-image-scan-boundary)) | Replace |
| FOSSA / Snyk License / `license-checker` / `pip-licenses` as a merge gate | [`security.scan-licenses`](../../src/security/README.md#scan-licenses) — explicit policy and `--license-gate gate` required; default `warn` does not block findings. Application mode defers dependency licences | Keep until equivalent enforcement and assessed dependency scope are configured and verified |
| OWASP ZAP / DAST against a running app | `security.scan-web` | Replace |
| SonarQube as your quality *dashboard* / historical trend | — SonarQube stays; cicd is the pass/fail gate, not the trend store | Keep |

## Build & artifact

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| `docker build` (you have a Dockerfile) | `build.build` — container shape (`artifact: container`) | Replace |
| `npm run build` / `dotnet publish` → a zip or folder | Archive shape: `build-cmd` + `output-path` (`artifact: archive`) | Feed in |
| A source-only repo (library, infra) with no artifact | `artifact: none` — source gate + lockfile SBOM, no build | Replace |
| `syft` / SBOM generation | `build.sbom` (image) or the lockfile SBOM (archive/none) | Replace |
| `docker push` / artifact publish / deploy | — cicd builds and scans but **never publishes**; deployment stays yours | Keep |
| App/package **version bumping** | — stays yours (cicd only version-pins its own module refs) | Keep |

## Notify & evidence

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| `actions/github-script` PR comment / ADO PR-comment task | `notify.github` / `notify.ado` — severity-count comment from the evidence | Replace |
| Teams webhook step | `notify.teams` (set `TEAMS_WEBHOOK`) | Replace |
| Manual SBOM generation step | `sbom.cdx.json` in the evidence artifact — upload it to your inventory from your own workflow | Replace |
| Bespoke "collect all reports" / artifact-upload glue | `combined-evidence.json` — one aggregated envelope + `findings.sarif`, `sbom.cdx.json`, `comment.md` | Replace |

## The image-scan boundary

`security.scan-image` takes a built Dagger `Container`, so it needs an image
cicd holds. In the commit pipeline it runs only for the **container** shape
(you authored a Dockerfile). Repository-mode `archive`/`none` retain source
checks and a source dependency SBOM, but **no image scan** of an external
SDK-container/buildpack output. Application mode additionally defers dependency
assessment and SBOM generation; see its [coverage contract](./commit-monorepo.md).
Do not remove an existing image scan merely because source evidence passed. See
[Artifact shapes](../explanation/artifact-shapes.md).

## Auth is platform-specific

Public modules support anonymous fetching; private forks or mirrors require
read-only source access. Verify the referenced release and platform access for
reusable workflows and actions. Alternatively, use a separate source checkout
and a local module path, such as
`-m ./src/composites/commit` from that checkout's root, with `--src` pointing at
the source to assess. Do not fall back to writer credentials or copy credentials
into the checkout.

Module-source access is separate from npm/NuGet feeds and notification auth.
GitHub PR comments use the job's own `GITHUB_TOKEN`; Azure DevOps PR comments need
`System.AccessToken` and `ADO_ORG` per the
[ADO auth guide](../how-to-guides/set-up-azure-devops-auth.md). Neither proves
module access or notification delivery. Default executable SAST also fetches
restrictively licensed rules; review the [runtime rule notice](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20)
before adopting that path.
