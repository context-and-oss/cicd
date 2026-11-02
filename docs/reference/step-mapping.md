# Step mapping: existing CI → cicd

The canonical lookup for **"I run X today — what is it in cicd?"** Both the
[migration explanation](../explanation/migrating-to-cicd.md) (the before→after
map) and the [incremental adoption how-to](../how-to-guides/adopt-incrementally.md)
(the do-it-now procedure) link here rather than restating this table.

Verdicts:

- **Replace** — cicd owns this; delete your step and let the module do it.
- **Feed in** — cicd runs *your* command witnessed; you keep the command, cicd
  attests the result.
- **Keep** — cicd does not replace this; it stays in your pipeline.

## Quality

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| `go test`, `pytest`, `dotnet test`, `vitest`/`jest` (auto) | `quality.check` — auto-detects language and runs the vanilla test runner | Replace |
| Your own test command with coverage | `quality.test` / the `test-cmd` + `coverage-path` inputs — runs it witnessed in a toolchain container, harvests coverage, ratchets it (ADR-002/003) | Feed in |
| Several test commands, one per stack, in a polyglot repo | `quality.test` / the `test-legs` input — one command, container and coverage report per language, and any detected language no leg tests is named in the evidence | Feed in |
| A hosted coverage gate (Codecov/Coveralls threshold) | The built-in coverage ratchet (baseline = previous default-branch evidence) | Replace |
| `golangci-lint`, `eslint`, `ruff`, `dotnet format` — **baseline** run | `quality.check` runs a language-appropriate baseline linter | Replace |
| A **project-specific** ESLint/Sonar ruleset you curate | — cicd runs baseline lint only; your curated config stays yours | Keep |

## Security

| You run today | cicd equivalent | Verdict |
|---------------|-----------------|---------|
| Baseline Semgrep SAST | `security.scan-source` (SAST) — pinned defaults, inline JavaScript support and curatable `--sast-rulesets` | Replace |
| CodeQL / SonarQube SAST | Overlapping, not equivalent analysis. Establish the required language/rule coverage before removing an existing scanner; cicd does not run these engines | Keep until replacement coverage is established |
| gitleaks / trufflehog / GitHub secret scanning | `security.scan-source` (secrets) | Replace |
| `npm audit`, `dotnet list package --vulnerable`, Snyk, Dependabot-as-gate | `security.scan-source` (dependency-vuln) | Replace |
| Trivy/Grype **image** scan action | `security.scan-image` — **container shape only** (needs a built image; see the [boundary](#the-image-scan-boundary)) | Replace |
| FOSSA / Snyk License / `license-checker` / `pip-licenses` as a merge gate | `security.scan-licenses` — Trivy license scan with a category allowlist, `warn` by default | Replace |
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

`security.scan-image` scans a built image tarball, so it needs an image cicd
holds. It runs only for the **container** shape (you authored a Dockerfile).
Services built by azd's SDK-container support or buildpacks — no Dockerfile —
get the full source gate and a lockfile SBOM, but **no image scan**. That is a
deliberate boundary, not a gap. See
[Artifact shapes](../explanation/artifact-shapes.md).

## Auth is platform-specific

The modules are fetched from the public cicd repository, so no credential is
needed to run them on either platform. What differs is the notification
surface: GitHub PR comments use the job's own `GITHUB_TOKEN`, Azure DevOps PR
comments need `System.AccessToken` and `ADO_ORG` per the
[ADO auth guide](../how-to-guides/set-up-azure-devops-auth.md). This is not a
step you "map" — it is new setup either way.
