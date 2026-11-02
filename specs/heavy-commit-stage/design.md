# Design — Heavy commit stage

## Blast radius
- `src/composites/commit/` — `main.go` (rewrite `Run`), `archive.go` (**delete**),
  `dagger.json` (+`stage-2`), `dagger.gen.go` (regen), `CLAUDE.md`.
- `src/security/` — `secrets_image.go`, `main.go` (`ScanImage` +`verifySecrets`),
  `secrets_image_test.go` (new), `dagger.gen.go` (regen).
- `src/stage-2/main.go` — one-line fix: pass npm/nuget feeds to the `quality.Test` call.
- `.github/workflows/commit.yml`, `templates/github-actions/commit.yml` — unify.
- `templates/azure-devops/commit.yml`, `templates/azure-devops/shared/commit.yml` — unify.
- `.github/workflows/cd.yml` — repoint the archive job to `commit` with `artifact=archive`.
- `.github/workflows/ci.yml` — composite-smoke for all three shapes.
- `scripts/commit-diff.sh` (new) + its test; `scripts/smoke/commit-shapes.sh` (new).
- **Deletions:** `src/composites/commit/archive.go`,
  `.github/workflows/commit-archive.yml`,
  `templates/github-actions/commit-archive.yml`,
  `templates/azure-devops/commit-archive.yml`,
  `templates/azure-devops/shared/commit-archive.yml`.
- `docs/decisions/ADR-005-*.md`, `docs/reference/index.md`,
  `docs/explanation/continuous-delivery/security/shift-left.md`.

## Seams
- **composite ↔ stage-2** — commit's source gate is `dag.Stage2().Run()`,
  returning `[]*dagger.File`. The composite owns this wiring; stage-2 is reused
  as-is (plus the feed fix). No stage-2 signature change → no contract change.
- **composite ↔ build/security** — the artifact tail calls `Build`+`Sbom`+
  `ScanImage` (container) or `BuildArchive`+`ScanArchive` (archive). `ScanImage`
  gains `verifySecrets`.
- **composite ↔ evidence** — `finishAudit` + `evidence.Wrap` aggregate any
  `[]*dagger.File`; `mergeCycloneDX` appends components across envelopes, so the
  container shape's source-FS + image SBOMs merge cleanly (verified,
  `evidence/main.go:272`). Unchanged.
- **workflow ↔ modules (diff)** — commit.yml computes `before..after` via
  `scripts/commit-diff.sh` and passes it as `--diff`. Modules already full-scan
  on an empty diff (`risk/opa.go:32`, intent equivalent). Pure workflow change.
- **CI ↔ fixtures** — `scripts/smoke/commit-shapes.sh` drives go-app / node-app /
  python-app for the three shapes; ci.yml wires it in.

## Contracts
`commit.Run` — the one entry point:

```go
func (m *Commit) Run(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    artifact string,   // +default="container"  — container|archive|none
    failOn string,     // +default="HIGH"
    // --- source gate (passthrough to dag.Stage2().Run) ---
    include []string, sastRulesets string /* +default="auto" */, diff *dagger.File,
    intentGlobs []string, minCoverage float64, coverageMinLines int,
    testCmd, coveragePath string, baseline *dagger.File,
    tolerance float64 /* +default=1.0 */, coverageGate string /* +default="gate" */,
    toolchainImage string,
    npmFeedUrl string, npmToken *dagger.Secret,
    nugetFeedUrl string, nugetToken *dagger.Secret,
    // --- container shape ---
    dockerfile string /* +default="Dockerfile" */, platform string /* +default="linux/amd64" */,
    // --- archive shape ---
    buildCmd, outputPath string,
    // --- heavier secrets ---
    verifySecrets bool, // +default=false
    // --- delivery ---
    teamsWebhook *dagger.Secret, runUrl string,
    dependencyTrackApiKey *dagger.Secret,
    dependencyTrackCustomer, dependencyTrackProject string,
) (*dagger.Directory, error)
```

Dispatch:

```go
srcGate := dag.Stage2().Run(src, commitSha, branch, repoUrl, /* stage-2 opts… */)
var artifactEvidence []*dagger.File
switch artifact {
case "container":
    img := dag.Build().Build(src, commitSha, branch, repoUrl, /* Dockerfile, Platform */)
    artifactEvidence = []*dagger.File{
        dag.Build().Sbom(img, commitSha, branch, repoUrl),
        dag.Security().ScanImage(img, commitSha, branch, repoUrl,
            dagger.SecurityScanImageOpts{FailOn: failOn, VerifySecrets: verifySecrets}),
    }
case "archive":
    if buildCmd == "" || outputPath == "" {
        return nil, fmt.Errorf("--artifact archive requires --build-cmd and --output-path")
    }
    out := dag.Build().BuildArchive(src, buildCmd, outputPath, commitSha, branch, repoUrl, /* ToolchainImage */)
    artifactEvidence = []*dagger.File{
        dag.Security().ScanArchive(src, out, commitSha, branch, repoUrl,
            dagger.SecurityScanArchiveOpts{FailOn: failOn}),
    }
case "none":
    // no build; SBOM comes from stage-2 scan-source Trivy-FS CycloneDX
default:
    return nil, fmt.Errorf("invalid --artifact %q: want container|archive|none", artifact)
}
return finishAudit(ctx, append(srcGate, artifactEvidence...), "commit", opts)
```

`scripts/commit-diff.sh` — prints a git range for `--diff`:
`before..after` for a normal push; `HEAD~1..HEAD` when `before` is all-zeros
(first/force push); empty string when no base resolves. Never `origin/main...HEAD`.

## Reference reading
- `src/stage-2/main.go` — the source gate reused wholesale (all six checks).
- `src/composites/commit/main.go` — `finishAudit`, artifact-agnostic tail.
- `src/cross-cutting/evidence/main.go:272` — `mergeCycloneDX` appends across envelopes.
- `src/risk/opa.go:32` — empty/absent diff → full-repo scan (main-run behavior).
- `.github/workflows/precommit.yml` — the diff step + `fetch-depth:0` pattern to mirror.
- `src/security/CLAUDE.md` — the `--sast-rulesets ""` false-pass footgun (never pass empty).
- `scripts/check-workflow-pins.py` — pin/command coherence lint; auto-guards deletions.
- ADR-005 (this feature), ADR-001 (shapes + no-auto-detect rule), ADR-004 (toolchain image).

## Decisions
- ADR-005: commit scans code + artifact, one `--artifact` entry, incremental diff (introduced earlier; corrected later).
- ADR-001: artifact shapes, ownership split, cicd never auto-detects build commands (existing; per-shape-entry clause superseded by ADR-005).
- ADR-004: toolchain-image is the digest-pinnable level for archive builds (existing).
