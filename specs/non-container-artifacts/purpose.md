# Non-container artifacts

## Problem
Many repositories consuming cicd ship zips, not Docker images — low-code
solution packages and .NET apps deployed as zips to a web app host. For them the commit stage is unusable (its only build
primitive is `DockerBuild`), there is no witnessed test/coverage evidence anywhere
(compliance requires demonstrating coverage trend), and the SBOM→Dependency Track
chain only exists on the image path. These teams get half the evidence plane or
must fake a Dockerfile to get the rest.

## Outcome
Repos that ship zips get the full cicd evidence chain — attested archive build,
lockfile SBOM, artifact secrets scan, witnessed test coverage with a file-less
ratchet gate, and Dependency Track upload — without writing a Dockerfile or
committing any CI-specific file.

## Users
Platform team (owns cicd, wants one evidence plane for the whole fleet) and
consumer teams in three shapes: Dataverse-zip repos, dotnet-zip→Azure repos, and
existing container repos (who must be entirely unaffected — additive v1.x release).
When an agent must choose between two reasonable behaviours, prefer the one that
keeps existing image-path consumers byte-for-byte unchanged.

## Success signal
(a) cicd's own CI runs `testdata/node-app` through `commit.RunArchive` and
`Quality.Test` end to end: the evidence bundle contains a lockfile-derived
CycloneDX SBOM, a secrets finding for the planted fixture in the built output,
and witnessed coverage with a ratchet verdict. (b) A real consumer
PR shows witnessed coverage and ratchet status in its PR comment (post-ship,
human-verified).

## Non-goals
- No consumer lint-config execution — the vanilla auto-detect lint baseline stays;
  cicd never runs a consumer's own eslint/analyzer config.
- No deploy — `RunArchive` attests, it never imports to Dataverse or pushes to
  Azure. (Consumers wanting build-once-deploy-same-artifact can call
  `build-archive` directly and export.)
- No diff-coverage — ratchet only; diff-coverage is a possible follow-up.
- No report ingestion — cicd executes tests; it never wraps consumer-provided
  test reports as evidence.
- No CI-specific files committed to consumer repos beyond the caller stub —
  explicitly no coverage-baseline file.
- No auto-detected build commands — the archive build command is always explicit.
- Image path frozen — `Run`, `Build`, `ScanImage` signatures unchanged.
- DAST/`ScanWeb` untouched.
- ADO baseline-fetch parity deferred (GH-first; documented TODO).

## Glossary
- **Archive** — any artifact that is a directory or zip rather than an OCI image
  (Dataverse solution zip, dotnet publish output, a vite `dist/`).
- **Artifact shape** — one of exactly two pipeline forms: `image` (existing
  Docker path) or `archive` (new). Each has its own composite entry point.
- **Witnessed evidence** — a result cicd produced by executing the consumer's
  command itself in a cicd-controlled container, as opposed to ingesting a
  consumer-provided report.
- **Ratchet** — the coverage gate: measured coverage must be ≥ baseline − tolerance,
  per language. Not strictly monotonic; tolerance absorbs refactor noise.
- **Baseline** — the previous successful default-branch run's evidence artifact
  (`combined-evidence.json`), fetched by the workflow layer. Not a repo file.
- **Toolchain container** — the container image the consumer's build/test command
  runs in, resolved param > version-file detection > pinned default.
- **Caller stub** — the small workflow file in a consumer repo that calls cicd's
  reusable workflow (e.g. a consumer's `.github/workflows/precommit.yml`).
- **DT triad** — the three optional Dependency Track params (apiKey, customer,
  project); all-set uploads, any-set-but-not-all warns on stderr.

## Reversibility
Everything is additive: new functions, new optional params, new omitempty
envelope fields, new workflow inputs. Rollback = consumers stop calling the new
entry points; no migrations, no on-disk consumer formats. The one durable
commitment is public API surface (`BuildArchive`, `Test`, `ScanArchive`,
`RunArchive`, workflow inputs) — once fleet repos adopt them, renames become
breaking changes, so names ship deliberately (see design.md → Contracts).
