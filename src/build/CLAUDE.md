# build module

Domain module: OCI container build and SBOM generation. The module never publishes images — each consumer repo owns its own deployment. Unlike other modules, `Build()` returns a `*dagger.Container` (not evidence) so downstream steps share the same lazy image reference without rebuilding.

## Entry functions

```go
// Build a container from a Dockerfile. Returns the container, not evidence.
func (m *Build) Build(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    dockerfile string,  // default "Dockerfile"
    platform string,    // default "linux/amd64"
) (*dagger.Container, error)

// Generate CycloneDX SBOM with Trivy. Returns evidence.json.
func (m *Build) Sbom(
    ctx context.Context,
    image *dagger.Container,
    commitSha, branch, repoUrl string,
) (*dagger.File, error)

// Record that this run built and attested NO artifact (`--artifact none`).
// Runs no tool. Returns a warned-pass envelope carrying the
// "artifact: NOT ATTESTED — …" warning notify renders verbatim into the PR
// comment, plus `genericReport.artifactAttested: false` for machines.
func (m *Build) NoArtifact(
    commitSha, branch, repoUrl string,
) (*dagger.File, error)
```

`NoArtifact` is the only function here that executes nothing, and that is the
point. The commit composite's `none` branch used to record nothing at all, so the
audit of a repository shipping a dozen deployables and the audit of a repository
shipping none were byte-identical — the founding doctrine ("a tool that could not
run must never read as clean") on the artifact side, arriving through a selector
value rather than a crashed scanner. It is a **warned pass**, never a failure: a
library or an infra repo genuinely has nothing deployable, and `--fail-on NONE`
does not suppress a non-run, so failing would be a permanent red with no remedy.
Wording and reasoning live in `noartifact.go`; see
[specs/say-what-no-artifact-left-unattested.md](../../specs/say-what-no-artifact-left-unattested.md).

## Run locally

```sh
cd src/build && dagger develop   # once

# build only
dagger -m ./src/build call build \
  --src ./testdata/go-app \
  --commit-sha local --branch main --repo-url https://example.com \
  stdout

# generate SBOM (chains build → sbom)
dagger -m ./src/build call sbom \
  --image "$(dagger -m ./src/build call build --src ./testdata/go-app --commit-sha local --branch main --repo-url https://example.com)" \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/sbom-evidence.json

# the no-artifact record (what --artifact none puts in the audit)
dagger -m ./src/build call no-artifact \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/no-artifact-evidence.json
```

## Key files

- `main.go` — `Build()`, `Sbom()`, `NoArtifact()` entry points
- `noartifact.go` — the no-artifact envelope, its warning text and the
  machine-readable `artifactAttested: false` statement (untagged, unit-tested;
  also holds `moduleName`/`moduleStage` so the tests see the identity that ships)
- `markers.go` — the language marker-file list, the `find` predicate generated
  from it, and the suffix classification of what it returns; feeds
  `inferToolchainLanguage` in `archive.go` (untagged, unit-tested; byte-identical
  with `src/quality/markers.go`, which a `synced_files` group in
  `scripts/repo-inventory.json` enforces)
- `archiveexec.go` — `archiveBuildArgv()`, the exec that runs the consumer's
  build command as its own script (`sh -c "$1"`), never spliced into cicd's
  (untagged; its test runs the real wrapper under `sh`)
- `sbomfold.go` — **untagged**: `foldSbom()`, what `Sbom` states about the
  document Trivy wrote; `sbomfold_test.go` is its non-run matrix
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go`

## Constraints

- **An SBOM that is not a CycloneDX BOM is a non-run.** Trivy runs with
  `--exit-code 0`, and `Sbom` used to pass whenever the file was readable, so an
  empty file or `null` went out CLEAN with no inventory. The document must name
  `bomFormat: CycloneDX` and a `specVersion`; its top-level `components` are
  `examined`, and a BOM with none passes with a warning, because an image Trivy
  could not analyse lists none either.
- `Build()` is the only entry function that returns a container, not evidence. This is intentional — it lets `Sbom` and `security.ScanImage` share one lazy build.
- `NoArtifact()`'s warning must stay a single line and must contain no backtick:
  `notify/render.go` writes each warning as `` - `%s` ``, so a backtick closes the
  code span and a newline breaks the list item. Asserted in `noartifact_test.go`.
- OCI labels (`revision`, `source`, `ref.name`) are stamped automatically from the provenance args.
