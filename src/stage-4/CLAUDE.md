# stage-4 module

Stage orchestrator for commit-stage checks. Wires `build.Build` → `build.Sbom` + `security.ScanImage` and returns their evidence files as a slice. Does not notify — use `composites/commit` for that. The image is built and scanned but never published; each consumer repo owns its own deployment.

## Entry function

```go
func (m *Stage4) Run(
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    dockerfile string,  // default "Dockerfile"
    platform string,    // default "linux/amd64"
    failOn string,      // default HIGH
) []*dagger.File        // [sbom-evidence.json, security-image-evidence.json]
```

## Dependencies (dagger.json)

- `build` (root-level module)
- `security` (root-level module)

## Run locally

```sh
cd src/stage-4 && dagger develop   # once

dagger -m ./src/stage-4 call run \
  --src ./testdata/go-app \
  --commit-sha local --branch main --repo-url https://example.com \
  --fail-on NONE
```

## Constraints

- Never publishes the built image — the `build` module has no publish function. Each consumer repo owns its own deployment.
- Returns `[]*dagger.File` — sbom evidence + image security evidence.
- In CI, `module-test` verifies `dagger develop` (compilation) succeeds;
  `scripts/smoke/stage-orchestrators.sh` runs `Run` against a fixture and
  asserts the sbom + image-security evidence traces are present in the
  output, and `composite-smoke-commit`'s container shape exercises it
  indirectly through `commit`.
- Pass the returned files to `cross-cutting/evidence.Wrap` to produce `combined-evidence.json`.
