# build

See [build once and deploy the retained output](../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Builds OCI container images from Dockerfiles and generates CycloneDX SBOMs
with Trivy. This module never publishes images — each consumer repo owns its
own deployment.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/build` from a
separate source checkout's root. Source credentials are separate from package feeds.

```
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.7
```

## Usage

This is build inspection, not a CI evidence gate. Set `SHA` and `REPO_URL` first.

```bash
# Build an image
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.7 call build \
  --src=. --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL"
```

`build` returns a Dagger `Container`, not a published image coordinate or a
shell-ready `--image` value. In a caller-owned Dagger module, pass that object
directly to `Build().Sbom(...)` (SDK composition, not shell syntax).
[stage-4](../stage-4/README.md) wires build → SBOM + image scan and returns both
evidence files; aggregate them and enforce the fresh combined verdict, or use
[the commit composite](../composites/commit/README.md) for the full source and
artifact pipeline. Neither building nor exporting an envelope enforces a gate.

## Functions

| Function | Description |
|----------|-------------|
| `build` | Build a container image from a Dockerfile |
| `sbom` | Generate a CycloneDX SBOM from a container image |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
