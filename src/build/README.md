# build

See [build once and deploy the retained output](../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Builds OCI container images from Dockerfiles and generates CycloneDX SBOMs
with Trivy. This module never publishes images — each consumer repo owns its
own deployment.

## Install

```
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.2
```

## Usage

```bash
# Build an image
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.2 call build \
  --src=. --commit-sha=$SHA --branch=main --repo-url=$REPO_URL

# Generate SBOM from a built image
dagger -m github.com/context-and-oss/cicd/src/build@v5.1.2 call sbom \
  --image=<container> --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=sbom-evidence.json
```

## Functions

| Function | Description |
|----------|-------------|
| `build` | Build a container image from a Dockerfile |
| `sbom` | Generate a CycloneDX SBOM from a container image |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
