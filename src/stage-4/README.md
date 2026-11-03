# stage-4 — Commit

Chains `build` (OCI image + SBOM) and `security` (image secrets + vuln scan).
Use this module to run the full commit stage in one call.

Composes: [build](../build) + [security](../security)

## Install

```
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.1.3
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.1.3 call run \
  --src=. --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Build image + SBOM + image security scan — returns evidence files |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
