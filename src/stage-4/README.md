# stage-4 — Container artifact tail

Chains `build` (OCI image + SBOM) and `security` (image secrets + vuln scan).
This is **not** the full commit stage: source quality, SAST, source secrets,
dependency licence policy, risk, aggregation and caller-side enforcement are
not included. Use [composites/commit](../composites/commit/README.md#usage)
for the full source-plus-artifact pipeline and an export-and-gate recipe.
Commit wires its artifact tail directly; it does not call stage-4.

Composes: [build](../build) + [security](../security)

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/stage-4` from a
separate source checkout's root.

```
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.1.7
```

## Usage

Inspection only, not a CI gate. Set `SHA` and `REPO_URL`, and supply a source
root with a Dockerfile. The return is a slice of **both** SBOM and image-security
evidence files. A caller-owned Dagger pipeline must aggregate both, clean stale
output, fail on export failure and enforce the fresh combined verdict with
`jq -e '.passed == true'`; the commit recipe linked above includes those steps.
A pass does not imply full scope or clean results: keep warnings, non-runs,
suppressions and examined metadata.

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-4@v5.1.7 call run \
  --src=. --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Build image + SBOM + image security scan — returns evidence files |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
