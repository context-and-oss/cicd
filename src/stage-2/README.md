# stage-2 — Pre-commit

Chains `quality` (lint + test), `security` (SAST + secrets + vuln scan), and
`risk` (OPA risk-review gate) against source code. Use this module to run the full
pre-commit stage in one call.

Composes: [quality](../quality) + [security](../security) + [risk](../risk)

## Install

```
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.1.3
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.1.3 call run \
  --src=. --include=go --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  --sast-rulesets=p/security-audit
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Quality + security source scan + risk validation — returns evidence files |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
