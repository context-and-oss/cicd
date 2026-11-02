# composites/commit — Full Commit Pipeline

See [build once and deploy the retained output](../../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Runs source checks plus the selected container, archive or source-only artifact path, aggregates evidence, and retains built payloads for consumer-owned deployment. Optional shared preparation avoids repeated compatible compilation.
This is the entry point for running the complete commit-stage pipeline in CI.

Composes: [stage-4](../../stage-4) + [cross-cutting/evidence](../../cross-cutting/evidence) + [notify](../../notify)

## Install

```
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.2
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.2 call run \
  --src=. --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  --pipeline-name=commit \
  --webhook-url=$TEAMS_WEBHOOK
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Source gate + artifact assessment + evidence + retained deployable + optional notification |

## Docs

→ Full documentation at [docs/](../../../docs/index.md)
