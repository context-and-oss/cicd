# quality

See [build once and deploy the retained output](../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Runs linting and unit tests on source code.
Supports Go, Node.js, Python, and .NET. Returns an evidence envelope.

## Install

```
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.3
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.3 call check \
  --src=. --include=go --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json
```

## Functions

| Function | Description |
|----------|-------------|
| `check` | Lint + unit test for all detected languages |
| `test` | Witnessed execution of consumer-supplied tests — `--test-cmd` (one command) or `--test-legs` (one leg per language), with coverage harvest and ratchet. A leg may declare `services` — dependency containers bound to its network, reachable by alias, with a service that never became usable recorded as a non-run. A detected language no leg witnesses is named in the evidence |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
