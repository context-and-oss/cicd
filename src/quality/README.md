# quality

See [build once and deploy the retained output](../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Runs linting and unit tests on source code.
Supports Go, Node.js, Python, and .NET. Returns an evidence envelope.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/quality` from a
separate source checkout's root. Source credentials are separate from package feeds.

```
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.7
```

## Usage

Set `SHA` and `REPO_URL`; run with Dagger and `jq` from the source root:

```bash
set -eu
rm -f ./evidence.json
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.7 call check \
  --src=. --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./evidence.json || exit 1
jq -e '.passed == true' ./evidence.json >/dev/null || exit 1
```

Evidence export alone does not enforce the verdict. Use the same fresh-output,
export-failure and JSON checks for **each** required `check`/`test` envelope.
A pass is not a claim of clean or full-scope analysis: retain warnings, errors,
non-runs and examined/test/coverage metadata. The coverage ratchet detects drops,
not an absolute minimum; missing inputs can skip it fail-open. Keep required
absolute thresholds in the consumer test command unless an equivalent gate is
configured and verified.

## Functions

| Function | Description |
|----------|-------------|
| `check` | Lint + unit test for all detected languages |
| `test` | Witnessed execution of consumer-supplied tests — `--test-cmd` (one command) or `--test-legs` (one leg per language), with coverage harvest and ratchet. A leg may declare `services` — dependency containers bound to its network, reachable by alias, with a service that never became usable recorded as a non-run. A detected language no leg witnesses is named in the evidence |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
