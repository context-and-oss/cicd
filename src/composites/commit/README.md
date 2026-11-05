# composites/commit — Full Commit Pipeline

See [build once and deploy the retained output](../../../docs/how-to-guides/build-once.md) for shared preparation, package caches, consumer limits and verified artifact handoff.

Runs source checks plus the selected container, archive or source-only artifact path, aggregates evidence, and retains built payloads for consumer-owned deployment. Optional shared preparation avoids repeated compatible compilation.
This is the entry point for running the complete commit-stage pipeline in CI.

In repository mode, composes [stage-2](../../stage-2) + a shape-specific [build](../../build)/[security](../../security) tail + [cross-cutting/evidence](../../cross-cutting/evidence) + [notify](../../notify). It does not call stage-4.
Application mode has a narrower [coverage and dependency-deferral contract](../../../docs/reference/commit-monorepo.md).

Default SAST fetches rules under the restrictive **Semgrep Rules License v1.0**, not Apache-2.0. Review the [runtime rule notice](../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20); hosted/redistributed use needs suitable rights or suitably licensed consumer rules via `--sast-rulesets ./your-config.yml`.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use a separate source checkout
and replace the remote `-m` value with its local module path. Package-feed
credentials are separate; do not use a writer credential as a source-fetch fallback.

```
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.5
```

## Usage

Run from your source root with `SHA` and `REPO_URL` set, Dagger and `jq` installed, and a Dockerfile for this container example:

```bash
set -eu
rm -rf ./commit-evidence
dagger -m github.com/context-and-oss/cicd/src/composites/commit@v5.1.5 call run \
  --src=. --artifact=container --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./commit-evidence || exit 1
jq -e '.passed == true' ./commit-evidence/combined-evidence.json >/dev/null || exit 1
```

`run` produces evidence; successful export does **not** enforce its verdict.
Missing/malformed evidence and `passed != true` must fail CI. A pass covers only
configured checks: retain `warnings`, `errors`, suppressions, `sources` and
examined-scope metadata, not just the boolean. Optional Teams delivery uses
`--teams-webhook=env:TEAMS_WEBHOOK`; no notification secret is required.

## Functions

| Function | Description |
|----------|-------------|
| `run` | Source gate + artifact assessment + evidence + retained deployable + optional notification |

## Docs

→ Full documentation at [docs/](../../../docs/index.md)
