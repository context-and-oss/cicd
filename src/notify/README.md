# notify

Posts pipeline status notifications to Microsoft Teams, GitHub PRs, and Azure DevOps PRs.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/notify` from a
separate source checkout's root. Source credentials are separate from notification secrets.

```
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.8
```

## Usage

For intentional live delivery only, set `TEAMS_WEBHOOK` in the environment;
for an offline preview use `build-card` instead.

```bash
set -eu
rm -f ./delivery-evidence.json
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.8 call teams \
  --webhook-url=env:TEAMS_WEBHOOK \
  --summary=combined-evidence.json \
  --pipeline-name=precommit \
  export --path=./delivery-evidence.json || exit 1
```

Consuming/exporting the result performs the lazy delivery. Inspect `outcome`
and `warnings`: `passed` remains true for delivered, skipped and lost delivery,
so it is not delivery proof and this example is not a scan gate.

`ado` differs from Teams: it returns an error on failed comment delivery rather
than a warned-pass envelope. The ADO precommit starter's comment command has no
`continueOnError`; a delivery error can fail that step even when the scan verdict
passed. Inspect the command outcome separately from scan evidence.

## Functions

| Function | Description |
|----------|-------------|
| `teams` | Post an Adaptive Card to a Teams channel, and return an evidence envelope saying whether it was delivered, skipped for want of a webhook, or lost |
| `github` | Post a summary comment on a GitHub PR |
| `ado` | Post a summary comment on an Azure DevOps PR |
| `build-card` | Build a Teams card JSON without posting (for testing) |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
