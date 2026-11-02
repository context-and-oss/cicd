# notify

Posts pipeline status notifications to Microsoft Teams, GitHub PRs, and Azure DevOps PRs.

## Install

```
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.2
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/notify@v5.1.2 call teams \
  --webhook-url=$TEAMS_WEBHOOK \
  --summary=combined-evidence.json \
  --pipeline-name=precommit
```

## Functions

| Function | Description |
|----------|-------------|
| `teams` | Post an Adaptive Card to a Teams channel, and return an evidence envelope saying whether it was delivered, skipped for want of a webhook, or lost |
| `github` | Post a summary comment on a GitHub PR |
| `ado` | Post a summary comment on an Azure DevOps PR |
| `build-card` | Build a Teams card JSON without posting (for testing) |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
