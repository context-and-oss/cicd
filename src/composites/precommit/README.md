# composites/precommit — Full Pre-commit Pipeline

Wires `stage-2` (quality, security, risk, plus the opt-in change-intent gate) with evidence aggregation and Teams/GitHub/ADO notification.
This is the entry point for running the complete pre-commit pipeline in CI.

Composes: [stage-2](../../stage-2) + [cross-cutting/evidence](../../cross-cutting/evidence) + [notify](../../notify)


## Install

```
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.3
```

## Usage

```bash
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.3 call run \
  --src=. --include=go --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  --pipeline-name=precommit \
  --webhook-url=$TEAMS_WEBHOOK
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Full pre-commit: stage-2 (quality + security + risk, and intent with `--require-intent`) + evidence + notify |

## The verdict is the caller's job

`run` is a **producer, not a gate**. It exits `0` on a tripped gate exactly as it
does on a clean run: the verdict lives in `passed` inside
`combined-evidence.json`, and nowhere else. A caller that only checks the step's
exit status has a pipeline that scans and then goes green regardless — worse than
no scan, because it manufactures assurance.

So every caller has to read the verdict itself:

```bash
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.3 call run \
  ... export --path ./audit-evidence

passed=$(jq -r '.passed' ./audit-evidence/combined-evidence.json)
[ "$passed" = "true" ] || exit 1
```

Read `passed` defensively. A missing or unparseable `combined-evidence.json`
means the composite died before it produced a verdict, and no verdict is not a
pass — treat both as failure rather than letting `jq` return `null` and the
comparison fall through to green.

Worked examples, in increasing order of thoroughness:

| Caller | Gate |
|--------|------|
| [`.github/workflows/precommit.yml`](../../../.github/workflows/precommit.yml) | writes pessimistic defaults first, reads `passed`, prints findings and `errors[]` as `::error::` annotations, exits 1 |
| [`templates/local/scripts/cicd-prepush`](../../../templates/local/scripts/cicd-prepush) | fails on a missing file, on unparseable JSON, and on `passed != true`; `CICD_PREPUSH_MODE=advisory` to opt out |
| [`templates/azure-devops/`](../../../templates/azure-devops) | a gate step after the publish steps: fails on a missing or unparseable `combined-evidence.json` and on `passed != true` |

This split arrived in v1.16.1, when the composite stopped signalling a gate trip
through its exit status. It is deliberate — a producer that also aborts cannot
hand back the evidence explaining why — but it silently moved the gate into
every caller. The ADO templates picked it up later; a copy taken before that
has no gate step and needs the snippet above.

## Tuning SAST scope

`--sast-rulesets` (default `p/security-audit`; `auto` is refused by the security module) controls Semgrep. To cut false positives
on legacy/vendored/POC files, either curate the rulesets or point at your own config:

```bash
# comma-separated, NO spaces
--sast-rulesets p/security-audit,p/secrets,p/typescript
# or make your checked-in semgrep config the single source of truth
--sast-rulesets ./security.yml
```

To exclude specific files/paths, commit a `.semgrepignore` at your repo root — it is
honored automatically. See [src/security](../../security/CLAUDE.md) for the full rationale
and the empty-string footgun.

## Docs

→ Full documentation at [docs/](../../../docs/index.md)
