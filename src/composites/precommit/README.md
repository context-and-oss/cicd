# composites/precommit — Full Pre-commit Pipeline

Wires `stage-2` (quality, security, risk, plus the opt-in change-intent gate) with evidence aggregation, a rendered PR comment and optional Teams delivery. GitHub/ADO comment posting belongs to the caller.
This is the entry point for running the complete pre-commit pipeline in CI.

Composes: [stage-2](../../stage-2) + [cross-cutting/evidence](../../cross-cutting/evidence) + [notify](../../notify)


Default SAST fetches rules under the restrictive **Semgrep Rules License v1.0**, not Apache-2.0. Review the [runtime rule notice](../../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20); hosted/redistributed use needs suitable rights or suitably licensed consumer rules via `--sast-rulesets ./your-config.yml`.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/composites/precommit`
from a separate source checkout's root. Package-feed credentials are separate;
do not use a writer credential as a source-fetch fallback.

```
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.8
```

## Usage

Set `SHA` and `REPO_URL`; run with Dagger and `jq` from the source root:

```bash
set -eu
rm -rf ./audit-evidence
dagger -m github.com/context-and-oss/cicd/src/composites/precommit@v5.1.8 call run \
  --src=. --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./audit-evidence || exit 1
jq -e '.passed == true' ./audit-evidence/combined-evidence.json >/dev/null || exit 1
```

Optional Teams delivery uses `--teams-webhook=env:TEAMS_WEBHOOK`; omit it when
not configured. A pass is not proof of clean or full-scope analysis: retain
warnings, errors, suppressions, per-source outcomes and examined-scope metadata.

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

Every caller must clean stale output, fail if export fails, and read the fresh
verdict with `jq -e '.passed == true'`, as in the complete usage example above.

Read `passed` defensively. A missing or unparseable `combined-evidence.json`
means the composite died before it produced a verdict, and no verdict is not a
pass — treat both as failure rather than letting `jq` return `null` and the
comparison fall through to green.

Worked examples, in increasing order of thoroughness:

| Caller | Gate |
|--------|------|
| [`.github/workflows/precommit.yml`](../../../.github/workflows/precommit.yml) | writes pessimistic defaults first, reads `passed`, prints findings and `errors[]` as `::error::` annotations, exits 1 |
| [`templates/local/scripts/cicd-prepush`](../../../templates/local/scripts/cicd-prepush) | fails on a missing file, on unparseable JSON, and on `passed != true`; `CICD_PREPUSH_MODE=advisory` to opt out |
| [`templates/azure-devops/`](../../../templates/azure-devops) | a verdict step fails on missing/unparseable `combined-evidence.json` or `passed != true`; independently ensure output freshness on reused agents |

The ADO precommit starter does not explicitly clean its export destination;
retain the fresh-output cleanup in the complete recipe when adapting it,
especially on reused agents. Posting a comment is not a substitute for the
verdict gate or evidence upload.

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
