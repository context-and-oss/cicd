# stage-2 — Pre-commit

Chains quality lint/tests (plus witnessed BYO tests when supplied), source
security, source/dependency licence policy, risk validation and opt-in intent.
Licence findings warn by default; intent gates only with `--require-intent`.
Returns a slice of evidence files, not an aggregated or enforced CI verdict.
Use [precommit](../composites/precommit/README.md#usage) for aggregation and a
complete caller-side gate example.

Composes: [quality](../quality) + [security](../security) + [risk](../risk) +
[intent](../cross-cutting/intent)

Default SAST rules are under the restrictive **Semgrep Rules License v1.0**, not
Apache-2.0. Review the [runtime rule notice](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20);
hosted/redistributed use needs suitable rights or suitably licensed consumer
rules through `--sast-rulesets ./your-config.yml`.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/stage-2` from a
separate source checkout's root. Source credentials are separate from package feeds.

```
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.2.0
```

## Usage

Inspection only, not a CI gate. Set `SHA` and `REPO_URL`. A caller-owned Dagger
pipeline must aggregate **all** returned required envelopes and enforce the
fresh combined verdict; checking only command success or one file is fail-open.
For the complete clean/export/`jq -e '.passed == true'` recipe, use precommit
linked above. Retain warnings, non-runs, suppressions and examined metadata.

```bash
dagger -m github.com/context-and-oss/cicd/src/stage-2@v5.2.0 call run \
  --src=. --include=go --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  --sast-rulesets=p/security-audit
```

## Functions

| Function | Description |
|----------|-------------|
| `run` | Quality + source security + licence policy + risk + opt-in intent — returns evidence files |

## Docs

→ Full documentation at [docs/](../../docs/index.md)
