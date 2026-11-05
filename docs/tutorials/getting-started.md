# Getting started

`context-and-oss/cicd` is a set of reusable Dagger modules for continuous delivery.
You can use the complete pipelines, call one module at a time, or compose your
own flow from the same building blocks.

**Source access:** public modules can be fetched anonymously; private copies
require read-only access. Verify the referenced release and the hosting platform's
workflow/action access policy. See
[availability and source access](../../README.md#availability-and-source-access)
for separate source-checkout/local-`-m` use. Feed and notification tokens do not
grant module access. Default SAST rules have
[Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

## Why use it?

Use these modules when you want delivery checks that are portable across CI
systems and reproducible on a developer machine.

The modules give you:

| Need | What this repo provides |
|------|-------------------------|
| Consistent checks | The same Dagger module runs locally, in GitHub Actions, and in Azure DevOps |
| Evidence | Each domain module returns a JSON evidence envelope with provenance, findings, and pass/fail state |
| Selective adoption | You can adopt `quality`, `security`, `risk`, `build`, or `notify` independently |
| Composability | Stage and composite modules wire domain modules into pre-commit and commit pipelines |
| CI portability | Starter templates exist for GitHub Actions and Azure DevOps |

GitHub Actions and Azure DevOps are both first-class paths in these guides. The
module calls are the same in both systems; only auth, secrets, triggers, and
artifact publishing differ.

## How the pieces fit

| Layer | Modules | Use when |
|-------|---------|----------|
| Domain modules | `quality`, `security`, `risk`, `build`, `notify` | You want one capability |
| Stage modules | `stage-2`, `stage-4` | You want standard stage behavior without notification and audit wrapping |
| Composite modules | `composites/precommit`, `composites/commit` | You want a ready-to-run CI entry point |
| Cross-cutting modules | `cross-cutting/evidence`, `cross-cutting/report`, `cross-cutting/contract` | You are building a custom pipeline |

## Run your first check

Install Docker, the Dagger CLI and [jq](https://jqlang.org/), then run a source
security scan from the root of your application repository:

```bash
rm -f ./evidence-security.json &&
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.4 call scan-source \
  --src . \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-security.json &&
jq -e '.passed == true' ./evidence-security.json > /dev/null &&
echo "security scan passed"
```

The `dagger call` exits 0 whatever it found: it reports whether the call ran,
not what the scan concluded. The verdict is in the file, and the `jq -e` line is
what turns it into an exit code. The `&&` chain means a failed export can never
fall through to grading an old file. To see why a run did not pass:

```bash
jq '{passed, outcome, findingsBySeverity, errors, warnings, sources, examined, rules}' evidence-security.json
```

| Field | Meaning |
|-------|---------|
| `passed` | The verdict. `false` when a finding reaches `--fail-on`, and also when a scanner could not run, at every `--fail-on` level, `NONE` included |
| `outcome` | What happened: `CLEAN` (ran, found nothing), `FINDINGS` (ran, found something; `passed` says whether it trips the gate), `FAILED` (ran, and what it ran against failed, such as a test suite), `SKIPPED` (nothing to do, by choice), `ERROR` (could not produce a usable result) |
| `findingsBySeverity` | What was found, counted by severity |
| `errors` | Non-runs and other gate failures; read before trusting a zero |
| `warnings` | Partial parsing, timeouts, suppressions, omitted archives and other scope limitations can appear here without failing the verdict |
| `sources`, `examined`, `rules` | Per-producer status and available examination/rule metadata; inspect alongside native reports |

The full file also embeds each tool's native report, SARIF or CycloneDX, when the
tool produced one. `passed` is a gate decision, not proof of clean or full-scope
examination. Preserve existing coverage minima, blocking licence policies,
full-history secrets scans and live credential verification until equivalent
scope and enforcement are configured and verified.

To make a job fail on the verdict, gate on `passed` after the call, chained with
`&&` or in a script running under `set -e`. Check one file per `jq -e`: given
several files, it exits on the last one only.

```bash
jq -e '.passed == true' evidence-security.json > /dev/null
```

CI gates need that verdict check; explicitly labelled shadow/inspection examples
intentionally omit it. Without grading, evidence can report failure while blocking
nothing.

## Use it entirely

Use both composite pipelines:

- `composites/precommit` for pull requests and non-main branches. It runs
  quality checks, source security scanning, risk validation, evidence wrapping,
  and optional notification.
- `composites/commit` for the main branch. It runs the same source gate as
  pre-commit, then an `--artifact container|archive|none` tail — building and
  scanning an OCI image, an archive, or neither — wraps evidence, and
  optionally notifies. cicd never publishes the artifact; deployment stays in
  your repo.

Start here: [Use the complete pipeline](../how-to-guides/use-complete-pipeline.md).

## Use only some of it

Call a domain module directly when you want one capability:

```bash
rm -f ./evidence-quality.json &&
dagger -m github.com/context-and-oss/cicd/src/quality@v5.1.4 call check \
  --src . \
  --include go \
  --fail-on HIGH \
  --commit-sha "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --repo-url "https://github.com/your-org/your-repo" \
  export --path ./evidence-quality.json &&
jq -e '.passed == true' ./evidence-quality.json > /dev/null
```

Start here: [Use individual modules](../how-to-guides/use-individual-modules.md).

Both GitHub Actions and Azure DevOps examples are included in that guide.

## Build your own

Build your own Dagger module when your pipeline has repo-specific order,
approval, deployment, or reporting rules. Import the domain modules you need,
call them in your preferred order, and use `cross-cutting/evidence` when you want
one combined audit directory.

Start here: [Build your own pipeline](../how-to-guides/build-your-own-pipeline.md).

## Mix and match

Common combinations:

| Scenario | Modules |
|----------|---------|
| Fast PR gate | `quality` + `security scan-source` |
| Main branch image gate | `build` + `security scan-image` |
| Governance review | `risk scan` locally, `risk validate` in CI |
| Full PR experience | `composites/precommit` |
| Full main-branch artifact flow | `composites/commit` |

Start here: [Mix and match modules](../how-to-guides/mix-and-match-modules.md).
