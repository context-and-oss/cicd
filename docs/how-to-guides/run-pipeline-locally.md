# Run the pipeline locally

This guide shows how to run the same checks that CI runs, on your own machine, before pushing.
Local execution gives you the same evidence envelopes and pass/fail decisions as the pipeline —
without waiting for a CI runner.

---

## Prerequisites

| Tool | Install | Verify |
|------|---------|--------|
| **Docker Desktop** | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) | `docker info` |
| **Dagger CLI** | `winget install Dagger.Dagger` (Windows) or `brew install dagger/tap/dagger` (macOS/Linux) | `dagger version` |
| **Go 1.26+** | [go.dev/dl](https://go.dev/dl/) | `go version` |
| **jq** | `brew install jq` (macOS) or your package manager | `jq --version` |

Docker Desktop must be running before any `dagger` command. `jq` is what
`./scripts/cicd-prepush` uses to read the run's verdict out of
`combined-evidence.json`; without it the runner stops rather than skipping the
check, because a gate that cannot read a verdict has not passed.

---

## First-time setup

Each Dagger module generates its own internal Go SDK. Run this once per module, and again
if you change `dagger.json`:

```bash
# Individual module
cd src/risk && dagger develop

# All modules at once
make develop-all
```

---

## Run the pre-push entrypoint

Use the checked-in runner when you want the same Dagger composite that CI uses,
with local Git metadata filled in for you:

```bash
./scripts/cicd-prepush
```

The runner writes evidence to `./out/prepush-evidence` and defaults to a blocking
`HIGH` gate. It reads `passed` from `combined-evidence.json` and exits non-zero
when the verdict is false, printing the findings and the errors behind it.

The errors matter as much as the findings: a step that *could not run* leaves no
finding at all, so a gate that trips with zero findings is only explainable by
the error list.

To collect evidence without blocking, run advisory mode:

```bash
CICD_PREPUSH_MODE=advisory ./scripts/cicd-prepush
```

Advisory prints the same verdict and the same lists, and always exits `0`.

To opt into the hook in this repo:

```bash
make install-hooks
```

To check whether it took — `core.hooksPath` is per-clone local config, so a
fresh clone starts ungated and nothing about a successful push tells you which
it was:

```bash
make check-hooks
```

That sets `core.hooksPath` to `.githooks`, whose `pre-push` hook simply calls
`./scripts/cicd-prepush`. You can bypass one local push with:

```bash
SKIP_CICD_PREPUSH=1 git push
```

### The change-intent gate is opt-in

The runner does not require a change-intent artifact unless you ask it to:

```bash
CICD_REQUIRE_INTENT=1 ./scripts/cicd-prepush
```

That gate asks whether your change carries an artifact saying *why* it exists (a
spec, a capsule, a `*.intent.md`, a `.changes/` entry) and whether that artifact
is coupled to the files you touched. It gates a team practice rather than the
code, so it is off by default — turn it on when your team writes these and wants
them enforced locally before the PR does it.

Off is never silent. Every run prints which state it is in, and the evidence
carries `intent-gate: NOT REQUIRED …` among its warnings when the gate was not
asked, so a clean local run never implies the gate passed. Note the flag only
exists from the release that introduced it: an older pinned composite rejects it
loudly rather than dropping it.

### Change scoping

The runner scopes the diff-driven gates — the risk infra scan, and the intent
gate when you turn it on — to what your change touches, so you see "is *my*
change clean?" rather than the whole repo's backlog. It figures the diff out for
you — you never pass `--diff` by hand:

- **Branch with commits** — scopes to `base...HEAD` (what you are about to push).
- **Uncommitted work, no commits yet** — falls back to the working-tree diff, so
  validating before you commit still runs scoped.
- **Clean tree on the default branch** — no diff, so the gates audit everything
  (on the default branch you want the full picture).
- **No remote / shallow clone / base unresolved** — no diff, full audit; the run
  prints `Change scope: full audit (no diff base resolved)` so it is never silent.

The base is auto-detected (`origin/HEAD`, then `origin/main`, then `main`).
Override it, or force a full audit, with one env var:

```bash
CICD_DIFF_BASE=origin/develop ./scripts/cicd-prepush   # diff against a different base
CICD_DIFF_BASE=none ./scripts/cicd-prepush             # force a full-repo audit
```

For application repositories, copy the local templates and then opt in manually:

```bash
mkdir -p scripts .githooks
cp templates/local/scripts/cicd-prepush scripts/cicd-prepush
cp templates/local/githooks/pre-push .githooks/pre-push
chmod +x scripts/cicd-prepush .githooks/pre-push
git config core.hooksPath .githooks
```

When copied into an application repo, the runner calls the released remote
`composites/precommit` module unless `CICD_PRECOMMIT_MODULE` overrides it.

---

## Run individual modules

These commands match exactly what the `module-test` CI job runs.
Run them from the **repo root**.

```bash
SHA="local"
BRANCH="main"
REPO="https://example.com"

# Code quality — lint + unit tests
dagger -m ./src/quality call check \
  --src ./testdata/go-app \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-quality.json

# Security — SAST, secrets, vulnerability scan
dagger -m ./src/security call scan-source \
  --src ./testdata/go-app --fail-on NONE \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-security.json

# Risk — OPA policy gate (reads committed findings.json/decisions.json)
dagger -m ./src/risk call validate \
  --source ./testdata/go-app --fail-on NONE \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO" \
  export --path /tmp/evidence-risk.json

# Build — OCI image build
dagger -m ./src/build call build \
  --src ./testdata/go-app \
  --commit-sha "$SHA" --branch "$BRANCH" --repo-url "$REPO"
```

Use `--fail-on NONE` during exploration — findings will not fail the gate, so you can
inspect output without being blocked. Switch to `--fail-on HIGH` to replicate the CI gate.

`NONE` covers findings only. A step that could not run — a linter whose config the
consumer's repo does not satisfy, a scanner that could not reach its database, a
test project that produced no results — still reports `passed: false` at `NONE`,
with the cause in `errors[]`. That is deliberate: the threshold a team sets while
onboarding is exactly when nobody yet knows what a working run looks like, so it
must not be the setting that hides a tool examining nothing.

---

## Run the full pre-commit pipeline

The `composites/precommit` module wires quality + security + risk + evidence aggregation
into a single call. This is what Stage 2 runs in CI.

```bash
cd src/composites/precommit && dagger develop   # once

dagger -m ./src/composites/precommit call run \
  --src ./testdata/go-app \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/smoke-evidence
```

Inspect the combined output:

```bash
cat ./out/smoke-evidence/combined-evidence.json | python3 -m json.tool | head -30
```

The exported directory contains:
- `combined-evidence.json` — merged pass/fail envelope across all modules
- `findings.sarif` — concatenated SARIF from security, quality, and infrastructure-policy scanners
- `sbom.cdx.json` — merged CycloneDX bill of materials

---

## Run against different language fixtures

The `testdata/` directory has fixtures for all supported languages:

```bash
# Node.js
dagger -m ./src/composites/precommit call run \
  --src ./testdata/node-app --include node \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/smoke-node

# Python
dagger -m ./src/composites/precommit call run \
  --src ./testdata/python-app --include python \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/smoke-python

# .NET
dagger -m ./src/composites/precommit call run \
  --src ./testdata/dotnet-app --include dotnet \
  --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/smoke-dotnet
```

---

## AI risk scan (risk module only)

`validate` reads existing findings. `scan` generates them — it requires an LLM connection.

**Option A — Claude API key (simplest)**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

dagger -m ./src/risk call scan \
  --source . \
  export --path .
# Writes findings.json and decisions.json to the repo root
```

**Option B — Claude CLI subscription (no API key)**

```bash
# Export and start the proxy once
dagger -m ./src/risk call proxy export --path ./claude-proxy.js
npm install -g @anthropic-ai/claude-code                 # once
export CICD_RISK_PROXY_TOKEN="$(openssl rand -hex 32)"   # the proxy refuses to start without it
node claude-proxy.js                                     # leave running in a separate terminal

# Run the scan from a shell with the same CICD_RISK_PROXY_TOKEN
dagger -m ./src/risk call scan \
  --source . --use-claude-cli \
  --llm-token env:CICD_RISK_PROXY_TOKEN \
  export --path .
```

The token reaches Dagger as a secret and the proxy only as a bearer header; the
proxy refuses any request without it, and runs the CLI with its tools and
session persistence switched off. What it refuses, and which files a scan sends,
is in the [risk module README](../../src/risk/README.md#what-the-scan-sends-to-the-model).
Scan a checkout or a `git archive` export: a `git worktree` is refused, because
its ignore rules live in metadata Dagger does not mount.

> **Linux note:** The proxy listens on `localhost:4000`, but Dagger containers use
> `host.docker.internal` (Docker Desktop only). On Linux, pass
> `--llm-url http://localhost:4000 --llm-token env:CICD_RISK_PROXY_TOKEN`
> instead of `--use-claude-cli`.

After scanning, review `decisions.json` and then validate:

```bash
dagger -m ./src/risk call validate \
  --source . --fail-on HIGH \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/evidence-risk.json
```

---

## Run unit tests (no Dagger required)

Internal packages and module pure helpers are tested with plain `go test`:

```bash
# Internal shared packages
cd src/internal && go test ./...

# Every module's pure helpers, in one command — the canonical runner. Walks
# the defended inventory, runs each module's complete -tags unit_test suite,
# and fails if a module with test files executes zero tests.
make test-module-units
```

To iterate on a single module, run its suite directly. `GOWORK=off` is
required: each Dagger module has its own `go.mod` and the repo-root `go.work`
deliberately lists only `src/internal`, so without it Go resolves the wrong
workspace and refuses before compiling.

```bash
# risk module pure helpers (parsing, scoring, rendering)
cd src/risk && GOWORK=off go test -tags unit_test ./...
```

---

## Inspect available functions

List every callable function in a module without running anything:

```bash
dagger functions -m ./risk
dagger functions -m ./quality
dagger functions -m ./composites/precommit
```

---

## Related

- [Pre-commit Quality Gates](../explanation/continuous-delivery/quality-gates/precommit-gates.md) — why Stage 2 exists
- [AI Risk Analysis](../explanation/continuous-delivery/security/risk-analysis.md) — how the risk module works
- [risk module README](../../src/risk/README.md) — risk-specific usage
- [security module README](../../src/security/README.md) — security-specific usage
