# Pre-commit Setup

How to configure Stage 2 pre-commit validation — both as a local developer workflow
and as the CI gate that runs on every push.

---

## Local developer workflow

The precommit composite runs quality, security, and risk checks in a single Dagger call.
Developers run this before pushing to catch issues while context is fresh.

**Prerequisites:** Docker Desktop running, Dagger CLI installed.

```bash
# First time — generate internal SDK
cd src/composites/precommit && dagger develop

# Run against your working directory
dagger -m ./src/composites/precommit call run \
  --src . \
  --fail-on HIGH \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path ./out/precommit-evidence
```

→ Full step-by-step instructions: **[Run the pipeline locally](../../../how-to-guides/run-pipeline-locally.md)**

---

## Git hook integration

The versioned local entrypoint is `./scripts/cicd-prepush`. Run it directly when
you want to reproduce the CI Dagger composite before pushing:

```bash
./scripts/cicd-prepush
```

To run it automatically on `git push`, opt into the checked-in hook path:

```bash
make install-hooks
```

That target verifies its own work: after setting `core.hooksPath` it asks git
whether it would actually run the hook, and fails if it would not. To ask the
same question at any time:

```bash
make check-hooks
```

`make lint`, `make test`, `make test-scripts` and `make prepush` print a one-line
warning when git would run no hook. They do not fail on it, and they do not
install it for you — silently rewriting a developer's git config as a side
effect of running the tests is worse than the problem.

### What the hook does and does not guarantee

The hook is **opt-in**, and a fresh clone starts locally ungated. The intended
server-side policy requires a pull request and the `ci` check on `main`, but
those effective requirements must be configured and verified in a destination.
Only once they are enforced does skipping the hook move discovery to the pull
request rather than permit an unchecked change into `main`. Copying the hook
or this guide establishes no branch protection.

A consumer repository is different. Copying the local runner (below) without an
equivalent required check makes the local hook the only gate there is, and one
developer who never ran the `git config` line is then ungated with nothing
saying so.

The hook is intentionally only an adapter: `.githooks/pre-push` calls
`./scripts/cicd-prepush`. To copy the same pattern into an application repo, copy
`templates/local/scripts/cicd-prepush` to `scripts/cicd-prepush` and
`templates/local/githooks/pre-push` to `.githooks/pre-push`, then run:

```bash
chmod +x scripts/cicd-prepush .githooks/pre-push
git config core.hooksPath .githooks
```

`chmod` is required on macOS / Linux. On Windows the file-mode bit is
irrelevant — Git Bash will execute the hook regardless — but running the
command from Git Bash is harmless, so the same snippet works everywhere.

By default the local runner blocks on `HIGH`: it reads `passed` from the run's
`combined-evidence.json` and exits non-zero when that verdict is false. The
composite itself never signals a gate trip through its exit status — it is a
producer, and the verdict lives only in the evidence — so this read is the whole
gate. For a non-blocking local pass, use:

```bash
CICD_PREPUSH_MODE=advisory ./scripts/cicd-prepush
```

Advisory reports the same findings and errors and exits `0` regardless.

`jq` is required, and the runner stops if it is missing rather than continuing
without the verdict check.

### Scoping the run to your languages

The runner auto-detects languages when `CICD_INCLUDE` is unset, which means a
repository holding vendored or deliberately broken code gets it audited. Scope
the run in your `.githooks/pre-push` adapter rather than in the runner, which is
meant to stay in sync with upstream:

```sh
CICD_INCLUDE=go,node
export CICD_INCLUDE
exec ./scripts/cicd-prepush
```

This repository's own hook does exactly that with `CICD_INCLUDE=go`, matching the
`--include go` that `.github/workflows/dogfood-precommit.yml` passes in CI.

You can bypass one local push with:

```bash
SKIP_CICD_PREPUSH=1 git push
```

The runner scopes the diff-driven gates to what your change touches — it derives
the diff from local Git state, so you never pass `--diff` by hand. Set
`CICD_DIFF_BASE=<ref>` to compare against a different base, or
`CICD_DIFF_BASE=none` to force a full-repo audit. See
[Run the pipeline locally](../../../how-to-guides/run-pipeline-locally.md#change-scoping)
for the full resolution rules.

The change-intent gate is opt-in and off by default; set `CICD_REQUIRE_INTENT=1`
to enforce it locally. Left off, the run says so and the evidence carries an
`intent-gate: NOT REQUIRED …` warning, so a clean run never reads as a gate that
passed.

> **Time budget:** The pre-commit stage targets 5–10 minutes. If it exceeds this,
> use advisory mode locally and rely on the CI gate at Stage 3.

---

## CI configuration

The `module-test` and `composite-smoke` jobs in `.github/workflows/ci.yml` run the
same commands automatically on every push and pull request targeting `main`.

The composite smoke job:
1. Calls `dagger develop` on `composites/precommit` to generate the internal SDK
2. Runs `composites/precommit call run` against `testdata/go-app`, `testdata/node-app`, and `testdata/dotnet-app`
3. Validates `combined-evidence.json` from each run

### Every CI caller has to gate for itself

The producer/verdict split described above for the local runner is not a local-runner
quirk — it is the composite's contract on every platform. Since v1.16.1 `run` exits
`0` on a tripped gate exactly as it does on a clean run, so a caller that checks only
the step's exit status scans the code and then reports green whatever it found.

Where that read currently happens:

| Caller | Reads `passed`? |
|--------|-----------------|
| `.github/workflows/precommit.yml` (reusable) | yes — annotates findings and `errors[]`, then exits 1 |
| `.github/workflows/dogfood-precommit.yml` | yes |
| `templates/local/scripts/cicd-prepush` | yes — and fails on a missing or unparseable evidence file too |
| `templates/azure-devops/precommit.yml` | yes — the `Gate on the evidence verdict` step |
| `templates/azure-devops/shared/precommit.yml` | yes — the same step |

Both Azure DevOps templates gate as shipped. The step is live, and
`scripts/check-ado-templates.py` refuses a commit or precommit template whose
verdict read is absent or commented out (only the DAST template may stay advisory,
and the allowance names why). If you copied either template while the step still
shipped commented out, your pipeline is advisory: paste the step in from the
current template.

Read the verdict defensively wherever you add it. A missing or unparseable
`combined-evidence.json` means the composite died before reaching a verdict, and no
verdict is not a pass: unguarded, `jq -r '.passed'` returns `null`, the comparison
against `"true"` is skipped by whatever shape the surrounding `if` took, and the gate
you just added reports success on a run that never finished.

---

## What the composite runs

| Module | What it checks |
|--------|---------------|
| `quality` | Lint (golangci-lint, ESLint, pylint, dotnet format), unit tests |
| `security` | SAST (Semgrep), secrets (Gitleaks), vulnerability scan (Trivy) |
| `risk` | OPA policy gate against committed `findings.json` + `decisions.json` |
| `cross-cutting/evidence` | Merges all evidence envelopes into `combined-evidence.json` |

---

## Related

- [Run the pipeline locally](../../../how-to-guides/run-pipeline-locally.md) — step-by-step local execution guide
- [Pre-commit Quality Gates](./precommit-gates.md) — why Stage 2 exists and what the time budget means
- [AI Risk Analysis](../security/risk-analysis.md) — how the risk module fits into pre-commit
