# Adopt cicd incrementally

Move an existing pipeline onto cicd **one stage at a time** — not a
rip-and-replace. cicd coexists with your legacy pipeline during the transition:
you hand it a single stage (say, the security scan), keep everything else, and
grow coverage from there.

This guide is written to be **agent-drivable**: a coding agent can read it and
perform the migration against your actual pipeline file. Each step names the
file to edit and the exact change to make.

> **Concepts first?** The [migration map](../explanation/migrating-to-cicd.md)
> explains the ownership model and before→after shape. The exhaustive per-step
> lookup is the [step-mapping reference](../reference/step-mapping.md). This
> page is the *doing*.

## Prerequisites

1. An existing GitHub Actions or Azure DevOps pipeline in the repo.
2. Docker + the Dagger CLI available on the runner (the templates install the
   CLI for you).
3. **Module-source access.** Public modules support anonymous fetching; private
   copies require read-only access. Verify the release and platform workflow/action
   access policy. See
   [availability and source access](../../README.md#availability-and-source-access)
   for the separate-checkout/local-`-m` path. Feed tokens do not grant source access.
   Azure DevOps PR comments need the separate setup in
   [set up ADO authentication](set-up-azure-devops-auth.md).
4. Review the runtime [Semgrep Rules License restrictions](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20)
   before executing SAST, including through composites.

## Which path fits my repo?

Decide before editing anything:

| If you… | Path | Start at |
|---------|------|----------|
| Want the whole gate and are on GitHub Actions / ADO | **Templates** | [Use the complete pipeline](use-complete-pipeline.md) — then skip to [Verify](#step-4-verify-and-widen) |
| Want to hand over **one stage at a time** and keep the rest | **Incremental** (this guide) | [Step 1](#step-1-pick-the-first-stage-to-hand-over) |
| Have a repo-specific order, approvals, or custom reporting | **Custom** | [Build your own pipeline](build-your-own-pipeline.md) |

## Step 1: Pick the first stage to hand over

Best first target is **source security scanning** — highest value, no artifact
dependency, drop-in. Confirm which of your steps it replaces using the
[step-mapping reference](../reference/step-mapping.md); typically a Semgrep,
CodeQL, gitleaks, or `npm audit` step.

## Step 2: Add the cicd call alongside your pipeline

Add one job that calls `security.scan-source` — **do not delete anything yet**.
Running both in parallel proves cicd finds what your existing step finds before
you cut over.

GitHub Actions — add to `.github/workflows/` (a new file or a new job).
Install Dagger, then call the module:

```yaml
  cicd-security:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - name: Install Dagger
        # Checksum-verified download, no `curl install.sh | sh`.
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.1.7
        with:
          version: 0.20.8
      - name: cicd security scan (shadow)
        run: |
          rm -f ./evidence-security.json
          dagger -m github.com/context-and-oss/cicd/src/security@v5.1.7 call scan-source \
            --src . --fail-on HIGH \
            --commit-sha "$GITHUB_SHA" \
            --branch "$GITHUB_REF_NAME" \
            --repo-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
            export --path ./evidence-security.json
```

Azure DevOps — add a step to your `azure-pipelines.yml`:

```yaml
  # Install Dagger first: copy the "Install Dagger CLI" step from
  # templates/azure-devops/commit.yml (checksum-verified, no sudo).
  - bash: |
      set -euo pipefail
      rm -f ./evidence-security.json
      dagger -m github.com/context-and-oss/cicd/src/security@v5.1.7 call scan-source \
        --src . --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./evidence-security.json
    displayName: cicd security scan (shadow)
```

Open `evidence-security.json` — pass/fail, findings by severity, embedded
SARIF. Compare against your existing step's output.

The shadow job deliberately does not grade the verdict: a successful export
can contain `passed: false`. Execution/export failures can still fail the job.
Read `errors[]`, `warnings[]` and per-source scope, examined and rule metadata
alongside `passed`; a passing threshold is not full coverage. `NONE` suppresses
findings, not scanner non-runs.

## Step 3: Cut over — delete the replaced step

Remove a legacy step only after its equivalent scope, policy and enforcement
are configured **and verified**. A source snapshot does not replace a history
secrets scan or live credential verification; a coverage ratchet does not replace
a minimum; licence warn mode does not replace a blocking policy. Preserve those
protections until parity is demonstrated. For the verified replacement:

> In `<your pipeline file>`, delete the `<Semgrep/CodeQL/gitleaks/npm-audit>`
> step, keep the `cicd-security` job from Step 2, and add a step after the
> scan that fails the job on the verdict:
> `jq -e '.passed == true' ./evidence-security.json > /dev/null`.

Without that last step cicd reports a failure and blocks nothing.

Now cicd owns source security; the rest of your pipeline is untouched.

## Step 4: Verify and widen

Repeat Steps 1–3 for the next stage, in rough value order:

1. **Source security** (`security.scan-source`) — done above.
2. **Quality** (`quality.check`, or `test-cmd` / `test-legs` to witness your
   own tests — `test-legs` for one command per language in a polyglot repo).
3. **Build + SBOM + image scan** (the `commit` stage, `artifact` shape per your
   repo — see [Which shape is my repo?](../explanation/migrating-to-cicd.md#which-shape-is-my-repo)).
4. **Notify** (`notify.github` / `notify.ado` PR comments; `notify.teams`).

When most stages are cicd-owned, collapse them into the composite caller
(`precommit.yml` + `commit.yml` from `templates/`) so you run one gate instead
of N jobs — [Use the complete pipeline](use-complete-pipeline.md). Retain
consumer-owned protections that the composites do not equivalently enforce.

## Order of operations (agent checklist)

1. Confirm authorized read access to the module source and platform sharing policy.
2. Identify the legacy step to replace via the [step-mapping reference](../reference/step-mapping.md).
3. Add the cicd call **alongside** (Step 2) — never delete first.
4. Compare evidence output against the legacy step.
5. Delete only the legacy protection whose scope, policy and enforcement have verified parity (Step 3).
6. Repeat for the next stage; collapse into the composite once most are covered.

## Related

- [Migration map](../explanation/migrating-to-cicd.md) — the conceptual before→after.
- [Step-mapping reference](../reference/step-mapping.md) — exhaustive per-step lookup.
- [Use the complete pipeline](use-complete-pipeline.md) — the end state.
- [Set up Azure DevOps authentication](set-up-azure-devops-auth.md).
