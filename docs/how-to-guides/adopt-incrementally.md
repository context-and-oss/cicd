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
3. **Outbound access to GitHub from the runner.** The cicd modules are fetched
   from the public repository; no credential is needed on either platform.
   Azure DevOps PR comments need the one-time setup in
   [set up ADO authentication](set-up-azure-devops-auth.md).

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
        uses: context-and-oss/cicd/.github/actions/install-dagger@v5.1.2
        with:
          version: 0.20.8
      - name: cicd security scan (shadow)
        run: |
          dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
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
      dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 call scan-source \
        --src . --fail-on HIGH \
        --commit-sha "$(Build.SourceVersion)" \
        --branch "$BUILD_SOURCEBRANCHNAME" \
        --repo-url "$(Build.Repository.Uri)" \
        export --path ./evidence-security.json
    displayName: cicd security scan (shadow)
```

Open `evidence-security.json` — pass/fail, findings by severity, embedded
SARIF. Compare against your existing step's output.

The shadow job does not gate on purpose: `dagger call` exits 0 whatever the
verdict, so a failing scan leaves your pipeline green while you compare. The
verdict is the envelope's `passed` field; `errors[]` names any scanner that
could not run, and a scanner that could not run never reads as passed, even
with `--fail-on NONE`.

## Step 3: Cut over — delete the replaced step

Once cicd's evidence matches (or beats) your old step, **remove the legacy
step** it replaces. For a coding agent, the concrete edit is:

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
of N jobs — [Use the complete pipeline](use-complete-pipeline.md). At that
point your hand-rolled pipeline is gone and the caller stub is all that remains.

## Order of operations (agent checklist)

1. Confirm the runner can reach GitHub (the modules are public; no secret).
2. Identify the legacy step to replace via the [step-mapping reference](../reference/step-mapping.md).
3. Add the cicd call **alongside** (Step 2) — never delete first.
4. Compare evidence output against the legacy step.
5. Delete the legacy step only after parity (Step 3).
6. Repeat for the next stage; collapse into the composite once most are covered.

## Related

- [Migration map](../explanation/migrating-to-cicd.md) — the conceptual before→after.
- [Step-mapping reference](../reference/step-mapping.md) — exhaustive per-step lookup.
- [Use the complete pipeline](use-complete-pipeline.md) — the end state.
- [Set up Azure DevOps authentication](set-up-azure-devops-auth.md).
