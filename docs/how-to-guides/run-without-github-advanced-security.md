# Run cicd without GitHub Advanced Security

Your repository is private, and you are deciding whether cicd's source gate can
stand in for GitHub's paid code-scanning and secret-scanning products (GitHub
Code Security and GitHub Secret Protection, sold together as Advanced
Security). This guide says what the reusable workflows do when those products
are off, what cicd covers in their place, and what nothing in cicd replaces.

Switching a product off is a decision for whoever administers the repository.
cicd does not make it and does not need it made: the same workflows run with
the products on or off.

## What the workflows do when Code Scanning is off

The `precommit`, `commit` and `dast` reusable workflows ask GitHub whether
Code Scanning is available before they upload `findings.sarif`:

| GitHub answers | The workflow |
|---|---|
| 200 or 404 (the API exists) | uploads the SARIF; a rejected upload fails the job |
| 403 (Code Scanning not enabled) | skips the upload with a `::notice::`; findings stay in the PR comment, the job summary and the evidence artifact |
| anything else | fails the job: a third answer is not a pass |

The gate itself does not change. `.passed` in `combined-evidence.json` comes
from the scans, not from the upload, so a repository without Code Scanning
fails over the same findings, at the same `fail-on` (default `HIGH`), as one
with it. `commit-monorepo` never uploads SARIF.

## What cicd covers

| GitHub feature | cicd | Equivalent? |
|---|---|---|
| CodeQL code scanning | `security.scan-source`: Opengrep over pinned rules (taint inside one function), the .NET SDK's Roslyn security analyzers on a C# or VB tree, zizmor on GitHub Actions workflows | **No.** Overlapping rules, a different engine. CodeQL follows data across the whole program in every language it supports |
| CodeQL's cross-function dataflow | [`security.scan-taint`](../../src/security/README.md#scan-taint): Opengrep's interfile analysis for Go, Java and JavaScript/TypeScript, advisory by default and wired into no composite | **Partly**, for those languages, to a stated call depth; not for C# |
| Secret scanning | Gitleaks on the working tree, and on history when the checkout carries `.git` | **Partly.** It gates the pipeline run; it does not block a push or watch every branch |
| Push protection | none | **No.** A secret cicd finds has already been pushed |
| Dependency review on a PR | `scan-source`'s Trivy dependency scan, a merge gate | **Yes**, as a gate; Dependabot alerts and security updates are not part of Advanced Security and stay on |
| The Security tab: alert history, dismissals, per-branch state | the evidence artifact (90-day retention), the PR comment, the job summary | **No.** Each run stands alone. A dismissal is an in-repo decision instead: `nosemgrep`, `--vuln-accept`, `.gitleaksignore`, each disclosed in the evidence |
| Inline annotations on the PR diff | the PR comment's findings table | **No** |
| Copilot Autofix | none | **No** |

Read "No" as a gap to accept or to fill another way, not as a defect to wait
for. The [step mapping](../reference/step-mapping.md#security) has the same
rows from the other direction.

## Decide per repository

1. **Public repository: keep CodeQL.** Code Scanning is free there, and
   cicd's upload lands beside CodeQL's under its own category (`cicd-precommit`,
   `cicd-commit`, `cicd-dast-<mode>`). Nothing to switch off.
2. **Private repository: run both first.** Wire cicd in with Advanced Security
   still on, as in [Adopt cicd incrementally](adopt-incrementally.md), and
   compare what each reports over the same commits before switching anything
   off.
3. **Decide Secret Protection apart from Code Security.** Push protection has
   no cicd equivalent at all, so its trade-off is not the same one.
4. **After the switch, read the notice.** The first run without Code Scanning
   logs the 403 notice above. A run that fails at the probe is a token or API
   problem, not a repository without Code Scanning.

Azure DevOps has no equivalent probe: the templates publish `findings.sarif`
as a pipeline artifact, and the optional SARIF Scans Tab extension renders it.
GitHub Advanced Security for Azure DevOps is a separate product and decision.
