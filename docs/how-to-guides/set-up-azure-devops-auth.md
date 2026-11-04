# Set up Azure DevOps authentication

This guide separates module-source access from **PR-comment delivery**. The
repository is currently private; remote module fetches require separately
authorized read access. Feed and comment tokens do not grant that access. See
[availability and source access](../../README.md#availability-and-source-access)
for the separate-checkout/local-`-m` path and conditional future anonymous use.
Never reuse writer credentials or copy them into an application repository.
Everything here is what
`templates/azure-devops/precommit.yml` and `commit.yml` reference today — this
page is the authoritative walkthrough those templates' inline comments point
back to.

One auth surface for PR comments, then the optional ones:

| Surface | Secret? | Buys you |
|---------|---------|----------|
| `System.AccessToken` + `ADO_ORG` | built-in / plain | PR comments on pre-commit builds |
| `TEAMS_WEBHOOK` | secret | Teams notifications |
| `NPM_FEED_*` / `NUGET_FEED_*` | token secret + plain URL | Private feed access during the vuln scan |

Set variables under **Pipelines → your pipeline → Edit → Variables**, or in a
**Library → Variable group** linked to the pipeline. "Secret" means click the
lock icon — its value is write-only afterward.

---

## 1. `System.AccessToken` + `ADO_ORG` — post PR comments

The pre-commit pipeline posts a PR comment with severity counts (via
`notify call ado`). This uses the build's built-in `System.AccessToken`, but it
is **off and unprivileged by default** — two things to enable:

1. **Allow the job to see the token.** Enable *"Allow scripts to access the
   OAuth token"* on the agent job (job settings in the classic editor, or it is
   granted when the step maps `SYSTEM_ACCESSTOKEN: $(System.AccessToken)` as the
   templates do). The template's *Post PR comment* step already maps it — you
   only need the job-level setting if your org disabled it.
2. **Let the token comment on PRs.** Grant the **build service account** the
   *Contribute to pull requests* permission on the repo:
   *Repo → Settings → Repositories → your repo → Security →*
   `<Project> Build Service (<Org>)` → set **Contribute to pull requests** to
   *Allow*. Without this, an attempted API call can return **403**.
   `notify ado` returns delivery errors, and neither precommit template swallows
   that command's failure: an attempted delivery error fails the step.

Also set a **plain** variable `ADO_ORG` to your organisation name (e.g.
`example-org`). The comment API call needs it to build the org URL.

Prerequisite skips are not delivery success: both templates skip an unset
`ADO_ORG`; the shared template also skips an absent token or missing evidence.
The copy-based template does not have those latter two guards. Inspect the step
log to distinguish a skip from an attempted call and its error.

For Azure Repos, configure required target-branch **Build validation** selecting
the precommit pipeline. YAML `pr:` alone does not create PR validation. Verify
an actual PR build and comment separately; a green branch build is not proof.

> The commit pipeline triggers on push to `main` (no PR context), so it does
> **not** post PR comments — this surface only matters for `precommit.yml`.

---

## 2. Optional: Teams notifications

Set a **secret** variable `TEAMS_WEBHOOK` to an incoming-webhook URL. When
present, the composite posts a build card; when absent, notification is
skipped silently. No other configuration.

---

## 3. Optional: private package feeds

If your dependency-vuln scan needs authenticated access to an internal npm or
NuGet feed, set the URL as a **plain** variable and the token as a **secret**:

| Variable | Kind |
|----------|------|
| `NPM_FEED_URL` | plain |
| `NPM_FEED_TOKEN` | **secret** |
| `NUGET_FEED_URL` | plain |
| `NUGET_FEED_TOKEN` | **secret** |

The ADO templates omit corresponding feed flags when the URL variable is unset.
Do not configure feed credentials unless your dependency restore needs them.
The shared transport helper also accepts an empty feed URL even when a Secret
object exists; an optional empty NuGet secret is not itself a reason to add
credentials. This says nothing about access to the cicd module repository.

---

## Secret vs plain — quick reference

| Variable | Kind |
|----------|------|
| `TEAMS_WEBHOOK` | **secret** |
| `NPM_FEED_TOKEN` / `NUGET_FEED_TOKEN` | **secret** |
| `ADO_ORG` | plain |
| `NPM_FEED_URL` / `NUGET_FEED_URL` | plain |
| `System.AccessToken` | built-in (enable OAuth access on the job) |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `failed to resolve module` / `not found` | Missing source authorization, unreachable GitHub, or unavailable ref | Verify authorized read-only source access and the pinned release separately from feed tokens |
| Comment skipped in logs | A prerequisite guard fired | Set `ADO_ORG`; in the shared template also expose the token and produce evidence |
| Attempted comment fails with 403 | Build service lacks PR permission | Grant *Contribute to pull requests* and verify delivery on a PR build |
| Attempted comment fails resolving token | Token not exposed | Map `System.AccessToken` and check job OAuth access |

## Out of scope

Self-hosted agent setup is not covered here. GitHub Actions PR comments use the
job's own `GITHUB_TOKEN`, subject to event permissions; that token does not imply
access to a separate private module or reusable-workflow repository.

## Related

- [Use the complete pipeline](use-complete-pipeline.md) — wiring the templates in
- [Use the pipeline without a Dockerfile](use-without-dockerfile.md) — archive shape detail
