# Set up Azure DevOps authentication

This guide takes an Azure DevOps consumer from zero to a green pipeline that
**posts PR comments**. The cicd modules themselves are fetched from the
public GitHub repository and need no credential. Everything here is what
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
   *Allow*. Without this, the comment API returns **403 and the step swallows
   it** — the build stays green and the comment simply never appears.

Also set a **plain** variable `ADO_ORG` to your organisation name (e.g.
`my-company`). The comment API call needs it to build the org URL.

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

The commit template omits the corresponding `--*-feed-url` flags entirely when
the URL variable is unset, so leaving these blank is safe.

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
| `failed to resolve module` / `not found` fetching the module | The agent cannot reach `github.com`, or the `@vX.Y.Z` ref names no published tag | Check the agent's outbound access and the pin against the cicd releases |
| PR comment never appears (build green) | *Allow scripts to access the OAuth token* not enabled on the job | Enable it on the agent job |
| PR comment never appears (build green) | Build service lacks *Contribute to pull requests* | Grant it on the repo Security settings |
| PR comment step errors on `ADO_ORG` | `ADO_ORG` unset | Add the plain variable |

## Out of scope

Self-hosted agent setup is not covered here. GitHub Actions needs no
equivalent of this page: PR comments there use the job's own `GITHUB_TOKEN`.

## Related

- [Use the complete pipeline](use-complete-pipeline.md) — wiring the templates in
- [Use the pipeline without a Dockerfile](use-without-dockerfile.md) — archive shape detail
