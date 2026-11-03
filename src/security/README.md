# security

Runs SAST (Semgrep), secrets detection (Gitleaks/TruffleHog), vulnerability scanning (Trivy),
and dynamic analysis (OWASP ZAP) on source code, container images, or live web targets.
Returns an evidence envelope.

> **Licence of the default SAST rules.** `scan-source` fetches its default
> Semgrep rules (`p/security-audit`, and `p/owasp-top-ten` / `p/secrets` when
> named) from `semgrep/semgrep-rules` at a pinned commit at run time. Those rules
> are under the **Semgrep Rules License v1.0**, not cicd's Apache-2.0: internal
> business use only, no redistribution, not to be offered to others as a
> service. A hosted or redistributed use needs a suitable licence from Semgrep,
> or your own suitably licensed rules via `--sast-rulesets ./your-config.yml`,
> which replaces the pinned packs and still fails the gate if Semgrep could not
> scan. See [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

## Install

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3
```

## Functions

| Function | Description |
|----------|-------------|
| `scan-source` | SAST + secrets + filesystem vuln scan on source code |
| `scan-archive` | Source vuln scan + secrets scan of a built archive directory |
| `scan-image` | Secrets entropy + image vuln scan on a built container |
| `scan-sbom` | Rescan of an existing CycloneDX SBOM against today's vulnerability database |
| `scan-web` | Dynamic analysis (DAST) via OWASP ZAP against a live HTTP/S target |

## Usage

### scan-source

```bash
# Basic scan
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-source \
  --src=. --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json

# Scope to a subdirectory and exclude vendor/generated code
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-source \
  --src=. --path=src/api --exclude=vendor --exclude=generated \
  --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json
```

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `src` | Directory | required | Source directory to scan |
| `path` | string | `""` | Subdirectory to scope the scan to. Empty = whole `src`. |
| `exclude` | []string | `[]` | Directory names to remove before scanning |
| `sast-rulesets` | string | `"p/security-audit"` | Semgrep rulesets (`auto` is rejected — see CLAUDE.md). `p/security-audit` is pinned to a semgrep-rules commit; other registry packs are fetched live and reported as unpinned |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | Git commit SHA for evidence provenance |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |
| `nuget-feed-url` | string | `""` | Private NuGet feed index URL, used only by the lockfile-free .NET restore |
| `nuget-token` | Secret | none | Token for `nuget-feed-url`. Never written to the evidence envelope. |

#### Inline JavaScript and DOM text

The default `p/security-audit` and `p/owasp-top-ten` scans also analyse ordinary
inline JavaScript in selected UTF-8 `.html`/`.htm` files. No extra input is needed:
commit and precommit inherit it through their shared source gate. Findings point
to the original HTML, and extracted snippets do not inflate the file count.

These packs include cicd's own DOM-text-to-HTML rule. Prefer `textContent` for text
rather than assigning DOM text to `innerHTML`, `outerHTML` or
`insertAdjacentHTML`. Supported sanitizer models include numeric conversions and
imports of DOMPurify/isomorphic-dompurify. Hand-written escaping helpers may need
a reviewed rule-specific `nosemgrep` suppression; helper names alone are not proof
of sanitization. The emitted rule id is
`cicd-rules.cicd.javascript.dom-text-to-html`.

Data/import-map blocks and external-script bodies are not JavaScript targets.
Module and template script scopes remain independent; template scripts can run
when cloned and inserted. The evidence discloses partial/unsupported
markup and parser failures. Event-handler attributes, framework/server templates
and inter-module/inter-file flows are not covered by the adapter. Original
Semgrep ignore and file-size limits still apply. Custom/live rules are not
rewritten onto extracted files; a custom-only or secrets-only selection does not
gain the new default rule or inline pass.

#### .NET without a committed lockfile

Trivy resolves NuGet dependencies from `packages.lock.json`, `packages.config` or
a `*.deps.json` — never from a `.csproj`. A repository that commits none of those
would be reported as an unresolved ecosystem (`passed=false` at every threshold,
`--fail-on NONE` included), and the only remedy would be a change in your
repository.

So `scan-source` restores the graph itself, in a digest-pinned .NET SDK, and
scans that. This is **automatic** — there is no flag to enable and none to
disable — and it fires only when no resolvable input is present, so a repository
that already commits a lockfile is unaffected.

The successful run carries a warning, because a graph resolved at scan time is
not the graph a committed lockfile pins:

> …no packages.lock.json, packages.config or \*.deps.json is committed, so cicd
> restored the NuGet graph itself in mcr.microsoft.com/dotnet/sdk:8.0 … The graph
> was resolved now, not when this artifact is built: a project using a floating
> version range can build against package versions this scan never saw.

Committing a lockfile removes that gap and skips the restore:

```xml
<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
```

```bash
dotnet restore --use-lock-file   # then commit the generated packages.lock.json
```

If your packages come from a private feed, the restore needs to reach it:

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-source \
  --src=. --fail-on=HIGH \
  --nuget-feed-url=$NUGET_FEED_URL --nuget-token=env:NUGET_TOKEN \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json
```

A token passed with a non-HTTPS feed URL is refused before any container runs.

#### Repositories without dependencies

When the independent source-tree probe finds no supported dependency manifests
or lockfiles and Trivy consequently reports no scan targets, the dependency
vulnerability and source-SBOM concerns are reported as `SKIPPED` (not
applicable). They remain passing, but they do not claim that a dependency scan
or inventory ran. A resultless Trivy report remains an error when the tree does
declare a supported dependency ecosystem, and probe failures remain errors.

### scan-image

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-image \
  --image=<container> --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json
```

### scan-sbom

A vulnerability verdict is a frozen SBOM crossed with moving CVE knowledge, so
the verdict a release shipped with goes stale the day a new advisory lands.
`scan-sbom` takes the CycloneDX document a past run froze — cicd envelopes carry
it under `cyclonedxReport`, the commit audit directory ships it as
`sbom.cdx.json` — and rescans it with the same pinned Trivy the pipelines use,
returning a standard evidence envelope. This is the scheduled-rescan entry point
ADR-006 names for the mutable `vuln-current.json` beside a release's frozen
reports. It is wired into no composite; call it directly, on whatever schedule
your release process needs.

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-sbom \
  --sbom=sbom.cdx.json --fail-on=NONE \
  --commit-sha=$RELEASE_SHA --branch=main --repo-url=$REPO_URL \
  export --path=vuln-current.json
```

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `sbom` | File | required | CycloneDX SBOM document to rescan |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | The commit the SBOM was frozen at, so the envelope names the release it grades |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |

A file that is empty, not JSON, or not CycloneDX is refused before any scan
container runs: the rejection lands in `errors[]` and `passed=false` at every
threshold, `--fail-on NONE` included — a rescan that never read its SBOM must
never read as a rescan that found nothing.

### scan-web

Runs OWASP ZAP dynamic analysis against a live HTTP/S target. Use `--full=false` (default)
for a passive baseline scan safe for any environment. Use `--full=true` for an active full scan
that sends attack payloads — only run against environments you own and control.

```bash
# Passive baseline scan (safe for staging/production)
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-web \
  --target=https://staging.example.com \
  --full=false --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=web-evidence.json

# Active full scan (attack payloads — test environments only)
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.3 call scan-web \
  --target=https://test.example.com \
  --full=true --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=web-evidence.json
```

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | required | Full HTTP/S URL of the live target |
| `full` | bool | `false` | `false` = passive baseline; `true` = active full scan |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | Git commit SHA |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |

The evidence envelope includes the raw ZAP JSON report in `genericReport` with `genericFormat="zap-json"`.

## Docs

→ Full documentation at [docs/](../../docs/index.md)
