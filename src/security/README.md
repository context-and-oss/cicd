# security

Runs SAST (Opengrep, reading Semgrep-format rules), secrets detection (Gitleaks/TruffleHog), vulnerability scanning (Trivy),
and dynamic analysis (OWASP ZAP) on source code, container images, or live web targets.
Returns an evidence envelope.

> **Licence of the default SAST rules.** `scan-source` fetches its default
> Semgrep rules (`p/security-audit`, and `p/owasp-top-ten` / `p/secrets` when
> named) from `semgrep/semgrep-rules` at a pinned commit at run time. Those rules
> are under the **Semgrep Rules License v1.0**, not cicd's Apache-2.0: internal
> business use only, no redistribution, not to be offered to others as a
> service. A hosted or redistributed use needs a suitable licence from Semgrep,
> or your own suitably licensed rules via `--sast-rulesets ./your-config.yml`,
> which replaces the pinned packs and still fails the gate if the engine could
> not scan. See [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).

> **The SAST engine is Opengrep.** It replaced Semgrep OSS, which rejected
> C# 12 primary constructors and C# 14 null-conditional assignment and skipped
> `record` declarations without saying so. Opengrep (LGPL-2.1) is downloaded
> unmodified from its release page at run time and verified against a pinned
> sha256 before it runs. When upgrading, note:
>
> - the SAST tool row and message prefixes say `opengrep`, not `semgrep` — a
>   filter or query keyed on the old name matches nothing;
> - a C# tree can gain two true positives Semgrep OSS could not find (ECB mode,
>   MEDIUM; a key from a non-cryptographic RNG, HIGH), so a scan green at the
>   default `--fail-on HIGH` can go red over code that was always vulnerable;
> - a file with an unbalanced brace now yields nothing and is reported as
>   partly read, and intrafile taint through long loop-carried chains is
>   bounded without notice.
>
> Details: [specs/swap-semgrep-for-opengrep.md](../../specs/swap-semgrep-for-opengrep.md).

> **A .NET tree gets a second SAST engine.** When the tree holds a C#, VB or
> F# project, `scan-source` (including `--code-only`) builds each C#/VB project
> in the pinned .NET SDK with its bundled security analyzers switched on. The
> result is a separate `roslyn-analyzers` row and SARIF run, which can see
> across method calls in a way a pattern rule cannot. When upgrading, note:
>
> - **the scan now runs `dotnet build`**, so it executes your MSBuild logic and
>   costs a restore and a compile per project;
> - **cicd sets the severity by rule id.** Injection dataflow (CA3001–CA3012),
>   insecure deserializers and disabled certificate validation are HIGH, and
>   every other security rule is MEDIUM. Your `.editorconfig` cannot downgrade
>   a finding;
> - **switching a security rule off is disclosed as `NARROWED RULES`**, and a
>   `#pragma` or `[SuppressMessage]` is disclosed as a suppression;
> - **legacy (non-SDK), MAUI and workload-only projects are not built.** They
>   are counted and named, never silently skipped;
> - **`.semgrepignore` does not scope this leg.** For a directory of
>   intentionally vulnerable samples, switch the `Security` category off in
>   that directory's `.editorconfig`.
>
> Details: [specs/analyse-dotnet-with-roslyn.md](../../specs/analyse-dotnet-with-roslyn.md).

> **GitHub Actions workflows get their own auditor.** When the tree holds
> workflows, composite actions or a Dependabot file, `scan-source` (including
> `--code-only`) runs [zizmor](https://github.com/zizmorcore/zizmor) offline
> over them. The result is a separate `zizmor` row and SARIF run. When
> upgrading, note:
>
> - **template injection, `pull_request_target` misuse and similar audits gate
>   at HIGH**, so a workflow green until now can go red;
> - **`unpinned-uses` is MEDIUM, not zizmor's High**, so actions referenced by
>   tag do not fail the default gate;
> - **a `# zizmor: ignore[...]` comment or a `zizmor.yml` is disclosed**: what
>   it removed is listed in a warning and kept as an accepted suppression;
> - **a workflow zizmor cannot parse is named as not audited**, and the
>   offline-only audits it skipped are named as `NARROWED AUDITS`;
> - **`.semgrepignore` does not scope this leg.** Use `exclude`, a
>   `zizmor.yml`, or an ignore comment with its reason.
>
> Details: [specs/audit-github-actions-with-zizmor.md](../../specs/audit-github-actions-with-zizmor.md).

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/security` from a
separate source checkout's root. Source credentials are separate from package feeds.

```bash
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8
```

## Functions

| Function | Description |
|----------|-------------|
| `scan-source` | SAST + secrets + filesystem vuln scan on source code |
| `scan-licenses` | Source/dependency licence declarations and configured policy; findings warn by default |
| `scan-taint` | Cross-function and cross-file taint (Opengrep interfile) beyond what `scan-source` finds; advisory by default |
| `scan-archive` | Source vuln scan + secrets scan of a built archive directory |
| `scan-image` | Secrets entropy + image vuln scan on a built container |
| `scan-sbom` | Rescan of an existing CycloneDX SBOM against today's vulnerability database |
| `scan-web` | Dynamic analysis (DAST) via OWASP ZAP against a live HTTP/S target |

## Usage

Evidence producers do not make a CI gate merely by exporting successfully.
The basic source and licence examples below enforce a fresh verdict. Other
examples are **inspection recipes, not CI gates**; to enforce any of them,
remove its stale output first, fail on export failure, and run
`jq -e '.passed == true'` on **each** required fresh envelope. Missing or
malformed JSON must fail. Keep warnings, errors, suppressions, examined counts
and per-source outcomes: `passed` is not a claim of clean or full-scope analysis.

### scan-source

```bash
# Basic CI gate; set SHA and REPO_URL first, with Dagger and jq installed
set -eu
rm -f ./evidence.json
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-source \
  --src=. --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./evidence.json || exit 1
jq -e '.passed == true' ./evidence.json >/dev/null || exit 1
```

Alternative scoped inspection only; not equivalent to whole-repository coverage:

```bash
# Inspect the declared subdirectory and exclusions
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-source \
  --src=. --path=src/api --exclude=vendor --exclude=generated \
  --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=scoped-inspection.json
```

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `src` | Directory | required | Source directory to scan |
| `path` | string | `""` | Subdirectory to scope the scan to. Empty = whole `src`. |
| `exclude` | []string | `[]` | Directory names to remove before scanning |
| `sast-rulesets` | string | `"p/security-audit"` | Semgrep-format rulesets (`auto` is rejected — see CLAUDE.md). `p/security-audit`, `p/owasp-top-ten` and `p/secrets` use pinned manifests from a semgrep-rules commit; other registry packs are fetched live and reported as unpinned |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | Git commit SHA for evidence provenance |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |
| `nuget-feed-url` | string | `""` | Private NuGet feed index URL, used only by the lockfile-free .NET restore |
| `nuget-token` | Secret | none | Token for `nuget-feed-url`. Never written to the evidence envelope. |

#### Finding classification metadata

Evidence schema 1.7 adds optional per-finding `concern`, `category`,
`subcategories`, `confidence`, `weaknessIds` and `classificationSource`.
For SAST, cicd projects an allowlisted subset of the **same invocation's**
native rule metadata into SARIF result properties; the evidence aggregator
carries it into `combined-evidence.json.findings`. Both ordinary and inline
JavaScript scans use this path, including custom rules and compatibility reruns.

- `concern: sast` declares the scan that produced the match. A custom style
  rule can therefore have concern `sast` and category `style`: concern is not
  proof of security relevance.
- Known categories are `security`, `correctness`, `maintainability`, `style`
  and `unknown`. Missing or unsupported metadata leaves the field absent
  (unknown); category is never guessed from rule names or severity.
- `subcategories` preserves the scanner's `audit`/`vuln` labels where supplied.
  Neither label confirms that a particular occurrence is exploitable.
- `confidence` is the rule's HIGH/MEDIUM/LOW value, when supplied. It is
  independent of severity. SARIF `precision: very-high` is not used.
- `weaknessIds` contains normalized CWE identifiers, without arbitrary prose.
  `classificationSource: scanner-metadata` describes their origin, not an
  independent verification. Unclassified findings remain present.

No review decisions are invented, no findings are filtered, and severity,
suppressions, counts and `fail-on` behaviour remain unchanged. Optional metadata
that cannot be read leaves classification unknown rather than failing a scan.
Other scanners and older evidence can omit these fields; absence is never clean.
The native JSON is not exported as a new payload, and matched source remains
subject to the existing SARIF redaction.

#### Inline JavaScript and DOM text

The default `p/security-audit` and `p/owasp-top-ten` scans also analyse ordinary
inline JavaScript in selected UTF-8 `.html`/`.htm` files. No extra input is needed:
commit and precommit inherit it through their shared source gate. Findings point
to the original HTML, and extracted snippets do not inflate the file count.

These packs include cicd's own DOM-text-to-HTML rule. Prefer `textContent` for text
rather than assigning DOM text to `innerHTML`, `outerHTML` or
`insertAdjacentHTML`. Supported sanitizer models include numeric conversions and
imports of DOMPurify/isomorphic-dompurify. Hand-written escaping helpers may need
a reviewed rule-specific `nosemgrep` (or `noopengrep`) suppression; helper names alone are not proof
of sanitization. The emitted rule id is
`cicd-rules.cicd.javascript.dom-text-to-html`.

Data/import-map blocks and external-script bodies are not JavaScript targets.
Module and template script scopes remain independent; template scripts can run
when cloned and inserted. The evidence discloses partial/unsupported
markup and parser failures. Event-handler attributes, framework/server templates
and inter-module/inter-file flows are not covered by the adapter. Original
`.semgrepignore` and file-size limits still apply. Custom/live rules are not
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
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-source \
  --src=. --fail-on=HIGH \
  --nuget-feed-url=$NUGET_FEED_URL --nuget-token=env:NUGET_TOKEN \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=evidence.json
```

A token with an explicit non-HTTPS feed URL is refused before containers run,
except HTTP to loopback for local protocol tests. An empty feed URL does not
require adding a credential; omit optional feed settings when not needed.

#### Repositories without dependencies

When the independent source-tree probe finds no supported dependency manifests
or lockfiles and Trivy consequently reports no scan targets, the dependency
vulnerability and source-SBOM concerns are reported as `SKIPPED` (not
applicable). They remain passing, but they do not claim that a dependency scan
or inventory ran. A resultless Trivy report remains an error when the tree does
declare a supported dependency ecosystem, and probe failures remain errors.

### scan-licenses

Default `--license-gate warn` does not block licence findings. To enforce the
chosen policy in repository mode (set provenance variables first):

```bash
set -eu
rm -f ./license-evidence.json
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-licenses \
  --src=. --license-gate=gate --license-allow=permissive \
  --license-allow=notice --license-allow=unencumbered --fail-on=LOW \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./license-evidence.json || exit 1
jq -e '.passed == true' ./license-evidence.json >/dev/null || exit 1
```

`LOW` blocks every out-of-policy licence finding; a higher severity threshold
can leave lower-severity policy violations non-blocking even in gate mode.
These categories are an example policy, not legal clearance. Review the
allowlist for your use and retain existing controls until equivalent assessed
scope and enforcement are configured and verified. Inspect dependency-coverage,
SKIPPED/not-read and exclusion disclosures; a pass does not mean every dependency
licence was read. [Application mode](../../docs/reference/commit-monorepo.md)
checks source declarations only and defers dependency licence assessment.

### scan-taint

`scan-source` follows untrusted input inside one function. `scan-taint` runs
Opengrep's interfile analysis over the pinned audit and OWASP rules whose
authors marked them interfile (Go, Java, JavaScript and TypeScript; no C# rule
is), so a request parameter handed to a helper in another file and
concatenated into SQL there is found. It runs the same rules twice, with and
without interfile analysis, and reports only what the second run adds:
`scan-source` already reports the rest, and the aggregate would count it twice.

It is a separate step, not part of `scan-source`, because of its cost: on a
mid-sized Go repository the interfile run took over ten times as long and more
than twice the memory, and on a very large tree it was killed for memory. Call
it where that cost fits, a nightly or a release branch, before making it a
merge gate.

```bash
# Advisory (default): findings are reported, the step passes unless a run failed
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-taint \
  --src=. \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./taint-evidence.json || exit 1
jq -e '.passed == true' ./taint-evidence.json >/dev/null || exit 1
```

`--taint-gate=gate` enforces `--fail-on` (default `HIGH`). Warn mode passes
over findings, never over a run that did not complete: an engine that was
killed, a rule set below its floor, or a baseline run that failed (without it,
the findings `scan-source` also makes cannot be told apart) is an error at
every setting. A chain of calls longer than `--interfile-depth` (default 3) is
not followed, and the evidence names each rule that stopped there as
`DEPTH CAPPED`; `--interfile-depth=-1` removes the limit, at a cost in time and
memory. A rule that ran out of time over the whole program is named as a
`PARTIAL SCAN`. Details:
[specs/report-cross-file-taint-as-advice.md](../../specs/report-cross-file-taint-as-advice.md).

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `src` | Directory | required | Source directory to scan |
| `path` | string | `""` | Subdirectory to scope the scan to. Empty = whole `src`. |
| `exclude` | []string | `[]` | Directory names to remove before scanning |
| `taint-gate` | string | `"warn"` | `warn` reports findings without failing over them; `gate` enforces `fail-on`. There is no `off`: not calling the step is off |
| `interfile-depth` | int | `3` | Calls followed from a source toward a sink; `-1` for no limit (write it `--interfile-depth=-1`) |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails in gate mode: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | Git commit SHA for evidence provenance |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |

### scan-image

`--image` accepts a Dagger `Container`, not a literal `<container>` shell token.
In a caller-owned Dagger module, pass the `Container` returned by `Build().Build`
directly to `Security().ScanImage(...)` (SDK composition, not executable shell).
[stage-4](../stage-4/README.md) supplies that wiring for a container artifact
tail; [commit](../composites/commit/README.md) adds source checks, aggregation
and a complete caller-side gate example. Image scanning is not a replacement
for source/history secrets scanning or provider/platform protections.

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
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-sbom \
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

Runs OWASP ZAP against exactly one of `--target`, `--service` or `--container`.
Use `--mode baseline` (default), `api` (document-driven) or `full` (active).
Every mode requires an explicitly authorized target and appropriate traffic limits;
even a passive baseline generates requests and is not safe for every environment.
API/full modes send attack traffic. See the [complete DAST reference](../../docs/reference/dast.md)
for target lifecycle, API inputs and scope disclosures.

```bash
# Passive baseline inspection (authorized target only)
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-web \
  --target=https://staging.example.com \
  --mode=baseline --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=web-evidence.json

# Active full scan (attack payloads — test environments only)
dagger -m github.com/context-and-oss/cicd/src/security@v5.1.8 call scan-web \
  --target=https://test.example.com \
  --mode=full --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=web-evidence.json
```

**Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | none | HTTP/S URL; exactly one of target/service/container |
| `service` | Service | none | Runner tunnel, e.g. `tcp://localhost:5000`; mutually exclusive with target/container |
| `container` | Container | none | Built Dagger container; mutually exclusive with target/service |
| `mode` | string | `baseline` | `baseline` (passive), `api` (document-driven), `full` (active) |
| `api-spec`, `api-spec-path` | File / string | none | API document file or path served by target; mutually exclusive, for API mode |
| `api-format` | string | `openapi` | `openapi`, `soap` or `graphql` |
| `fail-on` | string | `"HIGH"` | Minimum severity that fails: CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE |
| `commit-sha` | string | required | Git commit SHA |
| `branch` | string | required | Git branch name |
| `repo-url` | string | required | Repository URL |

The envelope carries cicd's `dast/1.0` payload in `genericReport` with
`genericFormat="dast/1.0"`. Its nested `zapReport` is a compact alert report,
not raw ZAP output: request/response bodies, headers and per-instance evidence
captures are omitted. [Report extraction](../cross-cutting/report/README.md)
returns the wrapper; explicitly select `.zapReport` if that compact document
is needed. Retain the original envelope's readiness, scope and non-run metadata.

## Docs

→ Full documentation at [docs/](../../docs/index.md)
