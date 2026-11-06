# security module

Domain module: SAST (Semgrep), secrets detection (Gitleaks/TruffleHog), and vulnerability scanning (Trivy). Covers both source code and built container images.

## Entry functions

```go
// Source scan: SAST + secrets (Gitleaks) + filesystem vuln scan (Trivy FS)
func (m *Security) ScanSource(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    sastRulesets string,    // Semgrep rulesets, default "p/security-audit" ("auto" is rejected)
    failOn string,          // CRITICAL|HIGH|MEDIUM|LOW|NONE, default HIGH
    nugetFeedUrl string,    // optional — private NuGet feed for the lockfile-free restore
    nugetToken *dagger.Secret, // optional — token for nugetFeedUrl (secret; never in the envelope)
    vulnAccept string,      // optional — "<id>=<reason>" risk acceptances, ONE PER LINE, disclosed in warnings[]
) (*dagger.File, error)     // evidence.json

// Image scan: secrets entropy (TruffleHog) + image vuln scan (Trivy image)
func (m *Security) ScanImage(
    ctx context.Context,
    image *dagger.Container,
    commitSha, branch, repoUrl string,
    failOn string,          // default HIGH
) (*dagger.File, error)     // evidence.json

// SBOM rescan: an existing CycloneDX document against today's vuln database
// (the scheduled-rescan entry point ADR-006 names; wired into no composite)
func (m *Security) ScanSbom(
    ctx context.Context,
    sbom *dagger.File,      // CycloneDX only — validated before any container runs
    commitSha, branch, repoUrl string, // commitSha = the commit the SBOM was frozen at
    failOn string,          // default HIGH
) (*dagger.File, error)     // evidence.json
```

## Run locally

Local inspection/shadow examples only, from an authorized checkout's root.
Default SAST rules are restrictively licensed; review the
[runtime rule notice](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
For CI, clean stale outputs, fail on export failure and enforce
`jq -e '.passed == true'` on each required fresh envelope; see the
[complete source gate example](README.md#scan-source).

```sh
(cd src/security && dagger develop)   # once

# source scan
dagger -m ./src/security call scan-source \
  --src ./testdata/go-app --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/evidence.json

# image scan (pass a container reference)
dagger -m ./src/security call scan-image \
  --image "alpine:3.19" --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/evidence.json

# SBOM rescan (feed back a cyclonedxReport a past run froze)
dagger -m ./src/security call scan-sbom \
  --sbom /tmp/sbom.cdx.json --fail-on NONE \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/evidence.json
```

## Key files

- `main.go` — `ScanSource()`, `ScanImage()` and `ScanWeb()` entry points (the
  dag wiring only; every decision each one makes lives in an untagged file below)
- `webinputs.go` — **untagged**: `validateWebInputs()`, the `--mode` /
  `--api-spec` / `--api-spec-path` refusals `ScanWeb` makes before any container
  runs, in the order it makes them
- `webfold.go` — **untagged**: `zapResult` (what one ZAP run came back with),
  `specScope()` (the endpoint count the API document gives, or the warning it
  cannot), `foldZAPRun()` (the add-on verdict, the dead-scan error, the parsed
  report, the import probe and the reach reconciliation folded into one
  `zapFold`) and `buildWebEnvelope()` (that fold as the evidence envelope)
- `sarifmerge.go` — **untagged**: `mergeSARIF()`, two SARIF documents under the
  first one's header
- `scopepath.go` — **untagged**: `checkScopePath()`, the `--path` shape rule
  (`applyPathFilter` in `main.go` only applies it)
- `sast.go` — Semgrep SAST runner
- `semgrepredact.go` — withholds the matched source from every semgrep report
  before anything reads it: snippets, fixes, interpolated messages and the
  backtick-quoted source in parser notifications (untagged; see "Semgrep's matched source never reaches the envelope")
- `semgrepnotifications.go` — reads Semgrep's `toolExecutionNotifications` out
  of the SARIF the envelope already carries and turns parse failures and rule
  timeouts into one `warnings[]` line (untagged; see "Read the part of the
  report where Semgrep says what it skipped")
- `semgreppack.go` and `rules/semgrep-{security-audit,owasp-top-ten,secrets}.txt`
  — the pinned `p/security-audit`, `p/owasp-top-ten` and `p/secrets`: the
  semgrep-rules commit, the frozen file/id manifests,
  the staging layout that reproduces registry ids, the `--config` plan that
  swaps the registry name for it, and the rule-set floor (untagged; see
  "Pinned default rules")
- `semgreprules.go` and `semgrep_gha.py` — detect the one measured upstream
  rule whose embedded-Bash parser rejects valid GitHub Actions run blocks,
  then replace only that matcher using a runtime adaptation of the pinned
  upstream rule. The generated copy retains original source/licensor notices
  and a prominent modification notice; no upstream body is embedded
- `secrets_source.go` — Gitleaks source secrets scan (the container calls only)
- `gitleaksscript.go` — the gitleaks command, its argument shapes, the archive
  depth and the debug-log filter (untagged; see "A secrets scan must open what
  the output ships")
- `gitleaksarchives.go` — reads the filtered log into the unopened-archive and
  too-deep `warnings[]` lines and the tree leg's `Examined` (untagged; same
  section)
- `gitleaksidentity.go` — strips gitleaks' `partialFingerprints` to
  `commitSha` and `date` on every leg, so the history leg's author, email and
  commit message never reach the envelope; a report it cannot walk is an error
  (untagged; see "A secrets scan withholds who committed, not only what")
- `gitleakssuppress.go` — discloses what `gitleaks:allow`, `.gitleaksignore`
  and a root `.gitleaks.toml` removed: the shadow scan's extra results put back
  as accepted SARIF suppressions (never counted), one `SUPPRESSED` warning per
  mechanism, and the `NARROWED RULES` warning (untagged; see "A gitleaks
  suppression is disclosed, never trusted silently")
- `secrets_image.go` — TruffleHog image entropy scan (the container call only)
- `trufflehogreport.go` — TruffleHog argument shape, output parsing and SARIF
  (see "A TruffleHog finding without a location is not a finding")
- `vuln_source.go` — Trivy filesystem scan, and the pre-scan .NET restore hook
- `vuln_image.go` — Trivy image scan
- `vuln_sbom.go` — Trivy rescan of an existing CycloneDX document
- `sbomscan.go` — `ScanSbom()` entry point (frozen-SBOM rescan, ADR-006)
- `sbominput.go` — refuses a rescan input that was never a CycloneDX document,
  before any container runs (untagged; a rescan that never read its SBOM must
  never read as a rescan that found nothing)
- `trivyflags.go` — the flags cicd pins on every Trivy scan (see "Scoping a Trivy scan")
- `vulnallow.go` — `--vuln-accept`: parsing, the partition that removes accepted
  rows from the counts and the gate, and the `warnings[]` disclosure that keeps
  them legible (untagged; see "An acceptance nobody can read")
- `trivyignore.go` — discloses that a consumer's `.trivyignore` narrowed the
  report before cicd could read it (untagged; same section)
- `trivyreport.go` — parses Trivy's native JSON into severities and findings (see
  "Vulnerability severity comes from Trivy, not from CycloneDX")
- `devonly.go` — clears a lockfile that holds only development dependencies:
  classifies the `--include-dev-deps` rescan, builds the `RUNTIME SET EMPTY`
  row and the corrected no-results error (untagged; see
  `specs/clear-a-development-only-lockfile.md`). Open gap: in a mixed tree an
  all-development or malformed lockfile beside a resolved ecosystem passes
  unremarked, because `unresolvedEcosystems` exempts any ecosystem with a lockfile
- `licencenuget.go` — the licence scan's NuGet restore and its zero-read rule:
  the `.nuspec` snapshot taken inside the restore exec, the licence-specific
  restore errors, and `licenceZeroRead` / `licenceZeroReadWarning` (a completed
  scan that read nothing is SKIPPED, never CLEAN; never when the scan errored).
  The restore warning is written after the scan and splits the restored projects
  into listed by Trivy, removed by `--license-exclude`, and not listed (a
  `trivy.yaml` skip, or no `PackageReference`) — restored is not read.
  Untagged; see `specs/read-nuget-licences-and-skip-a-licence-scan-that-read-nothing.md`
  and `specs/say-which-restored-projects-the-licence-scan-read.md`.
- `licencegomod.go` — the licence scan's Go module download, decided without
  Dagger: which `go.mod` files need one, the `go mod edit -json` plan (replaces
  applied, references validated before the go command sees them), the
  classification of `go mod download -json` into downloaded / not served by the
  proxy / failed, and the warning naming every module not read. Untagged; see
  `specs/read-go-dependency-licences-from-a-downloaded-module-graph.md`.
- `goexec.go` — the same download's containers: the pinned `golang` image,
  `GOPROXY` set to the Go module proxy alone (no `direct`), `GOTOOLCHAIN=local`,
  a `CacheSharingModePrivate` module cache, and the top-level-files snapshot
  Trivy reads through `GOPATH`. `licencegomod_test.go` reads this file to hold
  those settings.
- `licencecoverage.go` — how many of the dependency packages Trivy listed carry
  a licence it read (root and workspace packages are first-party and left out):
  `dependencyCoverage` in the payload, a `NOT READ` / `PARTLY READ` warning, and
  SKIPPED when none was read even if the tree's own LICENSE was judged. Untagged;
  see `specs/say-how-many-dependency-licences-were-read.md`.
- `ecosystems.go` — reconciles the ecosystems the tree *declares* against the ones
  Trivy *resolved a graph from* (see "A dependency scan that resolved nothing is
  not a clean dependency scan"). A solution file is a *listing*, not a marker
  that declares packages: a tree of `.sln`/`.slnx` and no project runs no
  restore, is not reported unresolved, and both dependency rows warn
  `SOLUTION WITHOUT PROJECTS` instead, decided from the probe and never from the
  restore ([specs/stand-down-on-a-solution-without-projects.md](../../specs/stand-down-on-a-solution-without-projects.md))
- `dotnetrestore.go` — the lockfile-free NuGet fallback's decisions: trigger,
  script rendering, exit-status classification, messages (untagged; see "A gate
  a consumer cannot clear")
- `dotnetexec.go` — the same fallback's containers: the pinned SDK, the band
  probe, the restore itself. The NuGet packages volume is mounted
  `CacheSharingModePrivate`: NuGet's cross-process lock lives in the
  container's own `/tmp`, so two concurrent restores into a shared volume race
  on its temp files (measured, see
  `specs/run-test-legs-under-the-parallelism-bound.md`).
  `nugetcachesharing_test.go` fails if the mount loses the option.
- `dotnetband.go` — which SDK band the tree asks for and which pinned band it
  restores in (untagged); a **byte-identical copy** of `src/quality/dotnetband.go`,
  declared under `synced_files`, so the two modules cannot resolve one tree to
  different bands
- `nugetfeed.go` — private-feed config and source-name discovery; a **byte-identical
  copy** of `src/quality/nugetfeed.go`, declared under `synced_files` in
  `scripts/repo-inventory.json` and enforced by `check_synced_files`
- `zapscript.go` — the paths inside the scan container and `zapRunScript`, the
  script that fills them (untagged, so the status it writes in shell and Go
  reads back is testable)
- `zapaddons.go` — the pinned passive-rule add-on, `-silent`, and the four
  answers staging it can produce (untagged; see "Stop ZAP downloading the
  add-on that owns its own socket")
- `zapimport.go` — whether ZAP refused the API document, read out of ZAP's own
  daemon log (untagged; see "The document ZAP would not take")
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go`

## SAST rulesets — why `auto` is rejected

The default is `p/security-audit`, **not** semgrep's `auto`, and `auto` is
rejected outright with an error. `semgrep scan --config auto` refuses to run
while telemetry is disabled:

```
[ERROR]: Cannot create auto config when metrics are off.
```

cicd runs every scanner with `--metrics=off` so a client's source tree is never
reported to a third party, so `auto` and cicd are mutually exclusive — it can only
ever produce an empty report. It was the default until the false-pass fixes, and the old command ended in
`|| echo '{"runs":[]}' > report.sarif`, so that exit-2 failure became a report
with zero findings and a green gate. **SAST was dead for every consumer on
defaults**, silently. `semgrepConfigFlags` now rejects `auto` and the empty
string, and `semgrepRunError` fails the gate on any semgrep that did not scan —
including an exit-zero run that reported no runs at all.

If you want `auto`'s breadth, name packs explicitly:
`--sast-rulesets p/security-audit,p/owasp-top-ten,p/typescript`.

## Pinned default rules

Both ordinary and inline scan commands disable Semgrep's optional engine-update
probe. The engine is digest-pinned; a retried update/banner request must not
consume the analysis deadline. This does not disable rule-source fetching or
make explicit live packs offline, and it changes no scan scope or timeout. See
[keep-local-semgrep-time-for-analysis](../../specs/keep-local-semgrep-time-for-analysis.md).

`p/security-audit`, `p/owasp-top-ten` and `p/secrets` never reach the
registry. `semgrepPlanFor` replaces every pinned pack named with one
`--config /<top>` per top-level directory of their files in a
`semgrep/semgrep-rules` checkout at `semgrepRulesCommit`, staged once, plus
the runtime-adapted `gha-curl-pipe-shell` when a named pack carried the upstream
one (left out of every manifest while it still fails to parse; `p/secrets`
never had it). The manifests freeze selected rule identities so registry drift
cannot silently narrow a named pinned pack while still reporting zero findings.

- **A staged file is not a pack.** The owasp files carry three pickle rules
  owasp does not include; an all-pinned plan passes them as `--exclude-rule`.
  With a live registry pack in the scan the plan excludes nothing, because
  `--exclude-rule` would take the rule from the live pack too. Trap: every
  pinned manifest's files must stay inside the `p/security-audit` manifest's
  files, or a co-located rule is unknown and lands unexcluded —
  `TestSemgrepPackCeilingHoldsByConstruction` holds that.

- **Ids are the floor's whole basis, so the layout is load-bearing.** Semgrep
  names a local rule from its path relative to cwd. Each file is staged at
  `/<dir>/<stem>/<file>` and the scan runs from `/src`; anywhere else (under
  `/src`, under `/cicd-semgrep-pack`) gives ids the floor cannot match.
  `semgrepReservedRoots` refuses a top directory that would land on the image's
  own filesystem, and the script refuses one that already exists.
- **Adapter staging fails closed.** `semgrep_gha.py` runs only when its config
  is selected. It reads the pinned rule and LICENSE (and NOTICE when present),
  validates the expected matcher shape, preserves upstream selectors/metadata,
  and emits a visibly modified runtime copy. Missing source/notices, an unknown
  shape or generation failure prevents the scan. Live-only scans fetch the
  pinned source only after the measured rule needs a rerun; ordinary custom
  and secrets-only scans do not generate the compatibility rule.
- **Below the floor is a non-run.** The selected workflow replacement's loaded
  identity is required even on a live-only rerun. `semgrepRuleSet` also requires every id of every
  pinned pack named in the SARIF's `tool.driver.rules[]`, lowercased on both
  sides. Extras are not
  checked. Zero loaded rules is a non-run whether pinned or not.
- **Fetch or staging failure never falls back to the registry.** Either is a
  non-run naming the pin.
- **Every other registry pack stays live** and is listed in `rules.unpinned` with an
  `UNPINNED RULES` warning; a config path is versioned with the commit and is
  not listed.
- **The rules are not Apache-2.0.** `semgrep/semgrep-rules` is under the
  Semgrep Rules License v1.0 (internal business use; no redistribution or
  offering as a service). cicd fetches them at run time and keeps only paths
  and ids in `rules/*.txt` — never commit a rule body here, and keep the
  disclosure in [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) and the
  READMEs true. A bump re-reads `LICENSE` at the new commit.
- **Bumping** is a rule-set change, not a version bump, so Renovate does not
  touch it. Procedure, trade-offs and residue:
  [specs/pin-the-default-sast-rules.md](../../specs/pin-the-default-sast-rules.md).

## Inline JavaScript and the DOM rule

`semgrepinline.go` embeds `semgrep_inline.py` and the first-party
`rules/dom-text-to-html.yml`. Audit/OWASP plans add the DOM rule to the ordinary
scan and defend its loaded id separately from the upstream manifest. The Python
adapter uses the ordinary JSON report's selected HTML/HTM paths, never a second
walk that could bypass `.semgrepignore`. It runs selected pinned JS/TS rules in
the same image on extracted script scopes, checks both input and rule coverage,
and appends a separately identified SARIF run before `redactSemgrepSARIF`.

Source maps cover primary, related and flow locations, parser notifications and
UTF-16 columns. Keep rule catalogues/indices per run and count original files only.
Internal failures are exit 125/non-runs, while malformed or unsupported markup is
a partial-scan disclosure. A failing inline pass retains the original scan's
findings. Classic blocks share document scope; modules and template scripts
remain separate. Templates can activate scripts when cloned, so their scripts are
analysed. Do not turn JSON/import maps, external-script bodies or inert text
contexts into JavaScript. Event-handler attributes and framework/server templates remain outside
this bounded adapter; it is not an HTML5-complete parser.

Custom/live rules are not rewritten onto temporary filenames, whose path semantics
would differ. Custom-only and secrets-only plans remain unchanged. A hand-written
sanitizer may need reviewed `nosemgrep`; never trust a helper solely by its name.
The Python unit suite is invoked by the canonical Go module-unit runner; the real
source-module regression is `scripts/smoke/semgrep-inline.sh`. Rationale and traps:
[specs/scan-inline-javascript-as-code.md](../../specs/scan-inline-javascript-as-code.md).

## SAST scope & noise control

`p/security-audit` is still broad. On repos with legacy, vendored, or POC files it
will surface findings the team never opted into — these are scope/config mismatch,
not code debt. Two levers control this, and they are **orthogonal** (rulesets pick
*which rules fire*; ignore picks *which files are scanned*):

- **Curate the rulesets** — `--sast-rulesets` takes a comma-separated list with
  **no spaces** (`semgrepConfigFlags` splits on `,` and emits one `--config` per
  entry, character-validated, then passes them as positional arguments so a
  ruleset value is never spliced into the scan step's shell script). Two forms:
  - Named packs: `--sast-rulesets p/security-audit,p/secrets,p/typescript`
  - A checked-in config path, resolved relative to the scanned root:
    `--sast-rulesets ./security.yml` — makes the consumer's own semgrep config the
    single source of truth, so cicd and their config can't drift.
- **Exclude files/paths** — commit a `.semgrepignore` at the repo root. Semgrep
  auto-loads it from the working directory; cicd mounts the full source tree, so it
  is honored with zero cicd configuration. This is the **only** mechanism that can
  exclude a single file. The `exclude` param is **directory-name removal only**
  (`WithoutDirectory`) — it cannot target a file, and is **not** plumbed through the
  `precommit`/`commit` composites or `stage-2`. Prefer `.semgrepignore` for both.
- **Suppress one reviewed match** — use Semgrep's rule-specific `nosemgrep`
  comment. Semgrep retains the result in SARIF with an accepted suppression;
  cicd keeps that native evidence and reports how many matches were suppressed,
  but excludes them from severity counts, `fail-on`, and the findings table.

**Footgun:** never pass `--sast-rulesets ""` (empty). It overrides the default with
no config; semgrep would scan with no rules and report **zero** findings. That is
now an error rather than a silent false pass, but consumer plumbing should still
omit the flag entirely when unset rather than pass an empty string. The reusable
GHA workflow does this via a conditional `extra[]`.

## Scoping a Trivy scan

Trivy auto-loads `trivy.yaml` from its working directory, and both scans run with
`WithWorkdir("/src")` (`trivyConfigDir`), so a `trivy.yaml` committed at the root
of the scanned repository is honoured with **zero cicd configuration** — the same
deal `.semgrepignore` gets. The scan target stays absolute (`/src`), which keeps
`skip-dirs` patterns relative to the source root and leaves the report unchanged
for a repo that ships no config.

This repository uses it on itself: `trivy.yaml` skips `testdata`, whose fixture
apps pin a vulnerable `lodash`, an ancient `Newtonsoft.Json` and a committed
secret **on purpose** so the integration tests have something to find. Those CVEs
are test data, not this repo's supply chain. Every finding outside `testdata` is
real; the dogfood gate found twelve on the day the vuln scan started working, and
they were fixed by bumping the affected modules' indirect dependencies, not
suppressed.

**Scope only — a consumer's config can never make a scan report less.** That is
not a happy accident, it is enforced. `trivyflags.go` pins on the command line
(which beats the config file) every knob that filters findings out of an
otherwise-successful scan:

| `trivy.yaml` key | pinned flag |
|---|---|
| `scan.scanners` | `--scanners vuln` |
| `severity` | `--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` |
| `vulnerability.ignore-unfixed` | `--ignore-unfixed=false` |
| `vulnerability.ignore-status` | `--ignore-status ""` |
| `pkg.types` | `--pkg-types os,library` |
| `db.skip-update` | `--skip-db-update=false` |

Measured against trivy 0.70.0 on a fixture with ten known CVEs: a config setting
`severity: [CRITICAL]` plus `ignore-unfixed: true` took the report from **10
vulnerabilities to 1** while the scan still succeeded — a silent under-report of
exactly the kind this module exists to prevent. With the flags pinned, the same
hostile config yields all 10. `trivyflags_test.go` pins the mapping.

`.trivyignore` (per-CVE suppression) is also auto-loaded and is *not*
neutralised — a file checked into the consumer's repository naming the CVE it
accepts is a decision, not an accident, and switching it off would turn every
consumer who has one red on an upgrade with no warning first. But it is no
longer the recommended mechanism, and `--vuln-accept` is. See the next section
for why, and `.trivyignore.yaml` (the richer form with `statement`/`expired_at`)
is **not** auto-loaded by trivy 0.70.0 at all — measured, it suppressed nothing.

**Maintenance risk, named because nothing detects it automatically:** a future
Trivy can add a new finding-filtering key. When bumping `trivyVersion`, re-read
the config reference for new keys under `severity`, `vulnerability` and `pkg` and
add the matching flag to `trivyPinnedFlags`.

## Constraints

- Evidence envelope includes SARIF (for SAST/secrets) and CycloneDX (for vuln) reports.
- Secrets findings are all treated as HIGH severity; `stampSARIFLevel` writes
  `"level":"error"` into gitleaks'/TruffleHog's own SARIF so the detail rows the
  dashboard and PR comment render agree with `findingsBySeverity`.
- A tool that fails to run lands in `errors[]` and sets `passed=false` — it is not
  reported as zero findings.
- `--fail-on NONE` never fails over findings — use during exploratory runs. It
  does **not** cover a scanner that could not run: `gatedPassed(ran, severityOK,
  threshold)` gates `severityOK` alone, so a Semgrep that could not build a
  config or a Trivy that could not reach its database fails at `NONE` too. It
  used to pass, which meant the flag a team sets on day one to see what cicd
  reports was also the flag that hid a scanner reporting nothing because it
  looked at nothing.
- `ScanSource` scans the **working tree always**, and git history additionally when
  the uploaded directory carries a `.git/` directory. Neither mode subsumes the
  other — measured against gitleaks v8.30.1:

  | fixture | `dir .` | `detect --source .` |
  |---|---|---|
  | secret only in history (deleted from the tree) | 0 | 1 |
  | secret uncommitted in the working tree | **1** | 0 |
  | no `.git` at all | **1** | 0 |

  `detect` was the only leg, which left two holes. A secret written or staged but
  not yet committed was reported by nothing, and a tree with no `.git` — every
  `testdata` fixture, so every `module-test` and `composite-smoke` cell — produced
  `0 commits scanned` and a clean report. The tree scan is the baseline because it
  examines what actually ships and is independent of clone depth; history is
  additive, for a credential that was committed and then deleted and so stays
  exposed to anyone who can clone.

  The two legs are deduplicated on rule + file + line, because a secret that is
  both committed and still in the tree is one leak found twice (gitleaks' own
  fingerprints differ only by a commit prefix, so keying on them would count it
  twice). Only the tree leg's document is kept as the base: both legs emit the
  full 222-rule catalogue (~49 KB), and merging whole documents would put a second
  copy in every envelope.

The rules this module was built against, each measured as a false pass before
it was fixed, live in
[docs/explanation/doctrine-security.md](../../docs/explanation/doctrine-security.md).
Read the rule, and the spec it links, before changing the code it names. One
line per rule:

- [An acceptance nobody can read is indistinguishable from a bug](../../docs/explanation/doctrine-security.md#an-acceptance-nobody-can-read-is-indistinguishable-from-a-bug)
- [Vulnerability severity comes from Trivy, not from CycloneDX](../../docs/explanation/doctrine-security.md#vulnerability-severity-comes-from-trivy-not-from-cyclonedx)
- [A scan that could not run must never read as "clean"](../../docs/explanation/doctrine-security.md#a-scan-that-could-not-run-must-never-read-as-clean)
- [A dependency scan that resolved nothing is not a clean dependency scan](../../docs/explanation/doctrine-security.md#a-dependency-scan-that-resolved-nothing-is-not-a-clean-dependency-scan)
- [A gate a consumer cannot clear is a gate that gets switched off](../../docs/explanation/doctrine-security.md#a-gate-a-consumer-cannot-clear-is-a-gate-that-gets-switched-off)
- [A TruffleHog finding without a location is not a finding](../../docs/explanation/doctrine-security.md#a-trufflehog-finding-without-a-location-is-not-a-finding)
- [A ZAP that died is not a target with nothing to find](../../docs/explanation/doctrine-security.md#a-zap-that-died-is-not-a-target-with-nothing-to-find)
- [A secrets scan must open what the output ships](../../docs/explanation/doctrine-security.md#a-secrets-scan-must-open-what-the-output-ships)
- [A missing `.git` is not a failure; an unreadable one is](../../docs/explanation/doctrine-security.md#a-missing-git-is-not-a-failure-an-unreadable-one-is)
- [A history-leg failure never discards the tree leg's findings](../../docs/explanation/doctrine-security.md#a-history-leg-failure-never-discards-the-tree-legs-findings)
- [Every gitleaks run passes `--redact`](../../docs/explanation/doctrine-security.md#every-gitleaks-run-passes---redact)
- [Semgrep's matched source never reaches the envelope](../../docs/explanation/doctrine-security.md#semgreps-matched-source-never-reaches-the-envelope)
- [A gitleaks suppression is disclosed, never trusted silently](../../docs/explanation/doctrine-security.md#a-gitleaks-suppression-is-disclosed-never-trusted-silently)
