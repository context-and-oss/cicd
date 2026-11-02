# composites/commit

Full commit-stage pipeline (ADR-005): the authoritative heavy gate that scans
**code and artifact for any repo shape** through one artifact-agnostic entry.

The source gate — every stage-2 code check (quality, SAST, secrets,
dependency-vuln, risk) — runs for **every** shape via a single
`dag.Stage2().Run(...)` call. The artifact tail is appended after it, selected
explicitly by `--artifact` (never auto-detected — ADR-001). Evidence from the
source gate and the artifact tail is aggregated into one audit directory and a
Teams notification is optionally posted. Artifacts are built and scanned but
never published — each consumer repo owns its own deployment.

The change-intent gate is deliberately **not** part of that source gate, and this
composite exposes no flag to enable it. Intent asks whether the author wrote down
why the change exists; commit runs on the push that already merged, where a
failure blocks nothing anyone can still amend — it turns `main` red over a
document, and because the source gate precedes the artifact tail, the artifact
this stage exists to build and scan never gets built. Require intent in
pre-commit instead (`precommit.Run --require-intent`), and see the amendment in
[ADR-005](../../../docs/decisions/ADR-005-commit-stage-code-and-artifact.md).

## Entry function

```go
func (m *Commit) Run(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    artifact string,            // default "container" — container|archive|none
    failOn string,              // default HIGH
    // --- source gate (passthrough to dag.Stage2().Run) ---
    include []string,
    sastRulesets string,        // default "p/security-audit" ("auto" is refused; never pass empty — semgrep false-pass footgun)
    diff *dagger.File,          // optional git diff <base>..HEAD (intent coupling checks only;
                                // the risk infra scan reads the whole tree here)
    minCoverage float64, coverageMinLines int,
    testCmd, coveragePath string, baseline *dagger.File,
    tolerance float64,          // default 1.0
    coverageGate string,        // default "gate" (gate|warn)
    toolchainImage string,      // ADR-004 explicit toolchain (BYO test + archive build)
    npmFeedUrl string, npmFeedRouting string, npmToken *dagger.Secret,
    nugetFeedUrl string, nugetToken *dagger.Secret,
    // --- container shape ---
    dockerfile string,          // default "Dockerfile"
    platform string,            // default "linux/amd64"
    // --- archive shape ---
    buildCmd, outputPath string, // both required for --artifact archive
    // --- heavier secrets ---
    verifySecrets bool,         // default false — image live-verified secrets (container only)
    // --- delivery ---
    teamsWebhook *dagger.Secret, runUrl string,
) (*dagger.Directory, error)
// Returns directory with: combined-evidence.json, findings.sarif, sbom.cdx.json, comment.md
```

## Artifact shapes

| `--artifact` | Artifact tail (after the source gate) | SBOM source |
|--------------|----------------------------------------|-------------|
| `container` (default) | `Build` → `Sbom(image)` + `ScanImage(verifySecrets)` | image SBOM + source-FS SBOM |
| `archive` | `BuildArchive` → `ScanArchive` (built-output secrets) — errors if `build-cmd`/`output-path` empty | source-FS SBOM |
| `none` | *(no build)* → `build.NoArtifact` (the "nothing was attested" record) | source-FS SBOM only (stage-2 scan-source Trivy-FS CycloneDX) |

Any other value errors with `invalid --artifact`. The container shape emits two
CycloneDX docs (source-FS + image); `evidence.mergeCycloneDX` appends both.

### `none` says what it left unattested

`none` is a shape, not a silence. The branch used to record nothing, so this
composite produced byte-identical evidence for a repository that ships eleven
deployables and one that ships none — `passed=true`, a `sbom.cdx.json`, and no
statement anywhere that no artifact had been built, SBOM'd or scanned. That is
the founding doctrine on the artifact side, reached through a selector value
instead of a crashed scanner.

So the tail is `build.NoArtifact`, which puts one warning in the envelope:

```
artifact: NOT ATTESTED — --artifact none was selected, so no artifact was built and neither an artifact SBOM nor an artifact scan ran (build.Build, build.Sbom, security.ScanImage, build.BuildArchive and security.ScanArchive were all skipped). sbom.cdx.json in this audit describes source lockfiles (stage-2 scan-source, Trivy-FS), not a deployable. Select --artifact container or --artifact archive to attest one, or read this as confirmation that this repository ships no deployable artifact.
```

`notify` renders warnings verbatim, so it reaches `comment.md` and the Teams
card; machines read `genericReport.artifactAttested: false`. It is a **warned
pass** — a repository with nothing deployable is legitimate, and `--fail-on NONE`
cannot clear a non-run, so gating it would be a permanent red with no remedy.
`scripts/smoke/commit-shapes.sh` asserts the record in both channels for `none`
and its *absence* for `container`/`archive`, so the disclosure cannot decay into
either silence or noise. See
[specs/say-what-no-artifact-left-unattested.md](../../../specs/say-what-no-artifact-left-unattested.md).

## Dependencies (dagger.json)

- `stage-2` (the source gate), `build`, `security`, `cross-cutting/evidence`,
  `notify`

## Run locally

```sh
cd src/composites/commit && dagger develop   # once

# container shape (has a Dockerfile)
dagger -m ./src/composites/commit call run \
  --src ./testdata/go-app --artifact container \
  --commit-sha local --branch main --repo-url https://example.com \
  --fail-on NONE \
  export --path ./audit-out

# archive shape (build command + output dir, no Dockerfile)
dagger -m ./src/composites/commit call run \
  --src ./testdata/node-app --artifact archive \
  --build-cmd "npm install --ignore-scripts && npm run build" --output-path dist \
  --commit-sha local --branch main --repo-url https://example.com \
  --fail-on NONE \
  export --path ./audit-out

# none shape (source-only repo, no deployable artifact)
dagger -m ./src/composites/commit call run \
  --src ./testdata/python-app --artifact none \
  --commit-sha local --branch main --repo-url https://example.com \
  --fail-on NONE \
  export --path ./audit-out
```

The three shapes are exercised by `scripts/smoke/commit-shapes.sh <shape>`.

## Output

The exported directory contains:
- `combined-evidence.json` — merged envelope (overall pass/fail + finding counts + findings)
- `findings.sarif` — concatenated SARIF from all scanning modules (quality lint, semgrep, gitleaks, image secrets, infrastructure policy)
- `sbom.cdx.json` — merged CycloneDX SBOM (source-FS, plus image for the container shape)
- `comment.md` — rendered PR comment

## Key files

- `main.go` — `Run()`: the dag wiring (prepare, stage-2, the artifact tail, then `finishAudit`); tagged `!unit_test`
- `audittail.go` — `finishAudit()`: Wrap, the Teams delivery as evidence, Wrap again, the PR comment; tagged, byte-identical to the commit, precommit and dast copies apart from the SDK import (`synced_files` in `scripts/repo-inventory.json`)
- `commitinputs.go` — the pre-flight refusals in the order `Run` applies them, the `artifactShape` selector, the app-mode/repository-mode mixing rule and `preparedImageRef` (untagged, unit-tested; the `invalid --artifact` wording is asserted by `scripts/smoke/commit-shapes.sh`)
- `preparation.go` — the `--prepare-cmd` contract (untagged, unit-tested)
- `appconfig.go` — the application workflow contract: legs, source paths, service validation (untagged, unit-tested)
- `app.go` — `runApp()`, the app-mode leg runner (tagged)
- `artifacts.go` — `retainArtifact()`, the assessed-output retention (tagged)
- `concurrency.go` — generated by `scripts/sync-concurrency.py`; never edit the copy

## Constraints

- **The infra scan reads the whole tree, not the push.** This stage runs on the
  commit that already merged, so there is no author left to hold responsible for
  one file, and it is the stage consumers are told to adopt as the
  whole-repository gate. Scoping it to one push scans `infra/main.bicep` on the
  commit that edits it and never again, and a misconfiguration that predates the
  scan — or that became one when a policy was added rather than when the file
  changed — is invisible forever. Every other concern here already reads the
  whole source view; risk was the exception. Both paths set it: repo mode
  through `stage-2`'s `InfraScope: "tree"`, app mode directly on
  `risk.Validate`. Precommit keeps `changed`, where it earns its keep.

- The source gate runs for every shape — code defects never reach `main` ungated
  regardless of artifact shape.
- `--artifact` is always explicit; cicd never auto-detects the build command (ADR-001).
- Never pass `--sast-rulesets ""` — an empty ruleset silently reports zero
  findings (see `security/CLAUDE.md`). The default is `p/security-audit` and `auto` is
  refused; the commit workflow supplies the heavy pack.
- For the container shape, `build.Build()` is constructed once and passed lazily
  to `Sbom` and `security.ScanImage` — no redundant rebuilds.
- `finishAudit` is artifact-agnostic — it aggregates any `[]*dagger.File`.
- Teams notification failure is non-fatal, and no longer silent: `notify.Teams` returns an evidence envelope that is merged into `combined-evidence.json` by a second `Evidence().Wrap` call, so a webhook that was never configured or a card that was lost is a `warnings[]` line in the pull request comment rather than a transport error inside a twenty-minute log.
