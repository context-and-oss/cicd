# Design — Non-container artifacts

## Blast radius

```
src/internal/detect/        toolchain.go (new) + toolchain_test.go (new)     [01]
src/internal/evidence/      schema.go, schema_test.go (+ sync ripple)        [02]
testdata/node-app/          build.mjs (new), leaked.env.fixture (new)        [03]
src/build/                  archive.go (new), toolchain copy, contract.json  [04]
src/cross-cutting/contract/ "directory" outputSchema in verifier             [04]
src/quality/                byotest.go, coverage.go (cobertura), ratchet,
                            Check+lintOnly, contract.json                    [05]
src/security/               archive.go (new), contract.json                  [06]
src/composites/commit/      RunArchive + shared finishAudit helper           [07]
src/stage-2/                optional BYO-test params, contract.json          [08]
src/composites/precommit/   param pass-through + DT triad upload             [08]
.github/workflows/ci.yml    archive module-test + smoke cases                [09]
.github/workflows/          precommit.yml inputs + baseline fetch;
                            commit-archive.yml (new reusable)                [10]
templates/                  github-actions + azure-devops archive stubs      [10]
docs/                       how-to + reference; CLAUDE.md examples           [11]
```

Untouched by design: `src/stage-4/` (commit composite calls modules directly),
`src/notify/` (ratchet lines ride the existing Warnings rendering,
notify/main.go:49), `src/risk/`, existing reusable `commit.yml`.

## Seams

| Seam | Contract crossing it | Producer | Consumer |
|------|---------------------|----------|----------|
| toolchain resolution | `ResolveToolchain` precedence semantics | 01 (canonical) | 04, 05 (local copies) |
| envelope coverage fields | `coverageBaselineByLanguage`, `coverageRatchet` | 02 | 05 (writes), 10/auditors (read) |
| archive fixtures | node-app `npm run build` → `dist/` w/ planted secret | 03 | 04, 05, 06, 09 |
| built artifact | `BuildArchive(...) → *Directory` | 04 | 07 |
| witnessed test evidence | `Test(...) → *File` (envelope) | 05 | 08 |
| archive scan evidence | `ScanArchive(src, output) → *File` | 06 | 07 |
| composite entry points | `RunArchive`, stage-2 optional params | 07, 08 | 09, 10 |
| workflow inputs | `test-cmd`, `coverage-*`, `build-cmd`, `output-path`, `toolchain-image` | 10 | fleet caller stubs |

Gates: {01,02,03} → {04,05,06} → {07,08} → {09,10,11}. Briefs inside a gate are
independent and may run in parallel.

## Contracts

New/changed Dagger function signatures (Go, param names are API):

```go
// build (04) — returns the attested artifact; consumer owns buildCmd.
func (m *Build) BuildArchive(ctx, src *Directory, buildCmd, outputPath string,
    // +optional
    toolchainImage string,
    commitSha, branch, repoUrl string) (*Directory, error)

// quality (05) — witnessed BYO test + coverage harvest + ratchet.
func (m *Quality) Test(ctx, src *Directory, testCmd string,
    // +optional
    coveragePath string,
    // +optional — prior combined-evidence.json OR bare {"coverageByLanguage":{...}} (sniffed)
    baseline *File,
    // +default=1.0
    tolerance float64,
    // +default="gate"  gate|warn
    coverageGate string,
    // +optional
    toolchainImage string,
    // +optional
    include []string,
    commitSha, branch, repoUrl string) (*File, error)

// quality (05) — additive param on existing Check.
//   lintOnly bool +optional — skips the testLanguage loop.

// security (06)
func (m *Security) ScanArchive(ctx, src *Directory, output *Directory,
    // +default="HIGH"
    failOn string,
    commitSha, branch, repoUrl string) (*File, error)

// commit composite (07) — same DT/notify tail as Run via shared helper.
func (m *Commit) RunArchive(ctx, src *Directory, commitSha, branch, repoUrl,
    buildCmd, outputPath string,
    /* toolchainImage?, failOn?, teamsWebhook?, runUrl?, DT triad? — mirror Run */) (*Directory, error)
```

Envelope additions (02) — additive, omitempty, outputSchema stays
`evidence-1.0.0` (resolved at show-back):

```go
CoverageBaselineByLanguage map[string]float64 `json:"coverageBaselineByLanguage,omitempty"`
// "pass" | "fail" | "skipped:no-baseline" | "skipped:no-coverage-output" | "skipped:warn-mode"
CoverageRatchet string `json:"coverageRatchet,omitempty"`
```

Ratchet rule (05): per language present in BOTH measured and baseline maps —
`measured < baseline − tolerance` → gate-mode: error + `coverageRatchet="fail"`;
warn-mode: warning + `"skipped:warn-mode"`. Boundary `measured == baseline − tolerance`
passes. Missing baseline/coverage output → warning + `"skipped:<reason>"`, never
an error. Measured > baseline → info warning ("ratchet advances on merge").

contract.json verifier (04): `outputSchema` gains `"directory"` alongside
`"evidence-1.0.0"` and `"container"`.

Baseline file format (05, resolved at show-back): sniff — accept a full evidence
envelope/combined-evidence.json (read `coverageByLanguage`) or a bare
`{"coverageByLanguage": {...}}` map.

Toolchain resolution (01, ADR-004): explicit param > `.nvmrc` (node) /
`global.json` (dotnet) mapped to official tags (`node:<major>-alpine`,
`mcr.microsoft.com/dotnet/sdk:<major.minor>`) > pinned defaults
(node:20-alpine, golang:1.26-alpine, python:3.12-slim, dotnet/sdk:8.0).
Malformed version files fall through, never error. Only the explicit param is
digest-pinnable.

Workflow inputs (10): reusable `precommit.yml` adds optional `test-cmd`,
`coverage-path`, `toolchain-image`, `coverage-tolerance` (default "1.0"),
`coverage-gate` (default "gate"); plus a baseline-fetch step (latest successful
default-branch `precommit-evidence-*` artifact via gh api, `|| true` — absent
baseline is the documented bootstrap path, fails open). New reusable
`commit-archive.yml`: required `build-cmd`, `output-path`; optional
`toolchain-image`, `fail-on`, DT vars.

## Reference reading

- `CLAUDE.md` — module-add checklist, `make sync-schema`, no-shared-module rule
  (internal packages shared by file copy only).
- `src/composites/commit/main.go:78-110` — DT triad gating + partial-config
  warning to replicate verbatim in precommit (08) and reuse via helper (07).
- `src/security/main.go:58-87` — `runTrivyFS` producing CycloneDX from source;
  ScanArchive reuses it.
- `src/quality/test.go:141-265` — existing coverage parsers (go coverprofile,
  v8 json-summary, pytest-cov) and the sh-c/exit-code capture pattern for BYO
  execution; cobertura parser joins these.
- `.github/workflows/precommit.yml:127-132` — the evidence artifact upload the
  file-less baseline rides on.
- `src/internal/evidence/schema.go:62-77` — existing coverage fields the new
  ratchet fields sit beside.
- `.github/workflows/ci.yml:119-234` — module-test case statement to extend (09).
- `src/notify/main.go:49-51` — Warnings rendering; why notify needs no changes.
- `src/quality/gating_test.go` — the `unit_test` build-tag test pattern for
  module-local Go tests.

## Decisions

- ADR-001: Artifact shapes — image and archive; consumer-owned definitions,
  cicd-owned execution + evidence (introduced)
- ADR-002: Witnessed BYO test execution, precommit-only placement (introduced)
- ADR-003: File-less coverage ratchet — baseline from previous default-branch
  evidence artifact (introduced)
- ADR-004: Toolchain resolution precedence and the digest-pinning trade-off
  (introduced)
