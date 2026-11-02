# stage-2 module

Stage orchestrator for pre-commit checks. Wires `quality.Check` +
`security.ScanSource` + `risk.Validate` + `intent.Check` — plus
`quality.Test` when a consumer test command is supplied — and returns their
evidence files as a slice. Does not aggregate or notify — use
`composites/precommit` for that.

`intent.Check` gates only when the caller passes `requireIntent`. It runs
either way: opted out, it returns an envelope recording that nothing was
checked, because a gate absent from an audit and a gate that passed are
indistinguishable afterwards.

## Entry function

```go
func (m *Stage2) Run(
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    failOn string,          // default HIGH
    include []string,       // optional language override
    sastRulesets string,    // default "p/security-audit" ("auto" is refused)
    npmFeedUrl string,      // optional
    npmFeedRouting string,  // optional: registry (default) | npmrc
    npmToken *dagger.Secret,
    nugetFeedUrl string,    // optional
    nugetToken *dagger.Secret,
    diff *dagger.File,      // optional — intent coupling checks; risk when infra-scope=changed
    infraScope string,      // default "changed" | "tree" — which infra files risk reads
    intentGlobs []string,   // optional
    minCoverage float64,    // default 0 (disabled)
    coverageMinLines int,   // default 0
    testCmd string,         // optional — witnessed BYO test (quality.Test)
    testLegs string,        // optional — per-language legs, JSON; excludes testCmd
    coveragePath string,    // optional — coverage file testCmd writes (legs carry their own)
    baseline *dagger.File,  // optional — ratchet baseline (prior evidence)
    tolerance float64,      // default 1.0
    coverageGate string,    // default "gate" (gate|warn)
    toolchainImage string,  // optional — ADR-004 explicit toolchain for testCmd
    dependabotActionsPin bool, // optional — passthrough to intent.Check; see below
    requireIntent bool,        // optional — opt in to the change-intent gate
) ([]*dagger.File, error)
```

Returns one evidence file per leg: quality (lint+test, or lint-only when
`testCmd` or `testLegs` is set), witnessed tests (only when one of those is
set), source security, source licences, risk, intent — in that order. The slice
length is therefore 5 or 6; downstream consumers must not assume a fixed count.
The signature above is abridged: the licence, `vulnAccept`, `parallelism`,
`nodeProjectLimit` and `prepared*` parameters are in `main.go`. `requireIntent`
does not change the count: the intent envelope is always present.

The files are materialised before `Run` returns, at most `--parallelism`
(default 1, so sequentially) at a time. This is a storage bound, not a change to gate order or evidence: without the explicit
`Sync` barrier, the final aggregator can force the .NET quality image and all
security/risk images concurrently, exhausting a standard GitHub runner on a
large repository before any evidence can be uploaded.

## Dependencies (dagger.json)

- `quality`, `security`, `risk`, `intent` (root-level modules)

## Run locally

```sh
cd src/stage-2 && dagger develop   # once

dagger -m ./src/stage-2 call run \
  --src ./testdata/go-app \
  --commit-sha local --branch main --repo-url https://example.com \
  --fail-on NONE
```

## Key files

- `main.go` — `Run()`: the dag calls, the bounded `Sync` loop and the write
- `stage2plan.go` — `byoTestRequested()`, `validateStage2Inputs()`, `stage2Legs()` (each evidence file paired with the name it is recorded under, so files and names cannot drift apart) and `unusableEvidence()` (untagged, unit-tested)
- `concurrency.go` — generated copy of `src/internal/concurrency/concurrency.go`
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go`

## Constraints

- Returns `[]*dagger.File` (not `*dagger.File`) — one evidence file per
  module that ran; see above for the variable count.
- **`--infra-scope` is forwarded to `risk`, never acted on here.** The two
  composites that call this orchestrator want opposite answers — precommit
  `changed`, commit `tree` — and the rule belongs to the module that owns the
  scan, so there is one accepted-value set and one place a test reaches it.
  Pre-validating the string here would be a second copy to drift out of
  agreement. `diff` is still passed in both cases: the intent gate's coupling
  checks need the change set even when the infra scan is not narrowing by it.
- Keep the per-file `Sync` loop bounded (`RunBounded`, default 1). Returning a fully lazy slice makes
  the aggregator execute every heavy domain branch together and removes the
  runner-storage bound established for large consumers.
- When `testCmd` is set, `quality.Check` runs with `lintOnly: true` so the
  baseline lint is kept without a redundant vanilla test run (ADR-002).
- In CI, `module-test` verifies `dagger develop` (compilation) succeeds for
  this module; `scripts/smoke/stage-orchestrators.sh` runs `Run` against a
  fixture and asserts each dependency's evidence trace is present in the
  output, and `composite-smoke`/`composite-smoke-commit` exercise it
  indirectly through `precommit`/`commit`.
- Pass the returned files to `cross-cutting/evidence.Wrap` to produce
  `combined-evidence.json`.
- `requireIntent` is inverted at the call site (`NotRequired: !requireIntent`)
  and must stay that way. Dagger's generated Go client drops any optional
  argument holding its zero value, so an optional bool can only ever be
  transmitted as `true` — the state that must reach the server is "do not
  check", not "check". A positively-named parameter defaulting to on could
  never be turned off by a caller. See `src/cross-cutting/intent/check.go`.
- `dependabotActionsPin` only ever satisfies `intent.Check`'s presence tier
  via its independent diff re-validation
  ([specs/harden-workflow-supply-chain.md](../../specs/harden-workflow-supply-chain.md)) — the caller (precommit's reusable/dogfood workflows) must
  verify the PR actor is exactly `dependabot[bot]` before setting it; a
  human/mixed/structural diff still fails presence normally. Never set it
  for commit/push execution.
