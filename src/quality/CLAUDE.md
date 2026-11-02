# quality module

Domain module: multi-language lint + unit test. Auto-detects Go, Node, Python, .NET from marker files.

## Entry function

```go
func (m *Quality) Check(
    ctx context.Context,
    src *dagger.Directory,
    commitSha, branch, repoUrl string,
    // optional
    include []string,       // override language detection: go, node, python, dotnet
    failOn string,          // CRITICAL|HIGH|MEDIUM|LOW|NONE (default HIGH)
    npmFeedUrl string,      // internal npm registry
    npmFeedRouting string,  // registry (default) | npmrc: token only, project .npmrc routes scopes
    npmToken *dagger.Secret,
    nugetFeedUrl string,    // internal NuGet feed
    nugetToken *dagger.Secret,
    minCoverage float64,    // 0 disables the coverage gate (default 0)
    coverageMinLines int,   // skip the gate below this many coverable lines
    lintOnly bool,          // skip the per-language test step (BYO test, ADR-002)
) (*dagger.File, error)     // evidence.json
```

## Run locally

```sh
cd src/quality && dagger develop   # once, to generate SDK
dagger -m ./src/quality call check \
  --src ./testdata/go-app \
  --commit-sha local --branch main --repo-url https://example.com \
  export --path /tmp/evidence.json
```

## Key files

- `main.go` — `Check()`: the container calls only — it detects, runs each
  language's lint and test leg, and hands the results to the fold below
- `checkinputs.go` — **untagged**: `validateCheckInputs()`, the three refusals
  `Check` makes before any container runs, in the order it makes them
- `checkfold.go` — **untagged**: `checkFold` (`addLint`, `addTest`,
  `foldCoverage`) and `buildCheckEnvelope()` — the non-run verdict, the
  per-tool rows, the findings sum, the coverage gate loop and the ungated
  outcome, out from behind the Dagger build tag where a nil leg envelope was
  one line from a panic and the coverage gate was structurally unfailable
- `sarifmerge.go` — **untagged**: `mergeSARIFReports()`, the per-language
  SARIF documents under one header
- `lint.go` — per-language lint runners (golangci-lint, ESLint, pylint, dotnet-format)
- `pylinttargets.go` — **untagged**: which `.py` files the pylint leg lints
  (cicd lists them; hidden dirs, `node_modules`, `__pycache__`,
  `site-packages` and virtualenvs are pruned and named), the script that hands
  pylint exactly that list, and `lintOutcome` (a clean lint over zero files is
  SKIPPED). ESLint and pylint report `Examined` in files; golangci-lint and
  `dotnet format` report none, by design — neither gives a count cheaply. See
  [specs/say-how-much-the-lint-legs-read.md](../../specs/say-how-much-the-lint-legs-read.md)
- `test.go` — per-language test runners (go test, vitest, pytest, dotnet test)
- `testcounts.go` — conservative runner-summary parsers and complete-only
  per-language aggregation for native and caller-owned tests.
- `markers.go` — the language marker-file list, the `find` predicate generated
  from it, and the suffix classification of what it returns (untagged,
  unit-tested; byte-identical with `src/build/markers.go`, which a
  `synced_files` group in `scripts/repo-inventory.json` enforces)
- `gating.go` — `gatedPassed()`, byte-identical with the security and risk
  copies and enforced the same way; `legfold.go` holds the quality-only
  `prefixErrors`, `byoLegOutcome` and `byoTestLegOutcome` (untagged, unit-tested)
- `testlegrun.go` — `foldTestLeg()`, how every test leg (go, vitest, pytest,
  BYO) turns its exit sentinel into a result. Only a numeric exit is a result;
  an empty or garbage sentinel is a non-run, never `failed (exit )`, which NONE
  used to pass. `pytestNonRun`, `vitestNonRun` and `goTestNonRun` then
  reclassify the exits each runner uses for "no result": a Go package reported
  `[build failed]`/`[setup failed]` makes the leg a non-run that ran on part of
  the module (native and BYO), and a native `go test` that printed no package
  verdict did not run at all. See
  [specs/a-package-go-could-not-build-is-not-a-failing-test.md](../../specs/a-package-go-could-not-build-is-not-a-failing-test.md).
  A vitest leg whose project has no vitest installed is a non-run too: the
  script (`vitestcoverage.go`) never fetches one (`npx --no`) and pins the
  coverage provider to the project's vitest. `vitestSuiteNonRun` makes a run
  with a `Failed Suites` block (a file vitest could not load, or a hook that
  threw) a non-run naming the files, even beside a failing test; the counts of
  the files that ran are quoted, never reported as the suite's. See
  [specs/a-runner-that-never-started-is-not-a-failing-suite.md](../../specs/a-runner-that-never-started-is-not-a-failing-suite.md).
  `eslintreport.go` and `pylintreport.go` hold the matching `foldEslintRun`/`foldPylintRun`; `nonrun_matrix_test.go` runs every fault
  against every threshold (untagged, unit-tested)
- `nodeproject.go` — which directory the Node legs run in (see "The Node legs run where the project is")
- `byotest.go` — `Test()`: the witnessed BYO test entry point (the container
  calls only: detection, toolchain resolution, the .NET sweep, `runTestLeg`,
  the baseline read) and its per-leg container work
- `byotestexec.go` — **untagged**: `byoTestArgv()`, the exec that runs the
  consumer's test command as its own script (`sh -c "$1"`), never spliced into
  cicd's; its test runs the real wrapper under `sh`
- `byotestplan.go` — **untagged**: `validateTestInputs()` (every refusal Test
  states before a container is built, in the entry's order),
  `applyPreparedLeg()` (binds the prepared container to the one leg that shares
  it; refuses metadata naming no leg, disagreeing with a leg's image, or
  arriving without a container), `singleContainerWarning()` and
  `testPlanWarnings()` (what resolution alone can say)
- `legschedule.go` — **untagged**: `runLegsBounded()`, the legs under
  `--parallelism` (1–4, default 1 = one after another). Each slot writes its
  outcome by declaration index and stamps the leg's `Duration`; a leg the
  bound never started (cancelled context) is an error, never an envelope row.
  The fold runs afterwards in declaration order, so the evidence differs
  between a sequential and a concurrent run only in `durationMs`
  and the legs' containers differ from each other by `CICD_TEST_LEG` (the
  engine runs identical definitions once). `prepare.go`'s `commandCaches`
  mounts the NuGet packages volume `CacheSharingModePrivate`, because two
  concurrent cold restores into a shared volume race on NuGet's temp files
  (its lock is container-local); `nugetcachesharing_test.go` guards it
- `concurrency.go` — generated copy of `src/internal/concurrency/concurrency.go`
  (`ValidateParallelism`, `RunBounded`), regenerated by
  `scripts/sync-concurrency.py` and guarded by `check_generated_files`; never
  edit it here
- `byotestfold.go` — **untagged**: `legOutcome`, `byoTestFold` (`addLeg` files
  one leg's result: rows, prefixed lines, coverage keyed by language, the
  per-leg report and the .NET scope sentence), `baselineDoc` and
  `buildTestEnvelope()` (unwitnessed languages, the fail-open baseline parse,
  the ratchet, the verdict). A leg that did not run fails at every threshold;
  a ratchet regression folds in as FAILED
- `testlegs.go` — the `--test-legs` document, the coverage fold and the
  detected/witnessed/unwitnessed rules (untagged, unit-tested)
- `services.go` — a test leg's dependency services: the schema, the alias and
  limit rules, the alias→`CICD_SERVICE_*` mapping, the readiness script, the
  per-service report and every sentence a service failure puts in `errors[]` or
  `warnings[]` (untagged, unit-tested)
  Every service container carries the `dev.cicd.test-leg-service` label keyed
  by leg and alias. The engine dedupes identical service definitions, so
  without it two concurrent legs declaring the same database share one
  instance; measured with a Redis `INCR` probe, the second leg read 2
- `dotnettoolchain.go` — which SDK image a BYO .NET command runs in, from the
  same band request `quality.Check`'s legs read (untagged, unit-tested). The BYO
  leg used to resolve through `ResolveToolchainDetail`, which reads `global.json`
  and nothing else, so a `net10.0` repository with no `global.json` ran its tests
  in `sdk:8.0` and every project answered `NETSDK1045` — a leg that could not
  run, disclosing nothing, because an *absent* version file carries no `Note`.
  See [specs/run-a-byo-test-in-the-sdk-the-repository-needs.md](../../specs/run-a-byo-test-in-the-sdk-the-repository-needs.md)
- `goproject.go` — which directories the Go lint leg runs in: `go.work` `use`
  directives or discovered `go.mod` dirs (untagged, unit-tested)
- `golangcireport.go` — golangci-lint run-error classification, observed-version
  parsing, SARIF driver stamping (untagged, unit-tested)
- `goworkspace.go` — shared `go.work` `use` parser, used by both the Go lint leg
  and the Go test leg so the two cannot disagree about scope
- `dotnetband.go` — SDK band selection: the band request read from
  `global.json` or a literal `TargetFramework`, and the resolution to a pinned
  band (untagged); a **byte-identical copy** of `src/security/dotnetband.go`,
  declared under `synced_files`
- `dotnetreport.go` — .NET target discovery, run-error classification, TRX and
  cobertura parsing, and the `dotnet format --report` → SARIF parser (untagged,
  so `go test -tags unit_test` reaches it). The parser's uri is `FilePath` with
  `dotnetSrcMount` stripped, never the bare `FileName` — with the name alone,
  same-named files in different folders collapsed into one finding at the
  aggregator (~2,800 of over 200,000 on one consumer run); a fallback to the name is
  counted into `warnings[]`.
- `dotnetrunner.go` — which `dotnet test` CLI the repository asks for
  (`global.json`), the argv each runner needs, the cobertura glob and the
  Microsoft.Testing.Platform exit map (untagged, unit-tested)
- `dotnetexec.go` — the .NET container: SDK base, private-feed wiring, target
  discovery, runner discovery, observed SDK version
- `dotnetoutput.go` — when a `dotnet test` exit is not explained by its `.trx`,
  the bounded tail and matched failure signatures kept in `genericReport`
  (`dotnet-test-output/1.0`), and the caps (untagged, unit-tested)
- `redact.go` — `scrubCredentials`, the one door every quoted or kept line of
  tool output passes before it reaches the envelope (untagged, unit-tested)
- `diagnostics.go` — wraps each leg's `genericReport` payload under its format
  key for `Check`'s aggregate (`quality-diagnostics/1.0`)
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go` (sync with `make sync-schema`)

## Constraints

- Returns a single aggregated evidence envelope covering all detected languages: `languages` lists what was detected, per-language lint SARIF documents are merged into `sarifReport`, and per-language coverage lands in `coverageByLanguage`.
- Test failures surface via `passed=false` and `errors[]`, not as findings — `findingsCount`/`findingsBySeverity` count lint/scan findings only.
- The evidence and SARIF driver report the ESLint version that actually ran
  (`eslintVersionLabel`), or `unknown` — never a constant. There is no `eslintVersion`
  in `images.go`: the version belongs to the consumer's lockfile.
- The ESLint script is `eslintScript(pm, install bool)` (`eslintreport.go`). It
  resolves ESLint through the project's package manager (`npx --no -- eslint`,
  or `yarn eslint` under yarn berry; never fetched), writes 127 itself when none
  resolves, and records the install's exit so `eslintRemedy` names a failed
  install instead of sending the reader to `devDependencies`.
- Both auto Node legs install with the project's own package manager
  (`nodeinstall.go`, detected per project by `nodedetect.go`): `packageManager`
  first, then the lockfile. pnpm and yarn come from corepack in the node image,
  so the image stays below Node 25 (renovate.json). Installs are frozen
  (`npm ci`, `--frozen-lockfile`, `--immutable`) whenever a lockfile exists, and
  every one runs with lifecycle scripts off. A project whose manager is
  ambiguous (two lockfiles, `packageManager` contradicting the lockfile, yarn
  berry without `packageManager`) is a named non-run, never a guess. The private
  feed reaches npm and pnpm (`NPM_CONFIG_*` and `PNPM_CONFIG_*`); yarn gets
  none, and a warning says so. Spec:
  [install-with-the-projects-package-manager.md](../../specs/install-with-the-projects-package-manager.md).
- `npmFeedRouting` picks how the npm feed is applied. `registry` (the default)
  makes it the registry for every package, which needs a feed that proxies the
  public registry. `npmrc` binds only the token to the feed's host and leaves
  routing to the project's `.npmrc` (`@scope:registry=<feed>`), for a feed with
  no public upstream; pnpm ignores a scoped registry from the environment, so
  cicd cannot set the route itself. The auto Node legs warn when that `.npmrc`
  routes nothing to the feed. Spec:
  [route-npm-scopes-through-the-projects-npmrc.md](../../specs/route-npm-scopes-through-the-projects-npmrc.md).
- Pure .NET logic lives in `dotnetreport.go` (untagged, unit-tested); the
  container work is in `dotnetexec.go`. Target discovery runs in `alpineImage`,
  not the SDK image — a filesystem question must not depend on the SDK being
  usable. The test-project markers are one POSIX-ERE list shared by the container
  `grep` and the Go matcher, so the shell rule and the tested rule cannot drift.
- `--fail-on NONE` collects findings without failing the pipeline, and **only
  findings**. It used to suppress run failures too: the threshold was checked
  before anything else, so a linter that never executed recorded its cause in
  `errors[]` and still reported `passed=true`. That put the false pass back one
  layer above the classification built to stop it, on the exact setting a team
  reaches for while onboarding — when nobody yet knows what a working run looks
  like. `gatedPassed(ran, severityOK, threshold)` now gates `severityOK` alone;
  `ran=false` fails at every threshold.
- Private feed credentials (`npmToken`, `nugetToken`) are passed as Dagger secrets, never as plain strings.

The rules this module was built against, each measured as a false pass before
it was fixed, live in
[docs/explanation/doctrine-quality.md](../../docs/explanation/doctrine-quality.md).
Read the rule, and the spec it links, before changing the code it names. One
line per rule:

- [A linter that could not run must not read as "no findings."](../../docs/explanation/doctrine-quality.md#a-linter-that-could-not-run-must-not-read-as-no-findings)
- [The Node leg lints what the consumer configured, with the consumer's own ESLint](../../docs/explanation/doctrine-quality.md#the-node-leg-lints-what-the-consumer-configured-with-the-consumers-own-eslint)
- [The Node legs run where the project is, not at the mount root](../../docs/explanation/doctrine-quality.md#the-node-legs-run-where-the-project-is-not-at-the-mount-root)
- [A leg that emits several same-tool SARIF runs stamps each with its identity](../../docs/explanation/doctrine-quality.md#a-leg-that-emits-several-same-tool-sarif-runs-stamps-each-with-its-identity)
- [The Go lint leg had never run — on any repository, ever](../../docs/explanation/doctrine-quality.md#the-go-lint-leg-had-never-run--on-any-repository-ever)
- [For golangci-lint, only the exit status is trustworthy — a valid report is not proof of a run](../../docs/explanation/doctrine-quality.md#for-golangci-lint-only-the-exit-status-is-trustworthy--a-valid-report-is-not-proof-of-a-run)
- [The Go lint leg runs per module, and `go.work` outranks discovery](../../docs/explanation/doctrine-quality.md#the-go-lint-leg-runs-per-module-and-gowork-outranks-discovery)
- [The golangci-lint version in evidence is the one that ran](../../docs/explanation/doctrine-quality.md#the-golangci-lint-version-in-evidence-is-the-one-that-ran)
- [The .NET legs had the same defect in four places, all measured](../../docs/explanation/doctrine-quality.md#the-net-legs-had-the-same-defect-in-four-places-all-measured)
- [The SDK is pinned once per band, and the band is read from the repository](../../docs/explanation/doctrine-quality.md#the-sdk-is-pinned-once-per-band-and-the-band-is-read-from-the-repository)
- [A target framework above the band that ran is named as such, in both legs](../../docs/explanation/doctrine-quality.md#a-target-framework-above-the-band-that-ran-is-named-as-such-in-both-legs)
- [Which `dotnet test` CLI ran is discovered, named, and never assumed](../../docs/explanation/doctrine-quality.md#which-dotnet-test-cli-ran-is-discovered-named-and-never-assumed)
- [An empty coverage report is not a 100% measurement](../../docs/explanation/doctrine-quality.md#an-empty-coverage-report-is-not-a-100-measurement)
- [Coverage documents are deduped on the measurement, not on the bytes](../../docs/explanation/doctrine-quality.md#coverage-documents-are-deduped-on-the-measurement-not-on-the-bytes)
- [And that note may claim only what the key compared](../../docs/explanation/doctrine-quality.md#and-that-note-may-claim-only-what-the-key-compared)
- [The .NET test leg names its denominator, on both branches](../../docs/explanation/doctrine-quality.md#the-net-test-leg-names-its-denominator-on-both-branches)
- [And a BYO leg names its denominator too, or a witnessed language reads as a witnessed repository](../../docs/explanation/doctrine-quality.md#and-a-byo-leg-names-its-denominator-too-or-a-witnessed-language-reads-as-a-witnessed-repository)
- [A coverage gate that could not measure must not read as satisfied](../../docs/explanation/doctrine-quality.md#a-coverage-gate-that-could-not-measure-must-not-read-as-satisfied)
- [`ran` travels beside the envelope, not inside it](../../docs/explanation/doctrine-quality.md#ran-travels-beside-the-envelope-not-inside-it)
- [An empty findings list is `[]`, never `null`](../../docs/explanation/doctrine-quality.md#an-empty-findings-list-is--never-null)
- [A test run that witnessed one of two stacks must not read like a test run that witnessed both](../../docs/explanation/doctrine-quality.md#a-test-run-that-witnessed-one-of-two-stacks-must-not-read-like-a-test-run-that-witnessed-both)
- [A test leg that needs a database gets one, and a database it could not get is a non-run](../../docs/explanation/doctrine-quality.md#a-test-leg-that-needs-a-database-gets-one-and-a-database-it-could-not-get-is-a-non-run)
- [A credential that could not be applied must not read as no credential](../../docs/explanation/doctrine-quality.md#a-credential-that-could-not-be-applied-must-not-read-as-no-credential)
- […and a working credential must not go over the wrong transport](../../docs/explanation/doctrine-quality.md#and-a-working-credential-must-not-go-over-the-wrong-transport)
- [An error naming one line of a long log is a claim, not evidence](../../docs/explanation/doctrine-quality.md#an-error-naming-one-line-of-a-long-log-is-a-claim-not-evidence)
- [A lint leg says how many files it read, and a file pylint could not read is not a finding](../../docs/explanation/doctrine-quality.md#a-lint-leg-says-how-many-files-it-read-and-a-file-pylint-could-not-read-is-not-a-finding)
