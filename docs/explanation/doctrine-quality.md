# The quality doctrine

The rules the `quality` module was built against, each measured as a false
pass before it was fixed. They belong with [the engineering doctrine](./doctrine.md);
the module's layout, entry functions and key files are in
[src/quality/CLAUDE.md](../../src/quality/CLAUDE.md).

## A linter that could not run must not read as "no findings."

The Node leg used
to end in `2>/dev/null || true`, so an ESLint that never executed — npx unable to
resolve the binary in a monorepo with no root `package.json`, a bad config —
produced an empty report that parsed as clean and passed the gate with nothing in
`errors[]`. `eslintRunError` (`eslintreport.go`) now classifies the exit status:
ESLint's contract is 0 = no problems, 1 = problems reported, ≥2 = could not run,
and npx contributes its own codes (127) on top. Anything else, or a 0/1 exit with
an empty report, lands in `errors[]` and fails the gate. `parseEslintJSON`
returning nil means "not an ESLint report", never "no findings".

## The Node leg lints what the consumer configured, with the consumer's own ESLint

It runs bare `npx --no -- eslint --format json .` — no config flags. It used
to run `--no-eslintrc --env browser,node,es2021 --rule '{"no-undef":"error"}'`, i.e.
cicd's own single-rule lint with the repository's real config, plugins, severities
and overrides all discarded; and since ESLint 9 removed `--no-eslintrc` and `--env`,
that command exits 2 with an empty report on any flat-config repo, so the leg could
not run at all there. Bare invocation works on both config eras (measured on 8.57.1
and 9.39.5). Plain `npx` is deliberately not used: it would fetch an unpinned ESLint
from the network when the repo has none, making the gate's verdict come from a
version nobody chose. `npx --no` refuses the fetch and resolves the way node does, up
through an npm workspace root, where the install hoists a member's ESLint (measured:
`./node_modules/.bin/eslint` in the member exited 127 on a project that declared it).
Project detection lints the topmost `package.json` today, so that case needs a leg
run inside a member; the resolver is the vitest leg's, so the two cannot disagree
once one does.
When nothing resolves, `eslintScript` records exit 127 itself — `npx --no` reports a
package it will not fetch as exit 1, which is ESLint's own "found problems" — and
`eslintRunError` says so with the remedy, chosen by the install's recorded exit: a
failed install names its exit and says to fix the install; a clean one says add
ESLint to `devDependencies`, point `--src` at the directory holding `package.json`, or
drop `node` from `--include`; on a prepared container, where cicd ran no install, it
says it cannot see the install and names both. A JS repo with no ESLint therefore
fails the gate rather than passing on a lint that never happened; that is the
intended trade-off.

## The Node legs run where the project is, not at the mount root

Language
detection searches for marker files to depth 4 and then threw the *location*
away, so both Node legs were pinned to `/src`. On a monorepo whose
`package.json` lives in a nested directory, `node` was detected and then linted at a root
with neither `package.json` nor `node_modules`: measured on that layout, ESLint
exited 127 and vitest exited 1 after `npx` fetched an unpinned vitest to run
against a tree with no tests — a red gate whose message points nowhere near the
problem. `resolveNodeProjects` (`lint.go`) now feeds both legs from one search,
and `nodeProjectDirs` (`nodeproject.go`) picks the directories: every
`package.json` with no package-bearing ancestor is a project.
- A root `package.json` beats everything, which is what npm/pnpm/yarn
  workspaces need — the root config governs the whole tree and the hoisted
  ESLint lives in the root `node_modules`.
- Without a root package, unrelated project roots are all kept even when they
  sit at different depths. A nested package is suppressed only when another
  discovered project directory is its ancestor. Each independent project is
  linted and tested and the results are merged: SARIF runs
  concatenated, severity counts summed, coverage weighted by coverable lines
  (`mergeNodeCoverage` — an unweighted mean lets a 100%-covered 5-line project
  drag a 40%-covered 5000-line project up to 70% and clear a 60% gate).
  `tool.version` lists every distinct ESLint that ran; per-project versions stay
  exact on each SARIF run's driver.
- `node_modules`, `bower_components` and `.yarn` are excluded — a `package.json`
  inside one describes a dependency, and without the filter a repo whose only
  `package.json` is vendored gets cicd linting its own linter's source. Build
  output (`dist/`, `build/`, `.next/`) is deliberately **not** excluded:
  skipping a directory means reporting less than the tree holds, and a repo that
  generates `dist/` normally has a package-bearing ancestor that governs it.
  ESLint's own ignore config is the consumer's lever otherwise.
- More than `--node-project-limit` (default 4) independent projects is an
  **error**, not a truncated run — each project costs its own dependency install, and
  linting 4 of 30 while reporting no findings is the false pass this module
  exists to prevent. The message names the projects and the remedy.
- Where the legs ran is recorded in `warnings[]`, including the project directory
  and the absence of a root package, so the evidence says where the verdict came
  from. Measured on the nested source-owned Node fixture: ESLint 8.57.1 ran,
  3 HIGH findings, 75% coverage — against 0 findings, no coverage and two
  `errors[]` entries before. A flat repo is byte-identical to before, warnings
  included.

## A leg that emits several same-tool SARIF runs stamps each with its identity

Since 2025-07-22 GitHub Code Scanning keys a run on (tool driver name, category)
and rejects an upload whose runs collide — and the multi-project Node leg, the
multi-module Go leg and the solution-less .NET leg each produce exactly that:
N runs, one driver name. `stampSARIFAutomationID` (`sarifdoc.go`) writes
`automationDetails.id = cicd/<tool>/<dir>` on each run when a leg produced more
than one; upload-sarif's `category:` input fills only runs without one, so
stamped runs keep their id as their category and single-run repos keep the
workflow category they always had (no alert re-keying). The id comes from the
project directory, never an ordinal, so adding a project does not shift its
siblings' identities. Same tolerance as `stampSARIFDriverVersion`: unparseable
bytes return untouched. See
[specs/one-sarif-run-per-category.md](../../specs/one-sarif-run-per-category.md).

## The Go lint leg had never run — on any repository, ever

It asked v1.57.2 for
`--out-format sarif`: `--out-format` is a v2 flag name and `sarif` is a v2 format,
so the two halves came from different major versions and every invocation died on
flag validation (exit 3, `unsupported output format "sarif"`, a zero-byte report).
The trailing `|| echo '{"version":"2.1.0","runs":[]}'` then wrote a clean report and
left the *shell* exiting 0, so Go saw no error, an empty severity map and
`ran=true`. v1.57.2 was dead a second way too — built with go1.22.1, it cannot load
export data from a current toolchain. CI and `src/internal/.golangci.yml` had both
moved to v2 while `images.go` stayed on v1; the module shipping Go linting to
consumers was the only place that never did. Now `golangciImage` is v2.12.2 and the
leg is proven by a real run against a planted violation, not by unit tests alone.
See [specs/prove-the-go-lint-leg-ran.md](../../specs/prove-the-go-lint-leg-ran.md).

## For golangci-lint, only the exit status is trustworthy — a valid report is not proof of a run

Measured on v2.12.2 pointed outside its workspace: it prints
`0 issues.`, writes a schema-correct SARIF document with an empty `results` array,
and exits 7. Those bytes are byte-for-byte what a clean tree produces, so no amount
of report inspection can tell the two apart. `golangciRunError` therefore treats
**only** exit 0 as a run (`--issues-exit-code 0` keeps findings out of the status,
so there is no equivalent of ESLint's legitimate exit 1), and additionally requires
the document to be SARIF — an empty file, non-JSON, bare `{}` or zero runs are all
non-runs. Each message carries the remedy for the failure mode it matched: v1
config schema, out-of-workspace scope, unsupported output format, stale toolchain.

## The Go lint leg runs per module, and `go.work` outranks discovery

`resolveGoModules` (`lint.go`) prefers a root `go.work`'s `use` directives and
otherwise discovers every `go.mod`; `goModuleDirs` (`goproject.go`) keeps **every**
module, including modules nested beneath another. That differs from
`nodeProjectDirs` because a discovered Node project governs package directories
beneath it, while a `go.mod` is a module boundary and `go list ./...` does not
descend past one. A root Go module therefore governs nothing beneath a nested
module, and keeping only top-level modules would leave work unlinted while
reporting success.
`vendor/`, `testdata/` and `.`/`_`-prefixed segments are skipped because the go tool
skips them — a linter reporting on code the build never sees describes nothing.
More than `goModuleLimit` (8) modules is an **error** with `ran=false`, never a
truncated lint. The directories linted and where that answer came from always land
in `warnings[]` (`linted 1 Go module(s) from go.work: src/internal`), so the scope
is auditable rather than implied. The `use` parser is shared with the Go *test* leg
(`goworkspace.go`) so the two legs cannot describe different repositories.

## The golangci-lint version in evidence is the one that ran

`golangciVersionLabel` parses `golangci-lint --version` and returns `unknown` when it
cannot — never `golangciVersion`. `stampSARIFDriverVersion` writes it onto each SARIF
run's driver, which is where the Node leg keeps its per-project ESLint version too,
and the only per-leg structure that survives aggregation: `Check` folds every leg
into one envelope whose `Tool` is a bare `{"name":"quality"}`.

## The .NET legs had the same defect in four places, all measured

`dotnet` is
the worst offender because both of its tools exit 0 on work they never did.
- `dotnet format` ended in `|| true` with an `|| echo '[]' > report` fallback, so
  exit 1 (restore failure) and exit 145 (`global.json` naming an SDK the pinned
  image does not carry) produced the same envelope as a clean tree.
  `dotnetFormatRunError` now treats **only** exit 0 and 2 as runs and requires a
  non-empty report — a clean run writes `[]`, so an empty read means the tool
  wrote nothing.
- `dotnet test` was invoked at the source root. MSBuild resolves the single
  project in the working directory and does **not** recurse, so a repo whose
  root project is not a test project ran zero tests and exited 0. Targets are
  now discovered explicitly and a non-test project is never handed to
  `dotnet test`; a run must produce a parseable `.trx` accounting for ≥1 test.
  `IsTestProject` is matched as `IsTestProject>[[:space:]]*true` — as a bare
  substring it also matched `<IsTestProject>false</IsTestProject>`.
- `--collect:"XPlat Code Coverage"` inside a `sh -c` body word-splits into three
  arguments, so the collector name became `XPlat` and no cobertura report was
  ever written — silently, exit 0. Written as `"--collect:XPlat Code Coverage"`.
  The collector also needs `coverlet.collector`; `Microsoft.NET.Test.Sdk` does
  not pull it in, and without it `dotnet test` logs
  `Could not find data collector` and still exits 0.
- `Tool.Version` reported the compile-time pin constant (then
  `dotnetSDKVersion`, since replaced by the per-band constants below), so it
  described the pin rather than the SDK that ran. It is now read from
  `dotnet --version` inside the container.

## The SDK is pinned once per band, and the band is read from the repository

A .NET SDK image carries its band in the tag: `sdk:8.0` cannot restore `net10.0`
at all, and the failure is a *non-run*, which no `--fail-on` threshold forgives.
So a single pin never meant "cicd defaults to 8.0", it meant cicd could not lint
or unit-test any consumer above 8.0 — every `net9.0`/`net10.0` repository failed
the source gate on cicd's own image choice. `images.go` now pins one
digest per band (`dotnetSDK80Image`, `dotnetSDK100Image`), `dotnetSDKBands`
(`dotnetreport.go`) is the ordered list, and `dotnetSDKBase` (`dotnetexec.go`)
maps a band to its image. Adding a band means all four: the constant pair, the
list, a `case` in that switch, and a `scripts/runtime-images.json` entry.
- **Raising the one pin instead was rejected**, because it moves the same wall the
  other way: the 10.0 SDK ships no 8.0 targeting pack, so every `net8.0` consumer
  would acquire a package dependency on a currently offline leg, and
  `dotnet format`'s analyser defaults would change under every .NET verdict this
  repo has produced. Both bands side by side keeps `net8.0` byte-identical.
- **`dotnetSDKBase` is a `switch` over constants and must stay one.**
  `scripts/check-runtime-image-pins.py` resolves each `From(...)` argument through
  package constants and local literals and classifies what it cannot resolve as an
  ADR-004 consumer-resolved toolchain, which it never fails. So
  `From(dotnetSDKImages[band])` would *pass* the pin gate by looking like the one
  thing the gate exempts, while cicd's own tool image went unpinned. The tidier
  spelling is the one that silently switches the check off.
- **The band comes from the repository, not from a flag.**
  `discoverDotnetBandRequest` reads `global.json`'s `sdk.version` first, else the
  highest literal `net<major>.<minor>` across `*.csproj` and
  `Directory.Build.props` (the monorepo's usual home for it, and where cicd was
  most likely to be blind). `dotnetResolveBand` then picks the **lowest pinned
  band at or above** the request, records which and why in `warnings[]`, and
  resolves nothing-readable to the lowest band — so a `net8.0` consumer keeps the
  exact image, analysers and digest it had. 9.0 is deliberately not pinned (STS,
  out of support); `net9.0` routes to 10.0.
- **A band above everything cicd pins still fails loud.** It runs the highest
  pinned band with a warning saying so — not a silent fallback: if the build
  really needs the higher band the restore dies, `dotnetFormatRunError` /
  `dotnetTestRunError` classify it a non-run, and `gatedPassed` fails it at every
  threshold, `NONE` included. Refusing up front on a project-file string was
  rejected for the same reason the enrichment below is enrichment-only. A band
  reaching `dotnetSDKBase` with no image is `dotnetUnpinnedBandError` and `ran=false`;
  there is no `default:` arm, because a verdict attributed to an SDK nobody
  selected is the false pass this module exists to prevent.

## A target framework above the band that ran is named as such, in both legs

`dotnet format` does not relay NETSDK1045 at all (measured: only "Restore
operation failed"), so `dotnetTFMAboveBand` reads the literal
`net<major>.<minor>` values out of the `<TargetFramework(s)>` elements and
compares them to the band that ran. `dotnet test` *does* relay it, but exits
**1** — its "tests failed" code — so the remedy hangs off the wrote-no-`.trx`
branch, not the did-not-run branch. The remedy now points at `global.json`'s
`sdk.version` as the *selector* among the pinned bands, which is what it became
once more than one band exists — before, pinning a newer SDK there was the
instinctive fix and it swapped a legible error for exit 145, so the message ruled
it out explicitly. The project read only ever *enriches a failure that already
happened* — a `TargetFramework` can come from an MSBuild property or a condition
this cannot see, so it must never be able to fail a run on its own. See
[specs/name-the-dotnet-target-band.md](../../specs/name-the-dotnet-target-band.md)
and its amendment.

## Which `dotnet test` CLI ran is discovered, named, and never assumed

VSTest and Microsoft.Testing.Platform are two mutually exclusive command-line
surfaces, and on the .NET 10 SDK an MTP project cannot be driven through the
VSTest target at all — measured on 10.0.400: exit 1 with *"Testing with VSTest
target is no longer supported"* without the opt-in, exit 5 with
`Unknown option '--logger'` with it, and exit 1 the other way round when a
VSTest project sits under an MTP opt-in. All three are non-runs, i.e. a
permanent red on a legitimate repository at every `--fail-on`.
`discoverDotnetTestRunner` (`dotnetexec.go`) reads the repository-root
`global.json` in the same cheap `alpineImage` probe as target discovery and the
band, and `dotnetRunnerFromGlobalJSON` / `dotnetTestArgs` / the exit map live in
`dotnetrunner.go` (untagged, unit-tested).
- **`global.json`'s `"test": {"runner": …}` is the only selector.** It is
  matched case-insensitively and it is repository-**wide** — there is no
  per-project form, which is why the warning says so. `dotnet.config`'s
  `[dotnet.test.runner]` is measured *not* honoured on 10.0.400, and
  `IsTestingPlatformApplication` was rejected as a probe on three measurements:
  it describes what a project *is* rather than what the CLI parses, it fails
  with MSB1063 on a solution, and on a cold NuGet cache it returns empty —
  an answer that looks like `false`.
- **An unreadable opt-in is an error, not a default.** Malformed JSON or an
  unsupported runner name yields no envelope-level guess; `dotnetTestArgs`
  returns `nil` for an unresolved runner and has no `default:` arm, because an
  invocation nobody selected is the false pass this module exists to prevent.
  (The SDK agrees: a bad value makes *every* `dotnet` command throw.)
- **Every flag is an argv element**, delivered through `sh -c script sh "$@"`.
  That is what keeps `--collect:XPlat Code Coverage` from re-splitting into
  three arguments and silently collecting nothing at exit 0.
- **The coverage harvest globs `*.cobertura.xml`.** MTP writes
  `<guid>.cobertura.xml`; the literal coverlet filename matched **0 files** over
  a pooled run holding two reports. `--coverage-output` is never passed — the
  guid is the collision avoidance, and pinning the name makes two applications
  write one path — there is no `-maxdepth`, since that would be right for the
  pooled layout and silently wrong for the per-project one, and
  `--coverage-output-format cobertura` is mandatory because bare `--coverage`
  exits 0 writing a binary report. Every document appears twice (pool root plus
  `.trx` attachment), so `parseCoberturaSet`'s dedup is load-bearing: attachment
  copies must collapse into single measurements.
- **A BOM is why the `coverageGlob` path found documents but merged none.** MTP
  writes every cobertura with a UTF-8 BOM, and `strings.TrimSpace` does not
  remove one — U+FEFF left Unicode's `White_Space` property in 4.0.1, so
  `unicode.IsSpace` reports false. `sniffCoverageReport` picked its parser from
  the first character of the trimmed text, so a BOM'd document began U+FEFF
  rather than `<` and no arm of the switch fired. `parseCobertura` is innocent
  — `xml.Unmarshal` strips the BOM itself — which is also why cicd's own .NET
  leg never hit it: `parseCoberturaSet` calls the parser directly and never
  goes through the sniffer. `stripBOM` runs **before** the switch and not inside
  its XML arm, because the JSON arm has identical exposure the moment any tool
  writes a BOM'd json-summary, and a document carrying two BOMs stays malformed
  rather than being laundered into a measurement. Under it sat the defect that
  let it ship: nothing parsing produced warnings and no errors, so the leg
  recorded `ratchetSkipNoCoverage` — **fail-open by ADR-003 design**, and right
  for a consumer who configured no coverage, but it says *there was nothing to
  measure* about a run holding documents cicd could not read.
  It also misdescribed its own reason for skipping, which is the half that is
  invisible if only the merge count is read: the verdict moves from
  `skipped:no-coverage-output` — *the command produced no coverage report*,
  false about a command that produced reports — to `skipped:no-baseline`, which
  is true. The source-owned reproduction is `testdata/dotnet-mtp-app`. `coverageSetErrors` makes
  documents-found-and-none-read an `errors[]` entry; `Matched == 0` stays a
  warning, because a command that writes no report is legitimate and failing it
  is a permanent red with no remedy.
  And the leg label has exactly one owner now, `legPrefix` in the caller.
  `coverageSetWarnings` prefixing itself was wrong in both directions, not one:
  `legPrefix` returns `""` when the run has a single leg (pinned by
  `legPrefix("test-cmd", 1) == ""` — `test-leg test-cmd:` is nonsense), so with
  two or more legs the warning rendered `test-leg web: test-leg web: …`, and
  with one leg it was the **only** leg warning that carried a label at all while
  every sibling carried none. Removing it therefore *drops* the prefix from a
  single-leg run, which reads like a regression and is the rule being applied:
  measured before `stripBOM`, `test-leg dotnet: coverage pattern …`; after, no prefix,
  the same as every other warning that run emits. The doubling itself is
  visible inside a *single* multi-leg envelope: `coverageSetWarnings` lines
  carried the same leg prefix twice while sibling warnings carried it once —
  same leg count, same renderer — which localises the defect to the two owners
  rather than to anything about `legPrefix`.
- **The BOM path is proven by a real MTP run, and `passed` is not the
  assertion.** `scripts/smoke/mtp-byo-coverage.sh` (in the `module-test` quality
  cell) drives a BYO leg over `testdata/dotnet-mtp-app`. Measured before `stripBOM`,
  the same case reports `passed: true`, no `errors[]`, `coverageMeasured: false`
  and `matched 1 file(s), merged 0 document(s)` — so a test asserting `passed`
  would have gone green against the defect. The assertion is the merge count and
  the ratchet verdict. The leg passes `toolchainImage` explicitly because the BYO
  path resolves a .NET image from `global.json`'s `sdk.version` alone and this
  fixture carries only the runner opt-in; it is a bare tag, not a digest, because
  a leg image is ADR-004's consumer-resolved toolchain and
  `check-runtime-image-pins.py` scans `From(...)` in `src/` only, so a digest
  there would be a second copy of `images.go` no gate can hold in step.
- **`dotnetCoverageOutcome` keeps four states apart**, so "produced a report
  cicd failed to find" cannot read as "produced none": a cobertura found under
  `*/bin/*` while the results directory is empty is an **error that names itself
  a cicd defect**. The `coverlet.collector` remedy is VSTest-only — it cannot
  work under MTP, and a remedy that cannot work costs the reader a wasted change.
- **The MTP exit map is 0/1/2/5/8 with distinct diagnostics for 1, 5 and 8**
  (pinned by a test that fails if two collapse). Exit **2** is a real test
  failure, so the VSTest rule "anything outside {0,1} did not run" reported a
  broken test as a broken pipeline. Exit 1 does **not** assert the runner
  mismatch — a `.csproj` MSBuild cannot load exits 1 too (MSB4025) — so
  `dotnetMTPRunnerMismatch` gates that remedy on the SDK having said it. Exit 8
  is per *run*, not per project, and `--minimum-expected-tests 0` is
  deliberately never passed: it would silence the zero-test guard globally.
- **MTP test projects had to become detectable at all.** Every original entry in
  `dotnetTestMarkers` was VSTest vocabulary, so an MSTest 4 or xunit.v3 project —
  which references no adapter and no `Microsoft.NET.Test.Sdk` — was reported as
  "not a test project" and the whole runner path was unreachable from the shapes
  needing it. `Include[[:space:]]*=[[:space:]]*["']MSTest["']` and `xunit\.v3`
  are added; the MSTest one carries its attribute so it cannot match
  `MSTest.Analyzers` or `MSTest.Sdk`. `MSTest.Sdk` remains undetected and
  unmeasured, on purpose. See
  [specs/detect-the-dotnet-test-runner.md](../../specs/detect-the-dotnet-test-runner.md).

## An empty coverage report is not a 100% measurement

`parseCobertura` read
`line-rate` without asking whether anything had been counted, so a 178-byte
cobertura with `<packages />`, `line-rate="1"` and no `lines-valid` — what a
test project that instruments no code writes, under coverlet as well as MTP —
parsed as 100%, and `mergeDotnetCoverage` falls through to an unweighted mean
when no report carries a line count. An inflated figure is not merely wrong, it
is wrong in the direction that **survives a ratchet**: a deflated number is
noticed next run, an inflated one *sets the bar*. `ok=false` now when
`lines-valid` is absent, non-numeric or `<= 0` — the rule
`parseGoCoverprofile` already applied to its own zero-statement case. This must
land before or with any change that makes `--min-coverage` reachable from the
harnesses, never after, because a ratchet baseline recorded from a fabricated
100% cannot be retracted later.

## Coverage documents are deduped on the measurement, not on the bytes

Both harvests — `parseCoberturaSet` for cicd's own .NET leg, `buildCoverageSet`
for a BYO leg's pattern — drop repeats, because MTP writes each report twice:
once at the results-directory root and once under the trx attachment directory
(`In/<host>/`). Keying that on raw bytes was correct only by accident of how MTP
publishes an attachment. Observed attachment pairs are byte-identical, while
timestamps vary across project reports. As a hypothetical two-project example,
four files — each project's report plus its attachment copy — represent two
measurements. The pairs match byte for byte because the second member is a file
*copy*, not a second serialization. A release that serialized it instead would
put every project's reading into the fold twice: the coverable-line weighting
stays internally consistent, the percentage stays entirely plausible, and
`Duplicates` reads **0** — the evidence positively asserting no duplicate was
found. So the key is `coverageIdentity` (`coverageglob.go`), the document with
**every** `timestamp` attribute removed — the pattern is unanchored and carries no
element context, which is the behaviour wanted, since stripping more can only
merge more and no cobertura element carries a timestamp that distinguishes one
measurement from another. CAPS-023 and the comment above the pattern both said
"root", which the pattern never was; a test now pins the wider strip, because the
bounded-trade-off argument below is licensed by whichever of the two is true.
Shared by both harvests, so a rule holding in one cannot be assumed to cover the
other. The trade-off is bounded: two documents
differing in anything a number is derived from stay two readings, and an empty
cobertura contributes no reading at all. Amends CAPS-022 d04; see CAPS-023.

## And that note may claim only what the key compared

`duplicateNote` is the
one sentence in the harvest describing a check the reader cannot see, and it
shipped wrong twice in opposite directions. "byte-identical" was narrower than
the rule is run, sending a reader after a difference that need not exist.
Replacing it with `reporting the same measurement` overshot: the dedup happens
*before* `sniffCoverageReport`, so a harvest that merged no documents still
claimed its dropped duplicates were `reporting the same measurement` — a
measurement asserted beside the count saying none was obtained, false in an
evidence envelope about the document set that line exists to describe. Guarding the clause behind `Parsed > 0` is **not** the fix: it silences
the falsehood on the one harvest that produced it, leaves it wherever a parse
fails for another reason, and drops the count on the path a reviewer most needs
it. The dedup is a textual test, so the note states the textual fact —
`identical apart from any timestamp attribute` — which holds on every path, and
`TestDuplicateNoteClaimsOnlyWhatTheKeyCompared` fails on both the shipped
wording and the conditional variant. Note the inversion between the two bullets:
here the message drifted from the key, above the comment drifted from the code
while the message was already right. Same class, opposite direction.

## The .NET test leg names its denominator, on both branches

The warning used
to name what ran and nothing else, so all-of-them and two-thirds-of-them rendered identically —
and the ratio was already in hand, since `dotnetDiscovery` carries `Projects`
(every csproj) beside `TestProjects` (the classified subset).
`dotnetTestScopeWarning` now reports `ran N of M .csproj found under the source
root` and, when they differ, the skipped count plus
`dotnetTextualClassificationNote` — because the classification is a `grep` of
each project file **on its own**, so a test SDK or `IsTestProject` arriving from a
`Directory.Build.props` is invisible and a real test project reads as a non-test
project. A tree can rely entirely on an explicit `IsTestProject` property
when its test dependencies arrive through shared props; removing
`IsTestProject>[[:space:]]*true` then drops all those projects from the textual
classification. That is also why `dotnetNoTargetError`'s
advice is no longer "Add a test project" alone: the remedy named is **committing a
solution**, since `dotnetTestTargets` returns a solution *before* it consults
`TestProjects` and MSBuild resolves what a grep cannot see. Widening the marker
list was rejected — each addition fixes one shape forever and leaves the mechanism
intact — and so was discovering by "references `Microsoft.NET.Test.Sdk`", which on
a props-injecting tree classifies a shared test-helper project as a test project.
**Both** branches report scope from one function: a solution repository has no
ratio to report, so it says that no per-project classification was applied, or its
silence would be indistinguishable from a classification checked and found
complete. A warning, never a failure — cicd cannot know whether a project without
a marker should have had one. See CAPS-024.

## And a BYO leg names its denominator too, or a witnessed language reads as a witnessed repository

The bullet above closes this for cicd's own .NET leg;
`witnessedLanguages` left it wide open one function over. Witnessing is per
**language** — one leg naming `dotnet` makes `dotnet` witnessed — so a
consumer's command touching part of a .NET tree produced an envelope identical
in every field a reader looks at to one touching all of it. Measured on
`testdata/dotnet-mtp-app` (2 `.csproj`, 1 with a test marker) with a single BYO
leg: **before, one warning — about the ratchet — and no count anywhere**; after,
`projectsDiscovered: 2`, `testProjectsDiscovered: 1` and a `warnings[]` line
naming both. Without the scope fields, a command that drops part of the project
scope produces no scope warning at all. `dotnetLegScopeWarning` (`legscope.go`, untagged)
states the counts and **refuses the division between them, in the sentence** —
cicd cannot know how many projects a consumer's command should have run, the
identical bind `coverageSetWarnings` is in one file over, and a ratio would be a
false accusation on the two legitimate shapes (a command that merges its reports
into one, and a command deliberately scoped to a subset), so both are named. It
fires on **every** .NET BYO run: there is no mismatch to condition on, and the
silent case is the one being repaired — the same argument
`dotnetTestScopeWarning`'s solution arm already makes. Four mechanics are
load-bearing. The caveat is `dotnetBYOClassificationNote`, **not**
`dotnetTextualClassificationNote`, because that one ends by naming *committing a
solution* as the remedy and on this path the command already chose its scope —
a remedy that cannot work is the small version of the lie being removed.
`CoverageDocumentsMerged` is a **pointer**: nil is no patterned harvest, 0 is a
harvest that merged nothing, and `omitempty` on an `int` would have said
`merged 0` about a leg never asked for one. A sweep that **failed** reports that
(`dotnetLegScopeUnknownWarning`) rather than rendering as an empty tree. And the
depth the sentence quotes is `markerSearchDepth`, which also ends the three
copies of `-maxdepth 4` `dotnetexec.go` used to carry — sharing with detection
is the *correct* coupling, since two different depths would let a `.csproj`
between them make detection report `dotnet` present while the sweep reports
nothing to run. It fires on every run, and what makes that defensible is the
**field** rather than the warning — the counts are near-constant per repository,
so a reader habituates, and `projectsDiscovered` /
`testProjectsDiscovered` / `coverageDocumentsMerged` are what a comparison of
two envelopes can still read. Cite that narrow rule with its actor named — a
*consumer who chooses to compare envelopes*, because nothing in cicd diffs
those fields and a rule that omits the actor is satisfied by a field no
mechanism consumes. For example, moving test markers into a props file can
change `testProjectsDiscovered` without changing `projectsDiscovered` or the
coverage harvest. Deleting a project instead changes the discovered-project
count. Comparisons can help investigate that distinction, but offsetting
additions and other changes can make it ambiguous. cicd still emits a caveat
rather than the diagnostic, and the reason is a **scope decision on one path**,
not an impossibility — `Test` already takes `--baseline` and
`parseBaselineCoverage` accepts a full evidence envelope, so a prior envelope
is an accepted input here already and only `coverageByLanguage` is ever read
from it. What holds is narrower and enough: this *warning* is composed on the
single-run path, so it must not assert a two-run conclusion.
Node has the same gap and is left undone because
the *unit* is undecided (packages, workspaces, suites and test files are not
one quantity), not because the counting is hard.

## A coverage gate that could not measure must not read as satisfied

`main.go` used to `continue` past a language with no coverage figure, so
`--min-coverage` passed for any language whose report failed to appear — which,
because of the word-split above, was every .NET run. A missing figure is now an
error. `--lint-only` is exempt: it deliberately never runs the test leg.

## `ran` travels beside the envelope, not inside it

`lintLanguage` and
`testLanguage` return `(*envelope, bool, error)` because `Check` has to fold
the two verdicts up separately, and the sub-envelope `Passed` field cannot
carry both — under `NONE` a leg with findings and a leg that never ran would
otherwise arrive at the aggregate identically. The envelope has no `ran` field
because `schema.go` is a verbatim copy shared across every module, so adding
one is a wire change (worth doing — a consumer reading evidence still has to
infer a non-run from `errors[]` strings — but not in the same change as the
gate fix). Each leg's `ran` is `len(errs) == 0` where its `errs` hold only
run failures (both lint legs, `dotnet format`), or an explicit flag where they
do not (`dotnetTestResult.ran`, `runGoTest`/`runVitest`/`runPytest`, where a
non-zero exit is a real result and a container error is not) — `runVitestIn`
returns its `ran` alongside its `errs` for that reason, and `runVitest` folds a
false from any project up. A third case is `false` outright, where cicd
*declined* to run the tool: the Node project-count refusal above never started
a linter or a test runner, so no threshold may forgive it.

## An empty findings list is `[]`, never `null`

Each report builder declared
`var results []map[string]any` and marshalled the nil slice, so the *clean* case —
the common one — shipped `"results": null`. It is schema-invalid (SARIF 2.1.0
§3.14.23: `run.results` may be absent, but present means array, so a consumer
iterating it faults), and it is the wrong fact: `[]` says "ran, reported no
problems", `null` says nothing at all. That is the same distinction
`eslintRunError`/`golangciRunError`/`gatedPassed` exist to protect, given away in
the document a consumer actually reads. cicd's own readers survive it — Go
unmarshals `null` into a nil slice and iterates zero times — which is why it went
unnoticed until a real consumer's evidence was read byte by byte. All three
builders now go through `singleRunSARIF` (`sarifdoc.go`) so the invariant lives in
one place; `src/internal/sarif` initialises `Runs` and coerces a nil `results`; the
merge paths in `main.go` (here and in `security`) start from an empty runs array.
The pylint parser moved to `pylintreport.go` (untagged) in the same change — it was
the one producer no unit test could reach.

## A test run that witnessed one of two stacks must not read like a test run that witnessed both

`Test` took one `--test-cmd`, ran it in one container
and harvested one coverage report; the container came from `langs[0]`, i.e.
the first entry of the fixed order (go, node, python, dotnet) in
`autoDetectLanguages`. On a repository with both a `package.json` and a
`.csproj` the witnessed stack was therefore decided by an enum's ordering
rather than by anything about the repository — and the envelope said so
nowhere: it listed **every detected** language under `languages` and reported
`passed=true`. `--test-legs` (a JSON array of legs, each with its own label,
language, command, coverage report and optional image; mutually exclusive with
`--test-cmd`) makes the polyglot case expressible, but the load-bearing half
is the reporting: `languages` now lists what was **witnessed**, a
`genericReport` (`genericFormat: byo-test-legs`) carries the
detected/witnessed/unwitnessed triple as structure, and an unwitnessed
detected language always produces a `byo-test: NOT WITNESSED …` warning that
notify renders verbatim into the PR comment. It is a **warning, not
`passed=false`**: nothing failed to run, which is the case `lintLanguage`'s
default branch already settles ("nothing was asked of a tool, so nothing
failed to run", `ran=true`) and which the intent gate settles the same way —
an unasked gate reports loudly and does not fail. An error here would also
turn a version bump red for every repository carrying an incidental marker
file. Note that in the **aggregate** (`combined-evidence.json`) `languages`
cannot shrink, because `Check`'s envelope still lists everything detected and
the aggregator unions the two — so the warning line and the `genericReport`
are the only signals at that level, which is why they are unconditional.
Two smaller rules hang off the same principle: a run-wide `--coverage-path`
beside legs is an **error** (a leg names its own, so the path could not be
harvested and the coverage it promises would silently never be measured),
while a run-wide `--toolchain-image` beside legs is a **warning** — in the
commit composite that same flag also selects the archive build's image
(ADR-004), so refusing it would make `--artifact archive` and `--test-legs`
mutually exclusive for no reason. More than `testLegLimit` (8) legs is an
error, never a truncated run.

## A test leg that needs a database gets one, and a database it could not get is a non-run

An integration suite has nothing to talk to inside a leg
container, so affected tests fail at fixture initialisation rather than
exercising the application. A leg declares `services` (alias, image, port, optional `env`,
optional `readyCmd`/`readyTimeout`, at most `serviceLimit` 4 per leg) inside
the existing `--test-legs` document, so the capability costs no new parameter,
no contract change and no starter-surface wiring. The rules are in
`services.go`, **untagged** — `byotest.go` is `//go:build !unit_test` and keeps
only container wiring, which is the same split every rule in this module has
had to make to be testable at all.
- **The engine is the gate, and the probe is what makes its verdict
  attributable.** `WithServiceBinding` is lazy, but the engine holds the
  *dependent exec* until the service's exposed port answers; a service that
  never listens fails that exec after about two minutes with `service exited before
  healthcheck`. Bound straight to the leg, that verdict lands on the leg's own
  test command, where `invalid nil ref` is indistinguishable from a crashed
  suite. So each service is bound first to a throwaway `alpineImage` container
  running `echo` — not detection, attribution: the same healthcheck, with the
  failure named to one alias. The probe stays in the pinned image precisely so
  the *bind* verdict never depends on a consumer image having a shell.
- **A declared service that did not become usable is `errors[]` →
  `ran=false`.** `gatedPassed` then fails it at every threshold, `NONE`
  included, which is the whole point: the consumer runs `--fail-on NONE`, where
  a plain test failure is suppressible and a non-run is not. A warning here
  would be the founding doctrine given away on the setting that needs it most.
- **`readyCmd` runs in the service's own image.** The brief said pinned alpine
  and the brief was wrong: `pg_isready`, `redis-cli` and `mysqladmin` are not
  in alpine, so a readiness check confined there could express nothing beyond
  `nc -z` — the engine's port gate spelled by hand, which is exactly the claim
  `readyCmd` exists to improve on. The container is a *client* reaching the
  service across the binding, so the service still cannot vouch for itself;
  what its image supplies is the client binary.
- **There is no fallback to the engine gate.** A `readyCmd` that was asked for
  and never passed is an error, never a downgrade to `readyVia:
  engine-healthcheck`. `readyVia` is on every report because `ready: true`
  means two different things: under `engine-healthcheck` it means a port
  accepted a connection — a floor, not a verdict — and `servicesSummary` says
  so in `warnings[]`, but **only** when at least one service rested on that
  floor. A leg whose services all passed their own checks has nothing to
  disclose, and a line on every run is the `build.NoArtifact` noise rule.
- **The alias charset is stricter than `validLegLabel`.** It is bound as a DNS
  label (no `.`, no `_`, no uppercase) *and* upper-cased into
  `CICD_SERVICE_<ALIAS>_HOST`, where `db-1`, `db.1` and `db_1` all collapse to
  one variable name and would overwrite each other silently.
  `validServiceAlias` is lowercase `[a-z0-9-]`, letter-initial,
  alphanumeric-final. The env-prefix collision check is kept even though the
  charset makes it unreachable today — it is the guard that survives widening
  the charset.
- **Env values never reach the envelope**; `serviceReport.envKeys` carries key
  names only, sorted, and the test asserts on the **serialised JSON** rather
  than a struct field, because the field that gets missed is the leak.
- **Two parsers read this document, so one corpus answers for both.** App mode
  marshals `[]appLeg` straight into `--test-legs`, so a key `appLeg` does not
  model is dropped in transit and the leg runs against nothing while the
  configuration says otherwise. `src/quality/testdata/leg-service-documents.json`
  is read by `TestLegServiceDocumentsParseAsDeclared` here and by
  `TestAppLegsAndTestLegsShareOneKeySet` in the commit composite; the modules
  are isolated Go modules and cannot share a type, so the agreement is
  asserted rather than assumed. It earned its keep immediately:
  `DisallowUnknownFields` matches field names **case-insensitively**, so
  `readycmd` was accepted here and refused there — one configuration, two
  verdicts depending on which composite read it. `checkServiceKeyCase` closes
  it for service keys only; the leg's own keys have been case-tolerant since
  `--test-legs` shipped and tightening them is a breaking change of its own.
- **No Docker socket, ever.** The services are engine-managed containers on the
  leg's network. A socket mount hands a consumer-authored command string root
  on the runner, depends on ambient daemon state and cannot be represented in
  evidence.
See [specs/reach-a-database-from-a-test-leg.md](../../specs/reach-a-database-from-a-test-leg.md).

## A credential that could not be applied must not read as no credential

Both
feed tokens were accepted, threaded through every leg, handed to the container as
secrets — and never applied. npm's auth env var was built by concatenation,
`"NPM_CONFIG_//"+feedUrl+"/:_authToken"`, from the same string that
`NPM_CONFIG_REGISTRY` needs; the registry var requires a scheme and npm's nerf
dart must not have one, so the key came out as
`NPM_CONFIG_//https://host/path//:_authToken`. npm does not normalise keys
starting with `//` (that guard is also what keeps `_packaging` from becoming
`-packaging`), so it was stored verbatim, matched no request, and the token was
dropped. On the NuGet side `dotnetexec.go` wrote a config declaring the source
with no `<packageSourceCredentials>` block and set `NUGET_AUTH_TOKEN` — an
environment variable NuGet reads nowhere; measured against a probe that
challenges with `401 WWW-Authenticate: Basic`, that config answered with
`Basic Og==`, base64 of `":"`, an empty user and an empty password. It also
hard-coded the source name `internal`, shadowing the consumer's own source and
any `packageSourceMapping` pointing at it. Both now go through `feeds.go`
(`npmAuthEnvKey`, `npmRegistryURL`, `nugetCredentialedConfig`,
`nugetCredentialsElement`), untagged so the exact bytes are unit-tested, and the
NuGet config body is shared with the BYO path — `byotest.go` had the correct
rendering all along, which is how one credential ended up with two behaviours.
Both halves are proven on the wire (Authorization headers, not unit tests) in
[specs/apply-the-private-feed-credential.md](../../specs/apply-the-private-feed-credential.md).

## …and a working credential must not go over the wrong transport

A token that
is applied is a token that gets sent: npm puts `Bearer <token>` on its first
request, NuGet answers a `Basic` challenge with `base64(cicd:<token>)`.
`validateFeedCredentials` (`feeds.go`) runs in `Check` and `Test` before any
container is built and refuses a non-https feed URL, so all four injection
paths are covered by one check rather than four. It **fails** instead of
dropping the token — dropping is the silent 401 the bullet above exists to
remove. `http://` to a loopback host stays legal, because that is how the seam
gets proven against a local server. Whether a *scheme-less* URL is acceptable
differs by tool, and not out of strictness: npm rejects a schemeless registry
so cicd upgrades it to https (`npmRegistryURL`), while NuGet reads a bare
source value as a **local directory path**, so a token handed with one would be
attached to a filesystem source and the restore would report missing packages
rather than a bad feed URL — `schemeRequired` refuses that. Also on the
reversibility of the credentials element name: NuGet *decodes* it before
matching a source, so `nugetCredentialsElement` escapes a literal
`_x0020_`-shaped underscore as `_x005f_` and emits non-BMP characters as UTF-16
surrogate halves. An element name that decodes to a source the consumer does
not have is not a parse error — the credential is never applied to the intended
source, so the restore 401s, or succeeds anonymously where the feed allows it,
which is the outcome that reads as clean while proving nothing.

## An error naming one line of a long log is a claim, not evidence

When
`dotnet test` exits non-zero and the `.trx` reports no failure — a consumer
run with every test passed, exit 1, a tool-restore `Unhandled exception` quoted from
a file that died with the container — `dotnetKeepOutput` keeps the last 200
lines (2 KiB per line, 64 KiB per target) plus up to 20 distinct lines
matching `dotnetFailureSignatures` in `genericReport` under
`dotnet-test-output/1.0`, and `dotnetTestExitFailure` quotes the match count
and three lines with a pointer to the rest. Also kept on every classified
non-run (both runners) and when coverage was requested and none was written.
**Not** kept when `tests.failed > 0`: the count is the verification and the
output there is the tests' own stack traces. Every path from output to
envelope — the kept record and the single quoted line — passes
`scrubCredentials` first, and the test asserts on the serialised JSON.
`truncatedLines` counts over stored lines only. Notify renders the `errors[]`
entry (≤ 3 × 300 bytes of diagnostics) and never the tail; `genericReport`
is unread there by design. Schema unchanged.

## A lint leg says how many files it read, and a file pylint could not read is not a finding

The pylint leg ran `pylint .`, which reads the directory as one package. On a
flat tree it printed one `F0010 parse-error` for a root `__init__.py` that does
not exist and linted nothing, and the parser counted that fatal as a HIGH
finding: the leg failed as if it had found a bug and passed at `--fail-on NONE`
as if it had run. cicd now lists the files, hands pylint exactly that list, and
reports `Examined` in files. A `fatal` message is a non-run naming the files
pylint could not read, never a finding. ESLint reports the count its JSON
already carried. A clean lint over zero files is `SKIPPED`. golangci-lint and
`dotnet format` keep a nil `Examined`, by design. See
[specs/say-how-much-the-lint-legs-read.md](../../specs/say-how-much-the-lint-legs-read.md).
