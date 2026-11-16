# Analyse .NET with the Roslyn security analyzers

## Why

Opengrep matches syntax. It reads one file at a time, cannot resolve which
method a call binds to, and cannot follow a value from a request parameter
through a helper into a SQL string or a file path. For C# that leaves the
injection class (SQL, path, command, XSS, LDAP, XPath, open redirect) reached
only when source and sink sit in one expression — the shape a pattern rule
can name.

The .NET SDK ships an analyzer set that runs inside the compiler, on its
semantic model: `Microsoft.CodeAnalysis.NetAnalyzers`. Its `Security`
category holds the CA3001–CA3012 dataflow rules and the symbol-resolved rules
for weak cryptography, insecure deserializers and disabled certificate
validation. They are the closest thing the open toolchain has to a
compiler-backed C# security scan, they need no download beyond the SDK image
cicd already pins for the lockfile-free restore, and they emit SARIF 2.1.0.

They are a second leg, not a replacement. The two legs overlap on purpose,
and each catches what the other cannot: Opengrep needs no build and reads
every file; the analyzers need a build and see across calls.

## What changed

- **A `roslyn-analyzers` row** in `ScanSource`, concern `sast`, beside
  `opengrep`. It runs whenever the tree holds a `.csproj`, `.vbproj` or
  `.fsproj` outside `bin/` and `obj/`, including `--code-only` scans, and has
  no row otherwise. Its SARIF run is merged into the envelope's report under
  its own driver name and `automationDetails.id`, so the evidence bundle's
  Code Scanning upload treats it as its own category.
- **It builds the code.** Each buildable project gets one `dotnet build` in the
  pinned SDK band the tree asks for (`dotnetResolveBand`, the restore's
  resolver), with `AnalysisModeSecurity=All` and the analyzers forced on.
  A cicd-owned targets file, injected through
  `CustomAfterMicrosoftCommonTargets`, points `ErrorLog` at a per-compile SARIF
  file and writes a sidecar naming the project, so a log is attributed to the
  project that wrote it and never inferred from its path. The build runs in a
  copy of the tree, with a private NuGet cache and the private-feed token, if
  any, as a Dagger secret.
- **What counts as analysed.** A project is analysed when at least one of its
  compile logs ran at least one enabled `Security` rule. Its build exit status
  does not decide that: a build can fail after the compile, and a compile can
  be skipped. A project whose compile reported a compiler error (`CS*`, `BC*`)
  was analysed over an incomplete program and is **partial**; so is one that
  produced a log and then failed. `Examined` reads
  `{unit: "C#/VB projects", count, total, partial}`.
- **A non-run is an error.** Projects to build and no analyzer log from any of
  them is `SAST did not run`, with the first compiler or MSBuild error line as
  the diagnosis. An unreadable status file, log listing or sidecar is an error
  too. `--fail-on NONE` does not cover any of them.
- **What cicd cannot build is named, never dropped**:

  | project | why | row |
  |---|---|---|
  | legacy (non-SDK) format | needs .NET Framework MSBuild | counted in `total`, named in a warning |
  | `<UseMaui>true` | needs the MAUI workload | same |
  | every target framework a platform workload (`-android`, `-ios`, …) | needs that workload | same |
  | `.fsproj` | the analyzers read C# and VB only | named in a warning, not counted |

  A tree with nothing cicd can build is a **skipped** row that says which, not
  an error: an error there is a gate the consumer cannot clear, and a gate the
  consumer cannot clear gets switched off
  ([doctrine](../docs/explanation/doctrine-security.md#a-gate-a-consumer-cannot-clear-is-a-gate-that-gets-switched-off)).
- **Narrowing is disclosed.** A `Security` rule the repository switched off
  (`NoWarn`, `.editorconfig`, a global config, a ruleset) did not run. The run's
  `ruleConfigurationOverrides` say so, and a `NARROWED RULES` warning names
  each rule with the number of projects that switched it off. A `#pragma` or
  `[SuppressMessage]` keeps the result in SARIF with an accepted suppression;
  it is excluded from the counts and disclosed as `N findings suppressed in
  source`, the same contract as `nosemgrep`.
- **cicd grades, not the repository.** The analyzers' own level is whatever
  the repository's configuration made it, so a consumer could downgrade a
  finding to a suggestion and pass the gate. `roslynSeverity` assigns the
  severity from the rule id, and the projected SARIF carries cicd's level:

  | rules | severity |
  |---|---|
  | CA3001–CA3012 (injection dataflow) | HIGH |
  | CA2300–CA2330 (insecure deserializers) | HIGH |
  | CA2350–CA2362 (`DataSet`/`DataTable` deserialization) | HIGH |
  | CA5359 (certificate validation disabled), CA5360 (dangerous calls in deserialization) | HIGH |
  | every other `Security` rule | MEDIUM |

  Weak hashes, weak ciphers and non-cryptographic RNGs are MEDIUM: they are
  real, and common enough in non-security uses (cache keys, jitter) that HIGH
  would make the default gate one a large share of .NET consumers cannot clear
  on day one.
- **Only security results, only in the tree.** Non-security diagnostics are
  dropped from the projection. A result whose location is outside the scanned
  tree or under `bin/` or `obj/` (generated or package code) is not reported;
  how many were dropped is a warning. Every location is rewritten relative to
  the tree; no `file://` or container path reaches the envelope.
- **The rule count is a measurement.** `rules.count` is the number of enabled
  `Security` rules the logs say ran, and `rules.pinned` names the SDK image the
  analyzers came bundled with.

## Measured

On `testdata/roslyn-sast` against the pinned 8.0 SDK: the injection finding
is HIGH at `web/OrderController.cs`, the weak hash MEDIUM, the
`#pragma`-suppressed one disclosed and not counted, the `.editorconfig`-disabled
RNG rule named as narrowed, the broken project partial, the legacy project
counted and named, the F# project named. `testdata/dotnet-app` reads clean
over every project with 94 security rules enabled.

## What gets worse

- **A C# scan now costs a build.** Every `ScanSource` on a .NET tree, including
  a `--code-only` one, restores and compiles every project. That is the price
  of an analysis that sees across calls; there is no cheaper way to run it.
- **The scan runs the consumer's MSBuild.** Targets, tasks and package build
  logic execute in the scan container. The restore already did; the build does
  more of it. The container has no host mount and the feed token is a secret,
  but the build can read that token, as the restore can.
- **The graded party can still lie about its own log.** A consumer's MSBuild
  can rewrite or delete the analyzer log, or override `ErrorLog` after cicd's
  target. An empty or absent log reads as not analysed, never as clean; a
  forged one cannot be distinguished. A gate over code the consumer controls
  cannot close this.
- **Opinions the consumer had are overridden.** cicd's targets file takes
  `CustomAfterMicrosoftCommonTargets`; a repository that set its own loses it
  for the scan. A project that references its own NetAnalyzers package version
  runs that version's rules instead of the SDK's.
- **The SAST concern stops summing.** The concern now has rows counting files
  and rows counting projects; `foldExamined` refuses to add different units, so
  the concern's own `examined` reads "not stated" while each row keeps its own.
- **`.semgrepignore` and `trivy.yaml` do not scope it.** Both are another
  tool's file with another tool's matching rules; reimplementing either in cicd
  would be a second resolver for a question the tool already answers. The
  lever for a directory of intentionally vulnerable C# (samples, fixtures) is
  that directory's `.editorconfig` switching the `Security` category off, which
  the row discloses as `NARROWED RULES`. This repository's own dogfood scan now
  builds every testdata .NET project; measured, all eight build and read clean.
- **Committed `obj/` can skip the compile.** An up-to-date check that skips
  `CoreCompile` writes no log, and the project reads as not analysed.

There is no switch to turn the leg off. The case that can stay red is an SDK
project cicd should build and cannot; the remedy is `exclude` for that
directory, which the evidence names, or a fix in cicd.

## Licence

The analyzers ship inside the .NET SDK (MIT) in the digest-pinned SDK images
cicd already uses for the restore. Nothing is downloaded or redistributed.

## Checks

- `src/security/roslyn_test.go`: project classification, the severity table's
  boundaries, the projection (security only, deduplicated across compiles,
  suppressions excluded, cicd's level stamped), compile errors as partial, the
  non-run error, unbuilt projects named, nothing to build as skipped,
  locations kept inside the tree, the targets file well formed, and the build
  script driven against a stub `dotnet` with a hostile project path.
- `scripts/smoke/roslyn-analyzers.sh`, run by the `module-test` security cell
  and `make smoke`: the real SDK over `testdata/roslyn-sast`, asserting every
  row, result and warning above and that the default gate fails.

## Residue

- Only the arm64 SDK image was exercised locally; amd64 is exercised by CI.
- Interprocedural taint across projects is not analysed; CA3001–CA3012 follow
  data within a compilation.
- Analyzers skip code marked generated. A finding in generated code is not
  reported by the analyzers themselves, before cicd's own filter.
