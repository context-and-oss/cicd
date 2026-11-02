# Detect the .NET test runner, and never assume one

`dotnet test` is not one command-line surface, it is two. VSTest and
Microsoft.Testing.Platform (MTP) do not share a flag set, they are not
negotiable per invocation, and on the .NET 10 SDK an MTP project **cannot** be
driven through the VSTest target at all. cicd had one house invocation — the
VSTest one — so every MTP repository's test leg was a non-run, which
`gatedPassed` fails at every threshold including `--fail-on NONE`.

The irony is worth stating first, because it is the whole shape of the bug:
`Microsoft\.Testing\.Platform` was already in `dotnetTestMarkers`. cicd
confidently recognised an MTP project as one it could execute, and then drove it
with the other runner's flags.

## What was assumed

Five assumptions were compiled into `runDotnetTestOn`, all of them true in 2023
and none of them checked:

1. that `dotnet test` accepts `--logger trx`;
2. that `dotnet test` accepts `--collect:"XPlat Code Coverage"`;
3. that a coverage report is named `coverage.cobertura.xml`;
4. that an exit status outside `{0, 1}` means the tool did not run;
5. that there is only one answer to "which runner is this", so nothing needs to
   record which one ran.

Measured on SDK **10.0.400** (`mcr.microsoft.com/dotnet/sdk:10.0`, the digest
pinned as `dotnetSDK100Image`), against an MSTest 4.0.2 test project:

| project | `global.json` opt-in | flags cicd sent | result |
| --- | --- | --- | --- |
| MTP | absent | VSTest | **exit 1**, `Microsoft.Testing.Platform.MSBuild.targets(263,5): error : Testing with VSTest target is no longer supported by Microsoft.Testing.Platform on .NET 10 SDK and later.` — no `.trx` |
| MTP | present | VSTest | **exit 5**, `Unknown option '--logger'` — no `.trx` |
| VSTest | present | MTP | **exit 1**, `error : Project …/App.Tests.csproj uses VSTest. All projects must use that test runner.` |
| MTP | present | MTP | **exit 0**, `.trx` + cobertura written |

Every row but the last is a non-run: no test executed, no `.trx` was written.
None of them is a false *pass* — that is why the defect survived — but all three
are a permanently red source gate on a legitimate repository, with no threshold
that clears it and, before this change, a message pointing at the wrong thing.

## The opt-in is `global.json`, and only `global.json`

The runner is selected by `"test": {"runner": …}` in the repository-root
`global.json`. Measured properties of that key:

- it is matched **case-insensitively** — a lowercase
  `"microsoft.testing.platform"` selects the MTP CLI and runs;
- it is **repository-wide**. There is no per-project form. A tree where one test
  project is still VSTest-shaped fails as a whole (row 3 above);
- an unsupported value, or malformed JSON, makes **every** `dotnet` invocation
  throw — `InvalidOperationException: Test runner 'Banana' is not supported.`
  Not just `dotnet test`: `dotnet --version` too.

So `dotnetRunnerFromGlobalJSON` treats a malformed file or an unknown runner name
as an **error**, not as "no opinion". That is deliberately unlike
`dotnetBandFromGlobalJSON`, which falls back to reading the project files: the
band has a next place to look, the runner does not, and falling back here would
mean guessing an invocation — the exact defect being removed. It is also what
the SDK itself does.

Absent `global.json`, or a `global.json` with no `test` section, is VSTest —
the SDK default — and the note says which of those two it was.

### `dotnet.config` is not the opt-in (measured, not assumed)

The `[dotnet.test.runner]` section of `dotnet.config` is documented as a second
way to select the runner. On 10.0.400 it is **not honoured**: with the section
present and no `global.json`, the MTP flags still fail with MSB1001. It is
therefore not implemented, and the issue's own non-goal list agrees. This
paragraph exists so the absence reads as measured rather than overlooked.

### Rejected: the `IsTestingPlatformApplication` MSBuild property

The obvious alternative is to ask MSBuild what the project is:
`dotnet msbuild -getProperty:IsTestingPlatformApplication`. Rejected on three
measurements:

1. it describes what a **project** is, not what the **CLI** will parse. The CLI
   surface is chosen by `global.json`; a project can be an MTP application while
   `dotnet test` still parses VSTest flags, and that combination is row 1 of the
   table above — a non-run whose cause the property does not name;
2. it fails outright on a solution (`MSB1063`), so it cannot answer for the shape
   most consumers have;
3. on a **cold NuGet cache** it returns an empty string rather than an error,
   because the property is defined by a targets file that arrives with a package
   restore. An empty answer that looks like `false` is the failure mode this
   repository exists to refuse.

Also rejected: driving the test application directly (`dotnet exec` /
`dotnet run`), which bypasses the SDK's project graph and the private-feed
wiring; invoking an MSBuild `Test` target, which does not exist; and synthesising
a `global.json` inside the container to force a runner, which would make cicd
choose the consumer's runner for them and contradicts ADR-004's rule that the
consumer's toolchain is resolved from the consumer's repository.

## What now happens

`discoverDotnetTestRunner` (`src/quality/dotnetexec.go`) reads the repository
root `global.json` in the same cheap `alpineImage` probe that already answers the
target-discovery and band questions — a filesystem question must not depend on
the SDK being usable. `dotnetRunnerFromGlobalJSON` (`src/quality/dotnetrunner.go`,
untagged so unit tests reach it) resolves the bytes, and `dotnetTestArgs` builds
the invocation:

| runner | argv after the target |
| --- | --- |
| VSTest | `--logger trx --results-directory /tmp/test-results` + one element `--collect:XPlat Code Coverage` |
| MTP | `--results-directory /tmp/test-results --report-trx --coverage --coverage-output-format cobertura` |
| unknown | *nothing* — `nil`, and the caller refuses to run |

The `switch` has **no `default:` arm** and the nil is checked by the caller, for
the same reason `dotnetSDKBase` has none: a verdict attributed to an invocation
nobody selected is the false pass this module exists to prevent.

The runner is named in `warnings[]` on every run, the way the SDK band already
is:

```
test dotnet: dotnet test: runner Microsoft.Testing.Platform (global.json "test": {"runner": …}), which is repository-wide: every test project must use it
test dotnet: dotnet test: runner VSTest (no global.json in the repository root, so the SDK default applies)
```

That is assumption 5 paid off: an invocation nobody can audit from the evidence
is an invocation nobody can review.

### Every added argument is an argv element, never a shell word

The script body is delivered as `sh -c "$SCRIPT" sh "$@"`, so each flag reaches
`dotnet test` as a true argv element with zero shell quoting involved. This is
not tidiness. Written the obvious way, `--collect:"XPlat Code Coverage"` inside a
`sh -c` body is split by the shell into three arguments, the collector name
becomes `XPlat`, no coverage is collected — and `dotnet test` exits **0**. That
was a real silent false pass in this repository, and every argument added here
had to be incapable of reintroducing it.

## The coverage report has a different name, and the old glob found nothing

MTP's coverage extension writes `<guid>.cobertura.xml`, one guid per test
application. cicd globbed the literal coverlet name. Measured: over a pooled MTP
run that had just written two reports,
`find <results> -name 'coverage.cobertura.xml'` returned **0 hits**. So fixing
the invocation alone would have produced a green .NET leg with no coverage at
all, which is the same silence one field over. The glob is now
`*.cobertura.xml` (`dotnetCoberturaGlob`), shared by both runners.

Four decisions inside that harvest, each measured:

**`--results-directory` stays.** MTP accepts it and pools every test
application's reports into it, guid-named, without collision — measured on a
two-project solution: 2 `.trx` and 2 *distinct* cobertura documents at the pool
root. Without it, reports land inside each project's build tree
(`bin/<cfg>/<tfm>/TestResults/`), i.e. in the consumer's source directory.

**`--coverage-output` is never passed.** The guid *is* the collision avoidance.
Measured with `--coverage-output coverage.cobertura.xml` on the same
two-project solution: both applications write the same path in the pooled
directory. The result was 3 files with 2 distinct contents — the merged number
happened to stay right, because the copies MTP attaches to each `.trx` live in
separate directories and survived — but the root-level separation was destroyed
and the shared path is written concurrently by two applications. A well-formed
cobertura document holding one project's numbers is worse than no document,
because it reads as a successful measurement.

**No `-maxdepth 1`.** It would be correct for the pooled layout and silently
wrong for the per-project one, which is a shape-dependent correctness bug: the
same code would measure everything or nothing depending on a flag. `.trx` and
cobertura always co-locate, so one `results` constant is right for both.

**The dedup in `parseCoberturaSet` is now load-bearing.** Every cobertura exists
twice — once at the pool root and once as a `.trx` attachment. Verified directly
rather than taken on trust: 24 files for 12 test projects, byte-identical in
pairs, collapsing to 12 documents. `TestParseCoberturaSetPooledDuplicates` pins
that 24 → 12 with the merged line count, because a dedup that quietly stops
working double-counts every assembly and the merged percentage still looks
plausible.

**`--coverage-output-format cobertura` is mandatory.** Bare `--coverage` exits
**0** and writes `<guid>.coverage`, the binary default format, so zero cobertura
documents are harvested from a run that succeeded and said nothing. That is the
word-splitting bug arriving through a different door, and it is worse: VSTest at
least logged `Unable to find a datacollector`. Never emit `--coverage` without
the format pair.

## Coverage that was produced and not found ≠ coverage that was never produced

Widening a glob is not a proof, so `dotnetCoverageOutcome`
(`src/quality/dotnetreport.go`) keeps four states apart instead of two, in this
order:

| state | verdict |
| --- | --- |
| at least one usable document | silence |
| documents found, none with a coverable line count | **warning** — "an empty report is what a test project that instruments no code writes, and it is not a 100% measurement" |
| no documents in the results directory, but cobertura files exist under `*/bin/*` in the source tree | **error**, naming it a cicd defect rather than a consumer one |
| none anywhere, MTP | **error** naming `Microsoft.Testing.Extensions.CodeCoverage` |
| none anywhere, VSTest | **error**, keeping the `coverlet.collector` remedy |

The third row is the one that matters for the future: it is a live check that
cicd's own harvest is looking in the right place. If MTP moves the reports again,
that state fires an error naming cicd, instead of a leg that reports no coverage
and blames the consumer's project.

The `coverlet.collector` remedy is **wrong** under MTP — that package is a VSTest
data collector — so it is now emitted only on the VSTest path. A remedy that
cannot work is a message that costs the reader a wasted change.

## Exit statuses are a map with distinct answers, not two buckets

The VSTest branch treated every status outside `{0, 1}` as "did not run". Under
MTP that misreports a real test failure as a leg that never executed, which sends
the reader looking for a broken pipeline instead of a broken test. Measured map,
`dotnetMTPExitDiagnosis`:

| exit | meaning | classification |
| --- | --- | --- |
| 0 | tests ran, all passed | real result; the `.trx` checks own the verdict |
| 1 | the run never started | **non-run** |
| 2 | tests ran, some failed | real result — `.trx` and coverage were written |
| 5 | the command line was rejected | **non-run** |
| 8 | valid invocation, zero tests matched | **non-run** |

1, 5 and 8 get **distinct** diagnostics, pinned by a unit test that fails if any
two of them collapse to the same wording, because "did not run" without which
half of the sentence is a verdict with no remedy attached.

**Exit 1 does not assert its own cause.** The runner mismatch is its most likely
cause, but a project file MSBuild cannot even load exits 1 here too — measured,
`MSB4025` on a malformed `.csproj`, which happened while building the fixture for
this change and produced a message telling me to fix `global.json` for a broken
XML comment. Structure decides the non-run; the wording only selects which
explanation to offer, and `dotnetMTPRunnerMismatch` gates the mismatch remedy on
the SDK actually having said so. A verdict may never depend on a tool's wording;
an explanation may.

**Exit 5's remedy names the extensions.** A bare `xunit.v3` project accepts
neither `--report-trx` nor `--coverage`: measured on xunit.v3 3.1.0, exit 5,
`Unknown option '--report-trx'`, and cicd reports `passed=false` **at
`--fail-on NONE`**. MSTest 4 supplies both extensions transitively; xunit.v3
supplies neither, and the message says so rather than leaving the reader to
discover which of two dozen options was unknown. Getting there needed
`"unknown option"` added to `dotnetDiagnosticMarkers`: without it the first
matching line in that output is `error: 1`, roughly 200 rows *below* the sentence
that explains everything.

**Exit 8's scope is per run, not per project**, and the message says so. One
test project matching nothing — a `--filter` that empties it, a project holding
no tests — fails the whole run even when every other project executed. A reader
who assumes per-project scope will look for the wrong project.

**`--minimum-expected-tests 0` is deliberately not passed.** It would make exit 8
go away, and that is exactly the objection: the flag is global to the run, so it
would silence the zero-test guard for *every* project, turning "no test
anywhere" into a clean pass. That is the same false pass as the pre-2024
`dotnet test`-at-the-source-root bug this module already fixed once. A noisy exit
8 costs a consumer one `--filter` fix; silencing it costs a gate.

The target argument stays positional and untouched. The `--` separator MTP
accepts is optional; it is not added, because adding it would imply it was
load-bearing.

## The runner detection was unreachable from the projects that need it

Found while proving the fixture, and it is the second half of the same blindness:
`dotnetTestMarkers` was entirely VSTest vocabulary. An MTP test project
references no adapter and no `Microsoft.NET.Test.Sdk` — the runner is compiled
into the test application — so a current MSTest 4 or xunit.v3 test project
matched **none** of the six markers. Measured: a project whose only reference was
`<PackageReference Include="MSTest" Version="4.0.2" />` produced

```
none of the 1 projects found is a test project (no Microsoft.NET.Test.Sdk,
IsTestProject or test-adapter reference), so no test ran.
```

That is loud, not silent, which is how it survived — but it is a false red on a
legitimate repository, and it made the entire MTP invocation above unreachable
from the two project shapes that need it most. Two markers are added:
`Include[[:space:]]*=[[:space:]]*["']MSTest["']` and `xunit\.v3`. The MSTest one
is matched with its attribute, tolerating either quote character and whitespace
around the `=`, so it cannot collide with `MSTest.Analyzers` or `MSTest.Sdk` —
neither of which can run a test, and both of which a bare `MSTest` substring
would have matched. The list stays **one** POSIX-ERE alternation shared by the
container `grep` and the Go matcher, so the shell rule and the tested rule cannot
drift.

**And the fixture had to stop proving this by accident.** `testdata/dotnet-mtp-app`
initially passed discovery only because the words *Microsoft.Testing.Platform*
appeared in an **XML comment** in its `.csproj`. Its comments are now written
without any marker literal, so its detection depends on the package reference and
on nothing else. A fixture that passes for a reason other than the one under test
proves nothing.

Left open, deliberately: `<Project Sdk="MSTest.Sdk/4.0.2">`, the MSBuild-SDK
spelling of an MSTest project, matches no marker. Such a repository gets the loud
non-run above rather than a false pass. Nothing in this change measured a real
`MSTest.Sdk` run, so no expectation is pinned for it in either direction — an
unmeasured case must not read as a ruled-out one.

## Separately: an empty coverage report is not a 100% measurement

Named separately because it is a different failure, it is **not** MTP-specific,
and it must not be smuggled in as part of the runner work.

`parseCobertura` read `line-rate` and ignored whether anything had been counted.
Measured document — 178 bytes, written by an MTP test project with
`IncludeTestAssemblyInCoverage=false` and no product code, and byte-shaped
identically to what coverlet writes in the same situation:

```xml
<coverage line-rate="1" branch-rate="1" version="…" timestamp="…">
  <packages />
</coverage>
```

`line-rate="1"`, no `lines-valid`, no `lines-covered`. That parsed as **100%
coverage over 0 lines**, and `mergeDotnetCoverage` falls through to an unweighted
mean when no report carries a line count, so a repository whose only .NET test
project instruments nothing reported **100%** with nil lines.

An inflated coverage figure is not merely wrong, it is wrong **in the direction
that survives a ratchet**. A deflated figure is noticed on the next run; an
inflated one *sets the bar*, and every later run is measured against a number
nothing ever measured.

`parseCobertura` now returns `ok=false` when `lines-valid` is absent,
non-numeric, or `<= 0` — the same rule `parseGoCoverprofile` already applied to
its own zero-statement case. Blast radius, from reading the gate in `main.go`:
the coverage gate engages only under `minCoverage > 0 && !lintOnly`, so this can
turn a currently-green consumer red only when all three of a `--min-coverage`
above zero, no `--lint-only`, and a .NET report with no coverable lines hold at
once. The default `minCoverage` is 0.

**Sequencing.** This fix must land **before or together with** any work that
makes `--min-coverage` / `--coverage-min-lines` reachable from the harnesses —
never after. Landing the reachability first means baselines get recorded from the
fabricated 100%, and a ratchet baseline is not something a later fix can retract.

This is the **third** visit to the same `main.go` coverage-gate block for one
failure class (a missing figure that was skipped; a figure the word-split
prevented; now a figure that measured nothing). The pattern is not "coverage
parsing has bugs", it is that *absence and zero are the same bytes* in every
coverage format this repo reads.

## What was proven

Live runs, this change, real containers:

| run | result |
| --- | --- |
| `check --src ./testdata/dotnet-mtp-app --fail-on NONE` | `passed=true`, `coverageByLanguage {dotnet: 20}`, `coverageLinesByLanguage {dotnet: 10}` (2 of 10 sequence points), `errors[]` empty, runner named in `warnings[]`, `ran 1 test project(s)` (that scope warning was reworded by CAPS-024 to name the denominator: `ran 1 of 1 .csproj found under the source root`) |
| `check --src ./testdata/dotnet-app --include dotnet` (regression) | `passed=true`, 33.33% over 3 lines, no errors — unchanged, plus the new `runner VSTest (no global.json …)` note |
| bare `xunit.v3` 3.1.0, MTP opt-in, `--fail-on NONE` | `passed=false` — exit 5 classified as a non-run, remedy names the missing extensions |
| MTP project instrumenting nothing, `--min-coverage 50 --fail-on NONE` | `passed=false`, `coverageByLanguage` **null**, error `no coverage was measured; refusing to pass a gate that could not run`, warning `2 cobertura report(s) were produced but none carried a coverable line count` |

The first, second and fourth are asserted in CI by
`scripts/smoke/dotnet-runner-shapes.sh`, called from the `src/quality` arm of
`module-test` in `.github/workflows/ci.yml` — including the runner-name warning
in **both** directions, so a future change cannot quietly return to one house
invocation. The body lives in a script rather than inline because that `run:` is
this repository's largest and a body over roughly 24 KB makes GitHub refuse the
workflow at *startup*: inline, the three blocks took the step from 10.2 KB to
14.4 KB against a 16 KiB budget; as a call it is 11.2 KB. The empty-report
fixture is written into `/tmp` by that script rather than committed under
`testdata/`, because it exists to be refused and a permanently failing fixture
under `testdata/` would be picked up by every other consumer of that directory.
The script was run for real, not merely written: it exits 0 with
`dotnet runner shapes: OK (VSTest named, MTP ran and measured, empty report
refused)`.

## What a green tick here does *not* mean

- **It does not mean cicd supports every MTP project shape.** `MSTest.Sdk` is
  named above and is not detected. A test project referencing neither MSTest nor
  xunit.v3 nor an adapter is still reported as "not a test project".
- **It does not mean the merged .NET coverage figure is accurate.**
  `mergeDotnetCoverage` weights an assembly once per report that touched it, so
  two test projects covering one shared assembly bias the merged percentage. That
  predates MTP — coverlet produces the same overlap — and it is out of scope here;
  it needs filing separately. What this change fixes is coverage that was
  *missing* or *fabricated*, not coverage that is imprecisely weighted.
- **It does not mean a solution-level sweep works.** Per the issue's non-goals,
  `--solution` and the `dotnet.config` variant of the opt-in are separate; the
  MTP path here runs per discovered test project, exactly as the VSTest path
  does.
- **It does not prove the SDK's behaviour on any band but 10.0.** The MTP CLI
  exists on the 10.0 SDK; `dotnetSDK80Band` consumers keep the VSTest path they
  had, byte-identical, and nothing here changes what `sdk:8.0` does.
- **Two things reported in the issue are not reproduced here** and are recorded
  as unverified rather than as facts: a `--project` flag behaviour that could not
  be reproduced on 10.0.400 at all, and two consumer-side observations (a fixture
  timeout under concurrent instrumentation, and `[Trait]` shadowing from a base
  class) which are properties of a consumer's test suite rather than of cicd's
  invocation.
