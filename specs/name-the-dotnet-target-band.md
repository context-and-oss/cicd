# Intent: a target framework above the pinned SDK must say so, in both .NET legs

## Why

cicd's `quality.Check` .NET legs run in a digest-pinned SDK image — currently
`mcr.microsoft.com/dotnet/sdk:8.0`. A consumer whose projects target `net10.0`
cannot be built by it. That is a legitimate, expected failure; the problem was how it
read. Measured on this repository's own `dotnet-app` fixture with both `csproj`
files switched to `net10.0`, before this change:

```
ERR: lint dotnet: dotnet-app.csproj: dotnet format: did not run (exit 1):
     Unhandled exception: System.Exception: Restore operation failed.
ERR: test dotnet: … dotnet test: exited 1 but wrote no .trx result file, so no test
     executed: … error NETSDK1045: The current .NET SDK does not support targeting
     .NET 10.0. …
```

Both are true and neither is actionable:

- **The format leg names no cause at all.** `dotnet format` does not relay
  NETSDK1045 — it fails inside its own restore and reports only "Restore operation
  failed". A consumer reads that as a NuGet problem and goes looking at feeds.
- **The test leg names the code but not whose SDK it is.** "The current .NET SDK
  does not support targeting .NET 10.0" invites the conclusion that the *project* is
  wrong. It is not: the project is fine, the SDK cicd chose is old. Nothing in the
  message says an image is involved, let alone which one or what the levers are.
- **The obvious self-help makes it worse.** The instinct is to add
  `global.json` pinning SDK 10 — which the pinned image does not carry, so the next
  run exits 145 with a different message. A legible failure traded for a confusing
  one.

This is the `.NET10-vs-SDK8` mismatch found while prototyping the consumer
migration, and it will recur at every band boundary.

## What changed

All the logic lands in `src/quality/dotnetreport.go` — the untagged file, so
`go test -tags unit_test` reaches it without a Dagger session — with its cases in
`src/quality/dotnetreport_test.go`. `src/quality/lint.go` is the only call site
that changes: the format leg now passes the project file's contents to the
remedy builder, which is what lets it name the band.

- **`dotnetSDKRemedy` answers both band mismatches**, which are opposite ends of one
  axis: `global.json` naming an SDK the image lacks (exit 145, already handled) and a
  target framework above what the image's SDK can build (NETSDK1045, new). The new
  branch names the requested framework, names the pinned image, and lists the three
  real levers — `quality.Test` with `--toolchain-image` (ADR-004 resolves that one at
  run time, so it is the only per-consumer escape), dropping `dotnet` from
  `--include`, or raising the pin. It explicitly rules `global.json` **out**.
- **The test leg's remedy moved to the branch the failure actually reaches.** A band
  mismatch makes the *build* fail, so `dotnet test` exits 1 — which is also its
  "tests ran, some failed" code — and lands in the wrote-no-`.trx` branch, which had
  no remedy. The did-not-run branch it was attached to is never entered.
- **`dotnetTFMAbovePin` reads the project file for the format leg**, because the tool
  withholds the cause. It compares literal `net<major>.<minor>` values inside
  `<TargetFramework>`/`<TargetFrameworks>` elements against the pinned band. It only
  ever *enriches a failure that already happened* — it can never cause one, and a
  `""` result means "no hint to add", not "the bands agree".

## Proof

Real `dagger call check --include dotnet` runs against the repository's own
`dotnet-app` fixture, copied and switched to `net10.0`:

| Run | Result |
| --- | --- |
| net10.0 fixture, before | `passed=false`; format leg says only "Restore operation failed"; test leg quotes NETSDK1045 with no remedy |
| net10.0 fixture, after | `passed=false`; **all three** .NET errors carry "the project targets .NET 10.0, which is newer than the SDK in cicd's pinned image (mcr.microsoft.com/dotnet/sdk:8.0)" and the three levers |
| unmodified net8.0 fixture, after | `passed=true`, 0 findings, coverage 33.33%, `errors` absent, both warnings unchanged — no hint fires |

Unit coverage for the parts a run cannot exercise cheaply: multi-targeting reports the
highest offender; `net8.10` compares numerically, not lexically (it is above `8.0`
but sorts below it as text); a version in a `PackageReference` is not a target
framework; `$(DefaultTargetFramework)`, `netstandard2.0`, `net48` and a `.sln` all
yield no hint; the absent-SDK remedy does not claim the project targets anything.

## Decisions

**Enrich the failure, never decide it.** A pre-emptive "your band is too new, refusing
to run" check would be tidier and is the wrong trade: `TargetFramework` can come from
`Directory.Build.props`, an imported `.props`, or an MSBuild property, so a
project-file read is not authoritative. Guessing wrong would turn a working repository
red. Reading the file only to explain a failure the SDK already produced cannot do
that.

**The pin is not raised here.** SDK 10 can build `net8.0`, so bumping
`dotnetSDKVersion` would serve both bands and is probably the right long-term move —
but it changes `dotnet format`'s analyser defaults and every .NET verdict this repo
produces, so it needs its own change with its own proof runs, and it is a decision
about what cicd supports rather than a message fix. Until then the message names the
pin and the file to edit.

**Element-scoped regex rather than a full XML parse.** The project file may be
malformed — that is one of the failures being explained — and `encoding/xml` on a
broken csproj returns an error where a regex still finds the element. Scoping to the
`<TargetFramework(s)>` element first is what keeps a `PackageReference` version from
being read as a target.

## Known residue

**A solution-level format failure gets no hint.** When a single `.sln` exists the
format leg targets it, and a solution file carries no target framework, so
`dotnetTFMAbovePin` reads nothing. The test leg still explains it (it targets
projects), so the evidence is not silent overall — but the format error alone is.
Following project references out of a solution to find the band is possible and was
judged more machinery than the case warrants.

**`net48` and `netstandard` are ignored by design.** Neither can be above a `net8.0`
pin, so the only thing a match could do is produce a wrong hint. A .NET Framework
consumer's failure is a different one (the SDK image cannot build `net48` at all)
and deserves its own message, which does not exist yet.

**The remedy names the pin constant, not the SDK that ran.** `dotnetSDKVersion` is
the band the image carries and `readDotnetSDKVersion` already reports the observed
patch version elsewhere in the envelope; the remedy string does not have it in hand.
With no `global.json` the two always agree, so this is cosmetic — but it is the same
"describes the pin, not the run" shape called out in
[prove-the-dotnet-legs-ran.md](prove-the-dotnet-legs-ran.md).

## Amendment — the pin is raised, once per band

The decision above, *"The pin is not raised here"*, is superseded. It read the problem
as a message problem and it was a support problem: the pinned SDK band **is** what cicd
supports, so one pin meant one supported band. A `net10.0` consumer did not get a
clearer error, it got no lint and no unit test at all, at every `--fail-on` threshold
including `NONE`, on cicd's own image choice rather than on anything in its tree. The
message this spec added was correct and load-bearing the whole time; it was just
explaining a wall that should not have been there.

What changed:

- **One digest pin per supported band, not one pin.** `src/quality/images.go` carries
  `dotnetSDK80Image` and `dotnetSDK100Image`; `dotnetSDKBands` is the ordered list and
  `dotnetSDKBase` maps a band to its `From()`. Both are declared in
  `scripts/runtime-images.json` and covered by `renovate.json`.
- **Raising the single pin to 10.0 was still rejected**, for the reason this spec gave
  — it changes `dotnet format`'s analyser defaults and every .NET verdict the repo has
  produced — plus one it did not have: the 10.0 SDK ships no 8.0 targeting pack, so a
  `net8.0` consumer would acquire a package dependency on a leg that must work
  offline. Two bands side by side leaves `net8.0` byte-identical.
- **The band is read from the repository**, `global.json` `sdk.version` first, then the
  highest literal `TargetFramework` across `*.csproj` and `Directory.Build.props`, and
  resolved to the lowest pinned band at or above it. Nothing readable resolves to the
  lowest band — the pre-change behaviour.
- **`dotnetSDKBase` stays a `switch` over constants.** A map or slice index would make
  the `From()` argument unresolvable to `scripts/check-runtime-image-pins.py`, which
  classifies what it cannot resolve as an ADR-004 consumer-resolved toolchain and never
  fails it. The tidier spelling passes the pin gate *by evading it*.
- **A band above every pin is still loud.** It runs the highest pinned band with a
  warning that says exactly that; if the build genuinely needs more, the restore dies
  and the classification this spec built turns it into a non-run. A band with no image
  at all is `dotnetUnpinnedBandError` and `ran=false`. Neither path is a silent
  fallback to 8.0, which would have converted a correct hard failure into the false
  pass this repository exists to prevent.

Consequences for the text above:

- **"The remedy rules `global.json` out explicitly"** no longer holds, and its residue
  entry is retired. With more than one band pinned, `sdk.version` is the *selector*
  among them, so the remedy now offers it (with `"rollForward": "latestFeature"`)
  instead of warning that it swaps a legible error for exit 145. Exit 145 is still
  possible — a `sdk.version` naming a band cicd pins no image for — and is still
  classified as a non-run.
- **`dotnetTFMAbovePin` is now `dotnetTFMAboveBand`**, comparing against the band that
  actually ran rather than a single compile-time constant. That also retires the
  residue entry *"The remedy names the pin constant, not the SDK that ran"* for the
  band half; the observed patch version is still only reported elsewhere in the
  envelope.
- The solution-level and `net48`/`netstandard` residue entries stand unchanged.

Still true, and the reason the enrichment was not replaced by a refusal: **enrich the
failure, never decide it.** A `TargetFramework` behind an MSBuild condition means a
project-file read must never be able to fail a run on its own — which is exactly why
an above-every-band request runs the newest band and lets the SDK have the last word.
