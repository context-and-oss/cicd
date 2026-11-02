# Scan the NuGet graph a repository never committed, and say it was restored

Follows [count-vulnerabilities-from-trivys-verdict.md](count-vulnerabilities-from-trivys-verdict.md),
which made "the tree declares .NET and Trivy resolved no .NET graph" a loud
non-run. That check is right and, on its own, unfinishable by the person it
fails.

## The gate cicd could not let a consumer clear

Trivy 0.70.0 resolves .NET dependencies from `packages.lock.json`,
`packages.config` or a `*.deps.json` — and from nothing else. It does not read a
`.csproj`. NuGet writes a lockfile only when a project sets
`RestorePackagesWithLockFile`, which almost nobody does, so a repository of
twenty `.csproj` files routinely commits no NuGet graph at all.

`ecosystems.go` already refuses to call that clean. What it cannot do is make it
green: the remedy lives in the consumer's repository, in every project file, and
cicd has no lever on it. **A gate whose only remedy is somebody else's commit is
a gate that gets switched off**, and the switch is `--fail-on NONE` plus a
shrug — at which point the original hole is back with a config flag in front of
it. That is the failure mode this change exists to avoid, and it is a slower
version of the same false pass.

The observation that unblocks it is that the graph was never unobtainable, only
unasked for. `dotnet restore --use-lock-file` writes exactly the file Trivy
reads, and the SDK that writes it is a container this repository already knows
how to digest-pin.

Measured on `testdata/dotnet-app-nolock` (trivy 0.70.0, `mcr.microsoft.com/dotnet/sdk:8.0`):

| state | Trivy report |
|---|---|
| as committed | no `Results` array at all — zero packages, zero vulnerabilities |
| after the restore | 85 NuGet components in an 87-component SBOM, 2 HIGH CVEs, `Type: nuget` |

Both CVEs matter: `Newtonsoft.Json@9.0.1` lives in the root project and
`System.Net.Http@4.3.0` in `lib/`, which no solution names and nothing
references. A restore that reached only what it tripped over would report one.

The restored state needs no special-casing downstream: `nuget` in
`trivyResolvedTypes` satisfies the reconciliation's exculpating condition 3
exactly as a committed lockfile would.

That fixture is pure .NET, so before this change it hit `parseTrivyNative`'s
`Results: null` error rather than a silent zero. The *silent* form of the same
missing input needs a mixed tree — .NET projects beside npm lockfiles,
where the npm scan made the report look normal and the whole C#
supply chain was simply absent from a green verdict. Same missing input, same
remedy; only the loudness differs.

## What now happens

Before the Trivy filesystem scan, `runTrivyFS` asks `dotnetRestoreNeeded`
whether the tree declares .NET and holds no input Trivy can read. If it does,
the graph is restored in a pinned SDK and **that** tree is scanned.

- **Automatic, with no flag.** There is no opt-in and no opt-out. An opt-in
  fallback is one more thing a consumer has to know exists before their scan
  stops lying to them, and an opt-out is a documented way to restore the
  silence. The trigger is the absence of a resolvable input, which is a fact
  about the tree, not a preference.
- **The trigger asks the same table as the verdict.** `dotnetRestoreNeeded`
  reads `depEcosystems()` — the markers and inputs `unresolvedEcosystems` reads.
  A restore triggered by one list of filenames and judged by another is how a
  tree gets restored and still reported unresolved, or judged resolved on a
  lockfile the fallback never looked for.
- **The reconciliation still runs against the original probe.** The tree as the
  consumer committed it, not the restored one. Re-probing would let the
  fallback's own output clear the check that judges it, so a restore that wrote
  lockfiles Trivy then resolved nothing from would go quiet.
- **A restore that produced nothing enriches the old verdict rather than
  replacing it.** `dotnetRestoreAttemptedNote` appends *"cicd also attempted to
  restore the graph itself in `…sdk:8.0` and that did not produce one either"*,
  because without it the message reads as though cicd never tried, and the first
  thing a consumer does about it is what cicd already did.

## Three properties, each a way this could have become the thing it removes

**1 — the restore never manufactures a pass.** A restore container that does not
complete is an error appended to `errors[]`; the scan proceeds over the source as
committed and lands on the unresolved-ecosystem non-run it would have had anyway,
now carrying the reason. `gatedPassed(ran, severityOK, threshold)` gates only
`severityOK`, so this fails at every threshold including `--fail-on NONE`.

**2 — a partial restore is a failure, and this is the load-bearing one.** A tree
of twenty projects where one fails to restore ends up holding nineteen
`packages.lock.json` files. Nineteen lockfiles are a resolvable input, so
`unresolvedEcosystems` goes quiet, so the twentieth project's dependencies are
absent from a **green** verdict — the founding false pass reintroduced by its own
remedy, and reintroduced in the shape that is hardest to see, because the report
is now full of real findings.

So each project is restored individually, each exit status is captured
separately, and any failure is reported by name. Restoring the tree in one
`dotnet restore` would have collapsed all twenty statuses into one and made this
undetectable. `TestDotnetRestorePartialFailureIsAnError` pins it.

The restored tree is still scanned when some project failed: the projects that
did restore hold real, actionable findings, and discarding them to report that a
different project was unreadable trades a located finding for a message. The
classification is what stops that from reading as complete.

**3 — a restored graph is not a committed graph, and says so.** Versions are
resolved at scan time. Where a project pins exact versions the two agree; where
it uses a floating range they can differ, so the scan can describe packages the
build will not use. That is a real limitation, and the success path is therefore
a **warning**, not silence:

> security dependency scan: dotnet — no packages.lock.json, packages.config or
> \*.deps.json is committed, so cicd restored the NuGet graph itself in
> mcr.microsoft.com/dotnet/sdk:8.0 (2 project(s); …) and scanned that. The graph
> was resolved now, not when this artifact is built: a project using a floating
> version range can build against package versions this scan never saw.
> Committing a lockfile removes that gap and skips the restore — set
> `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in each
> project (or a Directory.Build.props), run `dotnet restore --use-lock-file`, and
> commit the generated packages.lock.json files.

`notify` renders warnings verbatim into the Teams card and the PR comment, so
this is where a consumer is told a committed lockfile closes the gap: it lands on
the pull request of every consumer the fallback fires for, it names the gap in one
sentence, and it gives the three steps that close it. A warning a consumer cannot
act on is noise they learn to scroll past.

## Which SDK, and why the answer is a switch of literals

`dotnetband.go` reads what the tree asks for — `global.json`'s `sdk.version`
first, else the highest literal `TargetFramework` across the project files and
the `Directory.Build.props` that can set one for a whole tree — and rounds up to
the nearest band cicd pins. A `PackageReference` deliberately does not set the
band: it names a package version, not a toolchain.

`dotnetSDKBase` is a `switch` with **one literal `From()` per band and no
`default:` arm**, and it has to stay that way.
`scripts/check-runtime-image-pins.py` discovers image selections by resolving
each `From()` argument through package constants; an argument it *cannot* resolve
is classified as an ADR-004 consumer-resolved toolchain and is never failed. So
`From(dotnetSDKImages[band])` would not fail the pin gate — it would **pass** it,
by looking like the one thing the gate deliberately exempts, while cicd's own
tool image went unpinned. The tidier spelling is the one that silently switches
the check off.

No `default:` for the same reason the restore has no fallback: substituting some
other band for one nobody pinned would attribute a dependency graph to an SDK
nobody selected. A band with no pin is an error, and so is a `global.json`
requesting one above every pinned band.

Both `8.0` and `10.0` are declared in `scripts/runtime-images.json` against
`src/security/images.go` as well as `src/quality/images.go`, and covered by the
existing `runtime image: dotnet-sdk` renovate group.

## Credentials

A restore reaches the network, and against a private feed it carries a token.
`ScanSource` and `ScanArchive` take `--nuget-feed-url` / `--nuget-token`, and
`stage-2` forwards the same pair it already hands `quality.Check` — one set of
feed credentials for the whole pipeline, not a second one to configure.

- The transport is checked **before any container is built**:
  `feedTransportOK(…, schemeRequired)` refuses a token bound for a cleartext
  endpoint. NuGet does not refuse on the consumer's behalf — it answers the 401
  challenge with Basic auth over whatever transport it was given. Failing here
  rather than dropping the credential is deliberate: a dropped credential is a
  silent 401, which reaches the consumer as "restore failed" and names neither
  the feed nor the token.
- The token is a Dagger secret (`WithSecretVariable`), referenced from
  `NuGet.Config` as `%NUGET_AUTH_TOKEN%`. It is never interpolated into a shell
  word, never written to the config file, and never reaches an error string or
  the evidence envelope.
- The `<packageSourceCredentials>` block is keyed by the source **name** the
  consumer's own `NuGet.config` gives that URL, discovered by
  `nugetSourceNameForFeed`. Inventing a name declares a second source for the
  same URL, which breaks any `packageSourceMapping` pointing at the real one and
  leaves the restore unauthenticated against a feed it can see.

That last piece is verbatim behaviour from `src/quality`, so it now lives in a
byte-identical `nugetfeed.go` in both modules — Dagger modules are isolated and
share code by file copy. Two copies is a drift this repository has been bitten by
before, so `scripts/repo-inventory.json` declares the pair under a new
`synced_files` block and `check_synced_files` in `scripts/repo_surface.py` fails
CI when they diverge. A missing copy is a problem, not a skip.

The commit composite's archive shape forwards the pair to `ScanArchive` too. That
is not decoration: `ScanArchive` runs its own Trivy-FS leg over the same `src`
that `stage-2` already scanned, so omitting the credentials would not skip a
feature — it would run the restore a second time, anonymously, and fail against
the private feed the first one reached. Identical inputs make it a cache hit
instead.

## Scope

**.NET only.** The `depEcosystems` table stays general and `dotnetRestoreNeeded`
is written against it, so node and python fallbacks are additions rather than
rewrites — but they are not in this change. Their gap is a *gitignored* lockfile,
which is a narrower and less common state than .NET's, where the default is
unscanned.

**Nothing changes for a repository that commits a lockfile.** The trigger is the
absence of a resolvable input, so a compliant repository sees no restore, no
warning and no extra container. The fallback is invisible to the consumers who
took the advice.

**Source scans only.** `security.ScanImage` and `build.Sbom` mount no source
tree, so a container layout that lands no `.deps.json` still yields a silent zero
there. That is untouched and stated here so it is not read as covered.

## What was proven

- `TestDotnetRestorePartialFailureIsAnError` — nineteen lockfiles do not clear
  the twentieth project.
- `TestDotnetRestoreScriptNeverSplicesAConsumerPath` and
  `TestDotnetRestorePatternsAreShellSafe` — no consumer value reaches the shell
  body; project paths are read from a file and passed as a quoted `"$p"`.
- `TestDotnetRestoreNeededAgreesWithTheVerdict` — the trigger and the verdict
  read the same table.
- Ten tests in `dotnetband_test.go` over band resolution: round-up, above every
  pin, a band cicd never pinned, `global.json` precedence, and a
  `PackageReference` that must not set the band.
- A new `module-test` cell runs `scan-source` against `testdata/dotnet-app-nolock`
  and asserts `passed == true`, empty `errors[]`, the restore warning present,
  and findings for both `Newtonsoft.Json@9.0.1` (the root project) and
  `System.Net.Http@4.3.0` (a project no solution references) — so a fallback that
  restored only what it tripped over would fail. A negative control fails the
  cell if that fixture ever acquires a `packages.lock.json` or `*.deps.json`,
  because a fixture that quietly becomes compliant turns this into a test of
  nothing.
