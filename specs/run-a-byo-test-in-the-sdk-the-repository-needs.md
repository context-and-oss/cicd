# Intent: a consumer's own test command must run in the SDK its projects target

## Why

A consumer's `quality.Test` .NET leg reported

```
cicd module error: test-leg dotnet: test command failed (exit 1)
```

and nothing else. The envelope named no SDK, no version file and no remedy. The
run was the consumer's shadow pipeline build on cicd v3.7.2.

The command had not failed. It had never compiled. Every project in the leg
answered

```
/usr/share/dotnet/sdk/8.0.425/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.TargetFrameworkInference.targets(166,5):
error NETSDK1045: The current .NET SDK does not support targeting .NET 10.0.
```

because cicd had run the consumer's `dotnet test` in
`mcr.microsoft.com/dotnet/sdk:8.0` against a tree whose every `.csproj` declares
`<TargetFramework>net10.0</TargetFramework>`. The second-order effect followed
immediately: the coverage harvest swept for `*.cobertura.xml` and got
`find: '/tmp/test-results': No such file or directory`, so the ratchet had
nothing to read either.

cicd already knew the answer. In the **same pipeline run**, a few Dagger nodes
earlier, its own probe had printed

```
===CICD-GLOBALJSON===

===CICD-TFM===
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
```

— an empty global.json section, because the repository has none, and a
TargetFramework the repository states outright. `quality.Check`'s two .NET legs
read that probe through `discoverDotnetBandRequest` and `dotnetResolveBand`
(`specs/name-the-dotnet-target-band.md`) and select the 10.0 band correctly.

`quality.Test` did not. It resolved through `ResolveToolchainDetail`, the
ADR-004 root-version-file resolver, which for .NET reads `global.json` and
nothing else. No `global.json` meant no request, no request meant
`ToolchainFromDefault`, and the default is a compile-time pin of
`mcr.microsoft.com/dotnet/sdk:8.0`.

Two resolvers for one question, and the wrong one was wired to the leg that runs
the consumer's own command.

### Why it was silent

`ToolchainResolution.Note` is set only when a version file was *present and not
decisive*, and warned only then — deliberately, because a line on every run is a
line readers learn to skip
(`specs/name-the-version-file-cicd-could-not-use.md`). An **absent** global.json
carries no Note. So the one case where cicd's choice of SDK was both wrong and
unaskable produced no disclosure at all.

`quality.Check` has a remedy for exactly this error text — `dotnetSDKRemedy` /
`dotnetTargetBandRemedy` turn NETSDK1045 into *"the project targets .NET 10.0,
which is newer than the SDK …"* — and it is wired into the Check legs only. The
BYO leg's failure reached the consumer as `exit 1`.

## What changed

`quality.Test`'s .NET path no longer goes through `ResolveToolchainDetail`.
`resolveTestToolchain` branches on `Dotnet` into `resolveDotnetTestToolchain`
(`byotest.go`), which gathers two facts and decides nothing:

- `discoverDotnetBandRequest(ctx, src)` — the same cached alpine probe the Check
  legs read, so both answers come from one reading of one tree.
- `globalJSONSdkVersion(versionFileFS(ctx, src))` — the root file's three-state
  read.

The rule is `dotnetTestToolchain` in the new **untagged** `dotnettoolchain.go`:

| Repository says | Image | `From` | `Note` |
|---|---|---|---|
| `global.json` sdk.version naming a pinned band | that band | `global-json` | none |
| a literal `TargetFramework` naming a pinned band | that band | `target-framework` | none |
| a band cicd pins no image of | nearest pinned band that can build it | the source | `dotnetResolveBand`'s sentence, passed through |
| nothing readable, and a `global.json` present but not decisive | oldest pinned band | `default` | names the file, what it said, and the image used |
| nothing readable, and no `global.json` | oldest pinned band | `default` | none |

`ToolchainFromTargetFramework` is added to the resolution-level vocabulary in the
canonical `src/internal/detect/toolchain.go` and synced.

## Proof

`src/quality/dotnettoolchain_test.go`, 11 assertions under `-tags unit_test`.
`TestATargetFrameworkChoosesTheSDKWhenNoGlobalJSONDoes` is the measured run.
`TestTheBYOLegResolvesTheSameBandAsTheCheckLegs` drives five requests through
both `dotnetResolveBand` and `dotnetTestToolchain` and refuses a disagreement —
the defect being fixed was a second resolver disagreeing, so the agreement is
asserted rather than assumed. `TestEveryPinnedBandIsReachable` fails on an empty
band list rather than passing vacuously.

## Decisions

**The image stays a readable tag, not a digest.** `dotnetSDKBase` hands the Check
legs digest-pinned `dotnetSDK80Image` / `dotnetSDK100Image`; the BYO leg keeps
`mcr.microsoft.com/dotnet/sdk:<band>`. That is ADR-004 level 3 — the container a
*consumer's* command runs in is theirs, resolved at run time — and pinning it
here would move a consumer's test runner onto a digest cicd bumps on its own
schedule. The band was what was wrong, so the band is the only thing that moves.

**The rule lives in an untagged file.** `byotest.go` is `//go:build !unit_test`,
so a switch written there is invisible to `make test-module-units`. This is the
same move `specs/refuse-a-language-set-that-scans-nothing.md` made, for the same
reason: a `default`-less switch survived in a tagged file untested.

**Silence still means "nothing anomalous".** A band cicd served exactly carries
no Note, so a correct `net10.0` resolution adds no line. Only a request cicd
could not serve, or a version file present and not decisive, speaks.

**A probe failure is an error, not a fallback.** It is the same tiny image that
answers the target sweep, so a failure means the engine or the mount is broken.
The caller returns it with no envelope, so nothing can be misread as a result.

**The source strings are constants.** `dotnetBandSourceGlobalJSON` /
`dotnetBandSourceTFM` replace literals that were spelled in
`parseDotnetBandRequest` and would now have been spelled again in the switch that
maps them to a resolution level.

## Known residue

**`build.BuildArchive` has the same defect.** `src/build/archive.go:117` calls
`ResolveToolchain(lang, "", fsys)`, so a `net10.0` repository building an archive
runs `dotnet build` in the 8.0 default for the same reason. It is not fixed here:
`BuildArchive` returns a `*dagger.Directory` and so has no `warnings[]` to carry
a disclosure — the limitation `specs/name-the-version-file-cicd-could-not-use.md`
already records. Filed separately.

**The BYO leg still gets no NETSDK1045 remedy.** `dotnetSDKRemedy` is wired into
the Check legs only. With the band resolved correctly the error should not arise,
but a repository that reaches a band cicd cannot serve will still see the bare
exit status rather than the sentence explaining it.

## What green does not mean

A correctly resolved band says the SDK can build the target framework. It says
nothing about whether the consumer's command tested the whole repository —
`dotnetLegScopeWarning` answers that, separately, and refuses to divide its own
numbers.
