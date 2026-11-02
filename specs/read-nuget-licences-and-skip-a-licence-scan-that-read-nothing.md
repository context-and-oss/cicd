# Read NuGet licences, and skip a licence scan that read nothing

## Problem

`security.ScanLicenses` read MediatR as `CLEAN` with `examined 0 licence
declarations`. "0 outside policy" over zero declarations is a policy that
judged nothing, and `CLEAN` is the word for one that judged something and found
it acceptable. The non-run matrix pinned the empty report `{"SchemaVersion":2}`
as "a clean read".

Measured on MediatR with the pinned Trivy:

| What Trivy was given | Licence declarations read |
|---|---|
| The tree with its restored `packages.lock.json` files | 0 |
| The same tree plus the restored NuGet packages folder | 277 |
| The same tree plus a snapshot holding only the `.nuspec` files | 277 |

Trivy reads a NuGet package's licence from its `.nuspec`, never from the
lockfile. A lockfile names versions, not licences, so every .NET tree read zero
NuGet licences whether it committed a lockfile or not.

## Decision

cicd clears it for .NET and says so for everything else.

- `ScanLicenses` runs the dependency-input probe. When the tree holds .NET
  markers — lockfile or not, unlike the dependency scan's restore — it restores
  the NuGet graph with the same pinned SDK band, feed and token as `ScanSource`
  (`--nuget-feed-url`, `--nuget-token`, forwarded by stage-2), and Trivy reads
  the restored tree with the `.nuspec` snapshot mounted at the packages path.
- The snapshot is copied out of the shared cache volume **inside the restore
  exec**, so it is cached with the lockfiles that exec wrote. A cache volume is
  not part of an exec's cached result; reading it directly would let an engine
  that pruned it hand the scan an empty folder, and 0 licences would read like a
  tree whose packages declare none.
- A probe failure, a restore that could not run, a project that did not
  restore, or a snapshot that could not be copied is an `errors[]` entry and the
  row's error: `ERROR`, failing at every threshold including `NONE`. The
  message says a lockfile does not clear it and names the feed and SDK-band
  remedies.
- A completed scan that read zero declarations and excluded none is `SKIPPED`,
  not `CLEAN`. It still passes: a tree whose packages carry no licence metadata
  Trivy can reach is not a gate the consumer can clear by changing code. The
  warning names what was there — up to three dependency inputs when present,
  and that cicd supplies installed package metadata only for .NET.
- A scan that excluded every declaration is not a zero read; the exclusion
  warning already reports it.

## Blast radius

- A .NET tree whose restore fails here (a private feed without credentials, a
  target framework outside the pinned bands) now reads a licence `ERROR` where
  it read `CLEAN` over nothing.
- So does a tree with a project that restores under no SDK at all. MediatR is
  one: `samples/MediatR.Examples.Windsor` targets `net6.0` and references
  `MediatR.Examples`, which targets only `net10.0`, so `dotnet restore` fails
  `NU1201` in every SDK. That is a defect in the tree, not a band cicd lacks,
  and the stage-2 path forwards no directory exclusion to the licence leg, so
  fixing the project is the only way to clear it. The remedy names the case.
- Every .NET tree pays a restore in the licence leg, also when it commits a
  lockfile.
- The snapshot holds the whole shared cache's `.nuspec` files, not only this
  tree's. Trivy looks packages up by the id and version the lockfile names, so
  that costs bytes, not correctness.

## Still open

- Under a floating version range, the licences come from a graph resolved now;
  the restore warning says so.
- The dependency scan's own restore (`dotnetrestore.go`) gives the same
  feed-or-band remedy without the "restores under no SDK" clause; it runs only
  without a lockfile, so MediatR never reaches it.
- npm, pip, Go and the rest still read no dependency licence from a lockfile.
  They now read `SKIPPED` with the inputs named instead of `CLEAN`.

## Verification

- `src/security/licencenuget_test.go`: the snapshot runs before `exit 0`, both
  scripts parse under `sh -n`, the unmatched glob is guarded, the licence
  restore fires on a committed lockfile, every restore error case, the
  zero-read decision, its warnings, and the shipped row is `SKIPPED` and
  passing while an error beside it is `ERROR` and failing at `NONE`.
- `src/security/nonrun_matrix_test.go`: the empty licence report is now a zero
  read, not a clean one.
- End to end at `--fail-on NONE`:
  - MediatR: 307 licences read where 0 were, and `ERROR` on the one sample
    project that restores nowhere (`NU1201`, reproduced by hand in
    `sdk:10.0`).
  - `testdata/go-app`: `SKIPPED` and passing, examined 0, the warning naming
    `go.mod`.
  - `testdata/dotnet-app`: `CLEAN`, 10 licences (`sdk:8.0`).
  - `testdata/app-workspace`: `CLEAN`, 3 licences, with the restore warning
    (the positive control `scripts/smoke/commit-apps.sh` asserts).
