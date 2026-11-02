# Stand down on a solution without projects

## Problem

A tree whose only .NET files are solution files (`.sln`, `.slnx`) failed both
dependency rows with an error the consumer could not clear. This repository
is one: `src/internal/detect/testdata/slnx-solution-only/App.slnx` is a fixture
for language detection. With `security.scan-licenses` and
`security.scan-source` run on `./src/internal`, each row read `ERROR`:

- the licence row: "the .NET restore the NuGet licences are read from found no
  project file under /src …, so no NuGet package metadata exists and no NuGet
  licence was read";
- the vulnerability row: the same restore error, followed by "dotnet is present
  in the scanned tree … but trivy resolved no dotnet dependency graph from it".

Both are true and neither is a gap. A solution names projects; the projects
declare the packages. With no project there is no NuGet graph, so a restore has
no input and a lockfile has no project to belong to. The remedy the vulnerability
error gives (commit `packages.lock.json`) cannot be followed. A gate the consumer
cannot clear gets switched off, so cicd has to clear it.

## Decision

- **A solution file is a listing, not a dependency marker.** The ecosystem table
  in `src/security/ecosystems.go` gains `listings` beside `markers`; for .NET it
  is `*.sln`, `*.slnx`. An ecosystem whose markers in the tree are all listings
  is *listings only*. We chose a field on the one table rather than a .NET check
  at each call site, because the restore trigger, the licence trigger and the
  unresolved verdict must keep asking the same table; that is why they share it.
- **Listings only means no restore and no verdict.** `dotnetRestoreNeeded` and
  `dotnetLicenceRestoreNeeded` return nothing, `unresolvedEcosystems` skips the
  ecosystem, and a resultless Trivy report over such a tree is `NOT APPLICABLE`
  rather than an error, since a listing is the one probe line that does not
  count there.
- **It is named, not silent.** Both rows carry
  `<row>: SOLUTION WITHOUT PROJECTS — N solution file(s) (…)`, naming the files
  and the project patterns looked for. The licence row's `NOT READ` warning no
  longer lists a lone solution as a dependency input it read nothing from.
- **Decided from the probe, never from the restore.** The probe walks the whole
  tree, `bin/` and `obj/` included; the restore skips those. A tree whose only
  project sits under `bin/` is therefore not listings only. It still reaches the
  restore, and the restore's no-project error, which describes a real gap,
  stays an error. Reconciling against what the restore found instead would let
  the restore's own blind spot decide that there was nothing to read.

## Blast radius

- A solution-only tree, or a tree with a solution beside another ecosystem,
  moves from `ERROR` to its other rows' verdict plus the warning. A pure
  solution-only tree reads `SKIPPED` on both dependency rows.
- A solution that lists a project type cicd does not restore (`.sqlproj`,
  `.esproj`, `.proj`) used to fail and now warns. The warning says so: that
  project's NuGet packages are judged only from a `packages.lock.json`
  committed beside it. We accept that, rather than keep the error, because the
  error's remedy did not cover those projects either, and the restore never
  read them.
- Any tree with a `.csproj`, `.fsproj` or `.vbproj` anywhere is unchanged.

## Proof

`src/security/ecosystems_test.go`, `TestSolutionsWithoutProjects`: one `.slnx`
(the fixture's path), a `.sln` beside a `.slnx`, a solution beside a project
(the restore fires, `dotnet` is unresolved), a project only under `bin/` (the
restore fires), and a solution beside an unlocked `package.json` (only `node`
is unresolved). `TestSolutionsWithoutProjectsWarning` holds the wording and
the cut list. Disabling the listings check, and separately counting a listing
in the not-applicable check, each turned the suite red.

End to end, on `./src/internal` at `--fail-on NONE`: `scan-licenses` and
`scan-source` no longer carry the restore error or the unresolved `dotnet`
verdict, and each carries the `SOLUTION WITHOUT PROJECTS` warning naming
`detect/testdata/slnx-solution-only/App.slnx`.

| Scan | Before | After |
|---|---|---|
| `scan-licenses` | `ERROR`, the restore found no project file | `SKIPPED`, passes; the tree's one `go.mod` requires nothing, so `NOT READ` still names it |
| `scan-source` | `ERROR`, the restore found no project file | `CLEAN`, passes |
