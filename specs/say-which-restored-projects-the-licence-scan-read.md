# Say which restored projects the licence scan read

## Problem

The licence scan restores every .NET project under the scanned tree so Trivy
can read each NuGet package's licence from its `.nuspec`
(`specs/read-nuget-licences-and-skip-a-licence-scan-that-read-nothing.md`). The
restore runs before Trivy, and its warning was written then: "cicd restored the
NuGet graph in … (N project(s)) so Trivy could read each package's licence".

Restored is not read. Trivy honours the tree's own `trivy.yaml` skips after the
restore has run, and `--license-exclude` drops what its patterns cover. On this
repository the restore sweeps eight fixture projects, all under `testdata/`,
which `trivy.yaml` skips. Trivy read none of them, and the warning still named
eight projects restored for Trivy to read. A reader of the evidence had no way
to tell that run from one that judged eight NuGet graphs.

Skipping the restore for a project Trivy will not read would need cicd to read
`trivy.yaml` itself, a second resolver for a question Trivy already answers, and
the doctrine forbids that. Trivy's report answers it after the fact.

## Decision

- The restore warning is written after the scan, from the same report
  `readLicenceCoverage` reads. A restored project counts as listed when a
  `nuget` result with at least one dependency package sits in its directory.
  Matching on directory, not file name, also matches NuGet's per-project
  lockfile name in a folder that holds several projects.
- Each restored project falls in one bucket, and the warning names each
  non-empty one: listed; removed by `--license-exclude` (via `covers`, so a
  pattern that removed no declaration stays reported inert); or not listed,
  which a project with no `PackageReference` explains and a `trivy.yaml` skip
  also produces. The warning names both causes, because cicd cannot tell them
  apart without the second resolver.
- "Listed" means the lockfile was read, not the licences. Whether those
  packages carry a licence is the dependency coverage line's to say
  (`specs/say-how-many-dependency-licences-were-read.md`), and the warning
  points there.
- The drift caveat (a floating version range resolved now) is kept only when at
  least one project was listed: nothing read cannot have drifted.
- When the scan did not complete, the warning says what was restored and that
  how much was read is unknown. It never says "none".

The verdict does not change. A restore that completed but was not read is the
consumer's own scope, narrowed by their `trivy.yaml` or their patterns, and the
warning names it. A row with no dependency licence read at all is already
`SKIPPED` by the coverage rule.

## Blast radius

The restore warning's text, on every .NET tree. Nothing greps it: no smoke
script, test or document quoted the old sentence. A tree whose projects are all
listed reads as before, plus one sentence pointing at the coverage line.

## Proof

`src/security/licencerestore_test.go`:

- the measured case: three projects restored, an empty report, "none of them"
  and every project named as not listed, with no drift caveat;
- all three listed, with no gap named;
- one listed, one removed by `testdata/**`, one not listed, each bucket named;
- the exclusion pattern stays inert after the split;
- a root-level project and a per-project lockfile name both match by
  directory, and an npm lockfile in a project's folder does not;
- a scan that failed reports the read as unknown.

Each case drives `readLicenceCoverage` over a Trivy-shaped report, so the target
form is the one Trivy writes (`<dir>/packages.lock.json`, class `lang-pkgs`,
type `nuget`), checked against a measured report.

## Residue

The restore still runs for projects Trivy then skips, which costs an SDK image
pull and a restore for nothing. Removing it needs the skip list before Trivy
runs; that is the second resolver this spec declines. A project that sets
`NuGetLockFilePath` outside its own directory reads as not listed.
