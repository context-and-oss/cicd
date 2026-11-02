# Claim the source inventory under sbom

## Why

A consumer monorepo runs the commit composite with `--artifact none`. Its bundle for `main`
ships a `sbom.cdx.json` of under 200 KB listing a couple of dozen components, and the same bundle's
`concerns/index.json` lists `sbom` under `notAnswered`. A consumer reading the
bundle by concern (a fleet dashboard, the notify table) reports the repository as
having no inventory, next to the inventory.

The cause is that nobody claims it. `runTrivyFS` does two things under one tool
name: it resolves the dependency graph into a CycloneDX document, and it looks
that document up for known vulnerabilities. `ScanSource` and `ScanArchive` have
carried both results since their per-tool rows landed, but only the
lookup had a row, filed under `sca` because a vulnerability lookup answers the
dependency question. The document itself, which cross-cutting/evidence merges
into `sbom.cdx.json`, had no row. `build.Sbom` declares `ConcernSBOM` for the
image it inventories; with no artifact there is no image, and the source
inventory that the no-artifact envelope explicitly points readers to
("sbom.cdx.json in this audit describes source lockfiles") was declared by no
producer.

## What

`inventory.go` adds a fourth row to `security-source` and a third to
`security-archive`: `tool: trivy`, `concern: sbom`, `examined: N components`,
`CLEAN` when the document parsed. The count is the document's own, because
Trivy lists the lockfile beside every package it names; the package count
stays on the `sca` row in Trivy's words ("resolved packages").

The row is declared by the producer instead of derived downstream from the
presence of `sbom.cdx.json`, for the reason `Concern`'s own doc gives: the
aggregator only sees the document, and a DAST-cadence bundle ships an empty
one. The producer knows whether the inventory is a scan result or a
placeholder.

Three rules keep the rows and the envelope agreeing about one run:

- a scan error is carried on the row once and stays out of `errors[]` a second
  time, since it is already there from the scan;
- a scan that succeeded but left no parseable inventory is an error on the row
  AND in `errors[]`, so the envelope's `passed` falls with the row rather than
  reading `true` beside an `ERROR`;
- zero components is `CLEAN` over `0 components`, because a tree with no
  lockfile has an empty inventory, and "the tree declares dependencies Trivy
  did not read" is already caught by the ecosystem reconciliation on the `sca`
  row.

The `codeOnly` and `artifactOnly` paths used to slice the dependency rows off
by position (`Sources[:2]`, `Sources[1:]`). They now leave the rows out when
building the list, since a fourth row would have made the positional slice
keep the wrong rows.

## Blast radius

Every `security-source` and `security-archive` envelope gains a row, and every
bundle's `concerns/sbom.json` appears (or, with a container artifact, gains a
second row scoped `security-source` beside build's). `passed` and `outcome` on
the fused envelope do not move for any scan that produced a document, which is
every scan that succeeded today. `ScanImage` is unchanged: `build.Sbom`
already claims the image inventory, and a second row for the same document
would count it twice.

## Provenance

Consumer names and private references in this spec were replaced with neutral
stand-ins because `AGENTS.md` keeps them out of the public tree. The mechanism
and the measured behaviour are unchanged.
