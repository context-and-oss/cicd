# Say how many dependency licences were read

## Problem

The zero-read rule (`specs/read-nuget-licences-and-skip-a-licence-scan-that-read-nothing.md`)
makes a licence scan that read no declaration `SKIPPED`. It does not catch a
scan that read one. "Scanned" counts licence declarations, and a declaration is
not a dependency.

Measured with the pinned Trivy, on one Go module of this repository with 36
dependencies, and on the whole repository (16 Go manifests and a root
`LICENSE`):

| Tree | Module cache | Mode | Dependencies with a licence | Declarations read |
|---|---|---|---|---|
| one module | absent | metadata only | 0 of 36 | 0 |
| one module | absent | `--license-full` | 0 of 36 | 0 |
| one module | populated | metadata only | 36 of 36 | 50 |
| one module | populated | `--license-full` | 36 of 36 | 50 |
| whole repository | absent | `--license-full` | 0 of 540 | 1 (the root `LICENSE`) |

cicd scans a checkout, which has no module cache. So the default run on the
whole repository read the root `LICENSE`, judged it acceptable, and reported
`CLEAN` with `examined 1` — a policy that had judged none of the 540
dependency packages. The zero-read rule did not fire, because one declaration
had been read.

`--license-full` was on by default on the stated grounds that metadata mode
reports nothing for Go. The table shows what full mode actually adds for Go: the
tree's own `LICENSE`, never a dependency's. Go dependency licences come from the
module cache in either mode.

Only Trivy's own package list tells the two runs apart. The licence report
carries it already: every `lang-pkgs` result lists its `Packages`, each with a
`Relationship` and the `Licenses` Trivy read, without `--list-all-pkgs`.

## Decision

- `readLicenceCoverage` counts the dependency packages Trivy listed and how many
  carry a licence. `root` and `workspace` packages are the consumer's own and
  are left out of both counts; an empty or unknown relationship counts as a
  dependency, because a package nobody classified is not one cicd may assume is
  first-party.
- A manifest the `--license-exclude` filter covers is left out of both counts,
  matched by its `Target` like a metadata declaration. The pass uses
  `covers`, which records no hit, so a pattern that removed no declaration is
  still reported inert.
- The counts go into the payload as `dependencyCoverage`, per ecosystem with
  its manifests.
- **None read**: a completed scan that listed dependencies and read a licence
  for none of them is `SKIPPED`, even when declarations from the tree's own
  files were judged. Those declarations stay judged: a finding among them
  still makes the row `FINDINGS`, because a finding outranks `SKIPPED`. The
  warning, `Dependency licences: NOT READ`, names each ecosystem's count and
  manifests, says the declarations judged came from the tree's own files, and
  names where dependency licences come from.
- **Some read**: `Dependency licences: PARTLY READ — W of N`, naming only the
  ecosystems that fell short. The row stays graded; what was read is real.
- A scan that read no declaration at all keeps the existing zero-read warning,
  byte for byte, and gets no coverage warning beside it.
- A scan that errored is never `SKIPPED` by this rule.

`Examined` stays `{licence declarations, Scanned}` with no total. Packages are a
different unit, and a `Total` in packages under a count of declarations would
make a ratio of two things that do not divide. The denominator lives in the
payload and the warning instead. The warning carries the counts because
`buildCombined` drops the generic payload from the audit bundle.

The source-only mode is untouched by construction: `sourceLicenseReport`
re-marshals a type with no package list, and that mode says it does not assess
dependency licences. The SBOM rescan reads only what the SBOM declares, so its
warning says that instead of pointing at a module cache.

The `--license-full` default stays on, and its comments now say why: it is
what reads the tree's own `LICENSE`, not what reads a Go dependency.

## Blast radius

- A Go tree, a Python tree without site-packages, and a Node tree without
  `node_modules` read `CLEAN` before and read `SKIPPED` with a `NOT READ`
  warning now. They still pass at every threshold. A consumer cannot clear it
  by changing code, so it must not fail.
- A tree where Trivy read some dependency licences gains a `PARTLY READ`
  warning and keeps its verdict.
- A .NET tree whose restore succeeded reads every NuGet licence and is
  unchanged.

## Proof

`src/security/licencecoverage_test.go` builds the measured Go shape: one root
package, 36 dependencies with no licence, and a root `LICENSE` as one
declaration, which is the whole-repository case at one module's size. It
asserts `0 of 36`, `SKIPPED`, the warning text, and that the zero-read rule
does not fire. It also covers the populated cache (36 of 36, no
warning), a partly read mixed graph, a workspace of first-party packages only,
an excluded manifest that leaves the pattern inert, an errored run, the
source-only report, the SBOM wording, an unparseable package list, and the
payload field.

## Residue

Closed for public Go modules by
`specs/read-go-dependency-licences-from-a-downloaded-module-graph.md`: the
licence scan downloads the module graph from the Go module proxy and Trivy reads
each module's licence from a snapshot of it. A private module is still not read,
because cicd has no Go credential input; that spec names it in the envelope.
