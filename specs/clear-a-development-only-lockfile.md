# Clear a development-only lockfile instead of reporting it as a non-run

## Problem

`trivy fs` leaves development dependencies out of its results. A repository
whose only lockfile holds nothing but development dependencies therefore gets a
native report with `"Results": null`, the same report Trivy writes for a
lockfile it could not parse at all. `security.ScanSource` reads both as
`errTrivyNoTargets`; because the dependency-input probe finds the lockfile, the
scan is an ERROR that fails at every threshold, including `--fail-on NONE`.

Observed on an all-development Poetry lockfile: the default scan and
`--include-dev-deps=false` both return no results. `--include-dev-deps` resolves
the lockfile with every package flagged `Dev: true`, including development
vulnerabilities. The original inventory and vulnerability totals are omitted.
That consumer has a correct tree and a gate it cannot clear, which is the gate
that gets switched off. So cicd has to clear it.

## Decision

We chose to prove the lockfile parsed with a second scan rather than to accept a
resultless report as clean, because the two causes of `"Results": null` look
identical and only one of them is clean.

- The gated scan pins `--include-dev-deps=false` on `trivy fs`, so a consumer's
  `trivy.yaml` cannot widen it without the evidence saying so. Only `trivy fs`
  accepts the flag on the pinned release (`image`, `sbom` and `convert` refuse
  it), so it is pinned there and not in the shared flag set.
- When the gated scan reports no targets **and** the independent probe found a
  dependency input, cicd reruns `trivy fs` with `--include-dev-deps` into a
  separate native report. That report is never converted to CycloneDX, never
  feeds the SBOM, and never reaches the severity gate.
- **The rescan resolved packages, all flagged development:** the dependency row
  is `CLEAN` with `examined 0 resolved packages` (no total: the development
  packages are out of scope, not unread). Its `RUNTIME SET EMPTY` warning names
  the lockfile, the package count, the development vulnerabilities by severity
  and the first ten by ID, and says the classification is Trivy's. The source
  SBOM row is `CLEAN` over 0 components, with its own `RUNTIME SET EMPTY`
  warning.
- **The rescan is also empty, unreadable, or lists a package Trivy did not flag
  as development:** the scan stays an error. The message now says a dependency
  input was found (count and an example path, without the `/src/` mount
  prefix), that Trivy produced no results for it, why the rescan could not
  clear it, and the remedy. It still wraps `errTrivyNoTargets`, so the original
  string survives.
- Ecosystem reconciliation runs against the **original** probe and the rescan's
  resolved types, never a probe of the rescan (the same trap as the .NET
  restore: a second reader must not define what the first was asked to read).

Development vulnerabilities are listed, not gated. Gating them would make every
repository whose test tooling has a CVE fail a runtime gate; hiding them would
throw away a measurement cicd already paid for.

## Not claimed

A **mixed** tree, where another ecosystem resolves (a `go.mod` beside an
all-development or malformed `poetry.lock`), never reaches this path: the gated
report has targets, and `unresolvedEcosystems` exempts any ecosystem that has a
lockfile. That lockfile passes unremarked. It is recorded as an open gap in
`src/security/CLAUDE.md`; closing it means comparing each probed lockfile with
the report's targets, which is a separate change.

## Verification

`src/security/devonly_test.go` pins the classification: a rescan with all
development packages clears the row; an empty, `null`, malformed, package-less,
non-object or runtime-carrying rescan keeps the error, keeps `errTrivyNoTargets`
in the chain, never prints a `/src/` path and never passes. It also pins the
`fs`-only flag, the dev-rescan arguments, the warning's cap of ten named
vulnerabilities, and that a `.csproj` beside a development-only `poetry.lock`
is still unresolved for .NET.

End to end at `--fail-on NONE`: the all-development case reads
`trivy CLEAN, examined 0 resolved packages` with both `RUNTIME SET EMPTY`
warnings, including the development vulnerability disclosure. The source-owned
`testdata/go-app` still reports its HIGH `jwt-go` finding over 2 resolved packages.
