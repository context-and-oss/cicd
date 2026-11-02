# ADR-001: Artifact shapes — image and archive

## Status
Accepted

## Context
The repositories consuming cicd are heterogeneous: containerized services sit
next to solution zips and .NET zips deployed to a web app host. The commit
stage's only build primitive was `DockerBuild`, so non-container repos got no
attested artifact, no artifact-level scanning, and no SBOM→Dependency Track
chain. Forcing a Dockerfile onto a zip-shaped repo produces evidence about an
artifact that never ships — misleading attestation, worse than none.

A competing model — cicd owning lint/build/test execution with each repo's own
configs — was rejected: it either runs degraded vanilla configs (theater) or
inherits every repo's toolchain breakage (unbounded platform-team load), and it
breaks local/CI parity.

## Decision
cicd models exactly two artifact shapes:

- **image** — existing path: consumer owns the Dockerfile; cicd executes
  `DockerBuild`, SBOMs and scans the image.
- **archive** — new path: consumer owns an explicit build command; cicd executes
  it in a resolved toolchain container, treats the output directory as the
  attested artifact, SBOMs from source lockfiles, and secrets-scans the built
  output.

Ownership split: consumers own *definitions* (Dockerfile, build command, test
command, lint/format/typecheck configs entirely); cicd owns *execution and the
evidence plane* (build/test execution, SBOM, scans, Dependency Track, risk gate,
evidence aggregation, notifications). Deploy stays consumer-owned.

Each shape gets its own composite entry point (`Run` / `RunArchive`) rather than
mode-switching params on one function.

## Consequences
Easier: non-container fleet is first-class; image path stays frozen (additive
v1.x); contracts stay flat and machine-verifiable; `dagger call --help` shows
only relevant params per shape.
Harder: shared composite tail (evidence→comment→DT→notify) is maintained behind
two entry points via a private helper; docs must explain which shape to pick.
Committed to: every future artifact shape is a new entry point, not params on an
existing one; cicd never auto-detects build commands; archive SBOMs come from
source lockfiles (bundles/published DLLs yield garbage dependency data) while
secrets scans target the built output (bundled-.env class of leak).

## Alternatives rejected
- Mode-switching params on `Run` (`--build-cmd` flips behavior): conditional
  contract semantics, dead params per mode, "what if both are set" policing.
- cicd-owned build/test definitions: platform team becomes the bottleneck for
  every red build in the fleet; local/CI parity breaks.
- Dockerfile-wrapping zips to reuse the image path: attests an artifact that
  never ships.
