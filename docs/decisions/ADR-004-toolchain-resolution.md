# ADR-004: Toolchain resolution precedence

## Status
Accepted

## Context
`BuildArchive` and `Quality.Test` run consumer commands in a toolchain container
cicd selects. Hardcoded images (node:20-alpine etc.) silently build/test with
the wrong runtime when a repo pins node 22 in `.nvmrc` or a specific SDK in
`global.json` — the attestation would lie. But this repo's supply-chain rule
pins third-party images by digest (CWE-494, see the trivy pin in
`src/build/images.go`), and version-file detection necessarily produces dynamic
tags that cannot be digest-pinned ahead of time.

## Decision
Resolution precedence for toolchain images:

1. **Explicit `toolchainImage` param** — consumer-supplied, may include a
   digest. The only digest-pinnable level.
2. **Version-file detection** — `.nvmrc` → `node:<major>-alpine`,
   `global.json` (`sdk.version`) → `mcr.microsoft.com/dotnet/sdk:<major.minor>`.
   Malformed or absent files fall through silently.
3. **Pinned language defaults** — the existing constants (node:20-alpine,
   golang:1.26-alpine, python:3.12-slim, dotnet/sdk:8.0).

Canonical implementation lives in `src/internal/detect` (plain Go, no Dagger
imports); modules carry local copies per the no-shared-module rule, mirroring
the schema.go precedent.

## Consequences
Easier: zero-config correct runtime versions; escape hatch for custom base
images and internal registries.
Harder: detection-level tags weaken the digest-pin rule for toolchain images —
documented in the how-to so security-sensitive consumers know the explicit
param is the digest-pinnable path.
Committed to: scanner/tool images (trivy, gitleaks, semgrep…) stay digest-pinned
regardless — this ADR covers only the container the consumer's own command runs
in, where the consumer's code already executes by definition.

## Amendment: the commitment is enforced, not just stated

The "stay digest-pinned regardless" commitment above was honoured in exactly one
place — `src/build`'s Trivy pin — and nowhere else. Every other scanner, linter,
policy engine, helper and repository-chosen language image shipped on a bare tag,
and that one pin named the amd64 *platform manifest* rather than the
multi-architecture image index, so it could not serve arm64 local development.

The commitment is now mechanical:

- every image cicd selects on its own behalf is declared in
  `scripts/runtime-images.json` as a readable `tag@sha256:<index digest>` and
  written as constants in the owning module's `images.go`;
- `scripts/check-runtime-image-pins.py` (CI's `lint-repo`, `make
  check-image-pins`) *discovers* `From(...)` references from source instead of
  consulting a list, so a brand new tool image on a mutable tag fails the build
  even though nothing has heard of it — and a pin no update manager would ever
  propose a bump for fails too;
- `renovate.json` recognises those pins and the Dagger version, grouped one tool
  family per pull request so a bad bump can be reverted alone.

**The precedence chain above is unchanged and is deliberately excluded from that
gate.** All three levels — the explicit `toolchainImage` param, version-file
detection, and the `detect.DefaultImages` fallback the same resolver returns when
no version file is present — produce a value at run time from consumer input, so
none of them can be digest-pinned ahead of time. Requiring it would either remove
the escape hatch or demand digest-pinned version-file detection, which is not
possible. The checker classifies those call sites (`src/build/archive.go`,
`src/quality/byotest.go`) as dynamic and never fails them, and a test asserts
they stay dynamic — if either ever resolves to a literal, this ADR's escape hatch
has silently become a hardcoded image.

The images now pinned are the ones outside that chain: the scanners, `conftest`,
`golangci-lint`, the Alpine helpers, and the language images `quality.Check`'s
own auto-detected lint/test passes select — a
path with no consumer image input at all, which is why it is not covered here.

Reference: [Runtime tool images](../reference/runtime-images.md).

## Alternatives rejected
- Explicit param required: every consumer configures it, and the wrong-version
  footgun returns the day someone bumps `.nvmrc` without bumping CI.
- Detection only, no param: dead end for internal registries and custom images.
