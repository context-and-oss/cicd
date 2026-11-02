# Intent: pin every repository-selected runtime image by digest, and make the pin rejectable

## Why

ADR-004 committed in writing to "scanner/tool images (trivy, gitleaks, semgrep…)
stay digest-pinned regardless". That sentence was true of exactly one image in
the tree. `src/build/main.go` pinned Trivy; Semgrep, Gitleaks, TruffleHog, ZAP,
conftest, golangci-lint, the Alpine helpers and the language images
`quality.Check` selects for an auto-detected language all
ran from a mutable tag. A mutable tag can be repointed between the review that
approved it and the run that executes it (CWE-494), and cicd's whole output is an
evidence envelope asserting which tool produced which finding — so an
unverifiable tool reference makes the attestation unverifiable too.

The one existing pin was also wrong in a way nobody could see. Its digest,
`sha256:4a092a85…`, is the amd64 *platform manifest* of `aquasec/trivy:0.50.4`,
not the image index, because it was copied out of `docker inspect
--format='{{index .RepoDigests 0}}'` as the comment beside it instructed. That
reference resolves on CI's amd64 runners and offers no arm64 child, so local
development on an arm64 machine could not pull it at all.

Stating the rule again would not have held, since the drift happened while the
rule was already written down. We chose to make the rule mechanical instead: a
checker that discovers image selections from source rather than from a list, so
the next tool image added on a bare tag fails without anyone remembering to
extend an allowlist.

## What changed

Each module that selects a tool container gained an `images.go` holding the
constants: `src/security/images.go`, `src/quality/images.go`,
`src/build/images.go` and `src/risk/images.go`. Every entry has one shape — a
`// renovate-image: <depName>` comment, a version constant carrying the readable
tag, and an image constant concatenating that tag with `@sha256:<digest>`. The
tag stays legible because pinning must not cost a reviewer the ability to see
which version is in play, and because the version constant remains the single
source of the tool version reported in evidence (`zapVersion` reaches
`toolInfo.Version` directly; the scanners record theirs inside the SARIF or
CycloneDX they emit). Call sites now read `From(trivyImage)` rather than
assembling a reference inline, so a reference cannot be written twice and drift.

Every digest is the multi-architecture image index, resolved with `dagger core
container from --address <repository>:<tag> image-ref` and checked to be the same
value under `--platform linux/amd64` and `--platform linux/arm64`. The Trivy pin
in `src/build/images.go` moved from the amd64 manifest to the index that carries
that manifest as its amd64 child, so amd64 content is byte-identical and arm64
now resolves. `scripts/runtime-images.json` records the two verified platforms
next to the entries, so widening that list is a visible act that obliges someone
to re-verify.

`scripts/runtime-images.json` is the declared inventory: family (the rollback
unit), role, repository, tag, digest, purpose and the source files that reference
it. `scripts/runtime_images.py` holds the discovery and checking logic and
`scripts/check-runtime-image-pins.py` is its command-line entry point, wired into
`lint-repo` in `.github/workflows/ci.yml` and available as `make
check-image-pins`. Discovery walks every `.go` file under `src` plus the root
`Makefile` and resolves each `From(...)` argument through package constants and
local literals, which is what lets it fail an image the inventory never heard of.
It then checks both directions — a selected image missing from the inventory and
an inventory entry no source references any more are both errors — and refuses an
entry that `renovate.json`'s custom managers would not match, so no pin can rot
without an update path.

The checker stays offline on purpose. It judges the immutable *form* of a
reference and never asks a registry what a tag points at, because proposing
version bumps belongs to update automation and proving a digest is pullable
belongs to a run against a real engine. That second half is
`assert_pinned_images_resolve` in `scripts/smoke/commit-shapes.sh`: the container
shape already executes the security, quality, risk and build images by digest as
part of the pipeline, and the new assertion additionally resolves every declared
reference directly, including image paths a fixture-based pipeline may not
exercise on a particular run.

`renovate.json` is bounded three ways rather than left at defaults.
`enabledManagers` is `custom.regex` only, since a `github-actions` manager would
compete with Dependabot for the action pins and would break the intent gate's
machine-origin path, which recognises `dependabot[bot]` by name. Every
`managerFilePatterns` entry is an anchored regex naming files this repository
owns — `src/**/images.go`, the root `Makefile`, `.github/workflows/` and module
`dagger.json` files — so `templates/`, `docs/` and `testdata/` are never
rewritten and consumer copy-paste examples keep their prose. `packageRules` group
one tool family per pull request, which is what makes a bad bump revertable
alone. Activating the Renovate App itself remains a human action; nothing in
ordinary CI reads this file.

`scripts/tests/test_runtime_image_pins.py` and
`scripts/tests/test_update_config.py` are the negative fixtures. They build
throwaway trees containing a tag-only scanner, a malformed digest, a static image
absent from the inventory, an inventory entry with no remaining source, an
unparseable reference, and a dynamic consumer-resolved image that must still be
accepted — plus a case proving a checker that only consulted a hardcoded
allowlist would miss a newly added static `From` call. `test_update_config.py`
runs the Renovate manager regexes against the real tree and asserts they match
every pin, the Dagger version strings and nothing under `templates/`.

`docs/reference/runtime-images.md`, `docs/decisions/ADR-004-toolchain-resolution.md`,
`CLAUDE.md` and `CHANGELOG.md` record the contract. The ADR amendment says
plainly that the consumer-toolchain precedence chain is unchanged and excluded
from the gate.

`CONTRIBUTING.md` gained a section stating that every change carries an intent
artifact and listing the rules such an artifact has to satisfy. This change
itself first shipped without one and the repository's own precommit run rejected
it, which is the gate working — but the obligation was written down nowhere a
contributor would look, so the same wall was waiting for the next change.

## Decisions

We did not pin the container a consumer's own build or test command runs in.
ADR-004 resolves it at run time from `--toolchain-image`, then `.nvmrc` /
`global.json`, then a language default, and all three levels produce a value from
consumer input, so none can be pinned ahead of time. The checker classifies those
two call sites — `src/build/archive.go` and `src/quality/byotest.go` — as dynamic
and never fails them, and a test asserts they stay dynamic, because if either
ever resolved to a literal the escape hatch would have quietly become a hardcoded
image.

We kept the version constants rather than collapsing each pin to a single string.
A bare digest would satisfy the gate and cost every reader and every evidence
consumer the tool version, and the two values cannot disagree while the image
constant is built from the version constant.

We treated the root `Makefile` as in scope even though it is not module source,
since `make policy-test` launches conftest directly and claims to run the same
image the real gate runs. Leaving it out would have allowed the claim to become
false with nothing failing.

We did not add a tag-only exception mechanism. No approved exception exists, and
an exception list is the failure mode this change exists to remove.

## Verification

`python3 -m unittest discover -s scripts/tests -t .` covers the new suites
alongside the existing ones. `python3 scripts/check-runtime-image-pins.py` passes
against the live tree and reports 24 static references across 14 declared images
and 12 update groups, with `src/build/archive.go` and `src/quality/byotest.go`
classified as consumer-resolved. `python3 scripts/check-repo-surface.py` and
`python3 scripts/check-workflow-pins.py` stay green, and
`bash scripts/test-module-units.sh` runs the module unit suites. Digest
resolution and the Dagger paths that consume these images are proved by the
container smoke rather than by the offline checker, for the reason recorded
above.
