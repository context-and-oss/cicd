# Runtime tool images

Information-oriented reference for the container images cicd runs. For the
decision behind the split between them see
[ADR-004](../decisions/ADR-004-toolchain-resolution.md).

## Two kinds of image, one rule each

| | Repository-selected tool image | Consumer-resolved toolchain image |
|---|---|---|
| Chosen by | this repository's own code | the consumer: `--toolchain-image`, or `.nvmrc` / `global.json` |
| Examples | Semgrep, Gitleaks, Trivy, TruffleHog, ZAP, conftest, golangci-lint, Alpine helpers | whatever the consumer's build or test command needs to run in |
| Rule | immutable: readable `tag@sha256:<digest>` | resolved at run time; only the explicit param can carry a digest |
| Where declared | the module's `images.go`, listed in `scripts/runtime-images.json` | nowhere — it is an input, not a pin |
| Enforced by | `scripts/check-runtime-image-pins.py` | not applicable; misclassifying one as static is itself a bug |

There is no tag-only exception in the first column.

Read the first row as *who chose the image*, not *who supplied the input*. One
path reads a consumer file and still lands in the left-hand column: the .NET
lint/test legs read `global.json` to pick **which of cicd's pinned SDK images**
runs. The consumer's input selects a row from a reviewed, digest-pinned set; it
never writes one. What the right-hand column exempts is a reference *composed* at
run time, which can name any image in the world and so cannot be reviewed in
advance.

## .NET SDK band selection

A .NET SDK image carries its band in the tag — `mcr.microsoft.com/dotnet/sdk:8.0`
cannot restore a `net10.0` project at all — so for the .NET legs of
`quality.check` the pin is not a default, it is the set of bands cicd can serve.
cicd therefore pins **one digest per band** (`src/quality/images.go`) and selects
one per run.

**Pinned bands: 8.0 and 10.0.** 9.0 is deliberately not pinned — it is STS and
out of support — so a `net9.0` project builds on the **10.0** SDK by roll-forward.

### Precedence

| | Source | Read from |
|---|---|---|
| 1 | `global.json` → `sdk.version` | the repository root only |
| 2 | highest literal `net<major>.<minor>` in a `<TargetFramework(s)>` element | `*.csproj` and `Directory.Build.props`, up to four directory levels deep, excluding `bin/` and `obj/` |
| 3 | nothing readable → the **lowest** pinned band (8.0) | — |

The request is then resolved to the **lowest pinned band at or above it**, since
a newer SDK builds an older target and never the reverse. Consequences worth
stating plainly:

- **A `net8.0` repository needs no migration action.** Same image, same digest,
  same `dotnet format` analyser defaults as before bands existed. Level 3 is also
  what a repository with a computed or conditioned `TargetFramework` lands on.
- **There is no consumer-facing flag, and none is planned.** Selection is
  repository-driven by design: `global.json`'s `sdk.version` already is the lever,
  and it is the one a .NET repository declares its SDK in anyway.
- **`--toolchain-image` does not reach these legs.** It steers only the container
  a *consumer's own* command runs in — `quality.test`'s `--test-cmd` and
  `build.build-archive`'s `--build-cmd`, ADR-004 level 1. Routing cicd's own gate
  commands through it was rejected: it would let the party being gated choose the
  SDK, the analyser set and the linter version behind cicd's verdict.
- **`global.json` selects, it does not force.** Naming a band cicd pins no image
  for does not obtain that band; it is the one way to still reach SDK exit 145
  (`A compatible .NET SDK was not found`), classified as a non-run. Prefer
  `"rollForward": "latestFeature"` so a patch-level difference inside a pinned
  band cannot 145 either.

### Where to read what actually ran

Every .NET run states the band and the reason in the evidence envelope's
`warnings[]`, one line per leg:

```text
dotnet format: SDK band 10.0 (requested by global.json)
dotnet test: SDK band 8.0 (no global.json sdk.version and no literal TargetFramework to read, so cicd's oldest pinned band is used)
```

That is the source of truth. Do not infer the band from the pin constants — the
whole point of the warning is that the verdict says which SDK produced it.

### A band cicd cannot serve

A request above every pinned band runs the **highest** pinned band and warns that
it did. This is not a fallback that forgives anything: if the build genuinely
needs the higher band, the restore dies, `dotnetFormatRunError` /
`dotnetTestRunError` classify that as a **non-run**, and `gatedPassed` fails a
non-run at *every* `--fail-on` threshold, `NONE` included. It is refused up front
only when the resolved band has no pinned image at all
(`dotnetUnpinnedBandError`, `ran=false`), which is a cicd defect rather than a
repository one.

What a consumer sees, and what to do about it:

1. `errors[]` carries `dotnet format: did not run (exit 1): … Restore operation
   failed` (or the `dotnet test` equivalent) followed by a remedy naming the band
   that ran and the bands cicd pins.
2. **If the framework is declared somewhere cicd cannot read it** — behind an
   MSBuild condition, in a property, in an imported `.props`, or deeper than four
   levels — set `sdk.version` in a root `global.json` to a pinned band. That is
   the fix for the common case, and it costs nothing.
3. **If the band genuinely is not pinned**, raise the pin in cicd: a constant pair
   in `src/quality/images.go`, an entry in `dotnetSDKBands`, a `case` in
   `dotnetSDKBase`, and a declaration in `scripts/runtime-images.json` plus a
   `renovate.json` group. `make check-image-pins` fails until all of them exist.
4. **As a stopgap**, drop `dotnet` from `--include` so cicd stops reporting a leg
   it cannot run, or move the tests to `quality.test` — your own `--test-cmd` in
   the toolchain your `--toolchain-image` names. Both cost coverage rather than
   restoring it: the first stops the .NET legs entirely, the second hands the
   toolchain back to the repository being gated. And `include` is a `commit.yml`
   passthrough — `precommit.yml` exposes no such input — so the first is
   unavailable to the pre-commit gate.

## The declared inventory

`scripts/runtime-images.json` lists every repository-selected image with its
repository, readable tag, digest, tool family, role and purpose. Each entry's
`sources` names the file where the pin literal is written — a module's
`images.go`, or the root `Makefile` for the conftest build `make policy-test`
runs.

Every digest is the **multi-architecture image index** digest, verified to be
identical under `--platform linux/amd64` (CI) and `--platform linux/arm64`
(local development). Resolve one with:

```
dagger core container from --address <repository>:<tag> image-ref
```

Do not paste a `docker inspect --format '{{index .RepoDigests 0}}'` value: that
is the single-architecture manifest. The build module's previous Trivy pin was
obtained that way and was amd64-only.

## Shape of a pin

Each image is declared in its module's `images.go` as a version constant plus an
image constant built from it, under a `renovate-image` marker:

```go
const (
	// renovate-image: aquasec/trivy
	trivyVersion = "0.70.0"
	trivyImage   = "aquasec/trivy:" + trivyVersion + "@sha256:be11…"
)
```

The version constant is what lands in the evidence envelope (`tool.version`) and
in SARIF tool drivers, so an auditor still reads `trivy 0.70.0` rather than a
bare digest. Because the image reference is built *from* that constant, emitted
metadata and the image actually pulled cannot disagree.

`images.go` carries no build tag, so the unit-test build (`-tags unit_test`) can
see these constants too.

## What CI checks, and what it does not

`scripts/check-runtime-image-pins.py` (wired into `ci.yml`'s `lint-repo`, also
`make check-image-pins`) is deterministic and offline. It:

1. **discovers** every `From(...)` argument under `src/`, plus Makefile image
   assignments, resolving each through package constants and local literals;
2. **classifies** each as repository-static or consumer-dynamic;
3. **fails** a static reference that is tag-only, carries a malformed digest, has
   no readable tag, or is absent from the inventory;
4. **fails** an inventory entry nothing references any more, or one whose
   `sources` no longer contain the pin;
5. **fails** an entry no `renovate.json` custom manager would match, or a tool
   family with no update group of its own.

Discovery is why step 3 works on an image nobody has seen before: a checker built
from a list of known images cannot see a new `From("some/tool:latest")` at all.

It does **not** contact a registry. Two things are therefore proved elsewhere:

- that a digest is a real, pullable, correct-platform manifest — proved by the
  Dagger smokes (`scripts/smoke/commit-shapes.sh container` resolves every
  declared image and the pipeline executes most of them for real);
- that a newer version exists — proposed by update automation, never by CI.

Run `python3 scripts/check-runtime-image-pins.py --list` to print the current
static/dynamic classification without validating anything.

## Update automation

`renovate.json` is bounded to the two version families this repository maintains
by hand: the static runtime images above, and the Dagger version
(`DAGGER_VERSION` in `.github/workflows/`, `engineVersion` in each module's
`dagger.json`).

- `enabledManagers` is `custom.regex` only. GitHub Actions stay SHA-pinned by
  Dependabot (`.github/dependabot.yml`); no second robot proposes action bumps.
- Every file pattern is an anchored regex naming files this repository owns.
  `templates/` (consumer copy-paste starters, rewritten by the release pin bump),
  `docs/` and `testdata/` are never touched.
- `packageRules` groups by tool family — one family, one pull request, one
  revert. A bad Trivy bump cannot drag Semgrep with it.

`scripts/tests/test_update_config.py` evaluates those managers against the real
files in the tree, in both directions: every declared pin is matched with its
exact tag and digest, and the consumer templates, docs and unrelated version
constants match nothing.

Installing or activating the Renovate App is a separate human action. Nothing in
ordinary CI reads `renovate.json`.

## Adding a static tool image

1. Resolve the multi-architecture digest with the `dagger core container`
   command above, on both platforms.
2. Add the version + image constants to the module's `images.go`, with the
   `// renovate-image: <repository>` marker.
3. Declare the image in `scripts/runtime-images.json` (family, role, purpose,
   sources).
4. Add a `packageRules` entry in `renovate.json` with
   `groupName: "runtime image: <family>"` and `matchDepNames: ["<repository>"]`.

`make check-image-pins` fails until all four exist.
