# Migrating to cicd from a hand-rolled pipeline

You have a working GitHub Actions or Azure DevOps pipeline that lints, tests,
builds, and scans in its own way. This page is the **map** from what you have
to what cicd expects — the *why* and the *what-maps-to-what*. When you are
ready to make the edits against your real pipeline file, follow the
[incremental adoption how-to](../how-to-guides/adopt-incrementally.md); the
exact per-step lookup lives in the [step-mapping reference](../reference/step-mapping.md).

## The mental-model shift

The single idea that makes everything else fall into place:

> **You own the inputs — lint config, test command, build definition. cicd owns
> the artifact + evidence plane.**

cicd is not a CI system and does not replace yours. It is a set of portable
Dagger modules your CI *calls*. What changes is not *where* your pipeline runs
but *who owns the checks*: cicd takes over the scanning, the artifact build, the
SBOM, and — crucially — turns every result into a single auditable **evidence
envelope** (`combined-evidence.json`) instead of scattered logs and tool
outputs.

What cicd explicitly does **not** take over:

- **Deployment.** cicd builds and scans an artifact; it never publishes or
  deploys. Pushing the image, importing the Dataverse solution, shipping the
  zip — yours.
- **Your curated lint/quality config.** Native lint legs use supported
  repository configuration (including your own ESLint); cicd does not recreate
  every existing quality gate or trend dashboard.
- **Version bumping** of your app or packages. cicd only pins its own module
  refs.

See [What stays yours](../how-to-guides/use-without-dockerfile.md#what-stays-yours)
and [ADR-002](../decisions/ADR-002-witnessed-test-execution.md) for the
ownership split.

## Before → after

### GitHub Actions

A caller stub can replace overlapping checks only after equivalent scope and
blocking behavior are configured and verified. Keep existing coverage floors,
license gates, secrets/history protections and specialized checks until then.
A coverage ratchet is not a minimum, the license policy defaults to warning,
and a snapshot scan is not history scanning or live credential verification.

The following before/after snippets illustrate structure, not complete workflows.
Default SAST uses runtime-fetched rules under restrictive, non-Apache terms:
review [the licensing boundary](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20)
before internal use, hosted-service operation or redistribution.

Before:

```yaml
# .github/workflows/build.yml — the hand-rolled version
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run lint
      - run: npm test -- --coverage
      - uses: aquasecurity/trivy-action@0.28.0    # image scan
      - uses: returntocorp/semgrep-action@v1       # SAST
      - run: docker build -t app .
      - run: syft app -o cyclonedx-json > sbom.json
      - uses: actions/github-script@v7             # PR comment
```

After — the reusable workflow runs the configured checks. The remote form below
requires authorized workflow/module access; anonymous fetch is available only
when the repository is public. For an authorized source checkout, use local
`-m ./src/composites/precommit` calls as described in the local-run guide instead
of adding writer credentials or copying secrets. This example assumes a
Node/Vitest project with its coverage provider declared in the lockfile.
Optional notification and private-feed secrets are deliberately omitted.

```yaml
# .github/workflows/precommit.yml — the caller stub
jobs:
  precommit:
    uses: context-and-oss/cicd/.github/workflows/precommit.yml@v5.2.0
    with:
      test-cmd: npm ci --ignore-scripts && ./node_modules/.bin/vitest run --coverage --coverage.reporter=json-summary --coverage.reportsDirectory=/tmp/cov
      coverage-path: /tmp/cov/coverage-summary.json
```

More than one stack in the repo? `test-cmd` runs one command in one container,
so use `test-legs` instead — one leg per language, each with its own command,
image and coverage report. See
[Use cicd without a Dockerfile](../how-to-guides/use-without-dockerfile.md#a-polyglot-repository-one-leg-per-language).

The `commit.yml` caller handles the build + image scan + SBOM tail on your
default branch, selected by the `artifact` input (`container` / `archive` /
`none`).

### Azure DevOps

A multi-stage `azure-pipelines.yml` maps to the ADO templates
(`templates/azure-devops/precommit.yml` + `commit.yml`), which invoke the same
composites via `dagger -m ...call`. The module calls are identical to GitHub
Actions; only auth, secrets, triggers, and artifact publishing differ. ADO auth
setup is its own walkthrough: [Set up Azure DevOps authentication](../how-to-guides/set-up-azure-devops-auth.md).

## Which shape is my repo?

The `commit` stage runs one source gate for every repo, then an artifact tail
selected by shape (ADR-001 — always explicit, never auto-detected):

| Your repo ships… | Shape | You set |
|------------------|-------|---------|
| A container image, with a Dockerfile | `container` (default) | nothing — or `dockerfile` / `platform` when it is not `./Dockerfile` built for `linux/amd64` |
| A zip / folder (Dataverse, Azure Web App, .NET publish) | `archive` | `build-cmd` + `output-path` |
| Nothing deployable (library, infra module) | `none` | `artifact: none` |

Do not write a Dockerfile just to satisfy the pipeline — an image you never
ship is worse than no image. Full treatment:
[Artifact shapes](artifact-shapes.md) and
[Use the pipeline without a Dockerfile](../how-to-guides/use-without-dockerfile.md).

## The payoff: one evidence envelope

The reason for the ceremony. Every module emits a JSON evidence envelope;
`cross-cutting/evidence` aggregates them into an **audit directory** your
pipeline uploads:

```text
audit-evidence/
  combined-evidence.json   # pass/fail + findings by severity + provenance
  findings.sarif           # SARIF 2.1.0 — renders in the GitHub/ADO security tab
  sbom.cdx.json            # CycloneDX SBOM
  comment.md               # the PR-comment / build-summary body
```

Instead of reverse-engineering pass/fail from tool logs, you get a generated
audit record of what ran, on which commit, and what it found. Required human
review, approval and any cryptographic signing are separate controls. A passing
verdict is not a claim of clean or complete scope: retain warnings, non-runs,
suppressions and examined metadata when reviewing or publishing evidence.

## Gotchas from real migrations

Review these boundaries before replacing existing checks:

- **Gitleaks history scope.** Source scanning checks the working tree and, when
  a readable `.git/` directory is mounted, the available Git history. A shallow
  checkout limits that history; absent/worktree-pointer metadata does not prove
  history was scanned. `--diff` does not scope the secrets scan. Rotate/revoke
  exposed credentials first, then review any justified `.gitleaksignore`, inline
  `gitleaks:allow` or config suppression. Tree suppressions are disclosed, but
  the history leg is not shadowed; retain an existing history control until
  equivalent scope and enforcement are verified.
- **Empty/auto Semgrep rulesets fail.** Empty rulesets and `auto` are rejected;
  loading no rules or missing a pinned rule floor is a non-run, not a clean
  pass. Omit the flag for the default pack or supply licensed, checked-in rules.
- **Source inventory is not an archive inventory.** Repository-mode archive
  dependency assessment uses supported source inputs. Lockfile-free .NET trees
  can be restored automatically, with scan-time version-resolution warnings;
  other ecosystems still require readable dependency inputs. Application mode
  defers dependency assessment entirely. Inspect dependency/SBOM outcomes,
  errors and examined counts, not just whether CycloneDX JSON exists. Neither
  a lockfile nor a restored graph proves the exact shipped contents (see
  [Artifact shapes](artifact-shapes.md)).
- **.NET SDK band mismatch — and the input that looks like the fix but is not.**
  cicd's own .NET legs run `dotnet format` and `dotnet test` in a digest-pinned
  SDK image, and an SDK image carries its band in the tag, so the band cicd picks
  decides whether your project can be restored at all. It picks from *your*
  repository: `global.json`'s `sdk.version` first, else the highest literal
  `net<major>.<minor>` in `*.csproj` / `Directory.Build.props`, resolved to the
  lowest pinned band at or above that. Three things to know before you change
  anything. **A `net8.0` repo needs no migration action** — same image, same
  analysers. A `net9.0` repo builds on the **10.0** SDK (9.0 is out of support and
  deliberately not pinned), which surprises people, so read the band off the
  envelope's `warnings[]` rather than assuming. And `toolchain-image` does **not**
  steer these legs — it steers only the container your *own* build or test command
  runs in (ADR-004), so reaching for it here changes nothing about the leg that is
  failing. If no pinned band can build your project, the leg is a **non-run** —
  which fails at every threshold, `fail-on: NONE` included — and `errors[]` names
  the band that ran and the remedy. Full rules, including how to get a band pinned:
  [.NET SDK band selection](../reference/runtime-images.md#net-sdk-band-selection).

## Where to go next

- [Adopt cicd incrementally](../how-to-guides/adopt-incrementally.md) — the
  do-it-now procedure, one stage at a time.
- [Step-mapping reference](../reference/step-mapping.md) — the exhaustive
  per-step lookup.
- [Set up Azure DevOps authentication](../how-to-guides/set-up-azure-devops-auth.md)
  — before anything runs on ADO.
