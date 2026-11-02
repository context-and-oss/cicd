# Contributing

This file is the contributor's guide: what to install, how the gates work, and what
every change has to carry. [CLAUDE.md](CLAUDE.md) is the codebase guide — layout,
architecture rules and commands — the
[engineering doctrine](docs/explanation/doctrine.md) is the reasoning behind each
guard, and [docs/how-to-guides/](docs/how-to-guides/index.md) holds the
consumer-facing recipes.

## Prerequisites

- Go 1.26.2 (`go.work` and every `src/*/go.mod` pin it)
- Python 3 — the `scripts/` tooling uses the standard library only
- The Dagger CLI at the version `DAGGER_VERSION` names in `.github/workflows/ci.yml`
- A running Docker daemon, for anything that calls `dagger`

## Local hooks

The pre-push hook that runs the pipeline against your change is checked in under
`.githooks/`, and git runs nothing there until you opt in:

```bash
make install-hooks
```

`make check-hooks` verifies the opt-in and **fails on every fresh clone** until you have
run it. That is deliberate: a hook that is not installed must not read as installed.

## Running the checks

```bash
make test                 # src/internal Go tests
make lint                 # golangci-lint on src/internal/
make lint-modules         # golangci-lint on every Dagger module, both tag sets (needs Dagger)
make test-module-units    # every module's -tags unit_test suite, no Dagger session
make test-scripts         # the scripts/ unit suites
make check-surface        # the defended repository surface (see below)
make check-go-format      # gofmt over every tracked Go file
```

`make test-module-units` fails in one situation that is not a defect in your change:
`dagger develop` writes a gitignored `dagger.gen.go` into the module directory, and
that file dispatches to entry methods the `unit_test` tag excludes, so the tagged build
stops at `undefined: Quality` (or `Build`, or `Dast`). Delete the generated SDK from
that module directory and run the suite again. CI never sees this because it runs the
suite on a clean checkout.

## Adding a module

Every entry function returns `(*dagger.File, error)` holding an evidence envelope; the
one exception is `build.Build`, which returns a container so downstream steps share the
same lazy image. Run `make sync-schema` after any change to
`src/internal/evidence/schema.go`. The step-by-step list — `dagger init`, the inventory
entry, the CI matrix cell, the composite wiring, the image pin — is in
[CLAUDE.md](CLAUDE.md#adding-a-new-module).

## Keeping the repository surface honest

[`scripts/repo-inventory.json`](scripts/repo-inventory.json) is the single manifest of what this
repository considers active: every Dagger module, and every file a consumer, contributor or auditor
reads as a current statement about how the repo behaves. `make check-surface` enforces it — declared
paths must exist, local markdown links must resolve, cicd version pins must agree on one version, and
every Dagger command an active file documents must exist in its module source. CI runs it on every
push and PR, so drift fails the build rather than shipping.

Two obligations follow:

- **Adding an active document** (`.md` under the repo root, `docs/` or `src/`) means adding it to the
  inventory. An undeclared active document fails the check; widening `historical_exclusions` to dodge
  that is not an option — exclusions cover planning/history only.
- **Adding or removing a public Dagger function** means updating the active docs and templates that
  `call` it in the same change. A documented command that no longer exists fails the check.

Run `make test-scripts` after touching anything under `scripts/`.

## Every change carries an intent artifact

The repo runs its own precommit composite against itself
([`.github/workflows/dogfood-precommit.yml`](.github/workflows/dogfood-precommit.yml)), and that
composite includes the intent gate. On a pull request the gate is scoped to the diff: it looks for a
file the change touches matching one of the patterns in `defaultGlobs`
([`src/cross-cutting/intent/main.go`](src/cross-cutting/intent/main.go)) — `.capsules/*.yaml|yml`,
`specs/*.md`, `docs/specs/*.md`, `*.intent.md`, `.changes/*.md`, `changes/*.md` — and a change that
touches none of them fails the `presence` rule at severity `error`. Because the dogfood run gates at `--fail-on MEDIUM`, that single finding turns the
**Precommit on self** check red on its own, with no other gate needing to report anything.

So add one — `specs/<change>.md` is the usual home — and write it for a reader, since the gate also
applies deterministic prose rules to it:

- no `TBD`, `TODO`, `FIXME` or `???`;
- at least one causal marker (`because`, `since`, `in order to`, `we chose`, `instead of`, …),
  because the artifact exists to record *why*;
- no unmeasurable qualifiers (`robust`, `simple`, `comprehensive`, `flexible`, … — see
  `weaselWords` in [`src/cross-cutting/intent/rules.go`](src/cross-cutting/intent/rules.go) for the
  full list);
- at least 30 words;
- any file path the artifact names has to appear in the diff, so an artifact cannot describe some
  other change.

`specs/` is a `historical_exclusions` prefix in the inventory, so a new spec needs no
`active_surfaces` declaration — it records intent at authoring time and is never rewritten to match
today's surface.

## Releases

The tree contains release automation, but destination settings, credentials,
bootstrap tags and the release/review loop have not been proven for this import.
Do not treat the source repository's release history as destination evidence.

### How it works

With its prerequisites configured and verified, the CD pipeline
(`.github/workflows/cd.yml`) is intended to follow successful CI on `main`.
The `next-version` step determines whether a releasable commit exists:

```text
CI passes on main
  └─> gate             confirm CI conclusion == success
        └─> next-version     git-cliff derives the next semver from commits since last tag
              └─> validate-modules    every Dagger module must load cleanly
                    └─> tag-and-release    deliver pins by PR, or tag pins already at target
                          └─> after pins PR merges: CI and CD run again before tagging
```

### Commit format

Follow [Conventional Commits](https://www.conventionalcommits.org/). Every subject on a
pull request must parse as one — the `commit-subjects` CI job refuses a subject
git-cliff cannot read, because a commit git-cliff drops is released silently to nobody.
Only these prefixes cut a release:

| Prefix | Version bump |
|--------|-------------|
| any `<type>!:` (e.g. `feat!:`, `fix!:`) / `BREAKING CHANGE:` in body | major |
| `feat:` | minor |
| `fix:` | patch |

`chore:`, `ci:`, `test:`, `docs:`, `refactor:`, `style:` — merged freely, never cut a release on their own.

### What gets bumped

`scripts/bump-version.py` rewrites every consumer-facing version pin declared in
[`scripts/repo-inventory.json`](scripts/repo-inventory.json) — root instructions, active docs,
templates, module and composite READMEs, and the reusable workflows. There is no second
hand-maintained list; a surface the inventory does not declare is not bumped and is not
checked, which is why adding an active document means adding an inventory entry. The bump
lands on `main` the way every other change does: on a `chore/release-v<version>` branch, as a
pull request with auto-merge requested. Arming auto-merge supplies no human
approval: `ci` and every other applicable requirement must still be satisfied.
The script does not push to `main` directly; required branch rules must be
verified in the destination
([specs/release-by-pull-request.md](specs/release-by-pull-request.md)).

The reusable workflows (`.github/workflows/precommit.yml`, `.github/workflows/commit.yml`)
are bumped in the *same* release commit, under a second `--scope workflows` pass. That pass
needs a credential carrying the `workflow` scope — GitHub refuses to let the default
`GITHUB_TOKEN` push anything under `.github/workflows/` — so the release job pushes with
`CICD_RELEASE_TOKEN` and fails loudly when it is absent rather than cutting a release whose
workflow pins lag.

After the rewrite, the release job runs `scripts/check-workflow-pins.py`: every managed pin
must agree on one version and every command a workflow or template `call`s must exist in its
module source. That guard checks pin coherence; it is not a human review and
cannot satisfy a required approving review.

### Bootstrapping a fresh copy

Reusable workflows and templates already pin cicd modules at `@vX.Y.Z`.
The release pipeline computes the next version from a reachable tag, and
`cd.yml`, the deliver script and `scripts/check-release-bump.py` refuse a
clone without one. This guard prevents a bump from a base nobody chose; it
is not proof that any existing pin resolves in the destination.

A later, separately approved import must use a reviewed parentless source
commit, not old Git history or copied GitHub state. Module coordinates retain
the intended canonical namespace and this candidate proposes coherent v5.1.2
pins; neither that proposal nor the planned cutover creates a tag or release. Before enabling destination automation, the
maintainer must approve the bootstrap version, confirm that pins match it, and
plan how the reviewed root commit and its matching tag/release will be made
available. Do not enable push-triggered release workflows before that baseline
exists, and do not remove the missing-tag guard to get past bootstrap.

The following are verification obligations, not claims that settings exist:

1. **Actions policy and repository settings.** Verify the referenced actions
   are allowed, auto-merge and merge commits are enabled, and stale release
   branches can be updated. Delivery uses `gh pr merge --auto --merge`.
2. **Branch protections and review policy.** Require pull requests, the `ci`
   context and strict up-to-date checks on `main`, plus the destination's
   chosen human-review requirements. Do not weaken them for bootstrap or to
   clear a stalled release. The current preflight requires the release
   identity to have bypass permission on every approval-requiring ruleset;
   an existing bypass permission is not an approval and does not prove that
   arming auto-merge will merge a review-required pull request. A policy that
   forbids such bypasses is incompatible with that preflight as written;
   resolve the release design through review before using it, not by disabling
   required protections.
3. **Release credential.** Verify `CICD_RELEASE_TOKEN` is available only where
   needed, with contents, pull requests and workflows read/write and metadata
   read. The preflight uses the repository rulesets endpoint's
   `current_user_can_bypass`; it does not need organisation administration
   write. Optional notification and feed credentials are needed only for runs
   that use those services. No credential configuration is established here.
4. **Preflight as the intended release identity.** Both checks must exit 0:

   ```bash
   python3 scripts/check-release-gate.py --branch main
   ```

   ```bash
   python3 scripts/check-release-handoff.py
   ```

   These are prerequisites, not proof of human approval or a completed loop.
5. **Verify the bootstrap and loop in the destination.** Confirm successful
   CI on the reviewed import baseline and that CD reports no unintended
   release. Exercise the scheduled drift detector. Then follow one real
   releasable change through its source PR, release-pins PR, required reviews,
   successful `ci`, merge, subsequent CI/CD, and matching tag and release.
   Observe the check ordering and review state rather than inferring delivery
   from an armed auto-merge request. A request stuck at `REVIEW_REQUIRED` needs
   investigation under the chosen policy; it is not permission to bypass it.

### Publication prerequisites and public-only follow-up checks

These settings and GitHub behaviours require destination verification; copying
source does not establish them. Confirm the pre-publication prerequisites before
an authorised visibility change. Private reporting, anonymous access and actual
fork CI require public visibility: check those immediately afterward, and never
claim they passed while the repository was private.

- [ ] **Owner team.** The team `.github/CODEOWNERS` names exists in the
  organisation and has write access to this repository. GitHub ignores a
  CODEOWNERS line whose team it cannot resolve, without failing anything.
- [ ] **Release credential.** `CICD_RELEASE_TOKEN` is set and effective for this
  repository — both preflights above pass as the identity that owns it.
  A secret inherited from the organisation counts only if this repository is in
  its access list.
- [ ] **Private reporting channel.** After the repository is public, private
  vulnerability reporting is enabled and a test report reaches the
  maintainers. [SECURITY.md](SECURITY.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) both send reports there.
- [ ] **One reviewed parentless import commit**, tagged and released at the
  approved bootstrap version its pins name; no old Git/GitHub state imported.
- [ ] **Anonymous module fetch — after publication.** From a machine with no GitHub credentials,
  `dagger -m github.com/context-and-oss/cicd/src/security@v5.1.2 functions`
  (the version the pins name) resolves the tag.
- [ ] **A pull request from a fork — after publication** runs `ci` without secrets and reports its
  status.
- [ ] **One real release cycle** completes end to end under the chosen review
  policy, including the release-pins PR and the subsequent tagging run.
- [ ] **Third-party terms.** Retain
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and applicable notices,
  including the recorded maintainer clearance for the embedded rasters.
  That clearance and the supplied own-code-only Semgrep use are already
  recorded decisions, not independent copyright certification. The runtime
  rules remain under their restrictive terms; hosted use or redistribution
  is not authorised by cicd's Apache-2.0 licence. The workflow compatibility
  adapter fetches its rule body at runtime and retains the upstream licence
  and modification notices; no upstream rule body is bundled in this tree.

### Emergency manual release

Use **Actions → Release (manual override)** (`.github/workflows/release.yml`) when CI is broken and you need to cut a hotfix outside the normal flow. Supply the version explicitly.
