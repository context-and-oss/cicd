# scripts/

The repository's own checks, release machinery and generators. Everything here
runs with Python 3, bash and git alone; nothing imports a third-party package,
because these run on bare CI runners and inside the release sandbox where no
dependency install happens first.

Convention: `check-<name>.py` is a command-line entry point and `<name>.py`
beside it is the importable logic, tested under `tests/`. Every check answers
with three exit codes: 0 is a pass, 1 is a finding, and 2 means the question
could not be asked (a tool missing, a network call failed). 2 is never a pass,
and no check has an override flag. `make` targets wrap the common ones; `make
help` lists them.

## Gates run on every push (`lint-repo`)

| Script | Logic | What it refuses |
|--------|-------|-----------------|
| `check-repo-surface.py` | `repo_surface.py`, `repo-inventory.json` | A declared path that is missing, a local link that does not resolve, cicd pins that disagree, a documented Dagger command that does not exist, an active document nobody declared, a workflow action the Actions policy would block |
| `check-workflow-pins.py` | `_pin_targets.py` | The release-blocking subset of the above: pins and commands in the consumer-facing workflows and templates |
| `check-runtime-image-pins.py` | `runtime_images.py`, `runtime-images.json` | A container image cicd selects on its own behalf that is not digest-pinned, declared and covered by a Renovate group (ADR-004) |
| `check-ado-templates.py` | `ado_templates.py` | An Azure DevOps template that does not gate, leaks a credential, or splices a `$(VAR)` macro into a shell line |
| `check-capsules.py` | `capsules.py` | A capsule whose YAML the policy engine cannot parse, or a capsule number claimed twice |
| `check-go-format.py` | `go_format.py` | A tracked Go file gofmt would rewrite, or a gofmt that could not run |
| `check-commit-subjects.py` | `commit_subjects.py` | A commit subject git-cliff would silently drop from the release notes |
| `check-hooks-installed.py` | | A clone where `git push` would run no pre-push hook (`make check-hooks`; `make install-hooks` fixes it) |
| `test-module-units.sh` | | The only module-unit runner: every module's `-tags unit_test` suite, failing when a module with tests runs zero |
| `tests/` | | The unit tests for every `*.py` here: `python3 -m unittest discover -s scripts/tests -t .` |

## The release pipeline

| Script | Logic | What it does |
|--------|-------|--------------|
| `check-release-bump.py` | `release_bump.py` | Derives the required bump from `git log` and refuses when git-cliff disagrees |
| `check-release-gate.py` | `release_gate.py` | Asks GitHub whether a ruleset really requires `ci` on `main`, and whether a delivered release PR merged through it |
| `check-release-handoff.py` | `release_handoff.py` | Reports a `main` pinned to a version no tag names |
| `check-release-drift.py` | `release_drift.py` | Reports releasable commits no release has tagged, from outside the release pipeline |
| `bump-version.py` | | Rewrites every consumer-facing pin to a new tag (`make bump-templates VERSION=X.Y.Z`) |
| `ci/deliver-release-pins.sh` | | Delivers the pin bump to `main` by pull request and reports exactly one of `pr-open`, `released`, `superseded` |
| `ci/wait-for-release-merge.sh` | | Waits for that pull request to merge so the caller can tag |
| `ci/write-release-intent.py` | | Writes `specs/release-latest.md`, the intent artifact the release PR must carry |
| `ci/classify-push-rejection.sh` | | Decides whether a rejected push is worth retrying |

The doctrine behind these, with the incidents that earned each check, is in
[CLAUDE.md](../CLAUDE.md#the-release-pipeline) and the specs it links.

## Generators and the inventory

| Script | What it does |
|--------|--------------|
| `repo-inventory.json` | The single defended manifest: modules, active documents, templates, workflows. `check-repo-surface.py` validates the tree against it and the Makefile reads it |
| `inventory-query.py` | Prints one field of the inventory, one entry per line, for shell and Make |
| `sync-schema.py` | Copies `src/internal/evidence/schema.go` into every module that embeds it (`make sync-schema`) |
| `sync-toolchain.py` | Regenerates every module copy of `src/internal/detect/toolchain.go` (`make sync-toolchain`) |
| `sync-concurrency.py` | Regenerates the module copies of the bounded scheduler |

A generated copy is guarded twice: the copies must agree with each other, and
the generator is re-run and diffed, because the drift that happens is both
copies agreeing while the canonical file moved.

## CI helpers and local runs

| Script | What it does |
|--------|--------------|
| `ci/dagger-develop.sh` | Runs `dagger develop`, retrying only the failures a retry can fix, and says which kind it hit |
| `ci/classify-dagger-develop-failure.sh` | The classifier behind that retry |
| `ci/lint-modules.sh` | golangci-lint over every Dagger module in both build-tag sets (`make lint-modules`) |
| `cicd-prepush` | The local pre-push pipeline (`make prepush`): runs the precommit composite against this checkout |
| `check-doc-commands.sh` | Runs the fenced `sh` blocks a guide marks `# doc-test` as executable documentation, and fails a guide that has none |
| `commit-diff.sh` | Resolves the revision range the diff-scoped risk and intent gates read in the commit stage |
| `smoke-all.sh`, `smoke/` | The behavioural fixture smokes, one script per shape, run the way CI runs them (`make smoke`, needs Docker) |
| `verify-build-artifact.py` | For consumers: verifies a downloaded cicd bundle before importing or deploying its payload |
