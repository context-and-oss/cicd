# Keep every target in one list so additions cannot drift between duplicate blocks.
.PHONY: sync-schema sync-toolchain develop-all lint lint-modules test test-scripts test-module-units policy-test \
        prepush install-hooks verify-contracts verify-pipeline bump-templates \
        check-surface check-pins check-image-pins check-ado-templates \
        check-capsules check-go-format check-hooks smoke fmt _require-inventory \
        _warn-hooks help

SCHEMA_SRC := src/internal/evidence/schema.go
TOOLCHAIN_SRC := src/internal/detect/toolchain.go

# The modules carrying a generated copy of the ADR-004 toolchain resolver. Not
# from the inventory: the inventory declares the copies as a synced group, and a
# second list derived from it would be the drift this target exists to stop.
TOOLCHAIN_MODULES := src/quality src/build

# Module lists come from the defended inventory (scripts/repo-inventory.json), not
# from copies maintained here. The copies drifted: SYNCED_MODULES named four
# modules that have no schema.go, and `if [ -f $m/schema.go ]` hid it as a skip.
MODULES := $(shell python3 scripts/inventory-query.py modules)
SYNCED_MODULES := $(shell python3 scripts/inventory-query.py schema-synced-modules)
CONTRACT_STEPS := $(shell python3 scripts/inventory-query.py contract-modules)

# `$(shell ...)` swallows a non-zero exit, so an unusable inventory would read as
# an empty list and every loop below would succeed having done nothing.
_require-inventory:
	@python3 scripts/inventory-query.py modules >/dev/null
	@[ -n "$(MODULES)" ] && [ -n "$(SYNCED_MODULES)" ] && [ -n "$(CONTRACT_STEPS)" ] \
		|| (echo "ERROR: scripts/repo-inventory.json produced an empty module list"; exit 1)

help:
	@echo "Targets:"
	@echo "  sync-schema        Copy internal/evidence/schema.go into every module that embeds it"
	@echo "  sync-toolchain     Regenerate every module copy of internal/detect/toolchain.go"
	@echo "  develop-all        Run 'dagger develop' in every module to regenerate internal SDKs"
	@echo "  lint               Run golangci-lint on internal/"
	@echo "  lint-modules       Run golangci-lint on every Dagger module, both tag sets (needs Dagger)"
	@echo "  test               Run go test on internal/"
	@echo "  test-scripts       Run the Python unit tests under scripts/tests/"
	@echo "  policy-test        Run conftest verify on the risk module's OPA policy suites"
	@echo "  test-module-units  Run the canonical clean-checkout module-unit runner (no Dagger session)"
	@echo "  smoke              Run the behavioural fixture smokes (needs Docker; SMOKE=<script> for one)"
	@echo "  check-surface      Validate the working tree against the defended repository inventory"
	@echo "  check-pins         CI-blocking pin/command guard (narrower scope, must stay green)"
	@echo "  check-image-pins   Validate that every repository-selected runtime image is digest-pinned"
	@echo "  check-ado-templates Validate Azure DevOps template behavior and secret handling"
	@echo "  check-capsules     Refuse a capsule whose YAML conftest cannot parse"
	@echo "  check-go-format    Refuse a tracked Go file gofmt would rewrite"
	@echo "  check-hooks        Refuse a clone where git would run no pre-push hook"
	@echo "  fmt                Rewrite tracked Go files with gofmt"
	@echo "  prepush            Run the local pre-push Dagger pipeline"
	@echo "  install-hooks      Opt into the checked-in Git hooks"
	@echo "  verify-contracts   Verify every module's Go source matches its contract.json"
	@echo "  verify-pipeline    Verify a pipeline manifest (MANIFEST=<file> required)"
	@echo "  bump-templates     Rewrite consumer-facing version pins (VERSION=X.Y.Z required)"

sync-schema: _require-inventory
	@for m in $(SYNCED_MODULES); do \
		[ -f $$m/schema.go ] || { echo "ERROR: $$m/schema.go missing but declared in the inventory" >&2; exit 1; }; \
		python3 scripts/sync-schema.py $(SCHEMA_SRC) > $$m/schema.go; \
		echo "synced $$m/schema.go"; \
	done

sync-toolchain:
	@for m in $(TOOLCHAIN_MODULES); do \
		python3 scripts/sync-toolchain.py $(TOOLCHAIN_SRC) > $$m/toolchain.go; \
		echo "synced $$m/toolchain.go"; \
	done

develop-all: _require-inventory
	@for m in $(MODULES); do \
		echo "==> dagger develop $$m"; \
		(cd $$m && dagger develop) || exit 1; \
	done

lint: _warn-hooks
	cd src/internal && golangci-lint run ./...

# The Dagger modules, in both build-tag sets. Removes and regenerates each
# module's gitignored SDK on the way; scripts/ci/lint-modules.sh says why and
# what each exit code means. The same script runs in ci.yml's lint-modules job.
lint-modules: _require-inventory
	bash scripts/ci/lint-modules.sh

test: _warn-hooks
	cd src/internal && go test -race ./...

test-scripts: _warn-hooks
	python3 -m unittest discover -s scripts/tests -t . -v

# Same conftest image+version+digest src/risk/images.go pins for the real gate,
# so a passing policy-test proves what conftest will actually do at runtime.
# *_test.rego files (excluded from the gate itself, see opa.go's
# loadPolicyDir) are the only thing conftest verify evaluates as assertions.
#
# Immutable by digest like every other repository-selected tool image
# (scripts/runtime-images.json); scripts/check-runtime-image-pins.py discovers
# this assignment and fails a tag-only or malformed reference here too.
# renovate-image: openpolicyagent/conftest
CONFTEST_VERSION := v0.58.0
CONFTEST_IMAGE := openpolicyagent/conftest:$(CONFTEST_VERSION)@sha256:bad948972156bf96d27d1f510db346ca4f7c5996e6ab298c43036505b60f8cc8

policy-test:
	docker run --rm -v $(CURDIR)/src/risk/policy/findings:/policy:ro $(CONFTEST_IMAGE) verify --policy /policy
	docker run --rm -v $(CURDIR)/src/risk/policy/infra:/policy:ro $(CONFTEST_IMAGE) verify --policy /policy
# Complete -tags unit_test suite for every module in the defended inventory
# that ships one (including risk and intent) — no Dagger session required.
# Fails on any test failure or on a module that executes zero tests.
test-module-units:
	bash scripts/test-module-units.sh

# Canonical active-surface check: declared paths exist, module discovery agrees,
# no undeclared active document, pins coherent, documented Dagger commands exist,
# local links resolve. Green on the live tree and wired into ci.yml's lint-repo
# job, so drift in any of those fails the build instead of shipping.
# The behavioural fixture smokes: they call the real composites through Dagger
# and assert on the evidence produced, so they are the only checks that catch a
# pipeline which still compiles and has stopped doing something. Deliberately
# NOT part of `prepush` or of the check-* sweep — each entry starts a real
# Dagger session against a fixture, so the suite is minutes per entry and needs
# a Docker daemon. Run one with SMOKE=<script>.
#
# The list lives in scripts/smoke-all.sh, and check_smoke_scripts_are_wired
# proves it still agrees with scripts/smoke/ — a second list here would be the
# drift that check exists to stop.
smoke:
	bash scripts/smoke-all.sh $(SMOKE)

check-surface:
	python3 scripts/check-repo-surface.py

# The release-blocking subset (ci.yml, cd.yml release commit): declared paths
# exist, pins coherent, pinned `call` commands exist. Deliberately narrower than
# check-surface — see scripts/check-workflow-pins.py's module docstring — because
# cd.yml runs it inside the release commit, where the only repair available is a
# pin rewrite. Both now run in CI; this one also gates the release.
check-pins:
	python3 scripts/check-workflow-pins.py

# ADR-004 runtime image gate: every static container image this repository's own
# code selects must be `tag@sha256:<digest>`, declared in
# scripts/runtime-images.json, and covered by renovate.json's update managers.
# Offline — it discovers `From(...)` references from source rather than trusting
# a list, and never resolves a tag against a registry.
check-image-pins:
	python3 scripts/check-runtime-image-pins.py

# Behavioural validation of the Azure DevOps templates: they parse under ADO's
# YAML subset, call the unified `run` with the flags the pipeline needs, pass
# every credential as `env:NAME`, never splice a consumer-supplied $(VAR) macro
# into a bash body, and clear the PAT they write. Also in ci.yml's lint-repo.
check-ado-templates:
	python3 scripts/check-ado-templates.py

# Capsules are prose in YAML, and an unquoted colon stops the file parsing.
# conftest ingests them in the infra policy scan and reports the line against a
# renamed input (/inputs/f0000), four minutes into the dogfood run — so the typo
# is named here instead, in seconds. Not a YAML validator; see scripts/capsules.py.
# Also in ci.yml's lint-repo.
check-capsules:
	python3 scripts/check-capsules.py

# Formatting was checked by nothing at all until two files had been unformatted
# since the commits that added them. Exit 2 when gofmt could not be run, because
# a formatter that never ran reports no unformatted files exactly like a clean
# tree. Scope is gofmt only; see scripts/go_format.py for why golangci-lint
# still does not reach the Dagger modules. Also in ci.yml's lint-repo.
check-go-format:
	python3 scripts/check-go-format.py

fmt:
	python3 scripts/check-go-format.py --write

prepush: _warn-hooks
	./scripts/cicd-prepush

# The install verifies itself, so "Installed local Git hooks" stops being a
# claim about what the two commands above were supposed to do and becomes an
# answer from git about what it would actually run. Setting core.hooksPath is
# not the same as being gated — see scripts/check-hooks-installed.py for the
# directions a config-only check gets wrong.
install-hooks:
	chmod +x scripts/cicd-prepush .githooks/pre-push
	git config core.hooksPath .githooks
	@python3 scripts/check-hooks-installed.py
	@echo "Installed local Git hooks from .githooks"

# Strict: exit 1 when git would run no pre-push hook. Deliberately not run by
# CI, and a no-op there if it ever is — core.hooksPath is per-clone local
# config that CI cannot see, and a CI clone is gated by the required `ci` check
# rather than by hooks. A check that failed in CI over an inherently local fact
# would be deleted within a week.
check-hooks:
	python3 scripts/check-hooks-installed.py

# One line on stderr, never a failure. This is the reminder half: a developer
# who never ran install-hooks is exactly the developer who will not run
# check-hooks either, so the targets they do run say so. It stays a warning
# because the alternative — installing the hook as a side effect of `make test`
# — mutates a developer's git config without being asked, and a hard failure
# here would block work over a local preference.
_warn-hooks:
	@python3 scripts/check-hooks-installed.py --warn

# Verify every module's Go source matches its contract.json signature.
# CONTRACT_STEPS (from the inventory, above) doubles as the module path
# (./<value>) and the path-style step argument the verifier uses to locate
# <value>/contract.json from the repo root.
verify-contracts: _require-inventory
	@for step in $(CONTRACT_STEPS); do \
		echo "==> verify-signature: $$step"; \
		dagger -m ./src/cross-cutting/contract call verify-signature \
			--module ./$$step \
			--repo . \
			--step $$step || exit 1; \
	done

# Verify a pipeline manifest against stage contracts.
# Usage: make verify-pipeline MANIFEST=pipeline.json
verify-pipeline:
	@[ -n "$(MANIFEST)" ] || (echo "Usage: make verify-pipeline MANIFEST=<path>"; exit 1)
	dagger -m ./src/cross-cutting/contract call verify-pipeline \
		--manifest $(MANIFEST) \
		--repo .

# Rewrite consumer-facing version pins (READMEs, guides, templates) to a new release tag.
# Usage: make bump-templates VERSION=0.1.4
bump-templates:
	@[ -n "$(VERSION)" ] || (echo "Usage: make bump-templates VERSION=X.Y.Z"; exit 1)
	python3 scripts/bump-version.py $(VERSION)
