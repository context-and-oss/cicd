#!/usr/bin/env bash
# golangci-lint over the Dagger modules under src/, in both build-tag sets.
#
# Why this exists. `make lint` and ci.yml's lint-repo job ran golangci-lint
# with working-directory src/internal, so the fifteen Dagger modules — the
# code that actually decides a gate — had never been through errcheck, govet
# or staticcheck. scripts/go_format.py recorded the hole; this closes it.
#
# Why two passes. A module's test files come in two tag sets. The entry
# functions live in `//go:build !unit_test` files, and `dagger develop`
# writes an untagged dagger.gen.go that dispatches to them, so the tagged
# suite only compiles once that generated SDK is gone — which is exactly how
# scripts/test-module-units.sh runs it. The untagged set, with the entry
# functions and the SDK, is the module as Dagger builds it. Each pass lints
# the files the other cannot see, so:
#
#   1. the generated SDK is removed and `-tags unit_test` is linted with
#      `unused` switched off, because in that tag set every constant an
#      entry function alone consumes is, truthfully, unused — the untagged
#      pass judges `unused` over the whole module. A module in which no file
#      declares the unit_test tag at all (none today: every module keeps
#      its entry function in a tagged file, so every module gets this pass)
#      skips this pass and says so: there, the tag set is the whole module
#      minus the SDK it needs to compile, so the pass could only ever report
#      `undefined: dag`, and the default pass below covers every file anyway.
#      The skip is printed, never silent, so a module that loses its tagged
#      files is visible in the log rather than quietly half-linted;
#   2. `dagger develop` regenerates the SDK through scripts/ci/dagger-develop.sh,
#      so a fetch fault is retried and named instead of reading as a compile
#      error;
#   3. the default tag set is linted with the full linter list.
#
# Locally this deletes and regenerates the gitignored SDK in each module and
# leaves go.mod as `dagger develop` rewrites it, the same state `make
# develop-all` leaves. It runs every module before reporting, so one red
# module cannot hide the findings in the next, and it exits:
#
#   0  every module linted clean in both passes
#   1  at least one module has findings, or its develop failed (named below)
#   2  a module directory is not a Dagger module, or the inventory could not
#      be read — the question could not be asked, which is never a pass
#
# Usage: lint-modules.sh [module-directory ...]
#        (default: every module in scripts/repo-inventory.json)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# Keep in step with the lint-repo step in .github/workflows/ci.yml, which
# lints src/internal with the same version; scripts/tests/test_lint_modules.py
# refuses the two drifting apart. `go run <module>@<version>` is verified
# against the Go checksum database, so this is as pinned as a digest.
GOLANGCI_LINT_VERSION="v2.12.2"
lint=(go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_LINT_VERSION" run)

# Every module has its own go.mod; the root go.work covers src/internal only.
export GOWORK=off

modules=()
if [ "$#" -gt 0 ]; then
	modules=("$@")
else
	while IFS= read -r m; do
		[ -n "$m" ] && modules+=("$m")
	done < <(python3 "$root/scripts/inventory-query.py" modules)
	if [ "${#modules[@]}" -eq 0 ]; then
		echo "::error::scripts/repo-inventory.json produced an empty module list" >&2
		exit 2
	fi
fi

for m in "${modules[@]}"; do
	case "$m" in
	/*) dir="$m" ;;
	*) dir="$root/$m" ;;
	esac
	if [ ! -f "$dir/dagger.json" ]; then
		echo "::error::$m is not a Dagger module (no dagger.json under $dir)" >&2
		exit 2
	fi
done

failed=()
for m in "${modules[@]}"; do
	case "$m" in
	/*) dir="$m" ;;
	*) dir="$root/$m" ;;
	esac

	rm -rf "$dir/dagger.gen.go" "$dir/internal/dagger"
	if grep -qs 'go:build.*unit_test' "$dir"/*.go; then
		echo "==> $m: golangci-lint -tags unit_test (generated SDK removed)"
		if ! (cd "$dir" && "${lint[@]}" --build-tags unit_test -D unused ./...); then
			failed+=("$m (unit_test tag)")
		fi
	else
		echo "==> $m: no file declares the unit_test build tag; tagged pass skipped (the default tag set covers every file)"
	fi

	echo "==> $m: dagger develop"
	if ! bash "$here/dagger-develop.sh" "$dir"; then
		failed+=("$m (dagger develop failed; default tag set not linted)")
		continue
	fi

	echo "==> $m: golangci-lint (default tag set)"
	if ! (cd "$dir" && "${lint[@]}" ./...); then
		failed+=("$m (default tag set)")
	fi
done

if [ "${#failed[@]}" -gt 0 ]; then
	echo "::error::golangci-lint failed for ${#failed[@]} module pass(es):" >&2
	printf '  %s\n' "${failed[@]}" >&2
	exit 1
fi
echo "lint-modules: OK (${#modules[@]} module(s), both tag sets clean)"
