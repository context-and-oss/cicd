#!/usr/bin/env python3
"""
Canonical active-surface check. Validates the live working tree against the
defended inventory in scripts/repo-inventory.json:

  1. EXISTENCE      every declared path exists (missing is an error, not a skip)
  2. MODULES        declared modules == `find src -name dagger.json`, both ways,
                    and the schema/contract subsets are real
  3. COMPLETENESS   no active markdown hides outside the inventory
  4. PINS           every context-and-oss/cicd pin in an active surface agrees on one
                    version
  5. COMMANDS       every documented `dagger ... call <cmd>` against a module in
                    this repo resolves to an exported Go method
  6. LINKS          every local markdown link in an active surface resolves

  7. PIN DEBT       every pin_guard.pending_repairs entry still names a pin that
                    actually lags (the list is empty and self-expiring)
  8. ACTIONS        every `uses:` in a declared workflow names an action this
                    repository's Actions policy will let start a run — a
                    disallowed one kills the run before any check run exists,
                    so the pipeline goes missing rather than red
  9. STEP SIZE      no `run:` body is large enough to stop the workflow from
                    starting — over the ceiling GitHub creates no job at all,
                    so the workflow's absence reads as nothing to report
 10. PR COMMENT     every workflow posting a PR verdict updates the comment
                    carrying notify's marker instead of appending a new one,
                    and every copy of that step is byte-identical
 11. INCLUDE SET    the --include language set in the module and in the
                    reusable workflow's guard accept the same values
 12. OUTPUT CHAIN   every reusable workflow output resolves end to end, so a
                    caller reading one does not silently read an empty string
 13. SYNCED FILES   every declared byte-identical copy still matches its source
 14. GENERATED      every generated copy still matches what its generator emits
 15. SMOKES         every behavioural smoke in scripts/smoke/ is both listed in
                    scripts/smoke-all.sh (so `make smoke` runs it) and invoked
                    by a `run:` step in a declared workflow (so CI runs it) —
                    a smoke that runs nowhere reads as coverage and is not
 16. VERSION        every copy of the evidence schemaVersion agrees with the
                    canonical const, contracts name the major family rather
                    than an exact version, and no workflow or smoke asserts a
                    stale literal — the version froze because moving it was an
                    unchecked six-place edit, and a frozen version misnames
                    the shape it ships
 17. DEVELOP        every `dagger -m ./src/<module>` in a declared workflow is
                    covered by an earlier scripts/ci/dagger-develop.sh — either
                    the module that job develops or something in its dependency
                    closure. An uncovered call generates that module's SDK
                    inside itself, where a module-fetch fault wears a compile
                    error's face and is never retried
 18. IS-A-VERSION   every context-and-oss/cicd reference in an active surface is
                    `@v<X.Y.Z>`. A branch, sha or `main` is invisible to the
                    skew check, the command check and the release bumper alike
                    — three checks going quiet together, which is how v3.8.4
                    shipped dast.yml pinned to a deleted branch
 19. REACHABLE      every parameter of a composite's entry function is named by
                    each starter surface that calls it, or carries a written
                    reason in composite_reach.unreachable. A knob nobody can
                    reach and a knob nobody needs look identical from outside,
                    which is how commit.yml shipped for five releases with no
                    licence policy input at all
 20. GUARDED FLAG  every flag whose value may not exist (an optional outbound
                    channel, the change diff) is appended to the argument array
                    from inside a conditional testing its variable, never passed
                    on the command line. An unset GitHub secret still arrives as
                    a non-nil, empty Secret and an undefined Azure DevOps
                    variable as its own literal text, so an unguarded flag
                    notifies nothing and reports success; an empty diff file
                    reads as a change that touched nothing
 21. SAST DEFAULT   no active surface says `--sast-rulesets` defaults to
                    "auto". The security module refuses that value, so the
                    documented default was the one input that could not run,
                    and the real default (p/security-audit) was named nowhere
 22. RUN SPLICE     no `${{ }}` expression appears inside a `run:` body of a
                    workflow, local action or GitHub template. GitHub
                    substitutes it before the shell parses the line, so a
                    branch name or consumer input carrying a quote or `$(`
                    runs as code; values reach the shell through `env:`
 23. DIFF SWALLOW   no `git diff` that feeds the change scope discards its exit
                    status with `|| :` or `|| true`. A diff that could not be
                    computed left an empty file, and the intent gate answered
                    an empty change set with a whole-tree audit that a pull
                    request carrying no artifact passed
 24. SUPERSEDED     the pre-commit callers cancel a run for a commit the pull
                    request no longer points at and group nothing else, and no
                    commit workflow declares `concurrency:` — GitHub keeps one
                    pending run per group, so grouping pushes to main leaves
                    the commits in between with no commit-stage evidence
 25. FIRST GATE     every `dagger call ... export --path *.json` in a first-use
                    surface (README.md, the getting-started tutorial) is
                    followed by `jq -e '.passed == true'` on that file, chained
                    with `&&` or under `set -e`. `dagger call` exits 0 whatever
                    the scan found, so an ungated first check blocks nothing,
                    and an unchained one grades a stale file when the export
                    fails. It proves the shape, not that any scan passes

Deterministic and offline: no network, no dagger, no git tag lookup. Wired into
ci.yml's lint-repo job, so any of the above failing fails the build.

Usage:
  python3 scripts/check-repo-surface.py                    # check the live tree
  python3 scripts/check-repo-surface.py --root <dir> --inventory <file>
  python3 scripts/check-repo-surface.py --modules           # module-inventory check only

--modules runs just the MODULES check (declared modules == `find src -name
dagger.json`, both directions) — fast and standalone, so CI and release module
loading can prove "all modules" against the live tree without paying for the
full surface scan (links, pins, commands, undeclared docs).

Exit 0 if clean, 1 on any violation, 2 if the inventory itself is unusable.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repo_surface import (  # noqa: E402
    InventoryError,
    check_all,
    check_module_inventory,
    default_inventory_path,
    default_root,
    load_inventory,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the defended repository surface.")
    parser.add_argument("--root", default=None, help="repository root (default: this checkout)")
    parser.add_argument(
        "--inventory", default=None, help="inventory manifest (default: scripts/repo-inventory.json)"
    )
    parser.add_argument(
        "--modules",
        action="store_true",
        help="run only the module-inventory check (declared modules vs. discovered dagger.json)",
    )
    args = parser.parse_args(argv)

    inventory_path = pathlib.Path(args.inventory) if args.inventory else default_inventory_path()
    root = pathlib.Path(args.root) if args.root else default_root()

    try:
        inv = load_inventory(inventory_path, root)
    except InventoryError as exc:
        print(f"repository surface check FAILED: {exc}", file=sys.stderr)
        return 2

    if args.modules:
        problems = check_module_inventory(inv)
        if not problems:
            print(f"module inventory check: OK ({len(inv.modules)} modules)")
            return 0
        print("module inventory check FAILED:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    results = check_all(inv)
    failed = [(name, problems) for name, problems in results if problems]

    if not failed:
        print(
            f"repository surface check: OK "
            f"({len(inv.active_surfaces)} active surfaces, {len(inv.modules)} modules, "
            f"{len(results)} checks)"
        )
        return 0

    print("repository surface check FAILED:\n", file=sys.stderr)
    for name, problems in failed:
        print(f"[{name}]", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(file=sys.stderr)
    total = sum(len(problems) for _, problems in failed)
    print(
        f"{total} problem(s) across {len(failed)} of {len(results)} checks.\n"
        f"Fix the surface, or correct scripts/repo-inventory.json if the inventory "
        f"itself is wrong. Do not widen historical_exclusions to make an active "
        f"surface pass.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
