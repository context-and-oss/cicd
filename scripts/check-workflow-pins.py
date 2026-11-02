#!/usr/bin/env python3
"""
CI guard for consumer-facing version pins. Four static checks, no network:

  1. EXISTENCE — every path the defended inventory declares actually exists.
     This used to be `if not path.exists(): continue`, which turned a deleted
     managed surface into a pass; the inventory entry for the deleted
     templates/azure-devops/commit-archive.yml survived exactly that way.

  2. CONSISTENCY — every cicd pin across the active surfaces points at one
     identical version. This is the invariant the release flow upholds by
     bumping every file atomically; the guard refuses to let any file lag. It
     catches the rot that froze .github/workflows/ at v0.2.0 while everything
     else moved to v1.0.0.

  3. IS-A-VERSION — every context-and-oss/cicd reference in an active surface is
     `@v<X.Y.Z>` and not a branch, a sha or `main`. Asked before consistency,
     because every mechanism here keys on `@v<X.Y.Z>`: a ref in any other shape
     is not compared, not rewritten by the bumper, and not command-checked. It
     is not reported wrong — it is not seen. v3.8.4 shipped dast.yml pinned to
     `@fix/dast-evidence-write`, a branch deleted when its PR merged, with this
     gate and check-repo-surface.py both green.

  4. COMMAND-EXISTS — every `dagger -m github.com/context-and-oss/cicd/<path>@v<ver>
     call <cmd>` in an active surface maps to an exported method in that
     module's source. Under the monorepo single-tag model the source at HEAD is
     what ships at the next tag, so this guarantees a reusable workflow never
     calls a command its pinned module won't have.

Consistency is enforced by EQUALITY across files, not by matching the latest git
tag — during a release cd.yml rewrites pins to the next version before the tag
exists, so a tag-equality check would red-flag the release commit itself. That a
tag exists at all is asserted elsewhere: cd.yml's next-version step and
scripts/ci/deliver-release-pins.sh refuse a clone with no reachable v* tag, and
scripts/check-release-bump.py refuses to treat a pinned tree as pre-release.

Scope comes from scripts/repo-inventory.json, not from a list maintained here.

This script is the RELEASE-blocking gate: cd.yml's release commit runs it inside
bump_and_validate, right after rewriting every managed pin, and ci.yml runs it
on every push/PR. Its scope stays deliberately narrow — pinned remote `call`
forms only, and pins listed in pin_guard.pending_repairs tolerated — because at
release time the only repair available is a pin rewrite. A failure here must be
something the bumper could have fixed; anything wider would block the release
on drift no release commit can repair.

pin_guard.pending_repairs is empty and should stay that way. It exists so a
future scope widening can be landed with an explicit, reasoned, self-expiring
exception (each entry is refused once its pin stops lagging) rather than a
silent skip — not as a standing allowance.

For the full active-surface check (this plus module discovery, undeclared
documents, local `-m ./src/...` command calls, local links, and no tolerance
for pending pin repairs) run scripts/check-repo-surface.py. Both run in ci.yml's
lint-repo job, so neither scope is unguarded on a pull request.

Exit 0 if clean, 1 on any violation, 2 if the inventory itself is unusable.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repo_surface import (  # noqa: E402
    InventoryError,
    check_cicd_refs_are_versions,
    check_dagger_commands,
    check_declared_paths_exist,
    check_pin_consistency,
    default_inventory_path,
    default_root,
    load_inventory,
)

CHECKS = (
    ("declared paths exist", check_declared_paths_exist),
    # Asked before skew, because skew can only compare refs it can see. A ref
    # that is not `@vX.Y.Z` is invisible to all three checks below and to the
    # release bumper, which is how v3.8.4 shipped dast.yml pinned to a deleted
    # branch with this gate green. It belongs in the release-blocking scope for
    # the same reason skew does: the only repair either one needs is a pin
    # rewrite, which is exactly what a release commit can do.
    ("every cicd reference is a version pin", check_cicd_refs_are_versions),
    ("cicd pins agree on one version", lambda inv: check_pin_consistency(inv, tolerate_pending=True)),
    ("documented Dagger commands exist", lambda inv: check_dagger_commands(inv, resolve_local=False)),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CI-blocking pin/command guard.")
    parser.add_argument("--root", default=None, help="repository root (default: this checkout)")
    parser.add_argument(
        "--inventory", default=None, help="inventory manifest (default: scripts/repo-inventory.json)"
    )
    args = parser.parse_args(argv)

    inventory_path = pathlib.Path(args.inventory) if args.inventory else default_inventory_path()
    root = pathlib.Path(args.root) if args.root else default_root()

    try:
        inv = load_inventory(inventory_path, root)
    except InventoryError as exc:
        print(f"workflow/template pin check FAILED: {exc}", file=sys.stderr)
        return 2

    failed = [(name, problems) for name, fn in CHECKS if (problems := fn(inv))]
    if not failed:
        print(
            "workflow/template pin check: OK (managed paths present, pins "
            "consistent, all called commands exist)"
        )
        return 0

    print("workflow/template pin check FAILED:\n", file=sys.stderr)
    for name, problems in failed:
        print(f"[{name}]", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(file=sys.stderr)
    print(
        "Fix: align every pin to one version (scripts/bump-version.py), ensure each "
        "called command exists in its module source, and keep "
        "scripts/repo-inventory.json in step with the files that actually exist.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
