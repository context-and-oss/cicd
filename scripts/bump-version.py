#!/usr/bin/env python3
"""
Rewrite consumer-facing version pins to a new release tag.

The managed file set and pin shapes are derived from the defended inventory
(scripts/repo-inventory.json) via scripts/_pin_targets.py, shared with the CI
guard (scripts/check-workflow-pins.py) so the two can't drift.

Scope:
  default    files the default GITHUB_TOKEN can push (TARGETS) — the safe set
  workflows  only .github/workflows/*.yml (WORKFLOW_TARGETS) — needs a push
             credential carrying the `workflow` scope (App/PAT)
  all        both

Usage:
  python3 scripts/bump-version.py <version>                  # e.g. 1.1.0 (no leading v)
  python3 scripts/bump-version.py <version> --scope workflows
  python3 scripts/bump-version.py <version> --scope all

A declared file that does not exist aborts the bump before anything is written.
Skipping it with a warning is how the inventory entry for the deleted
templates/azure-devops/commit-archive.yml rode through releases untouched.

Exits non-zero on bad input or a missing managed path. Prints one line per
rewritten file plus a count of the files that needed no change.
"""
from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _pin_targets import PATTERNS, TARGETS, WORKFLOW_TARGETS  # noqa: E402


def files_for_scope(scope: str) -> list[str]:
    if scope == "default":
        return TARGETS
    if scope == "workflows":
        return WORKFLOW_TARGETS
    if scope == "all":
        return TARGETS + WORKFLOW_TARGETS
    raise ValueError(f"unknown scope {scope!r}")


class MissingManagedPath(Exception):
    """A path the inventory declares does not exist. Never a warning."""


def bump(root: pathlib.Path, version: str, files: list[str]) -> tuple[int, int]:
    missing = [rel for rel in files if not (root / rel).is_file()]
    if missing:
        raise MissingManagedPath(
            "the inventory declares paths that do not exist:\n"
            + "\n".join(f"  {rel}" for rel in missing)
            + "\nRestore the files or remove them from scripts/repo-inventory.json."
        )

    changed = 0
    for rel in files:
        path = root / rel
        original = path.read_text()
        new = original
        for pat, repl in PATTERNS:
            new = pat.sub(repl.format(v=version), new)
        if new != original:
            path.write_text(new)
            print(f"updated   {rel}")
            changed += 1
    return changed, len(files) - changed


def main() -> int:
    args = sys.argv[1:]
    scope = "default"
    if "--scope" in args:
        i = args.index("--scope")
        try:
            scope = args[i + 1]
        except IndexError:
            print("ERROR: --scope needs a value (default|workflows|all)", file=sys.stderr)
            return 2
        del args[i : i + 2]

    if len(args) != 1:
        print("Usage: bump-version.py <version> [--scope default|workflows|all]", file=sys.stderr)
        return 2
    version = args[0]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"ERROR: '{version}' is not semver X.Y.Z", file=sys.stderr)
        return 1
    if scope not in ("default", "workflows", "all"):
        print(f"ERROR: unknown scope '{scope}' (default|workflows|all)", file=sys.stderr)
        return 1

    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        changed, unchanged = bump(root, version, files_for_scope(scope))
    except MissingManagedPath as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"\nBumped pins to v{version} (scope={scope}, {changed} file(s) changed, "
        f"{unchanged} already correct or carrying no pin)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
