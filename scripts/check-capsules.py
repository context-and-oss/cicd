#!/usr/bin/env python3
"""Refuse a capsule whose YAML conftest cannot parse, or whose number is not its own.

Deterministic and offline: no network, no `dagger`, no conftest, no PyYAML.
Runs in `lint-repo` so the typo is named in seconds, rather than surfacing four
minutes into the dogfood run as a line number against `/inputs/f0000`.

Not a YAML validator — see `scripts/capsules.py` for exactly what it does and
does not prove.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capsules import CAPSULE_GLOB, check_capsules  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse a capsule whose YAML conftest cannot parse, or whose number is not its own."
    )
    parser.add_argument(
        "--root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="repository root (default: the repository this script lives in)",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"capsule check: {root} is not a directory", file=sys.stderr)
        return 2

    problems = check_capsules(root)
    if not problems:
        count = len(sorted(root.glob(CAPSULE_GLOB)))
        print(
            f"capsule check: OK ({count} capsule(s), no unparseable YAML found, "
            f"every number claimed once)"
        )
        return 0

    print("capsule check FAILED:\n", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(
        f"\n{len(problems)} problem(s). A capsule that does not parse takes the whole "
        f"infra policy scan down with it, and conftest reports the line against a "
        f"renamed input rather than against the file: for [plain-scalar-colon] and "
        f"[tab-indent], quote the value or reword it so the colon is not followed by "
        f"a space; for [quoted-scalar-tail] and [reserved-first-char], quote the whole "
        f"value rather than part of it. For [name], [id] and [duplicate] nothing is "
        f"mis-scanned — the "
        f"capsule number is simply no longer a citation anything can follow, so "
        f"renumber to the next free number and move the `id:` field with the file.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
