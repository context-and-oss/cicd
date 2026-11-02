#!/usr/bin/env python3
"""
ADR-004 runtime image pin gate.

Validates the live working tree: every static container image this repository's
own code selects is immutable by digest, is declared in the runtime image
inventory, and has an update path.

  1. DISCOVERY   every `.From(...)` in src/ (and every Makefile image assignment)
                 is found and classified by resolving its argument through
                 package constants and local literals — not by consulting a list,
                 so a brand new tool image cannot slip past
  2. IMMUTABLE   every static reference is `tag@sha256:<64 lowercase hex>`; a
                 mutable tag, a malformed digest or a digest-only reference fails
  3. DECLARED    every static reference is in scripts/runtime-images.json with
                 accurate `sources`, and no entry outlives its last reference
  4. UPDATABLE   every declared image is matched by a renovate.json custom
                 manager and owned by a per-family update group

Dynamic references — an explicit `--toolchain-image`, or a tag derived from the
consumer's `.nvmrc` / `global.json` — are ADR-004's consumer-controlled toolchain
path. They cannot be digest-pinned ahead of time, are never failed here, and are
listed in the output so the classification is auditable rather than implicit.

Deterministic and offline: no network, no registry lookup, no dagger. Proposing
newer versions is renovate.json's job; proving a pin resolves is the Dagger
smokes' job (scripts/smoke/commit-shapes.sh). Wired into ci.yml's lint-repo job.

Usage:
  python3 scripts/check-runtime-image-pins.py
  python3 scripts/check-runtime-image-pins.py --root <dir> --inventory <file> \
      --update-config <file>
  python3 scripts/check-runtime-image-pins.py --list   # print the classification only

Exit 0 if clean, 1 on any violation, 2 if the inventory or update config is
unusable.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runtime_images import (  # noqa: E402
    InventoryError,
    check_all,
    default_inventory_path,
    default_root,
    default_update_config_path,
    discover_references,
    load_inventory,
    load_update_config,
    update_group_of,
)


def _print_classification(references) -> None:
    static = sorted((r for r in references if r.is_static), key=lambda r: (r.file, r.line))
    dynamic = sorted((r for r in references if not r.is_static), key=lambda r: (r.file, r.line))
    print(f"static images selected by this repository ({len(static)}):")
    for ref in static:
        print(f"  {ref.file}:{ref.line}  {ref.value}")
    print(
        f"consumer-resolved toolchain images, ADR-004, not pinnable here ({len(dynamic)}):"
    )
    for ref in dynamic:
        print(f"  {ref.file}:{ref.line}  From({ref.expression})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=None)
    parser.add_argument("--inventory", type=pathlib.Path, default=None)
    parser.add_argument("--update-config", type=pathlib.Path, default=None)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the discovered static/dynamic classification and exit 0",
    )
    args = parser.parse_args()

    root = (args.root or default_root()).resolve()
    inventory_path = args.inventory or default_inventory_path(root)
    config_path = args.update_config or default_update_config_path(root)

    try:
        inventory = load_inventory(inventory_path)
        if args.list:
            _print_classification(discover_references(root, inventory))
            return 0
        config = load_update_config(config_path)
        problems, references = check_all(root, inventory, config)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    _print_classification(references)

    if problems:
        print(f"\nFAIL: {len(problems)} runtime image pin problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    families = sorted({update_group_of(e) for e in inventory["images"]})
    print(
        f"\nOK: {len(inventory['images'])} declared runtime image(s) across "
        f"{len(families)} update group(s); every static reference is digest-pinned, "
        "declared and covered by renovate.json"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
