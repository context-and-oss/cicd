#!/usr/bin/env python3
"""
Print one field of the defended inventory, newline separated, for shell and Make
consumers. Deterministic and offline.

The Makefile used to carry its own copies of MODULES, SYNCED_MODULES and
CONTRACT_STEPS. Those copies drifted: SYNCED_MODULES named four modules with no
schema.go at all, and `if [ -f $m/schema.go ]` turned the mismatch into a silent
skip. Make now asks this script instead.

Usage:
  python3 scripts/inventory-query.py modules
  python3 scripts/inventory-query.py schema-modules
  python3 scripts/inventory-query.py schema-synced-modules
  python3 scripts/inventory-query.py contract-modules
  python3 scripts/inventory-query.py active-surfaces
  python3 scripts/inventory-query.py pin-default-targets
  python3 scripts/inventory-query.py pin-workflow-targets

Exit 0 on success, 2 on an unknown field or an unusable inventory. Never prints a
partial list on failure — a caller doing `$(shell ...)` must not mistake an error
for an empty set.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repo_surface import InventoryError, load_inventory  # noqa: E402

FIELDS = {
    "modules": lambda inv: inv.modules,
    "schema-modules": lambda inv: inv.schema_modules,
    "schema-synced-modules": lambda inv: inv.schema_synced_modules,
    "contract-modules": lambda inv: inv.contract_modules,
    "active-surfaces": lambda inv: inv.active_surfaces,
    "pin-default-targets": lambda inv: inv.pin_rewrite_default_targets,
    "pin-workflow-targets": lambda inv: inv.pin_rewrite_workflow_targets,
}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in FIELDS:
        print(
            f"usage: inventory-query.py <{'|'.join(sorted(FIELDS))}>",
            file=sys.stderr,
        )
        return 2
    try:
        inv = load_inventory()
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for value in FIELDS[argv[0]](inv):
        print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
