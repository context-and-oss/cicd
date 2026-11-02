"""
Consumer-facing version pin targets, derived from the defended inventory.

This module used to *be* the source of truth: a hand-maintained list of "files we
manage". It no longer maintains any list of its own. Everything comes from
scripts/repo-inventory.json via scripts/repo_surface.py, because a second list
is exactly what rotted:

  * the bumper's list omitted .github/workflows/, which froze at v0.2.0 while
    every other pin moved to v1.0.0;
  * it omitted nine module READMEs entirely, which are still pinned at v1.0.0;
  * it kept templates/azure-devops/commit-archive.yml after the file was deleted,
    and both consumers answered `if not path.exists(): continue`.

Kept as a module so scripts/bump-version.py and scripts/check-workflow-pins.py
have one import surface, and so the pin regexes have one home.

  TARGETS           surfaces the default GITHUB_TOKEN may push
  WORKFLOW_TARGETS  surfaces under .github/workflows/ — GitHub refuses to let the
                    default GITHUB_TOKEN push these (no `permissions:` key grants
                    it; only an App/PAT carrying the `workflow` scope can), so
                    bump-version.py touches them only under --scope workflows
  PATTERNS          rewrite rules used at release
  VERSION_SCAN      pin reader used by the consistency guard
  CALL_SCAN         pinned `call <cmd>` reader, kept for compatibility
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repo_surface import (  # noqa: E402
    PIN_REWRITE_PATTERNS,
    REMOTE_CALL_SCAN,
    VERSION_SCAN,
    load_inventory,
)

_INVENTORY = load_inventory()

TARGETS: list[str] = list(_INVENTORY.pin_rewrite_default_targets)
WORKFLOW_TARGETS: list[str] = list(_INVENTORY.pin_rewrite_workflow_targets)

PATTERNS = PIN_REWRITE_PATTERNS
CALL_SCAN = REMOTE_CALL_SCAN

__all__ = [
    "CALL_SCAN",
    "PATTERNS",
    "TARGETS",
    "VERSION_SCAN",
    "WORKFLOW_TARGETS",
]
