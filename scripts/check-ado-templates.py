#!/usr/bin/env python3
"""
Behavioural validation of the active Azure DevOps templates.

`scripts/check-workflow-pins.py` checks two static tokens in these files: that
the `@vX.Y.Z` pins agree and that a pinned `call <cmd>` exists. This checker
validates what the templates actually *do*:

  1. DECLARED       every ADO template the inventory declares exists, and no
                    template on disk goes undeclared
  2. PARSE          every template parses under ADO's YAML subset and has the
                    skeleton the runner needs (pool / variables / non-empty steps)
  3. STEP SHAPE     each step names exactly one action; bash steps are named
  4. REMOVED        no reference to a surface ADR-005 removed (run-archive,
                    commit-archive)
  5. INVOCATION     the composite call is the unified `run` with --src,
                    --fail-on and the repo triple; commit templates pass
                    --artifact
  6. SECRET FLAGS   every --token/--webhook/--api-key flag uses `env:NAME`, and
                    NAME is declared in that step's env: mapping
  7. INTERPOLATION  no consumer-supplied `$(VAR)` macro is spliced into a bash
                    body (ADO expands macros before the shell parses the line,
                    so quoting cannot contain the value)
  8. QUOTING        every expansion of an env:-provided value is double-quoted
  9. SECRETS        no secret env var is echoed, and a template that writes
                    ~/.git-credentials clears them again with condition: always()
 10. VERDICT        every template either reads `passed` from
                    combined-evidence.json or carries the "THIS PIPELINE DOES
                    NOT GATE" banner — the composites exit 0 on a tripped gate,
                    so a template that reads neither reports success whatever
                    it finds, and silence is indistinguishable from oversight
 11. MERGE LANES    every template that is not declared advisory in
                    ADVISORY_ALLOWED (with its reason) has a live step that
                    reads `passed` — the commit and precommit starters are the
                    merge gate on Azure DevOps, and a paste-ready gate shipped
                    commented out under a banner is documentation, not a gate
 12. SUPERSEDED     a precommit template that declares `pr:` states
                    `autoCancel: true`, and a commit template that declares
                    `trigger:` states `batch: false` — a batched commit build
                    leaves the commits it folded with no evidence of their own,
                    and both values are defaults a copy can flip unseen

Deterministic and offline: no network, no `dagger`, no ADO API, no PyYAML (the
ADO YAML subset is parsed directly — see scripts/ado_templates.py). Wired into
ci.yml's lint-repo job, so drift in any of the above fails the build.

Usage:
  python3 scripts/check-ado-templates.py
  python3 scripts/check-ado-templates.py --root <dir> --inventory <file>

Exit 0 if clean, 1 on any violation, 2 if the inventory itself is unusable.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from ado_templates import (  # noqa: E402
    TemplateError,
    check_all,
    default_inventory_path,
    default_root,
    load_templates,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the active Azure DevOps templates behaviourally."
    )
    parser.add_argument("--root", default=None, help="repository root (default: this checkout)")
    parser.add_argument(
        "--inventory",
        default=None,
        help="inventory manifest (default: scripts/repo-inventory.json)",
    )
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root) if args.root else default_root()
    inventory_path = (
        pathlib.Path(args.inventory) if args.inventory else default_inventory_path()
    )

    try:
        ts = load_templates(root, inventory_path)
    except TemplateError as exc:
        print(f"ADO template check FAILED: {exc}", file=sys.stderr)
        return 2

    results = check_all(ts)
    failed = [(name, problems) for name, problems in results if problems]

    if not failed:
        print(
            f"ADO template check: OK "
            f"({len(ts.templates)} templates, {len(results)} checks)"
        )
        return 0

    print("ADO template check FAILED:\n", file=sys.stderr)
    for name, problems in failed:
        print(f"[{name}]", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(file=sys.stderr)
    total = sum(len(problems) for _, problems in failed)
    print(
        f"{total} problem(s) across {len(failed)} of {len(results)} checks.\n"
        f"Repair the template. Do not relax a check to make a template pass — "
        f"consumers copy these files verbatim.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
