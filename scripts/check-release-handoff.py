#!/usr/bin/env python3
"""
Report when `main` is pinned to a version that no tag names.

Every managed pin on main should resolve. The exception is the few minutes
between a pins bump merging and the run that follows it cutting the tag — and
that window is exactly where this repository has been bitten, so the check does
not stop at "a pin dangles". It goes on to ask whether anything is still going
to cut the missing tag, and only says the handoff is broken on positive
evidence that nothing is.

Why it exists: `deliver-release-pins.sh` refuses to tag when main moved under a
release, and the refusal leaves main pinned to an uncut version by construction
— the branch is only reachable when main's pins already carry the target. It
then asserts, in a `::warning::` inside a run that reports success, that the
release run for the new tip will tag it. On 2026-09-10 that run never existed:
CI on the new tip died on `curl … exit 35` fetching the Dagger CLI, CD's gate
skipped every job, and main carried thirteen dangling `@v3.2.2` pins with every
check on every branch green. See specs/verify-the-release-handoff.md.

Callers, each catching a case the others cannot:

  cd.yml, on the CI-failed path   the fastest signal, and the one that fires on
                                  the exact event that strands a handoff
  deliver-release-pins.sh, stale  the moment the obligation is created
  release-drift.yml, scheduled    the backstop for a CD that never started at
                                  all, which no step inside CD can report

Deliberately NOT in ci.yml: a release pull request rewrites every pin to the
next version before that tag exists, so this would be red by construction on
every release branch.

Usage:
  python3 scripts/check-release-handoff.py
  python3 scripts/check-release-handoff.py --exclude-run-id 1000000001

Needs `git` with a non-shallow checkout carrying tags, and `gh` authenticated
with `actions: read`.

Exit 0   pins resolve, or a run that would cut the tag is in flight
Exit 1   pins dangle and nothing is going to fix it
Exit 2   a command the verdict depends on could not run — never a pass

The logic and its unit tests live in scripts/release_handoff.py and
scripts/tests/test_release_handoff.py.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_handoff import (  # noqa: E402
    ABANDONED,
    RESOLVED,
    ToolError,
    check,
    subprocess_runner,
)
from repo_surface import (  # noqa: E402
    InventoryError,
    default_inventory_path,
    default_root,
    load_inventory,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report pins on main that name a tag which does not exist."
    )
    parser.add_argument(
        "--exclude-run-id",
        default="",
        help=(
            "a workflow run to ignore when looking for the run that would cut "
            "the tag — pass $GITHUB_RUN_ID so a caller running inside CD does "
            "not read itself as the successor it is waiting for"
        ),
    )
    parser.add_argument(
        "--root", default=None, help="repository root (default: this checkout)"
    )
    parser.add_argument("--inventory", default=None, help="path to repo-inventory.json")
    args = parser.parse_args(argv)

    try:
        inv = load_inventory(
            inventory_path=pathlib.Path(args.inventory) if args.inventory else default_inventory_path(),
            root=pathlib.Path(args.root) if args.root else default_root(),
        )
    except InventoryError as exc:
        print("release handoff check FAILED: {}".format(exc), file=sys.stderr)
        return 2

    try:
        verdict = check(inv, subprocess_runner, exclude_run_id=args.exclude_run_id)
    except ToolError as exc:
        print(
            "release handoff check FAILED: {}\n"
            "This is not a verdict of 'pins resolve'. A detector that could not "
            "look must never read as a clean answer.".format(exc),
            file=sys.stderr,
        )
        return 2

    body = "\n".join(verdict.lines())
    if verdict.state == RESOLVED:
        print("release handoff check: OK — {}".format(body))
        return 0

    if verdict.state == ABANDONED:
        # ::error:: rather than a bare message: this is the one path where a
        # human has to do something, and the annotation is what puts it on the
        # run's summary instead of line 400 of a log nobody opens.
        print(
            "::error::main is pinned to a version no tag names, and no run is "
            "going to cut it.\n{}".format(body),
            file=sys.stderr,
        )
        return 1

    print("::notice::{}".format(body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
