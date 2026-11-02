#!/usr/bin/env python3
"""Answer one question: will `git push` from this clone run the pre-push gate?

`make install-hooks` sets core.hooksPath, and it is a one-time manual step with
nothing detecting that it was skipped. A fresh clone starts ungated, and the
skip is silent — the push simply succeeds, which is exactly what a passing gate
also looks like. That is the failure class CAPS-038 closed one level in (an
absent check reading as a passing one); this closes it one level further out.

What this is NOT: proof that main is safe. When applicable branch rules require
a pull request and the `ci` check, an uninstalled hook means finding out on the
pull request instead of before the push. This script does not verify those
remote protections; they must be checked in each destination. A local hook and
a required server-side check are different layers of protection.

Where it does cost protection is a consumer repo. templates/local ships this
same one-manual-step design, and a consumer that copies it without an
equivalent required check has made the local hook their only gate.

The question is asked of git, not of one config value: `git rev-parse
--git-path hooks` resolves core.hooksPath however it was set — local, global,
relative or absolute — so a developer who wired the hook their own way is
correctly reported as gated. Reading `git config --get core.hooksPath` and
comparing it to ".githooks" would have called that clone broken, and would
equally have called a clone with core.hooksPath set to an EMPTY directory
installed. Both directions are wrong, and the second is the one that lets an
ungated clone report success.

Usage:
  check-hooks-installed.py            strict; exit 1 when git would run no hook
  check-hooks-installed.py --warn     one line on stderr, always exit 0
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HOOK_NAME = "pre-push"
FIX = "make install-hooks"


def _git(*args: str) -> str | None:
    """Run a git command, or None if git is unavailable or the call fails."""
    try:
        out = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


GATED = "gated"
UNGATED = "ungated"
NOT_APPLICABLE = "not-applicable"


def hook_state() -> tuple[str, str]:
    """Whether git would run a pre-push hook here, as (state, message).

    The three states are kept distinct on purpose. An earlier version of this
    script folded "not applicable" into "gated" by returning None for both, and
    running it outside a work tree printed "OK (git would run the pre-push
    hook)" — a false claim, and precisely the absent-check-reads-as-passing
    failure this script exists to close. Not being in a work tree, or having no
    git at all, is not evidence that a hook is missing; it is evidence the
    question does not apply, and saying either "gated" or "ungated" there is a
    lie in one direction or the other.
    """
    if _git("rev-parse", "--is-inside-work-tree") != "true":
        return NOT_APPLICABLE, "skipped (not inside a git work tree)"

    hooks_dir = _git("rev-parse", "--git-path", "hooks")
    if hooks_dir is None:
        return NOT_APPLICABLE, "skipped (git could not report the hooks path)"

    hook = Path(hooks_dir) / HOOK_NAME
    if not hook.is_file():
        return UNGATED, (
            f"git would run no {HOOK_NAME} hook: {hook} does not exist. "
            f"Pushes from this clone are not gated locally. Fix: {FIX}"
        )

    # On Windows the file-mode bit is irrelevant and Git Bash executes the hook
    # regardless, so demanding +x there would report a working clone as broken.
    if os.name == "posix" and not os.access(hook, os.X_OK):
        return UNGATED, (
            f"git would skip {hook}: the file exists but is not executable, "
            f"so pushes from this clone are not gated locally. Fix: {FIX}"
        )

    return GATED, f"OK (git would run {hook})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--warn",
        action="store_true",
        help="print one line to stderr and exit 0 (for developer-facing make targets)",
    )
    args = parser.parse_args(argv)

    # A CI clone has no developer to gate and needs no local hook. Whether
    # server-side checks are required is outside this local hook check.
    if os.environ.get("CI"):
        if not args.warn:
            print("hook check: skipped (CI) — local hooks do not verify server-side required checks")
        return 0

    state, message = hook_state()
    if state != UNGATED:
        if not args.warn:
            print(f"hook check: {message}")
        return 0

    if args.warn:
        print(f"warning: {message}", file=sys.stderr)
        return 0

    print(f"hook check FAILED: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
