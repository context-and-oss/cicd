#!/usr/bin/env python3
"""
Refuse a commit whose subject git-cliff would silently drop.

A commit that does not parse as a conventional commit releases nothing: cliff's
config here filters it out, `--bumped-version` reports the version already tagged,
CD finds "nothing to bump" and reports success. That is indistinguishable from a
deliberate `chore:` sweep, which is why it has to be caught on the subject rather
than on the resulting version — and why `release-drift.yml` cannot catch it at all
(it asks the same cliff, and gets the same silence). Measured cases and the
rationale are in scripts/commit_subjects.py and
specs/refuse-a-commit-git-cliff-cannot-release.md.

Usage:
  python3 scripts/check-commit-subjects.py --base <sha>   # a pull request's range
  python3 scripts/check-commit-subjects.py --since-tag    # newest tag..HEAD
  python3 scripts/check-commit-subjects.py --subject "fix: x"   # judge one string

Merge commits are excluded: cliff cannot parse "Merge pull request #1 from …"
either, so every release in this repository's history carries some, and demanding
otherwise would fail every run while saying nothing.

Exit 0 when every examined subject parses, 1 when one does not, 2 when the range
could not be established — a check that examined nothing must never read as clean.
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from typing import List, Sequence

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from commit_subjects import Commit, render_report, review, subject_problem  # noqa: E402

# git log --format uses \x1f (unit separator) so a subject containing any
# printable character, tabs included, still splits correctly.
SEPARATOR = "\x1f"


class RangeError(Exception):
    """The set of commits to examine could not be established."""


def _git(args: Sequence[str]) -> str:
    proc = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RangeError(
            "git {} failed ({}): {}".format(
                " ".join(args), proc.returncode, proc.stderr.strip() or "no stderr"
            )
        )
    return proc.stdout.strip()


def _refuse_shallow() -> None:
    # A shallow clone truncates the range in the direction that hides a problem:
    # the base commit may be absent, so `base..HEAD` resolves to fewer commits or
    # fails outright. Refuse rather than examine a slice and call it the whole.
    if _git(["rev-parse", "--is-shallow-repository"]) == "true":
        raise RangeError(
            "shallow clone: the commit range is truncated, so a bad subject could "
            "sit outside it. Check out with fetch-depth: 0."
        )


def read_commits(rev_range: str) -> List[Commit]:
    raw = _git(["log", "--no-merges", "--format=%H{}%s".format(SEPARATOR), rev_range])
    commits = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        sha, _, subject = line.partition(SEPARATOR)
        commits.append(Commit(sha=sha, subject=subject))
    # git log is newest-first; report oldest-first so the output reads like history.
    return list(reversed(commits))


def resolve_range(base: str | None, since_tag: bool) -> tuple[str, str, bool]:
    """Return (rev_range, human scope, whether an empty range is legitimate)."""
    if base:
        # A base sha the local history does not contain means the range is a lie,
        # not an empty one.
        _git(["cat-file", "-e", "{}^{{commit}}".format(base)])
        return "{}..HEAD".format(base), "{}..HEAD".format(base[:8]), False

    if since_tag:
        proc = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=False,
        )
        tag = proc.stdout.strip()
        if proc.returncode != 0 or not tag:
            # No tags yet is legitimate (a repository before its first release).
            return "HEAD", "the whole history (no tags yet)", True
        # Empty is legitimate here: immediately after a release the tag *is* HEAD.
        return "{}..HEAD".format(tag), "{}..HEAD".format(tag), True

    raise RangeError("pass --base <sha>, --since-tag or --subject")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse a commit subject git-cliff cannot release."
    )
    parser.add_argument("--base", default=None, help="base sha of a pull request range")
    parser.add_argument(
        "--since-tag",
        action="store_true",
        help="examine every commit after the newest tag",
    )
    parser.add_argument(
        "--subject",
        default=None,
        help="judge one subject string and exit, touching no repository",
    )
    args = parser.parse_args(argv)

    if args.subject is not None:
        reason = subject_problem(args.subject)
        if reason is None:
            print("OK: {!r} parses as a conventional commit".format(args.subject))
            return 0
        print("REJECTED: {!r}\n  ^ {}".format(args.subject, reason), file=sys.stderr)
        return 1

    try:
        _refuse_shallow()
        rev_range, scope, empty_ok = resolve_range(args.base, args.since_tag)
        commits = read_commits(rev_range)
    except RangeError as exc:
        print(
            "commit subject check FAILED: {}\n"
            "This is not a verdict of 'every subject is fine'. A check that could "
            "not look must never read as clean.".format(exc),
            file=sys.stderr,
        )
        return 2

    if not commits and not empty_ok:
        print(
            "commit subject check FAILED: {} contains no non-merge commits, so "
            "nothing was examined. A pull request always carries at least one, so "
            "this means the range is wrong — not that the range is clean.".format(scope),
            file=sys.stderr,
        )
        return 2

    problems = review(commits)
    stream = sys.stderr if problems else sys.stdout
    for line in render_report(commits, problems, scope):
        print(line, file=stream)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
