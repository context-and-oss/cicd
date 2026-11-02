#!/usr/bin/env python3
"""
Refuse a release whose tag would disagree with the history it ships.

`cd.yml` computes the next version with `git cliff --bumped-version`. That
computation partitioned history by commit date, so a feature merged from a branch
that stayed open across a release was filed under a release that had already
shipped, and the bump came out a patch — twice, permanently. Adding
`--unreleased` fixes that partition. This asks the question the flag leaves
unasked: does the computed bump kind match what the commits in the range actually
require?

The comparison is independent of cliff on the axis that broke. The range comes
from `git describe --tags --abbrev=0`, which is reachability-based, and the bump
each commit requires is derived from its own subject and body. Rationale, the
measured tables and the rejected alternatives are in scripts/release_bump.py and
specs/prove-the-bump-matches-its-history.md.

Usage:
  python3 scripts/check-release-bump.py --next 1.15.0
  python3 scripts/check-release-bump.py --next 1.15.0 --current 1.14.3
  python3 scripts/check-release-bump.py --next ""      # CD decided to release nothing

`--current` is a cross-check, not an input: the base tag is resolved from git
either way, and a `--current` that disagrees with it means the release and this
check are looking at two different ranges, which is exit 2 rather than a verdict.

Merge commits are included. cliff processes them and drops them as unparseable, so
they contribute nothing here either — but excluding them would hide a `--no-ff`
merge whose subject *does* parse, and cliff would bump for that one.

Exit 0 when the bump agrees with the history, 1 when it does not, 2 when the
question could not be asked — a check that examined nothing must never read as
clean, and there is deliberately no override flag.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import List, Sequence

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_bump import (  # noqa: E402
    Commit,
    classify,
    render_report,
    review,
    split_subject_body,
)

# git log --format writes one record per commit. \x1f separates the sha from the
# raw message and \x1e ends the record, so a body containing blank lines, tabs or
# any printable character still splits correctly.
FIELD = "\x1f"
RECORD = "\x1e"

# cliff.toml's commit_parsers is a TOML array of inline tables. tomllib is 3.11+
# and this repository's scripts run on the runner's system python and on
# contributors' machines (3.9 here), so the one rule that matters is read with a
# regex over the array's lines instead of a TOML parse. A malformed array raises
# ConfigError rather than yielding an empty skip list: an empty list would silently
# reclassify every chore: commit as a patch and start failing every release.
_PARSER_LINE = re.compile(r"^\s*\{(?P<body>.*)\}\s*,?\s*$")
_MESSAGE_FIELD = re.compile(r"""message\s*=\s*(?P<q>['"])(?P<pattern>.*?)(?P=q)""")
_SKIP_FIELD = re.compile(r"skip\s*=\s*true")


class AskError(Exception):
    """The question could not be put to git or to the config."""


class ConfigError(AskError):
    """cliff.toml could not be read for the one rule this check needs."""


def _git(args: Sequence[str]) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise AskError(
            "git {} failed ({}): {}".format(
                " ".join(args), proc.returncode, proc.stderr.strip() or "no stderr"
            )
        )
    return proc.stdout.strip()


def _refuse_shallow() -> None:
    # A shallow clone truncates the range in the direction that hides the problem:
    # the base tag may be absent, so the range resolves to fewer commits and the
    # deciding feat can sit outside it. Refuse rather than judge a slice.
    if _git(["rev-parse", "--is-shallow-repository"]) == "true":
        raise AskError(
            "shallow clone: the commit range is truncated, so the commit that sets "
            "the required bump could sit outside it. Check out with fetch-depth: 0."
        )


def read_skip_patterns(config_path: pathlib.Path) -> List[str]:
    """cliff.toml's `skip = true` message regexes, in file order."""
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError("cannot read {}: {}".format(config_path, exc))

    lines = text.splitlines()
    try:
        start = next(
            i for i, line in enumerate(lines) if line.strip().startswith("commit_parsers")
        )
    except StopIteration:
        raise ConfigError(
            "{} declares no commit_parsers, so which commit types release nothing "
            "is unknown".format(config_path)
        )

    patterns: List[str] = []
    saw_close = False
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped.startswith("]"):
            saw_close = True
            break
        entry = _PARSER_LINE.match(line)
        if entry is None:
            continue
        body = entry.group("body")
        if not _SKIP_FIELD.search(body):
            continue
        message = _MESSAGE_FIELD.search(body)
        if message is None:
            # A skip rule keyed on something other than the subject (a body or
            # field match) cannot be applied to a subject here. Refuse rather than
            # ignore it: ignoring would classify commits cliff drops as releasable.
            raise ConfigError(
                "{} has a `skip = true` parser with no `message` pattern, which "
                "this check cannot apply to a commit subject: {}".format(
                    config_path, stripped
                )
            )
        patterns.append(message.group("pattern"))

    if not saw_close:
        raise ConfigError(
            "{}'s commit_parsers array is not closed, so the skip rules may be "
            "truncated".format(config_path)
        )
    if not patterns:
        raise ConfigError(
            "{} declares no `skip = true` parser. Without one, every chore:, ci:, "
            "test: and style: commit reads as releasable and this check would "
            "refuse every release. Refusing to guess.".format(config_path)
        )
    return patterns


def read_commits(rev_range: str) -> List[Commit]:
    raw = _git(
        [
            "log",
            "--format=%H{}%B{}".format(FIELD, RECORD),
            rev_range,
        ]
    )
    commits: List[Commit] = []
    for record in raw.split(RECORD):
        record = record.strip("\n")
        if not record.strip():
            continue
        sha, _, message = record.partition(FIELD)
        subject, body = split_subject_body(message)
        commits.append(Commit(sha=sha.strip(), subject=subject, body=body))
    # git log is newest-first; report oldest-first so the output reads like history.
    return list(reversed(commits))


def tree_carries_pins(root: pathlib.Path) -> bool:
    """Does any active surface pin a cicd version (`...@vX.Y.Z`)?

    Read with the same scanner `check_pin_consistency` uses, over the same
    inventory, so "the tree carries pins" means exactly what the pin gates mean
    by it. A tree that could not be inventoried raises AskError: the answer
    decides whether a tagless clone is pre-release or unbootstrapped, and a
    guess in either direction is a release decision nobody made.
    """
    from repo_surface import VERSION_SCAN, InventoryError, load_inventory

    try:
        inv = load_inventory(root / "scripts" / "repo-inventory.json", root)
    except InventoryError as exc:
        raise AskError("could not read the surface inventory: {}".format(exc))
    for rel in inv.active_surfaces:
        path = root / rel
        if not path.is_file():
            continue
        if VERSION_SCAN.search(path.read_text(errors="replace")):
            return True
    return False


def base_from_tag(tag: str, pins_present: bool) -> tuple[str, str, str]:
    """Return (rev_range, human scope, current version without a leading v).

    No reachable tag is two different states. A repository before its first
    release carries no pin and every commit is in range. A *copy* of a released
    tree carries pins at the version its tag named, and a tagless copy is one
    nobody bootstrapped: cd.yml refuses to run on it, and if that refusal is
    ever lost this is the layer that still says "0.0.0 is not where this tree
    is" rather than letting the bumper rewrite every pin from a base it made up.
    """
    tag = tag.strip()
    if tag:
        return "{}..HEAD".format(tag), "{}..HEAD".format(tag), tag.lstrip("vV")
    if pins_present:
        raise AskError(
            "no v* tag is reachable from HEAD, but the tree carries cicd pins, so "
            "this is an unbootstrapped copy of a released tree and not a "
            "repository before its first release. Tag it with the version its "
            "pins name (CONTRIBUTING.md, 'Bootstrapping a fresh copy')."
        )
    return "HEAD", "the whole history (no tags yet)", "0.0.0"


def resolve_base() -> tuple[str, str, str]:
    proc = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        capture_output=True,
        text=True,
        check=False,
    )
    tag = proc.stdout.strip() if proc.returncode == 0 else ""
    root = pathlib.Path(__file__).resolve().parent.parent
    return base_from_tag(tag, tree_carries_pins(root) if not tag else False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse a release whose bump kind disagrees with its history."
    )
    parser.add_argument(
        "--next",
        dest="next_version",
        required=True,
        help="the version CD computed, with or without a leading v; empty means "
        "CD decided to release nothing",
    )
    parser.add_argument(
        "--current",
        default=None,
        help="cross-check: the base version CD believes it is releasing from",
    )
    parser.add_argument(
        "--cliff-config",
        default="cliff.toml",
        help="path to cliff.toml (default: cliff.toml)",
    )
    args = parser.parse_args(argv)

    try:
        _refuse_shallow()
        rev_range, scope, current = resolve_base()
        if args.current is not None:
            declared = args.current.strip().lstrip("vV")
            if declared and declared != current:
                raise AskError(
                    "the release is bumping from v{} but the newest tag reachable "
                    "from HEAD is v{}, so the release and this check are looking at "
                    "different ranges. One of them is wrong; neither answer can be "
                    "trusted until they agree.".format(declared, current)
                )
        skip_patterns = read_skip_patterns(pathlib.Path(args.cliff_config))
        commits = read_commits(rev_range)
    except AskError as exc:
        print(
            "release bump check FAILED: {}\n"
            "This is not a verdict of 'the bump is correct'. A check that could "
            "not look must never read as clean.".format(exc),
            file=sys.stderr,
        )
        return 2

    # An empty --next is how cd.yml says "nothing to release". Comparing it as the
    # current version turns that into an ordinary no-bump verdict, which is still
    # checked: a range holding a feat must not produce it.
    next_version = args.next_version.strip().lstrip("vV") or current

    contributions = classify(commits, skip_patterns)
    problems = review(current, next_version, contributions)
    stream = sys.stderr if problems else sys.stdout
    for line in render_report(current, next_version, contributions, problems, scope):
        print(line, file=stream)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
