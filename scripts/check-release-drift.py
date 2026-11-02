#!/usr/bin/env python3
"""
Report when `main` carries releasable commits that no release has tagged.

Runs on a schedule from .github/workflows/release-drift.yml, deliberately outside
`cd.yml`: a notification that fires on CD's failure cannot fire when CD never
starts, and a workflow that never starts publishes no job and no check run at all.
So this asks from the outside — is main ahead of the newest tag, and for how long?

Past the threshold it opens one deduped issue labelled `release-drift`, keeps that
issue accurate while drift persists, and closes it when a release lands. The issue
closing itself is the signal.

Usage:
  python3 scripts/check-release-drift.py                       # maintain the issue
  python3 scripts/check-release-drift.py --dry-run             # measure only
  python3 scripts/check-release-drift.py --threshold-days 5
  python3 scripts/check-release-drift.py --now-epoch 1754300000 --dry-run

Needs `git`, `git-cliff`, a non-shallow checkout with tags, and `gh` authenticated
with issue write (the scheduled workflow supplies all four).

Exit 0 whether or not there is drift — the issue is the durable signal, and a
permanently red scheduled workflow is noise people learn to ignore. Exit 1 only
when a command the verdict depends on could not run, because a detector that could
not look must never read as "nothing to release".

The logic and its unit tests live in scripts/release_drift.py and
scripts/tests/test_release_drift.py.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_drift import (  # noqa: E402
    DEFAULT_THRESHOLD_DAYS,
    ToolError,
    check,
    subprocess_runner,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report unreleased releasable commits on main.")
    parser.add_argument(
        "--threshold-days",
        type=float,
        default=DEFAULT_THRESHOLD_DAYS,
        help="days of unreleased history before an issue is opened (default: %(default)s)",
    )
    parser.add_argument(
        "--now-epoch",
        type=int,
        default=None,
        help="override the clock, for reproducible local runs",
    )
    parser.add_argument(
        "--run-url", default="local run", help="URL of this run, cited in the issue body"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="measure and decide without reading or writing any issue",
    )
    args = parser.parse_args(argv)

    if args.threshold_days < 0:
        print(
            "release drift check FAILED: --threshold-days must not be negative "
            "(got {})".format(args.threshold_days),
            file=sys.stderr,
        )
        return 2

    now_epoch = args.now_epoch if args.now_epoch is not None else int(time.time())

    try:
        report = check(
            subprocess_runner,
            now_epoch=now_epoch,
            threshold_days=args.threshold_days,
            run_url=args.run_url,
            dry_run=args.dry_run,
        )
    except ToolError as exc:
        print(
            "release drift check FAILED: {}\n"
            "This is not a verdict of 'no drift'. A detector that could not look "
            "must never read as 'nothing to release'.".format(exc),
            file=sys.stderr,
        )
        return 1

    for line in report.lines():
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
