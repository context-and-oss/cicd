"""Detect releasable commits on main that no release has tagged.

A release that never happens is silent. Between v1.10.0 and v1.11.0 `cd.yml`
failed on every run for four days and ~46 merged commits piled up behind it with
nothing anywhere saying so: CI was green, every PR check list was green, and the
only evidence was a red run in a tab nobody had reason to open.

This is deliberately NOT a failure notification inside `cd.yml`. A step that runs
on CD's failure cannot fire when CD never starts, and that is a real failure mode
here — under the `selected` Actions policy a disallowed action makes GitHub refuse
the workflow at *startup*, publishing no job and no check run at all, which is how
`ci.yml` and `cd.yml` sat dead for four days while PRs merged on a check list that
never mentioned them. So this asks from the outside, on a schedule: is `main` ahead
of the newest tag, and for how long?

Same doctrine as every gate in this repository, one level up: **a release pipeline
that could not run must never read as "nothing to release".** Every command whose
answer feeds the verdict therefore fails loud — `git cliff` refusing to compute a
version raises, it never degrades to an implied "no drift". That inversion is the
exact false pass the run-error classification in `src/quality` and `src/security`
exists to prevent.

The one deliberate exception is the most-recent-CD-run summary: it is context
printed into the issue body, not an input to the verdict, so its absence degrades
to a note.

The verdict is reported by opening, updating or closing ONE deduped issue labelled
`release-drift`. The issue closing itself is the signal that a release landed.

Everything above `measure()` is pure, and everything below takes its commands
through a `runner` callable, so `scripts/tests/test_release_drift.py` drives the
whole decision path — including the failure modes — without git, `gh` or a clock.
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

LABEL = "release-drift"
LABEL_COLOR = "B60205"
LABEL_DESCRIPTION = "main carries releasable commits that no release has tagged"
# Anchors the body this script owns, so a human comment is never mistaken for
# machine output and an edit always replaces the right text.
MARKER = "<!-- release-drift-report -->"
DEFAULT_THRESHOLD_DAYS = 2.0
SECONDS_PER_DAY = 86400
# A human may open a second issue under the label; the extras are named in the
# output rather than silently ignored. Bounded so a label used for something else
# entirely cannot turn one API call into an unbounded page walk.
ISSUE_LIST_LIMIT = 50

ACTION_OPEN = "open"
ACTION_UPDATE = "update"
ACTION_CLOSE = "close"
ACTION_NONE = "none"

CD_SUMMARY_UNAVAILABLE = "unavailable — could not query workflow runs"

# (returncode, stdout, stderr)
CommandResult = Tuple[int, str, str]
Runner = Callable[[Sequence[str]], CommandResult]


class ToolError(RuntimeError):
    """A command whose answer the verdict depends on could not run."""


# ── pure logic ────────────────────────────────────────────────────────────────


class Drift:
    """The measured state of `main` relative to the newest tag."""

    def __init__(
        self,
        latest_tag: str,
        next_version: str,
        commits_ahead: int,
        oldest_unreleased_epoch: Optional[int],
    ) -> None:
        self.latest_tag = latest_tag
        self.next_version = next_version
        self.commits_ahead = commits_ahead
        self.oldest_unreleased_epoch = oldest_unreleased_epoch

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            "Drift(latest_tag={!r}, next_version={!r}, commits_ahead={!r}, "
            "oldest_unreleased_epoch={!r})".format(
                self.latest_tag,
                self.next_version,
                self.commits_ahead,
                self.oldest_unreleased_epoch,
            )
        )


def normalise_version(value: str) -> str:
    """Compare tags and computed versions on one spelling.

    `git describe` reports `v1.11.0` and `git cliff --bumped-version` also emits a
    leading v, but `cd.yml` strips it in places and a hand-pushed tag may not carry
    one. Comparing raw strings would report permanent drift the moment those
    spellings disagree — a false alarm that teaches people to ignore the issue,
    which is worse than no issue at all.
    """
    return value.strip().lstrip("vV")


def is_drifting(drift: Drift) -> bool:
    """True when a release is actually due.

    Both conditions are required and neither implies the other:

    * `commits_ahead` alone would flag a tree whose new commits are all of a type
      git-cliff does not release (a `chore:` sweep bumps nothing), producing an
      issue that no release could ever close.
    * a version difference alone would trust git-cliff's arithmetic over the
      history: with no commits after the tag there is nothing to release whatever
      it computes.
    """
    if drift.commits_ahead <= 0:
        return False
    return normalise_version(drift.next_version) != normalise_version(drift.latest_tag)


def drift_age_days(oldest_epoch: Optional[int], now_epoch: int) -> float:
    """Age of the oldest unreleased commit, in days.

    Clamped at zero. A commit timestamp is author-controlled, so a skewed clock or
    a rebase carrying a future date would otherwise yield a negative age that
    reads as below any threshold and hides real drift.
    """
    if oldest_epoch is None:
        return 0.0
    return max(0.0, (now_epoch - oldest_epoch) / SECONDS_PER_DAY)


def decide_action(
    drifting: bool,
    age_days: float,
    threshold_days: float,
    has_open_issue: bool,
) -> str:
    """Map the measured state onto the single issue this script owns.

    An already-open issue is updated whatever the age, deliberately: the threshold
    exists so no issue is opened during the normal window between a merge and its
    release, and it is not a reason to let an issue that already exists go stale
    and under-report the backlog.
    """
    if drifting:
        if has_open_issue:
            return ACTION_UPDATE
        return ACTION_OPEN if age_days >= threshold_days else ACTION_NONE
    return ACTION_CLOSE if has_open_issue else ACTION_NONE


def render_title(drift: Drift) -> str:
    tag = drift.latest_tag or "(no tag yet)"
    plural = "" if drift.commits_ahead == 1 else "s"
    return "release drift: main is {} commit{} ahead of {}".format(
        drift.commits_ahead, plural, tag
    )


def render_body(
    drift: Drift,
    age_days: float,
    threshold_days: float,
    cd_summary: str,
    run_url: str,
) -> str:
    tag = drift.latest_tag or "(none — this repository has no tag)"
    oldest = (
        time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(drift.oldest_unreleased_epoch))
        if drift.oldest_unreleased_epoch is not None
        else "unknown"
    )
    return "\n".join(
        [
            MARKER,
            "",
            "`main` carries **{}** commit(s) that no release has tagged.".format(
                drift.commits_ahead
            ),
            "",
            "| | |",
            "| --- | --- |",
            "| Newest tag | `{}` |".format(tag),
            "| Next version would be | `{}` |".format(drift.next_version),
            "| Oldest unreleased commit | {} ({:.1f} days old) |".format(oldest, age_days),
            "| Reporting threshold | {:g} days |".format(threshold_days),
            "| Most recent CD run | {} |".format(cd_summary),
            "",
            "A release is not overdue because someone forgot. It is overdue because",
            "nothing failed loudly: CI stays green, every PR check list stays green,",
            "and a failed — or entirely absent — CD run is visible only to whoever",
            "opens the Actions tab. That is how the gap before v1.11.0 reached ~46",
            "commits.",
            "",
            "A release cannot be pushed to `main` in this repository. See",
            "[the release-by-pull-request spec](../blob/main/specs/release-by-pull-request.md)",
            "for why, and for the pin-bump-by-pull-request path that works.",
            "",
            "Detected by `scripts/check-release-drift.py` ({}).".format(run_url),
            "This issue is maintained by that script and **closes itself** when a",
            "release lands; edits to the body above will be overwritten.",
        ]
    )


def close_comment(drift: Drift) -> str:
    return (
        "Drift cleared — `{}` now accounts for every releasable commit on `main`. "
        "Closed automatically by `scripts/check-release-drift.py`.".format(
            drift.latest_tag or "HEAD"
        )
    )


def pick_issue(issues: Sequence[Dict]) -> Tuple[Optional[int], List[int]]:
    """Choose the one issue to maintain and report any duplicates.

    Lowest number wins, so the choice is stable across runs: a human who opens a
    second issue under the label must not make this script flip between them.
    """
    numbers = sorted(int(issue["number"]) for issue in issues)
    if not numbers:
        return None, []
    return numbers[0], numbers[1:]


# ── command layer ─────────────────────────────────────────────────────────────


def subprocess_runner(cmd: Sequence[str]) -> CommandResult:
    proc = subprocess.run(list(cmd), capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _run(runner: Runner, cmd: Sequence[str]) -> str:
    code, out, err = runner(cmd)
    if code != 0:
        raise ToolError(
            "command failed (exit {}): {}\n{}".format(
                code, " ".join(cmd), (err or out).strip()
            )
        )
    return out.strip()


def _run_optional(runner: Runner, cmd: Sequence[str]) -> Optional[str]:
    code, out, _ = runner(cmd)
    return out.strip() if code == 0 else None


def measure(runner: Runner) -> Drift:
    """Measure drift from the repository itself. Raises ToolError, never guesses."""
    # A shallow clone makes every number below wrong in the direction that hides
    # drift: no tags reachable, a truncated commit count, and an "oldest" commit
    # that is only the oldest one fetched. Refuse rather than under-report.
    if _run(runner, ["git", "rev-parse", "--is-shallow-repository"]) == "true":
        raise ToolError(
            "shallow clone: tags and commit counts are truncated, so drift cannot "
            "be measured. Check out with fetch-depth: 0."
        )

    # No tags at all is a legitimate state (a repository before its first release),
    # so this one command is allowed to fail: git describe exits non-zero with
    # "No names found". Every other command's failure is fatal.
    latest_tag = _run_optional(runner, ["git", "describe", "--tags", "--abbrev=0"]) or ""

    # git-cliff decides what is releasable, the same way cd.yml decides it —
    # including --unreleased, which is what makes it the same way. Without the flag
    # cliff partitions by commit date and can compute a version from a range that is
    # not the one commits_ahead below measures by reachability, so drift would be
    # judged against a range this script never looked at.
    next_version = _run(runner, ["git", "cliff", "--unreleased", "--bumped-version"])
    if not next_version:
        raise ToolError(
            "git cliff --bumped-version exited 0 but printed no version; refusing "
            "to read that as 'nothing to release'"
        )

    rev_range = "{}..HEAD".format(latest_tag) if latest_tag else "HEAD"
    raw_count = _run(runner, ["git", "rev-list", "--count", rev_range])
    try:
        commits_ahead = int(raw_count)
    except ValueError:
        raise ToolError(
            "git rev-list --count {} printed {!r}, which is not a number".format(
                rev_range, raw_count
            )
        )

    oldest_epoch = None
    if commits_ahead > 0:
        # git log is newest-first, so the last line is the oldest commit in range.
        stamps = [
            line.strip()
            for line in _run(runner, ["git", "log", "--format=%ct", rev_range]).splitlines()
            if line.strip()
        ]
        if not stamps:
            raise ToolError(
                "git rev-list counted {} commit(s) in {} but git log listed none".format(
                    commits_ahead, rev_range
                )
            )
        try:
            oldest_epoch = int(stamps[-1])
        except ValueError:
            raise ToolError(
                "git log printed a commit timestamp that is not an epoch: {!r}".format(
                    stamps[-1]
                )
            )

    return Drift(latest_tag, next_version, commits_ahead, oldest_epoch)


def latest_cd_summary(runner: Runner) -> str:
    """One line describing the most recent CD run.

    Context only — never an input to the verdict — so a failure here degrades to a
    note rather than aborting. Anything that could change the answer fails loud
    instead; see measure().
    """
    raw = _run_optional(
        runner,
        [
            "gh", "run", "list", "--workflow=cd.yml", "--limit", "1",
            "--json", "conclusion,status,url,createdAt",
        ],
    )
    if raw is None:
        return CD_SUMMARY_UNAVAILABLE
    try:
        runs = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return "unavailable — unreadable response from gh run list"
    if not runs:
        return "none found"
    run = runs[0]
    return "{} / {} on {} ({})".format(
        run.get("status") or "?",
        run.get("conclusion") or "?",
        (run.get("createdAt") or "?")[:16],
        run.get("url") or "?",
    )


def open_drift_issues(runner: Runner) -> List[Dict]:
    raw = _run(
        runner,
        ["gh", "issue", "list", "--label", LABEL, "--state", "open",
         "--limit", str(ISSUE_LIST_LIMIT), "--json", "number,title"],
    )
    if not raw:
        return []
    try:
        issues = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolError("gh issue list printed unreadable JSON: {}".format(exc))
    if not isinstance(issues, list):
        raise ToolError("gh issue list printed {}, expected a list".format(type(issues).__name__))
    return issues


def ensure_label(runner: Runner) -> None:
    # --force makes this idempotent: it creates the label or updates it in place,
    # so a first run against a repository that has no such label does not fail at
    # issue creation with a message about a missing label. Not fatal on its own —
    # if the label genuinely cannot be made, `gh issue create` fails loudly next.
    _run_optional(
        runner,
        ["gh", "label", "create", LABEL, "--color", LABEL_COLOR,
         "--description", LABEL_DESCRIPTION, "--force"],
    )


class Report:
    """What one run decided, and what it did about it."""

    def __init__(
        self,
        drift: Drift,
        drifting: bool,
        age_days: float,
        action: str,
        issue_number: Optional[int],
        duplicates: Sequence[int],
        performed: bool,
        detail: str = "",
    ) -> None:
        self.drift = drift
        self.drifting = drifting
        self.age_days = age_days
        self.action = action
        self.issue_number = issue_number
        self.duplicates = list(duplicates)
        self.performed = performed
        self.detail = detail

    def lines(self) -> List[str]:
        out = [
            "tag={} next={} ahead={} age={:.1f}d drifting={} action={}".format(
                self.drift.latest_tag or "(none)",
                self.drift.next_version,
                self.drift.commits_ahead,
                self.age_days,
                self.drifting,
                self.action,
            )
        ]
        if self.duplicates:
            # No silent caps: say which issues were left alone rather than letting
            # "one issue maintained" imply it is the only one.
            out.append(
                "note: {} other open issue(s) carry the {} label and are left "
                "alone: {}".format(
                    len(self.duplicates),
                    LABEL,
                    ", ".join("#{}".format(n) for n in self.duplicates),
                )
            )
        if self.detail:
            out.append(self.detail)
        out.append(
            "release drift check: OK ({})".format(
                "drift reported" if self.drifting else "no unreleased releasable commits"
            )
        )
        return out


def check(
    runner: Runner,
    now_epoch: int,
    threshold_days: float = DEFAULT_THRESHOLD_DAYS,
    run_url: str = "local run",
    dry_run: bool = False,
) -> Report:
    """Measure, decide, and (unless dry_run) maintain the issue. Raises ToolError."""
    drift = measure(runner)
    drifting = is_drifting(drift)
    age = drift_age_days(drift.oldest_unreleased_epoch, now_epoch)

    # A dry run must not need issue-read permission either, so it reports the
    # measurement and the action it would take against "no issue open" — enough to
    # prove the measurement locally without implying it inspected the issue list.
    if dry_run:
        action = decide_action(drifting, age, threshold_days, has_open_issue=False)
        detail = (
            "dry run: no issue was read or written"
            if action == ACTION_NONE
            else "dry run: would {} the {} issue (an already-open one would be "
            "updated instead)".format(action, LABEL)
        )
        return Report(drift, drifting, age, action, None, [], performed=False, detail=detail)

    issues = open_drift_issues(runner)
    number, duplicates = pick_issue(issues)
    action = decide_action(drifting, age, threshold_days, number is not None)

    if action == ACTION_NONE:
        return Report(drift, drifting, age, action, number, duplicates, performed=False)

    if action == ACTION_OPEN:
        ensure_label(runner)
        body = render_body(drift, age, threshold_days, latest_cd_summary(runner), run_url)
        url = _run(
            runner,
            ["gh", "issue", "create", "--title", render_title(drift),
             "--body", body, "--label", LABEL],
        )
        detail = "opened {}".format(url or "(gh printed no URL)")
    elif action == ACTION_UPDATE:
        body = render_body(drift, age, threshold_days, latest_cd_summary(runner), run_url)
        _run(
            runner,
            ["gh", "issue", "edit", str(number), "--title", render_title(drift),
             "--body", body],
        )
        detail = "updated #{}".format(number)
    else:  # ACTION_CLOSE
        _run(runner, ["gh", "issue", "close", str(number), "--comment", close_comment(drift)])
        detail = "closed #{}".format(number)

    return Report(drift, drifting, age, action, number, duplicates, performed=True, detail=detail)
