"""Verify that a release handoff was discharged, instead of asserting it.

`scripts/ci/deliver-release-pins.sh` refuses to tag when main moved past the
commit its version was computed for. The refusal is right — v2.2.3 was computed
for a pins merge and cut on a `refactor!` that landed fourteen seconds later, so
a breaking change shipped inside a patch and the major it deserved could never
be computed again. What was wrong is what the refusal *said* about its cost:

    Refusing costs this version its number. The run for the new tip re-derives
    from the same history and releases a version that accounts for all of it,
    so nothing is lost but the gap in the sequence.

That is false, and not occasionally. The stale branch is only reachable from
`git diff --quiet` being true — main's pins ALREADY carry the target version —
and the guard above it has already established that no tag at or above the
target exists. So **every** stale emission leaves main pinned to a version that
has no tag. A consumer following main resolves `@v3.2.2` against a ref that was
never created and gets a hard failure, and it stays that way until some later
run cuts a tag.

The sentence quoted above is also the only thing holding that story together:
"the release run for the new tip tags that" is asserted inside a `::warning::`,
in a run that reports success, and nothing checks it. On 2026-09-10 it was not
true. CI on the new tip died in `Install Dagger CLI` on `curl … exit 35` — an
SSL connect error, nothing to do with the code — so CD's gate (`if:
conclusion == 'success'`) skipped every job, no run ever tagged, and main sat
with thirteen dangling `@v3.2.2` pins. `release-drift.yml` measures a different
thing (commits ahead of the newest tag) behind a two-day threshold, so the
break was ~2 days from being reported by anything.

This module asks the question that was missing, in two parts:

  1. **Do main's pins name a tag that exists?** A standing invariant, true at
     all times except the minutes between a pins merge and its tag. It does not
     care *how* it broke — a stranded handoff, a deleted tag, a hand-edited
     pin — which is the point: it catches routes to the broken state that
     nobody has thought of yet.

  2. **If not, is anything actually going to fix it?** Only positive evidence
     counts as abandonment: a CI or CD run for main's tip that has *concluded*
     unsuccessfully, or a CD run for the tip that concluded at all without a tag
     appearing. Anything in flight, and anything not yet observed, is `pending`.
     A red run on a condition that heals itself in one CI cycle is the false
     alarm that teaches people to ignore the signal, which is worse than no
     signal — see the same argument in `release_drift.normalise_version`.

Deliberately NOT part of `ci.yml`. A release pull request rewrites every pin to
the next version *before* that tag exists, so this check on a release branch is
red by construction; `check-workflow-pins.py` says the same thing about why it
compares pins to each other rather than to the newest tag.

Everything above `classify()` is pure, and everything below takes its commands
through a `runner` callable, so `scripts/tests/test_release_handoff.py` drives
the whole decision path — including the failure modes — without git or `gh`.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repo_surface import VERSION_SCAN  # noqa: E402

RESOLVED = "resolved"
PENDING = "pending"
ABANDONED = "abandoned"

# GitHub reports a run that has not finished under one of these. Treated as one
# set rather than "not completed" so a status this code has never seen is not
# silently read as finished — an unfinished run misread as concluded is exactly
# the false abandonment verdict that would make this check noise.
IN_FLIGHT = frozenset({
    "queued", "in_progress", "requested", "waiting", "pending", "action_required",
})

# (returncode, stdout, stderr)
CommandResult = Tuple[int, str, str]
Runner = Callable[[Sequence[str]], CommandResult]


class ToolError(RuntimeError):
    """A command whose answer the verdict depends on could not run."""


# ── pure logic ────────────────────────────────────────────────────────────────


class Verdict:
    """What one check decided, and the evidence it decided on."""

    def __init__(
        self,
        state: str,
        dangling: Dict[str, List[str]],
        tip: str = "",
        reason: str = "",
        remedy: str = "",
    ) -> None:
        self.state = state
        self.dangling = dangling
        self.tip = tip
        self.reason = reason
        self.remedy = remedy

    @property
    def broken(self) -> bool:
        return self.state == ABANDONED

    def lines(self) -> List[str]:
        if self.state == RESOLVED:
            return ["every managed pin names a tag that exists"]
        out = [
            "main is pinned to {} that no tag names:".format(
                "a version" if len(self.dangling) == 1 else "versions"
            )
        ]
        for version in sorted(self.dangling):
            locations = self.dangling[version]
            shown = locations[:5]
            more = len(locations) - len(shown)
            out.append(
                "  v{}  <-  {}{}".format(
                    version,
                    ", ".join(shown),
                    " (+{} more)".format(more) if more > 0 else "",
                )
            )
        out.append(self.reason)
        if self.remedy:
            out.append(self.remedy)
        return out


def unresolved_pins(
    pins: Dict[str, List[str]], tags: Sequence[str]
) -> Dict[str, List[str]]:
    """Pinned versions with no matching tag, keyed by version.

    Tags are compared on one spelling. `git tag` prints `v3.3.0` and a pin
    carries the bare `3.3.0`; comparing raw strings would report every pin
    dangling, which reads as a catastrophe and gets the check switched off.
    """
    have = {tag.strip().lstrip("vV") for tag in tags if tag.strip()}
    return {version: locs for version, locs in pins.items() if version not in have}


def _concluded_unsuccessfully(run: Dict) -> bool:
    status = (run.get("status") or "").strip()
    conclusion = (run.get("conclusion") or "").strip()
    if status in IN_FLIGHT or not status:
        return False
    # A concluded run with no conclusion is not a success. Reading a blank as
    # "fine" is the absent-signal-as-verdict failure this whole workstream
    # exists to remove.
    return conclusion != "success"


def _in_flight(runs: Sequence[Dict]) -> Optional[Dict]:
    for run in runs:
        if (run.get("status") or "").strip() in IN_FLIGHT:
            return run
    return None


def _describe(run: Dict) -> str:
    return "{} ({}/{})".format(
        run.get("url") or "run {}".format(run.get("databaseId") or "?"),
        run.get("status") or "?",
        run.get("conclusion") or "no conclusion",
    )


def classify(
    dangling: Dict[str, List[str]],
    ci_runs: Sequence[Dict],
    cd_runs: Sequence[Dict],
    tip: str = "",
) -> Verdict:
    """Decide whether anything is still going to cut the missing tag.

    Order is load-bearing. In-flight beats concluded, because re-running a
    failed CI leaves the failed attempt visible alongside the new one: checking
    conclusions first would call a handoff abandoned at the exact moment someone
    is discharging it.
    """
    if not dangling:
        return Verdict(RESOLVED, {})

    short = tip[:12] if tip else "main's tip"

    running = _in_flight(cd_runs)
    if running is not None:
        return Verdict(PENDING, dangling, tip, reason=(
            "a CD run for {} is still in flight — it is the run that would cut "
            "the tag: {}".format(short, _describe(running))
        ))

    running = _in_flight(ci_runs)
    if running is not None:
        return Verdict(PENDING, dangling, tip, reason=(
            "CI for {} has not finished; CD starts on its completion: {}".format(
                short, _describe(running)
            )
        ))

    if cd_runs:
        # CD fires on CI completing. Once CD for this commit has concluded and
        # the tag still does not exist, no further run will fire for it — the
        # trigger is spent. Whether that run failed or "succeeded" while
        # declining to tag makes no difference to the state main is left in.
        return Verdict(ABANDONED, dangling, tip, reason=(
            "CD for {} has already concluded and no tag was cut: {}. Nothing "
            "further will fire for this commit — CD is triggered by CI "
            "completing, and that trigger is spent.".format(
                short, _describe(cd_runs[0])
            )
        ), remedy=(
            "Land a commit on main — merging an open `chore/release-v*` pull "
            "request counts — so a fresh CI/CD pass re-derives the bump over "
            "the full history, or cut the tag by hand from {}.".format(short)
        ))

    if ci_runs:
        # The NEWEST run only, never "any run that failed". A re-run that went
        # green leaves the failed attempt in the listing, and judging on that
        # one would report a handoff abandoned after it had been discharged —
        # the same mistake as reading conclusions before status above, one step
        # further along.
        newest = ci_runs[0]
        if _concluded_unsuccessfully(newest):
            return Verdict(ABANDONED, dangling, tip, reason=(
                "CI for {} did not succeed, so CD's gate "
                "(`if: conclusion == 'success'`) skipped every job and no run "
                "will cut the tag: {}".format(short, _describe(newest))
            ), remedy=(
                "Re-run it: gh run rerun {} --failed".format(
                    newest.get("databaseId") or "<run-id>"
                )
            ))
        return Verdict(PENDING, dangling, tip, reason=(
            "CI for {} succeeded and the CD run it triggers has not been "
            "observed yet".format(short)
        ))

    # No run for the tip at all. A commit that merged seconds ago looks exactly
    # like this, so it is not evidence of abandonment — but it is also how a
    # workflow refused at startup looks, which is why the scheduled sweep in
    # release-drift.yml asks again later rather than this call deciding alone.
    return Verdict(PENDING, dangling, tip, reason=(
        "no CI run for {} has been observed yet".format(short)
    ))


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


def read_pins(inv) -> Dict[str, List[str]]:
    """Every cicd version pin in an active surface, keyed by version.

    Scope comes from the defended inventory for the same reason every other
    consumer takes it from there: a second hand-maintained list of "files we
    manage" is what froze .github/workflows/ at v0.2.0 while everything else
    moved on.
    """
    pins: Dict[str, List[str]] = {}
    for rel in inv.active_surfaces:
        path = inv.root / rel
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for version in VERSION_SCAN.findall(line):
                pins.setdefault(version, []).append("{}:{}".format(rel, lineno))
    return pins


def refetch_tags(runner: Runner) -> None:
    """Pull tags from the remote, tolerating failure.

    Called only on the way to an `abandoned` verdict. Between reading the tag
    list and finishing the run queries, the very tag being looked for can be
    pushed — the window is seconds wide and it is the one false positive this
    check would produce on the ordinary release path, where CD tags v3.3.0
    while this is still asking whether anyone is going to. A failed fetch does
    not change the verdict: the evidence for abandonment was already gathered,
    and degrading to "clean" because the network blinked is the inversion this
    module exists to prevent.
    """
    runner(["git", "fetch", "--tags", "--quiet", "origin"])


def read_tags(runner: Runner) -> List[str]:
    # A shallow or tagless checkout makes every pin look dangling, which would
    # turn a hygiene check into a false catastrophe. Refuse rather than report
    # a break that is an artefact of how the repository was fetched.
    if _run(runner, ["git", "rev-parse", "--is-shallow-repository"]) == "true":
        raise ToolError(
            "shallow clone: no tags are reachable, so every pin would read as "
            "dangling. Check out with fetch-depth: 0."
        )
    raw = _run(runner, ["git", "tag", "--list", "v*"])
    tags = [line.strip() for line in raw.splitlines() if line.strip()]
    if not tags:
        raise ToolError(
            "this checkout has no v* tags at all; refusing to report every pin "
            "as dangling on that basis"
        )
    return tags


def read_tip(runner: Runner) -> str:
    return _run(runner, ["git", "rev-parse", "HEAD"])


def runs_for(
    runner: Runner, workflow: str, sha: str, exclude_run_id: str = "", limit: int = 50
) -> List[Dict]:
    """Runs of one workflow against one commit, newest first.

    Filtered on `headSha` here rather than with `gh run list --commit` so the
    answer does not depend on the runner's `gh` being new enough to carry that
    flag — a missing flag would be an error, and an error on this path is a
    verdict this check must not reach by accident.
    """
    raw = _run(
        runner,
        [
            "gh", "run", "list", "--workflow", workflow, "--branch", "main",
            "--limit", str(limit),
            "--json", "headSha,status,conclusion,databaseId,url",
        ],
    )
    try:
        runs = json.loads(raw) if raw else []
    except json.JSONDecodeError as exc:
        raise ToolError("gh run list printed unreadable JSON: {}".format(exc))
    if not isinstance(runs, list):
        raise ToolError(
            "gh run list printed {}, expected a list".format(type(runs).__name__)
        )
    return [
        run
        for run in runs
        if run.get("headSha") == sha
        and str(run.get("databaseId") or "") != str(exclude_run_id)
    ]


def check(
    inv,
    runner: Runner,
    exclude_run_id: str = "",
    ci_workflow: str = "ci.yml",
    cd_workflow: str = "cd.yml",
) -> Verdict:
    """Measure and decide. Raises ToolError; never degrades to a pass."""
    dangling = unresolved_pins(read_pins(inv), read_tags(runner))
    if not dangling:
        return Verdict(RESOLVED, {})
    tip = read_tip(runner)
    ci_runs = runs_for(runner, ci_workflow, tip, exclude_run_id)
    cd_runs = runs_for(runner, cd_workflow, tip, exclude_run_id)
    verdict = classify(dangling, ci_runs, cd_runs, tip)
    if verdict.state != ABANDONED:
        return verdict

    # Last look before the loud answer. See refetch_tags.
    refetch_tags(runner)
    still = unresolved_pins(read_pins(inv), read_tags(runner))
    if not still:
        return Verdict(RESOLVED, {})
    return classify(still, ci_runs, cd_runs, tip)
