"""Whether the commit a release rides to main was actually gated.

A release pull request can merge without being gated if no effective
`required_status_checks` rule names `ci`. `gh pr merge --auto` can merge an
already-mergeable request immediately and exit successfully without arming
auto-merge. A check that starts after that merge can later make the commit look
green, but cannot establish that the merge was gated.

The ordering matters because a gate that was never consulted can otherwise
look like a gate that passed. Arming auto-merge also supplies no human approval;
review requirements and bypass permissions are separate from check ordering.

So the two claims are asked as questions, of GitHub, at the two moments they can
still be answered:

* `read_gate()` — before anything is written: does a `required_status_checks`
  rule on the branch actually name the context? A release cut from a branch
  nothing gates is not a release this pipeline may deliver.
* `merge_was_gated()` — after the merge command: if the request merged on the
  spot rather than arming auto-merge, did the context *conclude success on that
  commit before it merged*? Green-afterwards is the false pass above.

Both are pure functions over parsed JSON: no `gh`, no subprocess, no clock. The
CLI that fetches and exits is `scripts/check-release-gate.py`.
"""

from __future__ import annotations

import datetime
from typing import Any, NamedTuple

# The status context the release preflight requires, and the aggregate job in
# ci.yml that covers the selected validation suite. A new job is only covered
# once it is in the aggregate's dependency and result checks — see CLAUDE.md.
REQUIRED_CONTEXT = "ci"


class Gate(NamedTuple):
    """What GitHub reports as gating a branch."""

    required: bool
    """The context appears in a `required_status_checks` rule on the branch."""

    strict: bool
    """That rule also requires the branch to be up to date with the base."""

    contexts: tuple[str, ...]
    """Every required context, in the order GitHub listed them — the diagnostic.
    An empty tuple means no required status contexts were reported, even if
    other branch rules exist."""


def read_gate(rules: Any, context: str = REQUIRED_CONTEXT) -> Gate:
    """Read a `GET /repos/{o}/{r}/rules/branches/{branch}` response.

    The endpoint returns the *effective* rules — every ruleset that applies,
    flattened, whatever its level. Which applicable ruleset carries the
    required check is not the pipeline's business.

    Raises ValueError when the response is not that shape at all, because a body
    this cannot read is not evidence of an ungated branch — it is evidence of a
    question that went unanswered, and the two get different exit codes.
    """
    if not isinstance(rules, list):
        raise ValueError(
            "expected a JSON array of branch rules, got " + type(rules).__name__
        )
    contexts: list[str] = []
    strict = False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        params = rule.get("parameters") or {}
        if not isinstance(params, dict):
            continue
        for check in params.get("required_status_checks") or []:
            name = (check or {}).get("context") if isinstance(check, dict) else None
            if not name:
                continue
            contexts.append(name)
            if name == context and params.get("strict_required_status_checks_policy"):
                strict = True
    return Gate(
        required=context in contexts, strict=strict, contexts=tuple(contexts)
    )


class Verdict(NamedTuple):
    """Whether a merge that already happened was gated, and how we know."""

    gated: bool
    reason: str


def _instant(stamp: Any) -> datetime.datetime | None:
    """RFC 3339 → comparable, or None when it cannot be read.

    Both fields GitHub returns here are UTC and end in `Z`, which
    `fromisoformat` only accepts from Python 3.11. Normalising the suffix keeps
    this working on the older interpreter a contributor may have, and an
    unreadable stamp returns None rather than guessing — a timestamp that cannot
    be ordered cannot establish that anything happened *before* anything else.
    """
    text = str(stamp or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.datetime.fromisoformat(text)
    except ValueError:
        return None


def merge_was_gated(
    doc: Any, merged_at: str, context: str = REQUIRED_CONTEXT
) -> Verdict:
    """Did `context` conclude success on this commit *before* it merged?

    `doc` is a `GET /repos/{o}/{r}/commits/{sha}/check-runs` response. A green
    check earned after the merge cannot establish that the merge was gated.

    Selection follows GitHub's own rule semantics — the *latest* completed run
    with that name decides — so an earlier run cancelled by a concurrency group
    does not condemn a commit whose re-run passed.

    Raises ValueError when the response is not a check-runs payload.
    """
    if not isinstance(doc, dict):
        raise ValueError(
            "expected a check-runs object, got " + type(doc).__name__
        )
    runs = doc.get("check_runs")
    if not isinstance(runs, list):
        raise ValueError("response carries no check_runs array")

    total = doc.get("total_count")
    if isinstance(total, int) and total > len(runs):
        raise ValueError(
            f"GitHub reports {total} check runs on this commit but returned "
            f"{len(runs)}, so the answer is a page rather than the answer. A "
            "check run that could not be read must never be assumed green."
        )

    merged = _instant(merged_at)
    if merged is None:
        raise ValueError(f"unreadable merge timestamp {merged_at!r}")

    named = [r for r in runs if isinstance(r, dict) and r.get("name") == context]
    if not named:
        return Verdict(
            False,
            f"no check run named {context!r} exists on this commit at all, so "
            "nothing examined it before it merged",
        )

    completed: list[tuple[datetime.datetime, str]] = []
    for run in named:
        when = _instant(run.get("completed_at"))
        if run.get("status") != "completed" or when is None or when > merged:
            continue
        completed.append((when, str(run.get("conclusion") or "")))

    if not completed:
        # Include both timestamps so a check started after the merge cannot
        # be mistaken for one that gated it.
        stamps = sorted(
            "started {}, completed {}".format(
                r.get("started_at") or "?", r.get("completed_at") or "not yet"
            )
            for r in named
        )
        return Verdict(
            False,
            f"the {context!r} check run on this commit had not completed when "
            f"the commit merged at {merged_at} — {'; '.join(stamps)}. Green "
            "afterwards is not a gate; it is the same commit reading as gated "
            "once nobody is watching",
        )

    completed.sort(key=lambda item: item[0])
    when, conclusion = completed[-1]
    stamp = when.isoformat()
    if conclusion != "success":
        return Verdict(
            False,
            f"the last {context!r} check run to complete before the merge "
            f"(at {stamp}) concluded {conclusion or 'nothing'!r}",
        )
    return Verdict(
        True, f"{context!r} concluded success at {stamp}, before the merge at {merged_at}"
    )


class RulesetRef(NamedTuple):
    """One ruleset that carries a `pull_request` rule, by id and by the level
    GitHub says it lives at (`Repository`, `Organization`, `Enterprise`). The
    level decides which endpoint can show its bypass actors, and whether any
    endpoint can."""

    id: int
    source: str


class Review(NamedTuple):
    """Whether a `pull_request` rule on the branch requires human approval."""

    required_approvals: int
    """The largest `required_approving_review_count` across every applicable
    rule — rulesets stack, and the strictest one is the one a merge waits on."""

    rulesets: tuple[RulesetRef, ...]
    """Every ruleset whose rule asks for at least one approval. The release
    identity must be a bypass actor on each of them, not just one."""


def read_review_gate(rules: Any) -> Review:
    """Read the review half of the same `rules/branches/{branch}` response.

    The required-check rule says a merge waits on `ci`; a `pull_request` rule
    with a non-zero count says it also waits on a human. A release pull request
    is opened by an automated identity, and arming auto-merge does not supply
    an approval. This preflight asks whether the release identity has bypass
    permission on each review ruleset. That permission does not prove human
    review or that auto-merge will complete under the destination's policy.
    """
    if not isinstance(rules, list):
        raise ValueError(
            "expected a JSON array of branch rules, got " + type(rules).__name__
        )
    required = 0
    refs: list[RulesetRef] = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "pull_request":
            continue
        params = rule.get("parameters") or {}
        if not isinstance(params, dict):
            continue
        count = params.get("required_approving_review_count") or 0
        if not isinstance(count, int) or count <= 0:
            continue
        required = max(required, count)
        ruleset_id = rule.get("ruleset_id")
        if isinstance(ruleset_id, int):
            refs.append(RulesetRef(ruleset_id, str(rule.get("ruleset_source_type") or "")))
    return Review(required_approvals=required, rulesets=tuple(refs))


class Bypass(NamedTuple):
    """Whether one identity may merge past one ruleset's review rule, and why."""

    bypasses: bool
    reason: str


# What `current_user_can_bypass` may say. `pull_requests_only` lets the caller
# bypass by merging a pull request, which is the only way a release lands, and
# `exempt` means the ruleset's rules are not applied to the caller at all.
_BYPASSING = ("always", "pull_requests_only", "exempt")
_NOT_BYPASSING = ("never",)


def current_user_bypasses(ruleset: Any) -> Bypass:
    """Decide from a `GET /repos/{owner}/{repo}/rulesets/{id}` body whether the
    caller may merge past that ruleset.

    The repository endpoint answers the question directly in
    `current_user_can_bypass`, for repository rulesets and for the org and
    enterprise rulesets it returns as parents, with nothing beyond metadata
    read. Reading the `bypass_actors` list instead needs administration write
    on the organisation for an org ruleset and is impossible for an enterprise
    one, and even then a `Team` or `Integration` actor cannot be matched to a
    token. GitHub evaluates its own rule here, so this is the exact answer
    rather than a reconstruction of it.

    Raises ValueError when the body carries no recognised value: GitHub
    returns the property only from the repository endpoint, and an absent or
    unknown answer is a question that went unanswered, not a `never`.
    """
    if not isinstance(ruleset, dict):
        raise ValueError("expected a ruleset object, got " + type(ruleset).__name__)
    answer = ruleset.get("current_user_can_bypass")
    if answer in _BYPASSING:
        return Bypass(True, f"GitHub reports current_user_can_bypass '{answer}'")
    if answer in _NOT_BYPASSING:
        return Bypass(False, f"GitHub reports current_user_can_bypass '{answer}'")
    if answer is None:
        raise ValueError(
            "the ruleset body carries no current_user_can_bypass — GitHub "
            "returns it only from the repository-level rulesets endpoint"
        )
    raise ValueError(f"current_user_can_bypass is '{answer}', which this gate does not know")
