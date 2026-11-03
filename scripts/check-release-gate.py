#!/usr/bin/env python3
"""Ask GitHub whether the release path's own claim about `ci` is true.

Two modes, called by `scripts/ci/deliver-release-pins.sh` at the two moments the
question can still be answered. The logic is in `scripts/release_gate.py`; this
file fetches, prints and exits.

    check-release-gate.py --branch main
        Preflight, before anything is written. Fails unless a
        `required_status_checks` rule on the branch actually names the context,
        and, when a `pull_request` rule requires approvals, unless the release
        identity may bypass every ruleset that asks for one.

    check-release-gate.py --delivered-pr 17
        Readback, after `gh pr merge --auto --merge`. Fails unless the request is
        open with auto-merge genuinely armed, or merged with the context already
        concluded success on its head commit *before* it merged.

Exit codes, and the difference between them is the point:
    0  the claim holds
    1  the claim is false — the branch is ungated, or the merge was not gated
    2  the question could not be put to GitHub at all

2 is not a pass. A release delivered while this check was unable to look has
no verified gate; see the module docstring in scripts/release_gate.py.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from release_gate import (  # noqa: E402
    REQUIRED_CONTEXT,
    Bypass,
    RulesetRef,
    current_user_bypasses,
    merge_was_gated,
    read_gate,
    read_review_gate,
)

# A push remote may carry `https://x-access-token:<PAT>@github.com/...`, and gh
# quotes what it was given back at you on failure. The shell script redacts its
# push log for the same reason; this is the same belt for one regex.
_CREDENTIAL = re.compile(r"(x-access-token:)[^@]*@")


def _redact(text: str) -> str:
    return _CREDENTIAL.sub(r"\1***@", text or "").strip()


class Unanswerable(Exception):
    """GitHub could not be asked, or answered something unreadable — exit 2."""


def _gh_json(args: list[str]) -> object:
    proc = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise Unanswerable(
            f"`gh {' '.join(args)}` failed: "
            f"{_redact(proc.stderr) or _redact(proc.stdout) or 'no output'}"
        )
    try:
        return json.loads(proc.stdout or "")
    except json.JSONDecodeError as err:
        raise Unanswerable(
            f"`gh {' '.join(args)}` returned something that is not JSON ({err}): "
            f"{_redact(proc.stdout)[:400]}"
        ) from err


def check_branch(branch: str, context: str) -> int:
    """Is `context` a required status check on `branch`?"""
    rules = _gh_json(["api", f"repos/{{owner}}/{{repo}}/rules/branches/{branch}"])
    try:
        gate = read_gate(rules, context)
    except ValueError as err:
        raise Unanswerable(f"could not read the branch rules for {branch}: {err}")

    if not gate.required:
        listed = ", ".join(gate.contexts) if gate.contexts else "none at all"
        print(
            f"::error::the check named '{context}' is not a required status check "
            f"on {branch}, so merging a release pull request proves nothing and "
            f"no tag cut from {branch} is gated by anything. Required contexts "
            f"GitHub reports: {listed}. Restore the 'required_status_checks' rule "
            f"(context '{context}', strict policy on) to an applicable branch "
            "ruleset. Nothing was pushed.",
            file=sys.stderr,
        )
        return 1

    if not gate.strict:
        # Not fatal, but named: without it a superseded lower-version release
        # branch can still merge later and walk every pin backwards. The
        # supersede cleanup in deliver-release-pins.sh is the real defence and
        # its comment assumes this is on, so say so when it is not.
        print(
            f"::warning::'{context}' is required on {branch} but the strict "
            "policy (branch must be up to date) is off, so a stale release "
            "branch could still merge and downgrade every pin. The supersede "
            "cleanup closes those, but it is now the only thing that does."
        )

    print(f"gate: '{context}' is a required status check on {branch}.")

    # Auto-merge does not supply a human approval. This preflight requires
    # bypass permission on every applicable review rule; that permission is
    # not evidence of a review or proof that auto-merge will complete.
    review = read_review_gate(rules)
    if review.required_approvals == 0:
        print(f"gate: no pull_request rule on {branch} requires an approval.")
        return 0
    if not review.rulesets:
        raise Unanswerable(
            f"a pull_request rule on {branch} requires "
            f"{review.required_approvals} approval(s) but names no ruleset_id, so "
            "it cannot be asked whether the release identity may bypass it"
        )
    for ref in review.rulesets:
        verdict = _review_bypass(ref)
        if not verdict.bypasses:
            print(
                f"::error::a pull_request rule on {branch} requires "
                f"{review.required_approvals} approval(s) (ruleset {ref.id}, "
                f"{ref.source or 'unknown'} level) and the release identity "
                f"cannot bypass it: {verdict.reason}. A release pull request "
                "would remain REVIEW_REQUIRED until the review policy is "
                "satisfied; arming auto-merge supplies no approval. This "
                "preflight requires bypass permission on each applicable "
                "review ruleset. Verify the release identity and destination "
                "review policy without weakening required protections. "
                "Nothing was pushed.",
                file=sys.stderr,
            )
            return 1
        print(
            f"gate: ruleset {ref.id} requires {review.required_approvals} "
            f"approval(s); the release identity bypasses it — {verdict.reason}."
        )
    return 0


def _review_bypass(ref: RulesetRef) -> Bypass:
    """Ask GitHub whether the release identity may bypass one ruleset.

    The repository endpoint serves org and enterprise rulesets as parents and
    says `current_user_can_bypass` for each with metadata read alone, so every
    source is asked the same way. The org endpoint would need administration
    write on the organisation, and no enterprise endpoint is open to a
    repository credential at all.
    """
    ruleset = _gh_json(["api", f"repos/{{owner}}/{{repo}}/rulesets/{ref.id}"])
    try:
        return current_user_bypasses(ruleset)
    except ValueError as err:
        raise Unanswerable(f"could not read ruleset {ref.id}: {err}")


def check_delivered_pr(number: str, context: str) -> int:
    """Did the merge command leave a state that proves the claim in the body?"""
    pr = _gh_json(
        [
            "pr",
            "view",
            number,
            "--json",
            "state,mergedAt,autoMergeRequest,headRefOid,reviewDecision",
        ]
    )
    if not isinstance(pr, dict):
        raise Unanswerable(f"pull request #{number} did not describe itself as an object")

    state = str(pr.get("state") or "").upper()
    armed = pr.get("autoMergeRequest") is not None
    head = str(pr.get("headRefOid") or "")
    merged_at = str(pr.get("mergedAt") or "")
    # Diagnostic only: bypass permission is not a human approval, and an
    # armed auto-merge request still waits for applicable requirements.
    decision = str(pr.get("reviewDecision") or "none")

    if state == "OPEN":
        if armed:
            print(
                f"gate: pull request #{number} is open with auto-merge armed "
                f"(review decision: {decision}); merging still requires "
                f"'{context}' and all other applicable requirements to be satisfied."
            )
            return 0
        print(
            f"::error::pull request #{number} is open and auto-merge is NOT armed, "
            "even though the merge command exited 0. It will sit open forever and "
            "no tag will ever be cut — silently, which is the failure mode the "
            "pull-request delivery exists to remove. Check that the repository "
            "allows auto-merge and that the release credential may use it.",
            file=sys.stderr,
        )
        return 1

    if state != "MERGED":
        print(
            f"::error::pull request #{number} is {state or 'in an unknown state'} "
            "after the merge command exited 0 — it was neither armed for "
            "auto-merge nor merged, so the release was not delivered.",
            file=sys.stderr,
        )
        return 1

    # Merged on the spot. `gh pr merge --auto` can merge an already-mergeable
    # request immediately, so verify that the commit was already green.
    if not head:
        raise Unanswerable(
            f"pull request #{number} merged but reported no head commit, so the "
            "checks on it cannot be located"
        )
    doc = _gh_json(
        [
            "api",
            f"repos/{{owner}}/{{repo}}/commits/{head}/check-runs?per_page=100",
        ]
    )
    try:
        verdict = merge_was_gated(doc, merged_at, context)
    except ValueError as err:
        raise Unanswerable(
            f"could not establish whether '{context}' passed on {head[:8]} before "
            f"the merge: {err}"
        )

    if not verdict.gated:
        print(
            f"::error::pull request #{number} merged immediately rather than "
            f"waiting for '{context}', and the merge was not gated: "
            f"{verdict.reason}. The pins are on the branch, so this release must "
            "be treated as unreviewed and ungated. Restore the "
            f"'required_status_checks' rule (context '{context}') to an "
            "applicable branch ruleset.",
            file=sys.stderr,
        )
        return 1

    print(
        f"gate: pull request #{number} merged immediately, and legitimately — "
        f"{verdict.reason}."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--branch", help="assert the context gates this branch")
    mode.add_argument(
        "--delivered-pr",
        metavar="NUMBER",
        help="assert this pull request is armed for auto-merge, or merged gated",
    )
    parser.add_argument("--context", default=REQUIRED_CONTEXT)
    args = parser.parse_args(argv)

    try:
        if args.branch:
            return check_branch(args.branch, args.context)
        return check_delivered_pr(args.delivered_pr, args.context)
    except Unanswerable as err:
        print(
            f"::error::the release gate could not be verified: {err}. This is not "
            "a verdict that the gate is fine — a check that could not look must "
            "never read as clean. Branch preflight needs the release identity's "
            "repository contents and metadata read access. Delivered-PR "
            "verification needs a GitHub App token with Pull requests and Checks "
            "read; in Actions use GITHUB_TOKEN, not a fine-grained PAT, for "
            "that readback.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
