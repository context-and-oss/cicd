"""Regression proof for scripts/release_gate.py.

These fixtures use invented timestamps, ruleset names and IDs, not captured
repository state. They model a missing required-check rule and a check that
passes only after a merge. A green check alone cannot establish that a merge
was gated: only the ordering separates a prior gate from a later check.
The tests cover that ordering and the cases where the evidence is unreadable.

`scripts/tests/test_deliver_release_pins.py` drives the same logic through the
real delivery script with a stubbed `gh`; these are the direct unit tests, so a
branch that script cannot reach is still covered.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from release_gate import (  # noqa: E402
    REQUIRED_CONTEXT,
    Gate,
    current_user_bypasses,
    merge_was_gated,
    read_gate,
    read_review_gate,
)

CLI = REPO_ROOT / "scripts" / "check-release-gate.py"

# Invented effective-rule fixture: three rules, none a required status check,
# in the API's array shape. IDs below are fixture values.
UNGATED = [
    {
        "type": "pull_request",
        "parameters": {"required_approving_review_count": 0},
        "ruleset_source_type": "Enterprise",
        "ruleset_id": 1001,
    },
    {"type": "non_fast_forward", "ruleset_source_type": "Enterprise"},
    {"type": "deletion", "ruleset_source_type": "Enterprise"},
]

# Invented required-check rule with strict policy enabled.
GATED = UNGATED + [
    {
        "type": "required_status_checks",
        "parameters": {
            "do_not_enforce_on_create": False,
            "required_status_checks": [{"context": "ci"}],
            "strict_required_status_checks_policy": True,
        },
        "ruleset_source_type": "Organization",
        "ruleset_id": 1002,
    },
]

# Invented review-rule fixture requiring one approval. Rulesets match the
# target branch, so release pull requests are subject to them too. Bypass
# permission and human approval are separate; the preflight checks the former.
REVIEW_RULESET_ID = 1003
REVIEWED = GATED + [
    {
        "type": "pull_request",
        "parameters": {"required_approving_review_count": 1},
        "ruleset_source_type": "Organization",
        "ruleset_id": REVIEW_RULESET_ID,
    },
]


def ruleset(can_bypass="always", source="Organization"):
    """A `GET /repos/{owner}/{repo}/rulesets/{id}` body. `can_bypass=None`
    leaves `current_user_can_bypass` out, as the org endpoint does."""
    body = {"id": REVIEW_RULESET_ID, "name": "fixture-review-rule", "source_type": source}
    if can_bypass is not None:
        body["current_user_can_bypass"] = can_bypass
    return body


class TestReadGate(unittest.TestCase):
    def test_the_required_check_fixture_is_read_as_gating(self):
        self.assertEqual(read_gate(GATED), Gate(True, True, ("ci",)))

    def test_the_ungated_fixture_is_read_as_ungated(self):
        """Three rules, a required pull request among them, and nothing that makes
        any check matter. A `pull_request` rule reads like protection and is not
        the same question."""
        gate = read_gate(UNGATED)
        self.assertFalse(gate.required)
        self.assertEqual(gate.contexts, ())

    def test_an_empty_rule_list_is_ungated(self):
        self.assertEqual(read_gate([]), Gate(False, False, ()))

    def test_another_required_check_does_not_stand_in_for_ci(self):
        """A renamed or unrelated context is the plausible near miss, and the one
        that would be easiest to mistake for coverage."""
        rules = [{
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [
                {"context": "lint-repo"}, {"context": "module-test"},
            ]},
        }]
        gate = read_gate(rules)
        self.assertFalse(gate.required)
        self.assertEqual(gate.contexts, ("lint-repo", "module-test"))

    def test_the_strict_policy_is_reported_separately(self):
        rules = [{
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [{"context": "ci"}],
                "strict_required_status_checks_policy": False,
            },
        }]
        self.assertEqual(read_gate(rules), Gate(True, False, ("ci",)))

    def test_a_rule_from_any_ruleset_level_counts(self):
        """The endpoint returns effective rules across Enterprise, org and repo
        rulesets. Which level carries the check is not the pipeline's business."""
        for level in ("Enterprise", "Organization", "Repository"):
            with self.subTest(level=level):
                rules = [{
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": "ci"}]},
                    "ruleset_source_type": level,
                }]
                self.assertTrue(read_gate(rules).required)

    def test_a_body_that_is_not_a_rule_list_raises(self):
        """Unreadable is not the same answer as ungated: one is a fact about the
        branch, the other a fact about the question, and they exit differently."""
        for body in ({"message": "Not Found"}, None, "rules", 7):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    read_gate(body)

    def test_junk_entries_are_skipped_rather_than_crashing(self):
        rules = [None, "x", {"type": "required_status_checks"}, {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [None, {}, {"context": "ci"}]},
        }]
        self.assertTrue(read_gate(rules).required)

    def test_the_context_is_the_ci_aggregate_job(self):
        self.assertEqual(REQUIRED_CONTEXT, "ci")


class TestReadReviewGate(unittest.TestCase):
    def test_a_zero_count_rule_requires_nothing(self):
        review = read_review_gate(GATED)
        self.assertEqual(review.required_approvals, 0)
        self.assertEqual(review.rulesets, ())

    def test_a_review_rule_names_its_ruleset(self):
        review = read_review_gate(REVIEWED)
        self.assertEqual(review.required_approvals, 1)
        self.assertEqual(
            [(r.id, r.source) for r in review.rulesets],
            [(REVIEW_RULESET_ID, "Organization")],
        )

    def test_the_strictest_rule_wins_and_every_requiring_ruleset_is_listed(self):
        rules = REVIEWED + [
            {
                "type": "pull_request",
                "parameters": {"required_approving_review_count": 2},
                "ruleset_source_type": "Repository",
                "ruleset_id": 7,
            }
        ]
        review = read_review_gate(rules)
        self.assertEqual(review.required_approvals, 2)
        self.assertEqual([r.id for r in review.rulesets], [REVIEW_RULESET_ID, 7])

    def test_a_body_that_is_not_a_rule_list_raises(self):
        with self.assertRaises(ValueError):
            read_review_gate({"message": "Not Found"})

    def test_junk_entries_are_skipped(self):
        rules = [None, "x", {"type": "pull_request"}, {"type": "pull_request", "parameters": []}]
        self.assertEqual(read_review_gate(rules).required_approvals, 0)


class TestCurrentUserBypasses(unittest.TestCase):
    def test_always_passes(self):
        self.assertTrue(current_user_bypasses(ruleset("always")).bypasses)

    def test_pull_requests_only_suffices_because_a_release_lands_by_pull_request(self):
        self.assertTrue(current_user_bypasses(ruleset("pull_requests_only")).bypasses)

    def test_exempt_passes(self):
        self.assertTrue(current_user_bypasses(ruleset("exempt")).bypasses)

    def test_never_refuses_and_says_so(self):
        verdict = current_user_bypasses(ruleset("never"))
        self.assertFalse(verdict.bypasses)
        self.assertIn("'never'", verdict.reason)

    def test_an_absent_answer_raises_rather_than_refusing(self):
        """The org endpoint omits `current_user_can_bypass`. That is a question
        unanswered, which is exit 2, never 1."""
        with self.assertRaises(ValueError):
            current_user_bypasses(ruleset(None))

    def test_an_unknown_answer_raises_rather_than_guessing(self):
        with self.assertRaises(ValueError):
            current_user_bypasses(ruleset("sometimes"))

    def test_a_body_that_is_not_a_ruleset_raises(self):
        with self.assertRaises(ValueError):
            current_user_bypasses([])


def run(name="ci", status="completed", conclusion="success", started=None, completed=None):
    return {
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": completed,
    }


def doc(*runs, total=None):
    return {"total_count": len(runs) if total is None else total, "check_runs": list(runs)}


# All timestamps in this suite are invented ordering examples.
MERGED = "2040-02-10T14:35:10Z"


class TestMergeWasGated(unittest.TestCase):
    def test_the_ungated_merge_fixture_is_refused(self):
        """A synthetic check starts after the merge and later passes."""
        verdict = merge_was_gated(
            doc(run(started="2040-02-10T14:49:20Z", completed="2040-02-10T14:49:27Z")),
            MERGED,
        )
        self.assertFalse(verdict.gated)
        self.assertIn("14:49:20", verdict.reason)

    def test_a_check_completed_before_the_merge_is_accepted(self):
        verdict = merge_was_gated(
            doc(run(started="2040-02-10T14:00:00Z", completed="2040-02-10T14:25:00Z")),
            MERGED,
        )
        self.assertTrue(verdict.gated, verdict.reason)

    def test_completing_in_the_same_second_as_the_merge_is_accepted(self):
        """The boundary is inclusive: a merge triggered *by* the check passing can
        share its timestamp, and that is the intended path, not a suspicious one."""
        self.assertTrue(merge_was_gated(doc(run(completed=MERGED)), MERGED).gated)

    def test_a_failed_check_before_the_merge_is_refused(self):
        verdict = merge_was_gated(
            doc(run(conclusion="failure", completed="2040-02-10T14:25:00Z")), MERGED
        )
        self.assertFalse(verdict.gated)
        self.assertIn("failure", verdict.reason)

    def test_a_still_running_check_is_refused(self):
        verdict = merge_was_gated(
            doc(run(status="in_progress", conclusion=None, started="2040-02-10T14:25:00Z")),
            MERGED,
        )
        self.assertFalse(verdict.gated)
        self.assertIn("not yet", verdict.reason)

    def test_no_check_of_that_name_is_refused(self):
        verdict = merge_was_gated(
            doc(run(name="lint-repo", completed="2040-02-10T14:00:00Z")), MERGED
        )
        self.assertFalse(verdict.gated)
        self.assertIn("no check run named 'ci'", verdict.reason)

    def test_no_checks_at_all_is_refused(self):
        self.assertFalse(merge_was_gated(doc(), MERGED).gated)

    def test_the_latest_run_before_the_merge_decides(self):
        """GitHub's own semantics: a re-run supersedes. An earlier cancelled run
        must not condemn a commit whose re-run passed, and an earlier success must
        not rescue one whose re-run failed."""
        cancelled_then_green = doc(
            run(conclusion="cancelled", completed="2040-02-10T14:00:00Z"),
            run(conclusion="success", completed="2040-02-10T14:25:00Z"),
        )
        self.assertTrue(merge_was_gated(cancelled_then_green, MERGED).gated)

        green_then_failed = doc(
            run(conclusion="success", completed="2040-02-10T14:00:00Z"),
            run(conclusion="failure", completed="2040-02-10T14:25:00Z"),
        )
        self.assertFalse(merge_was_gated(green_then_failed, MERGED).gated)

    def test_a_run_that_completed_after_the_merge_is_ignored_not_credited(self):
        """A green run after the merge cannot vouch for it at any array position."""
        for order in (
            [run(completed="2040-02-10T14:25:00Z"), run(completed="2040-02-10T15:10:00Z")],
            [run(completed="2040-02-10T15:10:00Z"), run(completed="2040-02-10T14:25:00Z")],
        ):
            with self.subTest(order=[r["completed_at"] for r in order]):
                self.assertTrue(merge_was_gated(doc(*order), MERGED).gated)
        after_only = doc(run(completed="2040-02-10T15:10:00Z"))
        self.assertFalse(merge_was_gated(after_only, MERGED).gated)

    def test_a_truncated_page_raises_rather_than_passing(self):
        """GitHub states how many check runs exist. Fewer returned than exist means
        the deciding one may be the one that was not read."""
        with self.assertRaises(ValueError):
            merge_was_gated(doc(run(completed="2040-02-10T14:00:00Z"), total=140), MERGED)

    def test_a_body_that_is_not_a_check_runs_payload_raises(self):
        for body in ({"message": "Not Found"}, [], None):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    merge_was_gated(body, MERGED)

    def test_an_unreadable_merge_timestamp_raises(self):
        for stamp in ("", None, "yesterday"):
            with self.subTest(stamp=stamp):
                with self.assertRaises(ValueError):
                    merge_was_gated(doc(run(completed="2040-02-10T14:00:00Z")), stamp)

    def test_an_offset_timestamp_is_compared_correctly(self):
        """GitHub sends `Z`, but an offset form must not reorder events. Both
        stamps below are picked so that a *string* comparison gets it wrong:
        16:25+02:00 is 14:25Z, before the merge, yet sorts after it as text; and
        14:00-02:00 is 16:00Z, after the merge, yet sorts before it."""
        early = merge_was_gated(doc(run(completed="2040-02-10T16:25:00+02:00")), MERGED)
        self.assertTrue(early.gated, early.reason)
        late = merge_was_gated(doc(run(completed="2040-02-10T14:00:00-02:00")), MERGED)
        self.assertFalse(late.gated, late.reason)

    def test_an_unreadable_check_timestamp_cannot_vouch_for_the_commit(self):
        verdict = merge_was_gated(doc(run(completed="whenever")), MERGED)
        self.assertFalse(verdict.gated)


GH_STUB = r"""#!/usr/bin/env bash
[ -z "${STUB_LOG:-}" ] || printf '%s\n' "$2" >> "$STUB_LOG"
case "$2" in
  *rules/branches*) printf '%s\n' "$STUB_RULES" ;;
  *check-runs*) printf '%s\n' "$STUB_CHECK_RUNS" ;;
  */rulesets/*)
    [ "${STUB_RULESET_RC:-0}" = "0" ] || { printf 'gh: Not Found (HTTP 404)\n' >&2; exit 1; }
    printf '%s\n' "$STUB_RULESET" ;;
  *) printf '%s\n' "$STUB_PR" ;;
esac
[ "${STUB_GH_RC:-0}" = "0" ] || { printf 'gh: Not Found (HTTP 404)\n' >&2; exit 1; }
exit 0
"""


class TestCLI(unittest.TestCase):
    """The three exit codes, which are the whole interface: 0 the claim holds, 1
    it is false, 2 the question could not be put. 2 is not a pass."""

    def cli(self, *args, **stubs):
        tmp = pathlib.Path(tempfile.mkdtemp())
        gh = tmp / "gh"
        gh.write_text(GH_STUB)
        gh.chmod(0o755)
        env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}")
        env.setdefault("STUB_RULES", json.dumps(GATED))
        env.setdefault("STUB_PR", "{}")
        env.setdefault("STUB_CHECK_RUNS", "{}")
        env.setdefault("STUB_RULESET", json.dumps(ruleset("always")))
        self.last_log = tmp / "calls"
        env["STUB_LOG"] = str(self.last_log)
        for key, value in stubs.items():
            env["STUB_" + key.upper()] = value
        return subprocess.run(
            [sys.executable, str(CLI), *args], capture_output=True, text=True, env=env
        )

    def test_a_gated_branch_exits_zero(self):
        proc = self.cli("--branch", "main", rules=json.dumps(GATED))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_an_ungated_branch_exits_one(self):
        proc = self.cli("--branch", "main", rules=json.dumps(UNGATED))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("not a required status check", proc.stderr)

    def test_a_zero_approval_branch_asks_nothing_more(self):
        proc = self.cli("--branch", "main", rules=json.dumps(GATED))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no pull_request rule", proc.stdout)

    def test_a_reviewed_branch_with_a_bypassing_release_identity_exits_zero(self):
        proc = self.cli("--branch", "main", rules=json.dumps(REVIEWED))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"ruleset {REVIEW_RULESET_ID} requires 1 approval", proc.stdout)

    def test_the_ruleset_is_asked_at_the_repository_endpoint_not_the_org_one(self):
        """The org endpoint needs administration write on the organisation and
        does not answer current_user_can_bypass; the repository one needs
        metadata read and does. An org-level rule must still be asked there."""
        proc = self.cli("--branch", "main", rules=json.dumps(REVIEWED))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = self.last_log.read_text().splitlines()
        self.assertIn(f"repos/{{owner}}/{{repo}}/rulesets/{REVIEW_RULESET_ID}", log)
        self.assertFalse([c for c in log if c.startswith("orgs/")], log)

    def test_a_reviewed_branch_with_no_bypass_exits_one_naming_the_ruleset(self):
        proc = self.cli("--branch", "main", rules=json.dumps(REVIEWED), ruleset=json.dumps(ruleset("never")))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn(f"ruleset {REVIEW_RULESET_ID}", proc.stderr)
        self.assertIn("REVIEW_REQUIRED", proc.stderr)

    def test_an_enterprise_review_rule_is_answered_like_any_other(self):
        """The repository endpoint serves enterprise rulesets as parents, so a
        rule from one is no longer refused for want of an endpoint."""
        rules = GATED + [
            {
                "type": "pull_request",
                "parameters": {"required_approving_review_count": 1},
                "ruleset_source_type": "Enterprise",
                "ruleset_id": 1001,
            }
        ]
        bypassing = self.cli("--branch", "main", rules=json.dumps(rules),
                             ruleset=json.dumps(ruleset("always", source="Enterprise")))
        self.assertEqual(bypassing.returncode, 0, bypassing.stderr)
        held = self.cli("--branch", "main", rules=json.dumps(rules),
                        ruleset=json.dumps(ruleset("never", source="Enterprise")))
        self.assertEqual(held.returncode, 1, held.stdout)
        self.assertIn("Enterprise level", held.stderr)

    def test_a_ruleset_fetch_failure_exits_two(self):
        proc = self.cli("--branch", "main", rules=json.dumps(REVIEWED), ruleset_rc="1")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("must never read as clean", proc.stderr)

    def test_a_ruleset_without_a_bypass_answer_exits_two(self):
        proc = self.cli(
            "--branch", "main", rules=json.dumps(REVIEWED),
            ruleset=json.dumps(ruleset(None)),
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("current_user_can_bypass", proc.stderr)
        self.assertNotIn("administration", proc.stderr)

    def test_a_gh_failure_exits_two(self):
        proc = self.cli("--branch", "main", gh_rc="1")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("must never read as clean", proc.stderr)

    def test_a_non_json_answer_exits_two(self):
        proc = self.cli("--branch", "main", rules="<html>sign in</html>")
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_an_armed_pull_request_exits_zero(self):
        proc = self.cli("--delivered-pr", "17", pr=json.dumps({
            "state": "OPEN", "mergedAt": None,
            "autoMergeRequest": {"enabledAt": "2040-02-11T09:15:00Z"},
            "headRefOid": "a" * 40,
        }))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_an_unarmed_open_pull_request_exits_one(self):
        proc = self.cli("--delivered-pr", "17", pr=json.dumps({
            "state": "OPEN", "mergedAt": None, "autoMergeRequest": None,
            "headRefOid": "a" * 40,
        }))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("NOT armed", proc.stderr)

    def test_an_ungated_immediate_merge_exits_one(self):
        proc = self.cli(
            "--delivered-pr", "12",
            pr=json.dumps({
                "state": "MERGED", "mergedAt": MERGED,
                "autoMergeRequest": None, "headRefOid": "b" * 40,
            }),
            check_runs=json.dumps(doc(run(
                started="2040-02-10T14:49:20Z", completed="2040-02-10T14:49:27Z",
            ))),
        )
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("was not gated", proc.stderr)

    def test_a_closed_pull_request_exits_one(self):
        proc = self.cli("--delivered-pr", "17", pr=json.dumps({
            "state": "CLOSED", "mergedAt": None, "autoMergeRequest": None,
            "headRefOid": "a" * 40,
        }))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("neither", proc.stderr)

    def test_a_credential_in_a_gh_error_is_redacted(self):
        proc = self.cli(
            "--branch", "main", gh_rc="1",
            rules="fatal: unable to access "
                  "'https://x-access-token:ghp_notarealtoken@github.com/x/y.git/'",
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("ghp_notarealtoken", proc.stdout + proc.stderr)

    def test_a_mode_is_required(self):
        self.assertEqual(self.cli().returncode, 2)


if __name__ == "__main__":
    unittest.main()
