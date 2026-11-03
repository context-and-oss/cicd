"""Regression proof for scripts/ci/deliver-release-pins.sh.

A direct push to main cannot satisfy branch rules requiring both a pull
request and a check on the pushed commit when that commit has just been created.
These tests use scripted API responses, invented identities and timestamps,
not a destination's measured configuration or release history.

The first assertion below is therefore the blunt one: **this script must never
push to main.** The rest prove the delivery it does instead, including the parts
that fail silently if they regress:

* the branch is outside `refs/heads/release/**`, which can be covered by
  applicable branch rules that prevent creating it by push
* a credential that cannot reach the pull request API is refused *before* the
  branch is pushed, avoiding an orphaned release branch
* an already-open pull request is reused, never duplicated
* auto-merge is armed, so no runner sits idle waiting — and *proved* armed
  rather than assumed, because `gh pr merge --auto` merges an already-mergeable
  request on the spot and exits 0 either way. An armed request supplies no
  human approval and does not prove that every merge requirement is satisfied
* `ci` is confirmed to be a required status check on main *before* anything is
  written, since every claim below it — the pull request body, auto-merge, the
  trust the resulting tag inherits — rests on that being true
* a pull request authored by the Actions default token is refused, because one it
  creates triggers no workflow runs, so `ci` would never run and auto-merge would
  never fire — the request would sit open forever
* `git add -u` plus the artifact by name, never `git add -A`, which could sweep
  untracked build output into release commits
* a superseded run neither bumps nor tags, so a concurrent release cannot be
  downgraded
* pins already at the target report `released` so the caller tags — this is the
  seam a pull-request-delivered bump reaches on the next run, and the reason the
  tag is still cut by the pipeline rather than by hand

`git` and `gh` are stubs on PATH that log every invocation and answer from a
scripted scenario, and the repository is a temporary directory holding fake
bump/gate/artifact scripts. So these tests touch no repository, no remote and no
pull request, while driving the real script end to end.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import shutil
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "ci" / "deliver-release-pins.sh"
CLASSIFIER = REPO_ROOT / "scripts" / "ci" / "classify-push-rejection.sh"
# The real gate check and its logic module, copied into the temporary repository
# rather than stubbed: what it decides *is* the contract under test here.
GATE_CLI = REPO_ROOT / "scripts" / "check-release-gate.py"
GATE_LOGIC = REPO_ROOT / "scripts" / "release_gate.py"

GATED_RULES = json.dumps([
    {
        "type": "required_status_checks",
        "parameters": {
            "required_status_checks": [{"context": "ci"}],
            "strict_required_status_checks_policy": True,
        },
    },
])
# Invented ungated fixture: rules exist, none require a status check.
UNGATED_RULES = json.dumps([
    {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
    {"type": "non_fast_forward"},
    {"type": "deletion"},
])

ARMED_PR = json.dumps({
    "state": "OPEN",
    "mergedAt": None,
    "autoMergeRequest": {"enabledAt": "2040-02-11T09:15:00Z"},
    "headRefOid": "1111111111111111111111111111111111111111",
})
GREEN_CHECK_RUNS = json.dumps({
    "total_count": 1,
    "check_runs": [{
        "name": "ci",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2040-02-11T08:20:00Z",
        "completed_at": "2040-02-11T08:55:00Z",
    }],
})

GIT_STUB = r"""#!/usr/bin/env bash
# Stubbed git. Logs every invocation, then answers from the scenario.
printf '%s\n' "git $*" >> "$CALL_LOG"
case "$1" in
  fetch|add|commit|config) exit 0 ;;
  reset) touch "$STUB_STATE/reset_done"; exit 0 ;;
  rev-parse)
    # Before the reset HEAD is the caller's checkout; after it, the live tip.
    # A scenario that sets no tip leaves them equal, which is the healthy case.
    if [ -f "$STUB_STATE/reset_done" ] && [ -n "$STUB_TIP_SHA" ]; then
      printf '%s\n' "$STUB_TIP_SHA"
    else
      printf '%s\n' "$STUB_HEAD_SHA"
    fi
    exit 0 ;;
  describe) printf '%s\n' "$STUB_LATEST_TAG"; exit 0 ;;
  diff)
    case "$*" in
      *--quiet*) exit "$STUB_DIFF_QUIET_RC" ;;
      *--name-only*) printf '%s\n' $STUB_CHANGED; exit 0 ;;
    esac
    exit 0 ;;
  push)
    if [ -n "$STUB_PUSH_STDERR_FILE" ] && [ -f "$STUB_PUSH_STDERR_FILE" ]; then
      cat "$STUB_PUSH_STDERR_FILE" >&2
    fi
    # One scripted failure, then success, so a retry path can be driven.
    if [ -f "$STUB_STATE/push_failed" ]; then exit 0; fi
    if [ "$STUB_PUSH_RC" != "0" ]; then touch "$STUB_STATE/push_failed"; fi
    exit "$STUB_PUSH_RC" ;;
esac
exit 0
"""

GH_STUB = r"""#!/usr/bin/env bash
printf '%s\n' "gh $*" >> "$CALL_LOG"
# Fake credentials label auth roles without putting token values in logs.
role=unknown
case "${GH_TOKEN:-}" in
  stub-token) role=writer ;;
  stub-verify-token) role=verifier ;;
esac
printf '%s\n' "$role gh $*" >> "$AUTH_LOG"
if [ "$role" = verifier ] && [ "$STUB_VERIFY_RC" != 0 ]; then
  printf '%s\n' 'gh: Resource not accessible by integration (HTTP 403)' >&2
  exit "$STUB_VERIFY_RC"
fi
case "$1 $2" in
  "pr list")
    # Three different listings: the permission preflight probes with --limit 1,
    # the reuse lookup filters by --head, the superseded cleanup lists every open
    # release branch.
    case "$*" in
      *--limit*)
        if [ "$STUB_PREFLIGHT_RC" != "0" ]; then
          printf '%s\n' "GraphQL: Resource not accessible by personal access token (repository.pullRequests)" >&2
          exit "$STUB_PREFLIGHT_RC"
        fi
        printf '[]\n' ;;
      *--head*)
        if [ -f "$STUB_STATE/pr_created" ] || [ "$STUB_EXISTING_PR" != "" ]; then
          printf '%s\n' "${STUB_EXISTING_PR:-$STUB_NEW_PR}"
        fi ;;
      *)
        if [ -n "$STUB_OPEN_RELEASE_PRS" ]; then
          printf '%b\n' "$STUB_OPEN_RELEASE_PRS"
        fi ;;
    esac
    exit 0 ;;
  "pr create")
    previous=""
    for arg in "$@"; do
      if [ "$previous" = --body-file ]; then cp "$arg" "$STUB_STATE/pr_body"; fi
      previous="$arg"
    done
    touch "$STUB_STATE/pr_created"
    printf 'https://github.com/context-and-oss/cicd/pull/%s\n' "$STUB_NEW_PR"
    exit 0 ;;
  "pr view")
    # Two different views: the Actions-token refusal reads --jq '.author.login'
    # and so wants the resolved string, the gate readback wants real JSON.
    case "$*" in
      *"--json author"*) printf '%s\n' "$STUB_PR_AUTHOR" ;;
      *) printf '%s\n' "$STUB_PR_STATE_JSON" ;;
    esac
    exit 0 ;;
  "pr merge") exit "$STUB_MERGE_RC" ;;
  "pr close") exit "$STUB_CLOSE_RC" ;;
  "api "*)
    case "$2" in
      *rules/branches*)
        if [ "$STUB_RULES_RC" != "0" ]; then
          printf '%s\n' "gh: Not Found (HTTP 404)" >&2
          exit "$STUB_RULES_RC"
        fi
        printf '%s\n' "$STUB_RULES_JSON" ;;
      *check-runs*)
        if [ "$role" != verifier ]; then
          printf '%s\n' 'gh: Checks read requires the App fixture identity (HTTP 403)' >&2
          exit 1
        fi
        if [ "$STUB_CHECKS_RC" != 0 ]; then
          printf '%s\n' 'gh: Checks read denied (HTTP 403)' >&2
          exit "$STUB_CHECKS_RC"
        fi
        printf '%s\n' "$STUB_CHECK_RUNS_JSON" ;;
    esac
    exit 0 ;;
esac
exit 0
"""

BUMP_STUB = "import sys\n"
HANDOFF_STUB = (
    "import pathlib, sys\n"
    "pathlib.Path('handoff_called').write_text(' '.join(sys.argv[1:]))\n"
    "sys.exit({rc})\n"
)
GATE_STUB = "import sys\nsys.exit({rc})\n"
ARTIFACT_STUB = """import pathlib, sys
out = pathlib.Path("specs/release-latest.md")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("generated")
print(out)
"""


class Harness:
    """A temporary repository plus stubbed git and gh."""

    def __init__(self, tmp: str, **scenario) -> None:
        self.root = pathlib.Path(tmp)
        self.bin = self.root / "stubbin"
        self.state = self.root / "state"
        self.log = self.root / "calls.log"
        self.auth_log = self.root / "auth-calls.log"
        for d in (self.bin, self.state, self.root / "scripts" / "ci", self.root / "specs"):
            d.mkdir(parents=True, exist_ok=True)

        (self.root / "scripts" / "bump-version.py").write_text(BUMP_STUB)
        (self.root / "scripts" / "check-workflow-pins.py").write_text(
            GATE_STUB.format(rc=scenario.get("gate_rc", 0))
        )
        (self.root / "scripts" / "ci" / "write-release-intent.py").write_text(ARTIFACT_STUB)
        # The handoff check has its own 31 unit tests in
        # scripts/tests/test_release_handoff.py; what matters here is the
        # wiring — whether it is consulted at all, and whether its three
        # answers reach the caller intact.
        (self.root / "scripts" / "check-release-handoff.py").write_text(
            HANDOFF_STUB.format(rc=scenario.get("handoff_rc", 0))
        )
        # The real classifier — its wording is the contract this script relies on.
        (self.root / "scripts" / "ci" / "classify-push-rejection.sh").write_text(
            CLASSIFIER.read_text()
        )
        for real in (GATE_CLI, GATE_LOGIC):
            (self.root / "scripts" / real.name).write_text(real.read_text())

        for name, body in (("git", GIT_STUB), ("gh", GH_STUB)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)

        push_stderr = scenario.get("push_stderr")
        stderr_file = ""
        if push_stderr:
            p = self.root / "push_stderr.txt"
            p.write_text(push_stderr)
            stderr_file = str(p)

        self.env = dict(os.environ)
        self.env.update(
            PATH="{}:{}".format(self.bin, os.environ["PATH"]),
            CALL_LOG=str(self.log),
            AUTH_LOG=str(self.auth_log),
            STUB_STATE=str(self.state),
            STUB_LATEST_TAG=scenario.get("latest_tag", "v1.11.0"),
            STUB_HEAD_SHA=scenario.get("head_sha", "a" * 40),
            STUB_TIP_SHA=scenario.get("tip_sha", ""),
            STUB_DIFF_QUIET_RC=str(scenario.get("diff_quiet_rc", 1)),
            STUB_CHANGED=scenario.get("changed", "README.md .github/workflows/commit.yml"),
            STUB_PUSH_RC=str(scenario.get("push_rc", 0)),
            STUB_PUSH_STDERR_FILE=stderr_file,
            STUB_EXISTING_PR=str(scenario.get("existing_pr", "")),
            STUB_NEW_PR=str(scenario.get("new_pr", 140)),
            STUB_PR_AUTHOR=scenario.get("pr_author", "fictional-release-bot"),
            STUB_MERGE_RC=str(scenario.get("merge_rc", 0)),
            STUB_CLOSE_RC=str(scenario.get("close_rc", 0)),
            STUB_OPEN_RELEASE_PRS=scenario.get("open_release_prs", ""),
            STUB_PREFLIGHT_RC=str(scenario.get("preflight_rc", 0)),
            STUB_RULES_JSON=scenario.get("rules", GATED_RULES),
            STUB_RULES_RC=str(scenario.get("rules_rc", 0)),
            STUB_PR_STATE_JSON=scenario.get("pr_state", ARMED_PR),
            STUB_CHECK_RUNS_JSON=scenario.get("check_runs", GREEN_CHECK_RUNS),
            GH_TOKEN="stub-token",
            RELEASE_VERIFY_TOKEN="stub-verify-token",
            STUB_VERIFY_RC=str(scenario.get("verify_rc", 0)),
            STUB_CHECKS_RC=str(scenario.get("checks_rc", 0)),
            GITHUB_OUTPUT=str(self.root / "github_output"),
        )
        self.env.pop("GITHUB_ACTIONS", None)

    def run(self, version="1.12.0", source="cd.yml"):
        return subprocess.run(
            ["bash", str(SCRIPT), version, source],
            capture_output=True, text=True, cwd=str(self.root), env=self.env,
        )

    def calls(self) -> list:
        return self.log.read_text().splitlines() if self.log.is_file() else []

    def auth_calls(self) -> list:
        return self.auth_log.read_text().splitlines() if self.auth_log.is_file() else []

    def outputs(self) -> str:
        p = self.root / "github_output"
        return p.read_text() if p.is_file() else ""

    def handoff_args(self):
        """What the handoff check was invoked with, or None if it never ran."""
        p = self.root / "handoff_called"
        return p.read_text() if p.is_file() else None


_HARNESS_ROOTS: list = []


def harness(**scenario):
    tmp = tempfile.mkdtemp(prefix="cicd-release-harness-")
    _HARNESS_ROOTS.append(tmp)
    return Harness(tmp, **scenario)


def tearDownModule():
    """Remove every harness repository, including those of failed tests."""
    while _HARNESS_ROOTS:
        shutil.rmtree(_HARNESS_ROOTS.pop(), ignore_errors=True)


# The credential preflight is a read-only probe that runs before anything is
# written, so it is not evidence that a pull request was touched. Compared
# exactly rather than matched loosely, so a future `gh pr` call cannot slip past
# the assertions below by resembling it.
PREFLIGHT_CALL = "gh pr list --limit 1 --json number"


def pr_calls(calls: list) -> list:
    """Every `gh pr` invocation that opens, reuses, arms or closes a pull
    request — the preflight excluded."""
    return [c for c in calls if c.startswith("gh pr") and c != PREFLIGHT_CALL]


class TestNeverPushesToMain(unittest.TestCase):
    """Direct pushes must not replace pull-request delivery."""

    def test_no_push_targets_main(self):
        h = harness()
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        pushes = [c for c in h.calls() if c.startswith("git push")]
        self.assertTrue(pushes, "the script must push something")
        for push in pushes:
            self.assertNotIn("HEAD:main", push)
            self.assertNotIn("refs/heads/main", push)

    def test_push_targets_the_release_branch(self):
        h = harness()
        h.run()
        pushes = [c for c in h.calls() if c.startswith("git push")]
        self.assertTrue(
            any("HEAD:refs/heads/chore/release-v1.12.0" in p for p in pushes), pushes
        )

    def test_the_push_takes_a_lease_rather_than_clobbering(self):
        """`--force` is needed because a retry rewrites the branch, but a bare
        force would discard whatever a concurrent release run had put there."""
        h = harness()
        h.run()
        push = [c for c in h.calls() if c.startswith("git push")][0]
        self.assertIn("--force-with-lease", push)
        self.assertNotIn("--force ", push)

    def test_branch_is_outside_the_protected_release_namespace(self):
        """A release namespace can be protected against branch creation by push;
        use the delivery branch namespace instead."""
        h = harness()
        h.run()
        for call in h.calls():
            self.assertNotIn("refs/heads/release/", call)


class TestCredentialPreflight(unittest.TestCase):
    """Check pull-request access before writing anything, because a credential
    failure after pushing leaves a branch with no delivery pull request.
    Contents and workflows access alone do not grant pull-request access."""

    def test_a_token_that_cannot_read_pull_requests_fails_before_any_push(self):
        h = harness(preflight_rc=1)
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertEqual(
            [c for c in h.calls() if c.startswith("git push")],
            [],
            "nothing may be pushed once the credential is known to be unusable",
        )

    def test_it_also_leaves_the_working_tree_alone(self):
        """Not just the push: no commit either, so a re-run after fixing the token
        starts from a clean tree rather than an orphaned local release commit."""
        h = harness(preflight_rc=1)
        h.run()
        self.assertEqual([c for c in h.calls() if c.startswith("git commit")], [])

    def test_the_error_names_the_permission_to_grant(self):
        h = harness(preflight_rc=1)
        proc = h.run()
        self.assertIn("Pull requests: Read and write", proc.stderr)
        self.assertIn("Nothing was pushed", proc.stderr)

    def test_the_error_quotes_what_github_actually_said(self):
        """A remedy that does not carry the remote's own words makes the next
        person guess whether they are reading the right failure."""
        h = harness(preflight_rc=1)
        proc = h.run()
        self.assertIn("repository.pullRequests", proc.stderr)

    def test_no_result_is_emitted(self):
        """`released`/`pr-open`/`superseded` all describe a delivery that happened.
        A refused credential delivered nothing, so the caller must see no result
        at all rather than a quiet fourth answer."""
        h = harness(preflight_rc=1)
        proc = h.run()
        self.assertNotIn("result=", h.outputs())
        self.assertNotIn("result=", proc.stdout)

    def test_a_usable_token_is_probed_before_the_first_push(self):
        """The check is worthless if it runs after the thing it protects."""
        h = harness()
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = h.calls()
        probe = next(i for i, c in enumerate(calls) if c.startswith("gh pr list") and "--limit" in c)
        push = next(i for i, c in enumerate(calls) if c.startswith("git push"))
        self.assertLess(probe, push, calls)


class TestPullRequestDelivery(unittest.TestCase):
    def test_opens_a_pull_request_and_arms_auto_merge(self):
        h = harness()
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = h.calls()
        self.assertTrue(any(c.startswith("gh pr create") for c in calls), calls)
        merge = [c for c in calls if c.startswith("gh pr merge")]
        self.assertTrue(merge, calls)
        self.assertIn("--auto", merge[0])
        self.assertIn("chore/release-v1.12.0", merge[0])
        self.assertIn("result=pr-open", proc.stdout)
        self.assertIn("result=pr-open", h.outputs())

    def test_generated_body_does_not_substitute_checks_or_auto_merge_for_review(self):
        h = harness()
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = (h.state / "pr_body").read_text()
        self.assertIn("automated evidence, not a human review", body)
        self.assertIn("Auto-merge is requested; it supplies no approval", body)
        self.assertIn("every applicable check and review requirement", body)
        self.assertNotIn("that is the review", body)
        self.assertNotIn("Auto-merge is armed.", body)

    def test_pull_request_targets_main(self):
        h = harness()
        h.run()
        create = [c for c in h.calls() if c.startswith("gh pr create")][0]
        self.assertIn("--base main", create)
        self.assertIn("--head chore/release-v1.12.0", create)

    def test_an_open_pull_request_is_reused_not_duplicated(self):
        """A re-run after a failed release would otherwise leave two pull
        requests racing to merge the same bump."""
        h = harness(existing_pr=21)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(any(c.startswith("gh pr create") for c in h.calls()))
        self.assertIn("Reusing open pull request #21", proc.stdout)
        self.assertIn("result=pr-open", proc.stdout)

    def test_auto_merge_failing_fails_the_run(self):
        """If auto-merge is disabled on the repository, the release must not
        report success and leave a pull request nothing will merge."""
        h = harness(merge_rc=1)
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("result=pr-open", proc.stdout)


class TestActionsTokenRefusal(unittest.TestCase):
    def test_a_pull_request_authored_by_the_actions_token_is_refused(self):
        """A pull request the Actions default token opens triggers no workflow
        runs, so `ci` never runs and auto-merge never fires: the release would sit
        open forever, silently, which is the failure this change removes."""
        h = harness(pr_author="github-actions[bot]")
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("triggers no workflow runs", proc.stderr)
        self.assertIn("CICD_RELEASE_TOKEN", proc.stderr)
        self.assertFalse(any(c.startswith("gh pr merge") for c in h.calls()))

    def test_a_real_identity_is_accepted(self):
        h = harness(pr_author="some-release-identity")
        self.assertEqual(h.run().returncode, 0)


def merged_pr(merged_at, head="1" * 40):
    return json.dumps({
        "state": "MERGED",
        "mergedAt": merged_at,
        "autoMergeRequest": None,
        "headRefOid": head,
    })


def check_runs(*runs, total=None):
    return json.dumps({
        "total_count": len(runs) if total is None else total,
        "check_runs": list(runs),
    })


def ci_run(status="completed", conclusion="success", started=None, completed=None):
    return {
        "name": "ci",
        "status": status,
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": completed,
    }


class TestRequiredCheckPreflight(unittest.TestCase):
    """`ci` gating main is the assumption every other claim in this script rests
    on: the pull request body says so, auto-merge depends on it, and the tag cut
    afterwards inherits whatever trust it confers. An attached ruleset without
    a required-check rule cannot establish that protection."""

    def test_an_ungated_main_stops_the_release_before_anything_is_written(self):
        h = harness(rules=UNGATED_RULES)
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertFalse(any(c.startswith("git push") for c in h.calls()), h.calls())
        self.assertFalse(any(c.startswith("gh pr create") for c in h.calls()))
        self.assertEqual(h.outputs(), "")

    def test_the_error_names_the_applicable_rule_to_restore(self):
        proc = harness(rules=UNGATED_RULES).run()
        self.assertIn("not a required status check", proc.stderr)
        self.assertIn("required_status_checks", proc.stderr)
        self.assertIn("applicable branch ruleset", proc.stderr)

    def test_it_reports_which_checks_are_required_instead(self):
        """"Not this one" is useless advice when the answer might be a renamed
        context. This fixture has no required checks at all, which the
        message has to be able to say out loud."""
        proc = harness(rules=UNGATED_RULES).run()
        self.assertIn("none at all", proc.stderr)

        renamed = json.dumps([{
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [
                {"context": "build"}, {"context": "test"},
            ]},
        }])
        proc = harness(rules=renamed).run()
        self.assertIn("build, test", proc.stderr)

    def test_it_runs_before_the_first_push(self):
        """A gate check after the push protects nothing."""
        h = harness()
        self.assertEqual(h.run().returncode, 0)
        calls = h.calls()
        gate = next(i for i, c in enumerate(calls) if "rules/branches" in c)
        push = next(i for i, c in enumerate(calls) if c.startswith("git push"))
        self.assertLess(gate, push, calls)

    def test_the_tagging_path_is_gated_too(self):
        """`released` is the run that cuts the tag, and a tag on an ungated main
        is the same false pass one step further along."""
        h = harness(rules=UNGATED_RULES, diff_quiet_rc=0)
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("result=released", proc.stdout)
        self.assertEqual(h.outputs(), "")

    def test_the_superseded_path_is_gated_too(self):
        h = harness(rules=UNGATED_RULES, latest_tag="v2.0.0")
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("result=superseded", proc.stdout)

    def test_a_question_github_cannot_answer_is_not_a_pass(self):
        h = harness(rules_rc=1)
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("could not be verified", proc.stderr)
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))

    def test_a_strict_policy_that_is_off_warns_but_does_not_stop(self):
        """Required-but-not-strict lets a stale lower-version release branch merge
        later and walk every pin backwards. The supersede cleanup closes those, so
        this is a warning — but it is now the only thing standing there."""
        lax = json.dumps([{
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [{"context": "ci"}],
                "strict_required_status_checks_policy": False,
            },
        }])
        proc = harness(rules=lax).run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("::warning::", proc.stdout)
        self.assertIn("downgrade every pin", proc.stdout)
        self.assertIn("result=pr-open", proc.stdout)


class TestDeliveredPullRequestReadback(unittest.TestCase):
    """`gh pr merge --auto` cannot arm auto-merge on a request that is already
    mergeable: it merges it on the spot, exits 0, and says which of the two
    happened nowhere. Either can be legitimate; a merge with nothing having
    examined the commit must be refused."""

    def test_armed_and_waiting_is_the_normal_path(self):
        h = harness()
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("auto-merge armed", proc.stdout)
        self.assertIn("result=pr-open", proc.stdout)

    def test_a_request_left_open_and_unarmed_fails_the_release(self):
        """Exit 0 from the merge command with nothing armed means the request sits
        open forever and no tag is ever cut — silent, which is the failure mode the
        pull-request delivery exists to remove."""
        h = harness(pr_state=json.dumps({
            "state": "OPEN",
            "mergedAt": None,
            "autoMergeRequest": None,
            "headRefOid": "1" * 40,
        }))
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("auto-merge is NOT armed", proc.stderr)
        self.assertEqual(h.outputs(), "")

    def test_an_immediate_merge_on_an_already_green_head_is_accepted(self):
        """The legitimate immediate merge: a re-run whose branch already carried a
        passing `ci`. Verified, not assumed."""
        h = harness(
            pr_state=merged_pr("2040-02-11T09:15:00Z"),
            check_runs=check_runs(ci_run(
                started="2040-02-11T08:20:00Z", completed="2040-02-11T08:55:00Z",
            )),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("merged immediately, and legitimately", proc.stdout)
        self.assertIn("result=pr-open", proc.stdout)

    def test_a_check_that_started_after_the_merge_is_refused(self):
        """Invented timings: a check starts after the merge and later passes.
        The later green result cannot establish a prior gate."""
        h = harness(
            pr_state=merged_pr("2040-02-10T14:35:10Z"),
            check_runs=check_runs(ci_run(
                started="2040-02-10T14:49:20Z", completed="2040-02-10T14:49:27Z",
            )),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("was not gated", proc.stderr)
        self.assertIn("14:49:20", proc.stderr)
        self.assertEqual(h.outputs(), "")

    def test_a_failed_check_before_the_merge_is_refused(self):
        h = harness(
            pr_state=merged_pr("2040-02-11T09:15:00Z"),
            check_runs=check_runs(ci_run(
                conclusion="failure",
                started="2040-02-11T08:20:00Z", completed="2040-02-11T08:55:00Z",
            )),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("failure", proc.stderr)

    def test_a_commit_with_no_such_check_at_all_is_refused(self):
        h = harness(
            pr_state=merged_pr("2040-02-11T09:15:00Z"),
            check_runs=check_runs({
                "name": "lint-repo", "status": "completed", "conclusion": "success",
                "started_at": "2040-02-11T07:40:00Z",
                "completed_at": "2040-02-11T08:05:00Z",
            }),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("no check run named 'ci'", proc.stderr)

    def test_a_truncated_page_of_check_runs_is_not_a_pass(self):
        """GitHub says how many check runs exist. Fewer returned than exist means
        the green one might be the one that was not read."""
        h = harness(
            pr_state=merged_pr("2040-02-11T09:15:00Z"),
            check_runs=check_runs(ci_run(
                started="2040-02-11T08:20:00Z", completed="2040-02-11T08:55:00Z",
            ), total=140),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("could not be verified", proc.stderr)
        self.assertEqual(h.outputs(), "")

    def test_the_readback_follows_the_merge_command(self):
        h = harness()
        self.assertEqual(h.run().returncode, 0)
        calls = h.calls()
        merge = next(i for i, c in enumerate(calls) if c.startswith("gh pr merge"))
        readback = next(
            i for i, c in enumerate(calls)
            if c.startswith("gh pr view") and "--json state" in c
        )
        self.assertLess(merge, readback, calls)


def release_pr(number, version):
    return "{}\tchore/release-v{}\tchore(release): bump version pins to v{}".format(
        number, version, version
    )


class TestSupersededPullRequests(unittest.TestCase):
    """The leak this design creates if nothing cleans up.

    The branch name carries the version, so a target that moves — a `feat:`
    landing while a patch release waits — opens a second branch and orphans the
    first. The orphan can never merge either: main requires the branch to be up to
    date (`strict_required_status_checks_policy`) and has moved past it. Left
    alone, every superseded release leaves an open pull request proposing to
    downgrade every pin in the repository.
    """

    def test_a_lower_version_release_pr_is_closed(self):
        h = harness(open_release_prs=release_pr(23, "1.11.1"))
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        closes = [c for c in h.calls() if c.startswith("gh pr close")]
        self.assertEqual(len(closes), 1, h.calls())
        self.assertIn("23", closes[0])
        self.assertIn("closed superseded release pull request #23", proc.stdout)

    def test_the_current_branch_is_never_closed(self):
        h = harness(open_release_prs=release_pr(140, "1.12.0"))
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([c for c in h.calls() if c.startswith("gh pr close")], [])

    def test_a_higher_version_release_pr_is_reported_not_closed(self):
        """Whether this run is the superseded one is the tag guard's call, made
        against a real tag — never inferred from someone else's branch name."""
        h = harness(open_release_prs=release_pr(141, "1.13.0"))
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([c for c in h.calls() if c.startswith("gh pr close")], [])
        self.assertIn("at or above this run's v1.12.0", proc.stdout)

    def test_a_branch_that_only_looks_like_ours_is_left_alone(self):
        """A human working on chore/release-v1.11.1 must not have their pull
        request closed by a bot pattern-matching on a branch name."""
        h = harness(
            open_release_prs="139\tchore/release-v1.11.1\tfix: something a person is doing"
        )
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([c for c in h.calls() if c.startswith("gh pr close")], [])
        self.assertIn("may be a human's branch", proc.stdout)

    def test_a_close_failure_warns_but_still_reports_the_release(self):
        """Housekeeping must not fail a release that was already delivered — and
        must not stay quiet about what it left behind."""
        h = harness(open_release_prs=release_pr(23, "1.11.1"), close_rc=1)
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("result=pr-open", proc.stdout)
        self.assertIn("could not close superseded release pull request #23", proc.stdout)

    def test_no_open_release_pull_requests_is_not_an_error(self):
        h = harness(open_release_prs="")
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([c for c in h.calls() if c.startswith("gh pr close")], [])

    def test_several_lower_versions_are_all_closed(self):
        h = harness(
            open_release_prs="\\n".join([release_pr(20, "1.11.1"), release_pr(21, "1.11.2")])
        )
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        closes = [c for c in h.calls() if c.startswith("gh pr close")]
        self.assertEqual(len(closes), 2, h.calls())

    def test_cleanup_happens_after_auto_merge_is_armed(self):
        """Order matters: arming the release is the job, cleaning up is not. If
        closing hangs or fails, the release must already be armed."""
        h = harness(open_release_prs=release_pr(23, "1.11.1"))
        h.run(version="1.12.0")
        calls = h.calls()
        merge = next(i for i, c in enumerate(calls) if c.startswith("gh pr merge"))
        close = next(i for i, c in enumerate(calls) if c.startswith("gh pr close"))
        self.assertLess(merge, close)


class TestStaging(unittest.TestCase):
    def test_stages_tracked_changes_and_the_artifact_by_name(self):
        """`git add -A` could sweep untracked build output into a release commit."""
        h = harness()
        h.run()
        adds = [c for c in h.calls() if c.startswith("git add")]
        self.assertIn("git add -u", adds)
        self.assertTrue(any("specs/release-latest.md" in a for a in adds), adds)
        for add in adds:
            self.assertNotIn("-A", add.split()[2:])

    def test_the_artifact_is_generated_from_the_real_changed_set(self):
        h = harness()
        h.run()
        self.assertTrue(any("git diff --name-only" in c for c in h.calls()))


class TestSupersede(unittest.TestCase):
    def test_a_newer_tag_supersedes_without_bumping(self):
        """Two merges seconds apart spawn runs that compute different targets.
        Without this the superseded run rewrites every pin downward."""
        h = harness(latest_tag="v1.13.0")
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("result=superseded", proc.stdout)
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")

    def test_the_same_tag_supersedes(self):
        h = harness(latest_tag="v1.12.0")
        self.assertIn("result=superseded", h.run(version="1.12.0").stdout)

    def test_an_older_tag_does_not_supersede(self):
        h = harness(latest_tag="v1.11.0")
        self.assertIn("result=pr-open", h.run(version="1.12.0").stdout)

    def test_no_reachable_tag_refuses_before_touching_anything(self):
        """A copy with no reachable tag has no chosen release baseline.
        A fallback attached only to a pipeline's final command can hide an
        earlier failure and leave latest empty; refuse rather than bump from
        that unknown base."""
        h = harness(latest_tag="")
        proc = h.run(version="1.12.0")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("no v* tag is reachable", proc.stderr)
        self.assertIn("Bootstrapping a fresh copy", proc.stderr)
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")


class TestAlreadyAtTarget(unittest.TestCase):
    def test_pins_already_at_target_report_released_so_the_caller_tags(self):
        """The seam that makes a pull-request-delivered release still get its tag
        from the pipeline: the run after the merge finds nothing to bump."""
        h = harness(diff_quiet_rc=0)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("result=released", proc.stdout)
        self.assertIn("result=released", h.outputs())
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")


class TestMainMovedUnderTheRelease(unittest.TestCase):
    """The caller tags whatever HEAD is when it gets control, and the delivery
    points HEAD at the live tip. These pin down which tip it is allowed to be."""

    def test_a_tip_that_moved_reports_stale_and_is_not_tagged(self):
        """Tagging a later commit with an earlier commit's computed version can
        hide a breaking change inside a patch. Refuse the moved tip instead."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("result=stale", proc.stdout)
        self.assertIn("result=stale", h.outputs())
        self.assertNotIn("result=released", proc.stdout)

    def test_the_stale_warning_names_both_commits(self):
        """A release that declined to tag has to say which tip it refused and
        which one it was built for, or the operator cannot tell it from a run
        that simply had nothing to do."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        proc = h.run()
        self.assertIn("a" * 40, proc.stdout)
        self.assertIn("b" * 40, proc.stdout)

    def test_stale_touches_no_pull_request_and_pushes_nothing(self):
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        h.run()
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertFalse(any(c.startswith("git tag") for c in h.calls()))
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")

    def test_an_unmoved_tip_still_releases(self):
        """The guard must not cost the healthy path its tag: when the tip is the
        commit the version was computed for, this is the run that tags."""
        h = harness(diff_quiet_rc=0, head_sha="c" * 40, tip_sha="c" * 40)
        proc = h.run()
        self.assertIn("result=released", proc.stdout)
        self.assertNotIn("result=stale", proc.stdout)

    def test_a_moved_tip_with_pins_to_deliver_still_opens_a_pull_request(self):
        """Stale is a verdict about tagging, not about delivering. A run whose
        pins do not yet match has nothing to tag anyway, and must still deliver
        the bump against the live tip."""
        h = harness(diff_quiet_rc=1, head_sha="a" * 40, tip_sha="b" * 40)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("result=pr-open", proc.stdout)
        self.assertNotIn("result=stale", proc.stdout)


class TestTheStaleHandoffIsCheckedNotAsserted(unittest.TestCase):
    """The stale branch leaves main pinned to an uncut version because its
    pins already match and no tag at or above the target exists. A warning
    cannot establish that a successor will repair it.

    If CI on the new tip cannot fetch the Dagger CLI, CD can skip delivery and
    leave those pins unresolved. Check the successor instead of mistaking an
    abandoned handoff for a healthy release."""

    def test_the_handoff_is_actually_checked(self):
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        h.run()
        self.assertIsNotNone(h.handoff_args(), "the stale path must consult the check")

    def test_the_check_is_told_not_to_count_this_run_as_its_own_successor(self):
        """Without excluding it, the check finds this CD run in flight and
        reports that the successor it is looking for has already arrived."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        h.env["GITHUB_RUN_ID"] = "1000000001"
        h.run()
        self.assertIn("--exclude-run-id 1000000001", h.handoff_args())

    def test_a_handoff_nobody_will_discharge_fails_the_run(self):
        """A green delivery must not conceal an abandoned release handoff."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40, handoff_rc=1)
        proc = h.run()
        self.assertEqual(proc.returncode, 1, proc.stdout)

    def test_the_tagging_verdict_survives_a_failed_handoff_check(self):
        """`stale` and "nobody is coming" are different questions. The caller
        must still learn not to tag, or a broken handoff could argue this run
        into tagging the wrong commit."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40, handoff_rc=1)
        proc = h.run()
        self.assertIn("result=stale", proc.stdout)
        self.assertIn("result=stale", h.outputs())
        self.assertNotIn("result=released", proc.stdout)

    def test_a_handoff_in_flight_leaves_the_run_green(self):
        """Main is momentarily pinned to an uncut version on every ordinary
        release. Going red on a state that heals itself in one CI cycle is the
        false alarm that teaches people to ignore the signal."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40, handoff_rc=0)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_check_that_could_not_look_does_not_fail_the_release(self):
        """Exit 2 is "no answer", not "abandoned". A rate-limited API must not
        turn every concurrent release into a red run — and it is not read as a
        pass either: the warning says the scheduled sweep asks again."""
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40, handoff_rc=2)
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("release-drift.yml", proc.stderr)

    def test_the_warning_no_longer_claims_the_refusal_is_free(self):
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40)
        proc = h.run()
        self.assertIn("main is pinned to v1.12.0", proc.stdout)

    def test_the_healthy_path_never_consults_it(self):
        """A run that tags leaves main pinned to a version it is about to
        create, so there is no handoff to check and no API call to spend."""
        h = harness(diff_quiet_rc=0, head_sha="c" * 40, tip_sha="c" * 40)
        proc = h.run()
        self.assertIn("result=released", proc.stdout)
        self.assertIsNone(h.handoff_args())

    def test_a_delivery_run_never_consults_it(self):
        h = harness(diff_quiet_rc=1, head_sha="a" * 40, tip_sha="b" * 40)
        h.run()
        self.assertIsNone(h.handoff_args())

    def test_a_failed_handoff_check_still_pushes_and_tags_nothing(self):
        h = harness(diff_quiet_rc=0, head_sha="a" * 40, tip_sha="b" * 40, handoff_rc=1)
        h.run()
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertFalse(any(c.startswith("git tag") for c in h.calls()))
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")

class TestFailureModes(unittest.TestCase):
    def test_the_coherence_gate_failing_stops_the_delivery(self):
        """A pin set that disagrees with itself must never reach a pull request —
        a version pin must agree with the command that its module exposes."""
        h = harness(gate_rc=1)
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(any(c.startswith("git push") for c in h.calls()))
        self.assertNotIn("result=", h.outputs())

    def test_a_ruleset_refusal_fails_loud_with_the_real_reason(self):
        """Not retried: no number of attempts satisfies a rule. The remedy text
        names the branch-namespace trap so a protected release namespace is
        not mistaken for a transient push failure."""
        h = harness(
            push_rc=1,
            push_stderr=(
                "remote: error: GH013: Repository rule violations found for "
                "refs/heads/chore/release-v1.12.0.\n"
                "remote: \n"
                'remote: - Required status check "ci" is expected.\n'
                "remote: \n"
                " ! [remote rejected] HEAD -> chore/release-v1.12.0 (push declined "
                "due to repository rule violations)\n"
            ),
        )
        proc = h.run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no retry can satisfy", proc.stderr)
        self.assertIn('Required status check "ci" is expected', proc.stderr)
        self.assertIn("refs/heads/release/**", proc.stderr)
        self.assertIn("CICD_RELEASE_TOKEN", proc.stderr)
        self.assertEqual(pr_calls(h.calls()), [], "no pull request may be touched")

    def test_a_stale_branch_is_retried(self):
        """A non-fast-forward on the release branch means it moved under us, which
        a re-derive against the new tip does answer."""
        h = harness(
            push_rc=1,
            push_stderr=(
                " ! [rejected]        HEAD -> chore/release-v1.12.0 (non-fast-forward)\n"
                "error: failed to push some refs\n"
            ),
        )
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("re-deriving against the new tip", proc.stdout + proc.stderr)
        self.assertIn("result=pr-open", proc.stdout)

    def test_a_non_semver_version_is_refused(self):
        h = harness()
        proc = h.run(version="1.12")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not semver", proc.stderr)

    def test_missing_arguments_are_refused(self):
        h = harness()
        proc = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True,
            cwd=str(h.root), env=h.env,
        )
        self.assertNotEqual(proc.returncode, 0)


class TestVerificationCredentials(unittest.TestCase):
    def test_missing_or_empty_verifier_stops_before_any_api_or_git_call(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                h = harness()
                if missing:
                    h.env.pop("RELEASE_VERIFY_TOKEN")
                else:
                    h.env["RELEASE_VERIFY_TOKEN"] = ""
                proc = h.run()
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.assertIn("RELEASE_VERIFY_TOKEN is required", proc.stderr)
                self.assertIn("Checks read", proc.stderr)
                self.assertEqual(h.calls(), [])
                self.assertEqual(h.outputs(), "")

    def test_only_delivered_pr_readback_uses_the_app_identity(self):
        h = harness(open_release_prs=release_pr(23, "1.11.1"))
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = h.auth_calls()
        reader = [c for c in calls if c.startswith("verifier ")]
        self.assertEqual(len(reader), 1, calls)
        self.assertIn("gh pr view", reader[0])
        self.assertIn("--json state,mergedAt,autoMergeRequest,headRefOid,reviewDecision", reader[0])
        for fragment in ("rules/branches/main", "gh pr list", "gh pr create", "gh pr merge", "gh pr close"):
            self.assertTrue(any(c.startswith("writer ") and fragment in c for c in calls), calls)
        self.assertFalse(any(c.startswith("unknown ") for c in calls), calls)

    def test_immediate_merge_proof_reads_checks_with_app_not_writer(self):
        h = harness(pr_state=merged_pr("2040-02-11T09:15:00Z"))
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        checks = [c for c in h.auth_calls() if "check-runs" in c]
        self.assertEqual(len(checks), 1, h.auth_calls())
        self.assertTrue(checks[0].startswith("verifier gh api "), checks)
        self.assertIn("commits/" + "1" * 40 + "/check-runs", checks[0])
        self.assertIn("result=pr-open", proc.stdout)

    def test_denied_verifier_fails_without_falling_back_to_the_writer(self):
        h = harness(verify_rc=1)
        proc = h.run()
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("could not be verified", proc.stderr)
        self.assertNotIn("result=pr-open", proc.stdout)
        self.assertEqual(h.outputs(), "")
        calls = h.auth_calls()
        reader = [c for c in calls if c.startswith("verifier ")]
        self.assertEqual(len(reader), 1, calls)
        self.assertEqual(calls[-1], reader[0], calls)
        self.assertFalse(any("gh pr close" in c for c in calls), calls)

    def test_denied_checks_after_readable_pr_state_is_not_a_pass_or_writer_retry(self):
        h = harness(pr_state=merged_pr("2040-02-11T09:15:00Z"), checks_rc=1)
        proc = h.run()
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("Checks read denied", proc.stderr)
        self.assertIn("GitHub App token", proc.stderr)
        self.assertIn("GITHUB_TOKEN", proc.stderr)
        self.assertEqual(h.outputs(), "")
        checks = [c for c in h.auth_calls() if "check-runs" in c]
        self.assertEqual(len(checks), 1, h.auth_calls())
        self.assertTrue(checks[0].startswith("verifier gh api "), checks)
        for key in ("GH_TOKEN", "RELEASE_VERIFY_TOKEN"):
            self.assertNotIn(h.env[key], proc.stdout + proc.stderr)

    def test_neither_credential_value_reaches_output_or_command_arguments(self):
        h = harness(pr_state=merged_pr("2040-02-11T09:15:00Z"))
        proc = h.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        logs = proc.stdout + proc.stderr + "\n".join(h.calls() + h.auth_calls())
        for key in ("GH_TOKEN", "RELEASE_VERIFY_TOKEN"):
            self.assertNotIn(h.env[key], logs)

    def test_both_workflow_callers_bind_app_readback_and_keep_pat_writes(self):
        for workflow, job_id in (("cd.yml", "tag-and-release"), ("release.yml", "release")):
            with self.subTest(workflow=workflow):
                text = (REPO_ROOT / ".github" / "workflows" / workflow).read_text()
                job = re.search(
                    r"(?ms)^  " + job_id + r":\n(.*?)(?=^  [\w-]+:|\Z)", text,
                ).group(1)
                permissions = re.search(
                    r"(?m)^    permissions:\n((?:      [^\n]*\n)+)", job,
                ).group(1)
                self.assertEqual(dict(re.findall(r"(?m)^      ([\w-]+): (\w+)$", permissions)), {
                    "contents": "write", "pull-requests": "read", "checks": "read",
                })
                delivery = job.split("      - name: Deliver bumped pins by pull request\n", 1)[1]
                delivery = delivery.split("\n      - name:", 1)[0]
                self.assertIn("RELEASE_VERIFY_TOKEN: ${{ github.token }}", delivery)
                self.assertIn("RELEASE_TOKEN: ${{ secrets.CICD_RELEASE_TOKEN }}", delivery)
                self.assertIn('GH_TOKEN="$RELEASE_TOKEN"', delivery)
                self.assertIn("bash scripts/ci/deliver-release-pins.sh", delivery)
                self.assertIn(
                    'git remote set-url origin "https://x-access-token:${RELEASE_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"',
                    job,
                )


class TestSecrets(unittest.TestCase):
    def test_a_credential_in_a_push_log_is_redacted(self):
        h = harness(
            push_rc=1,
            push_stderr=(
                "remote: error: GH013: Repository rule violations found.\n"
                "fatal: unable to access "
                "'https://x-access-token:ghp_notarealtoken@github.com/context-and-oss/cicd.git/'\n"
            ),
        )
        proc = h.run()
        combined = proc.stdout + proc.stderr
        self.assertNotIn("ghp_notarealtoken", combined)
        self.assertIn("x-access-token:***@", combined)


class TestResultContract(unittest.TestCase):
    def test_exactly_one_result_is_emitted(self):
        for scenario, expected in [
            ({}, "pr-open"),
            ({"diff_quiet_rc": 0}, "released"),
            ({"latest_tag": "v2.0.0"}, "superseded"),
            ({"diff_quiet_rc": 0, "tip_sha": "b" * 40}, "stale"),
        ]:
            with self.subTest(expected=expected):
                h = harness(**scenario)
                proc = h.run()
                self.assertEqual(proc.returncode, 0, proc.stderr)
                emitted = [
                    line for line in proc.stdout.splitlines() if line.startswith("result=")
                ]
                self.assertEqual(emitted, ["result={}".format(expected)])
                self.assertEqual(h.outputs().strip(), "result={}".format(expected))

    def test_the_documented_results_are_the_only_ones(self):
        """The usage block is the contract both workflows branch on; a fourth
        result would be a branch neither of them handles."""
        text = SCRIPT.read_text()
        emitted = sorted(set(
            line.split("emit ")[1].strip()
            for line in text.splitlines()
            if line.strip().startswith("emit ")
        ))
        self.assertEqual(emitted, ["pr-open", "released", "stale", "superseded"])


if __name__ == "__main__":
    unittest.main()
