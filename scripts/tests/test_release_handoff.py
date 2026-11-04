"""Regression proof for scripts/release_handoff.py.

The defect: on 2026-09-10 `main` carried thirteen dangling `@v3.2.2` pins for
roughly forty minutes and every signal in the repository was green. The release
run that created that state reported **success** — it emitted `result=stale`,
correctly declining to tag a commit its version had not been computed for, and
then asserted in a `::warning::` that the run for the new tip would tag instead.
No such run existed: CI on the new tip had died on `curl … exit 35` fetching the
Dagger CLI, so CD's gate skipped every job. Nothing anywhere asked whether the
handoff had actually been discharged.

So the assertions below fall into two groups:

* the pins question — a version pinned across main with no tag naming it is a
  break whatever produced it, and it must not be reported as a version skew, a
  drift measurement, or anything else that reads as a matter of degree
* the handoff question — abandonment is claimed only on positive evidence.
  Anything in flight, and anything not yet observed, is `pending`, because a red
  run on a state that heals itself in one CI cycle is the false alarm that
  teaches people to ignore the signal

Both layers are driven through injected fakes: `classify` is pure, and the
command layer takes a `runner` callable, so nothing here touches git, `gh`, a
network or a clock.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from release_handoff import (  # noqa: E402
    ABANDONED,
    PENDING,
    RESOLVED,
    ToolError,
    check,
    classify,
    read_pins,
    runs_for,
    unresolved_pins,
)


def run(status="completed", conclusion="success", run_id=1, sha="b" * 40):
    return {
        "headSha": sha,
        "status": status,
        "conclusion": conclusion,
        "databaseId": run_id,
        "url": "https://github.com/context-and-oss/cicd/actions/runs/{}".format(run_id),
    }


DANGLING = {"3.2.2": [".github/workflows/commit.yml:12"]}


class FakeInventory:
    def __init__(self, root, surfaces):
        self.root = pathlib.Path(root)
        self.active_surfaces = tuple(surfaces)


class Recorder:
    """A runner that answers from a script and logs what it was asked."""

    def __init__(self, **answers):
        self.answers = answers
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        key = " ".join(cmd[:2])
        if key == "git rev-parse":
            if "--is-shallow-repository" in cmd:
                return 0, self.answers.get("shallow", "false"), ""
            return 0, self.answers.get("tip", "b" * 40), ""
        if key == "git tag":
            tags = self.answers.get("tags", ["v3.2.1"])
            if callable(tags):
                tags = tags(len([c for c in self.calls if c[:2] == ["git", "tag"]]))
            return 0, "\n".join(tags), ""
        if key == "git fetch":
            return self.answers.get("fetch_rc", 0), "", ""
        if key == "gh run":
            workflow = cmd[cmd.index("--workflow") + 1]
            return 0, json.dumps(self.answers.get(workflow, [])), ""
        raise AssertionError("unexpected command: {}".format(cmd))


class TestAPinnedVersionWithNoTag(unittest.TestCase):
    """The invariant. It does not care how the state was reached."""

    def test_a_pin_whose_tag_exists_is_not_reported(self):
        self.assertEqual(unresolved_pins({"3.3.0": ["a.yml:1"]}, ["v3.3.0"]), {})

    def test_a_pin_whose_tag_does_not_exist_is_reported_with_its_locations(self):
        pins = {"3.2.2": ["a.yml:1", "b.md:9"]}
        self.assertEqual(unresolved_pins(pins, ["v3.2.1", "v3.3.0"]), pins)

    def test_the_v_prefix_is_not_a_difference(self):
        """`git tag` prints v3.3.0 and a pin carries the bare 3.3.0. Comparing
        raw strings would report every pin on main dangling at once, which
        reads as a catastrophe and gets the check switched off."""
        self.assertEqual(unresolved_pins({"3.3.0": ["a.yml:1"]}, ["3.3.0"]), {})

    def test_a_repository_with_no_tags_reports_every_pin(self):
        pins = {"3.3.0": ["a.yml:1"]}
        self.assertEqual(unresolved_pins(pins, []), pins)

    def test_blank_tag_lines_are_not_tags(self):
        pins = {"3.3.0": ["a.yml:1"]}
        self.assertEqual(unresolved_pins(pins, ["", "   "]), pins)


class TestReadingPinsFromTheInventory(unittest.TestCase):
    def test_pins_are_grouped_by_version_and_carry_file_and_line(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.yml").write_text(
                "jobs:\n"
                "  x:\n"
                "    uses: context-and-oss/cicd/.github/workflows/commit.yml@v3.2.2\n"
            )
            (root / "b.md").write_text(
                "run: dagger -m github.com/context-and-oss/cicd/src/quality@v3.2.2 call x\n"
            )
            pins = read_pins(FakeInventory(root, ["a.yml", "b.md"]))
        self.assertEqual(sorted(pins), ["3.2.2"])
        self.assertEqual(pins["3.2.2"], ["a.yml:3", "b.md:1"])

    def test_ado_resource_pin_is_read_at_the_ref_line(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.yml").write_text(
                "resources:\n  repositories:\n    - repository: cicdTemplates\n"
                "      name: context-and-oss/cicd\n"
                "      endpoint: example-connection\n      ref: refs/tags/v3.3.0\n"
                "    - repository: other\n      name: example-org/shared-models\n"
                "      ref: refs/tags/v1.0.0\n"
            )
            pins = read_pins(FakeInventory(root, ["a.yml"]))
        self.assertEqual(pins, {"3.3.0": ["a.yml:6"]})

    def test_a_surface_that_cannot_be_read_is_skipped_not_fatal(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.yml").write_text(
                "uses: context-and-oss/cicd/.github/workflows/commit.yml@v3.3.0\n"
            )
            pins = read_pins(FakeInventory(root, ["a.yml", "gone.yml"]))
        self.assertEqual(pins, {"3.3.0": ["a.yml:1"]})


class TestNothingIsOwed(unittest.TestCase):
    def test_resolved_pins_end_the_question(self):
        verdict = classify({}, [run(conclusion="failure")], [])
        self.assertEqual(verdict.state, RESOLVED)

    def test_a_resolved_verdict_says_so_in_words(self):
        self.assertIn("exists", "\n".join(classify({}, [], []).lines()))


class TestAHandoffStillInFlight(unittest.TestCase):
    """Pending, every time. A red run on a state that heals itself in one CI
    cycle is the false alarm that teaches people to ignore the signal."""

    def test_a_running_cd_run_is_the_run_that_would_tag(self):
        verdict = classify(DANGLING, [], [run(status="in_progress", conclusion=None)])
        self.assertEqual(verdict.state, PENDING)
        self.assertIn("in flight", verdict.reason)

    def test_a_queued_ci_run_still_leads_to_cd(self):
        verdict = classify(DANGLING, [run(status="queued", conclusion=None)], [])
        self.assertEqual(verdict.state, PENDING)

    def test_a_rerun_beats_the_attempt_it_replaces(self):
        """`gh run rerun --failed` leaves the failed attempt visible next to the
        new one. Checking conclusions before status would call the handoff
        abandoned at the exact moment someone is discharging it."""
        verdict = classify(
            DANGLING,
            [run(conclusion="failure", run_id=1), run(status="in_progress", conclusion=None, run_id=2)],
            [],
        )
        self.assertEqual(verdict.state, PENDING)

    def test_a_green_ci_with_no_cd_yet_is_pending_not_broken(self):
        verdict = classify(DANGLING, [run()], [])
        self.assertEqual(verdict.state, PENDING)
        self.assertIn("has not been observed", verdict.reason)

    def test_no_run_at_all_is_pending_not_broken(self):
        """A commit that merged seconds ago looks exactly like a workflow that
        was refused at startup. Only the scheduled sweep can tell them apart,
        by asking again later."""
        verdict = classify(DANGLING, [], [])
        self.assertEqual(verdict.state, PENDING)

    def test_an_unrecognised_status_is_not_read_as_finished(self):
        verdict = classify(DANGLING, [run(status="pending", conclusion=None)], [])
        self.assertEqual(verdict.state, PENDING)


class TestAHandoffNobodyIsGoingToDischarge(unittest.TestCase):
    """The 2026-09-10 incident, and the shapes it can take."""

    def test_a_failed_ci_means_cd_never_starts(self):
        verdict = classify(DANGLING, [run(conclusion="failure", run_id=1000000002)], [])
        self.assertEqual(verdict.state, ABANDONED)
        self.assertIn("gate", verdict.reason)

    def test_the_remedy_names_the_run_to_rerun(self):
        """The operator should not have to work out which run stranded it."""
        verdict = classify(DANGLING, [run(conclusion="failure", run_id=1000000002)], [])
        self.assertIn("gh run rerun 1000000002 --failed", verdict.remedy)

    def test_a_cancelled_ci_is_the_same_break(self):
        verdict = classify(DANGLING, [run(conclusion="cancelled")], [])
        self.assertEqual(verdict.state, ABANDONED)

    def test_a_concluded_ci_with_no_conclusion_is_not_a_success(self):
        verdict = classify(DANGLING, [run(conclusion=None)], [])
        self.assertEqual(verdict.state, ABANDONED)

    def test_a_green_rerun_clears_the_attempt_it_replaced(self):
        """gh lists runs newest first. Judging on "any run that failed" rather
        than on the newest one reports a handoff abandoned after somebody has
        already discharged it — the same mistake as reading conclusions before
        status, one step further along."""
        verdict = classify(
            DANGLING,
            [run(run_id=2), run(conclusion="failure", run_id=1)],
            [],
        )
        self.assertEqual(verdict.state, PENDING)

    def test_the_newest_ci_run_is_the_one_that_decides(self):
        verdict = classify(
            DANGLING,
            [run(conclusion="failure", run_id=2), run(run_id=1)],
            [],
        )
        self.assertEqual(verdict.state, ABANDONED)
        self.assertIn("/2", verdict.reason)

    def test_a_cd_that_succeeded_without_tagging_is_still_a_break(self):
        """The sharpest form: the run reports success, and main is left naming a
        version that does not exist. CD fires on CI completing, so once CD for
        this commit has concluded the trigger is spent."""
        verdict = classify(DANGLING, [run()], [run(run_id=1000000003)])
        self.assertEqual(verdict.state, ABANDONED)
        self.assertIn("trigger is spent", verdict.reason)

    def test_the_report_names_the_version_and_where_it_is_pinned(self):
        verdict = classify(
            {"3.2.2": [".github/workflows/commit.yml:12"]},
            [run(conclusion="failure")],
            [],
        )
        body = "\n".join(verdict.lines())
        self.assertIn("v3.2.2", body)
        self.assertIn(".github/workflows/commit.yml:12", body)

    def test_a_long_pin_list_is_summarised_not_truncated_silently(self):
        locations = ["f{}.yml:1".format(i) for i in range(40)]
        verdict = classify({"3.2.2": locations}, [run(conclusion="failure")], [])
        body = "\n".join(verdict.lines())
        self.assertIn("(+35 more)", body)


class TestTheCheckEndToEnd(unittest.TestCase):
    def _inventory(self, tmp, version="3.2.2"):
        root = pathlib.Path(tmp)
        (root / "a.yml").write_text(
            "uses: context-and-oss/cicd/.github/workflows/commit.yml@v{}\n".format(version)
        )
        return FakeInventory(root, ["a.yml"])

    def test_a_shallow_checkout_refuses_rather_than_reporting_a_catastrophe(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            runner = Recorder(shallow="true")
            with self.assertRaises(ToolError) as caught:
                check(self._inventory(tmp), runner)
        self.assertIn("fetch-depth: 0", str(caught.exception))

    def test_a_checkout_with_no_tags_refuses_rather_than_flagging_everything(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            runner = Recorder(tags=[])
            with self.assertRaises(ToolError) as caught:
                check(self._inventory(tmp), runner)
        self.assertIn("refusing", str(caught.exception))

    def test_a_tag_pushed_while_the_runs_were_queried_is_not_reported_as_broken(self):
        """The one false positive the ordinary release path would produce: CD
        cuts the tag between the tag read and the verdict."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            runner = Recorder(
                tags=lambda nth: ["v3.2.1"] if nth == 1 else ["v3.2.1", "v3.2.2"],
                **{"ci.yml": [run(conclusion="failure")]}
            )
            verdict = check(self._inventory(tmp), runner)
        self.assertEqual(verdict.state, RESOLVED)
        self.assertIn(["git", "fetch", "--tags", "--quiet", "origin"], runner.calls)

    def test_a_failed_refetch_does_not_soften_the_verdict(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            runner = Recorder(fetch_rc=1, **{"ci.yml": [run(conclusion="failure")]})
            verdict = check(self._inventory(tmp), runner)
        self.assertEqual(verdict.state, ABANDONED)

    def test_pins_that_resolve_never_reach_the_api(self):
        """No run query, no tip read: the healthy path costs one git call."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            runner = Recorder(tags=["v3.2.2"])
            verdict = check(self._inventory(tmp), runner)
        self.assertEqual(verdict.state, RESOLVED)
        self.assertFalse([c for c in runner.calls if c[0] == "gh"])


class TestReadingRuns(unittest.TestCase):
    def test_runs_for_another_commit_are_not_this_commit_s_evidence(self):
        runner = Recorder(**{"cd.yml": [run(sha="a" * 40), run(sha="b" * 40, run_id=7)]})
        found = runs_for(runner, "cd.yml", "b" * 40)
        self.assertEqual([r["databaseId"] for r in found], [7])

    def test_the_caller_s_own_run_is_not_its_own_successor(self):
        """A step running inside CD must not read the run it is running in as
        the run that is going to fix the state it is reporting."""
        runner = Recorder(**{"cd.yml": [run(run_id=99), run(run_id=7)]})
        found = runs_for(runner, "cd.yml", "b" * 40, exclude_run_id="99")
        self.assertEqual([r["databaseId"] for r in found], [7])

    def test_unreadable_json_is_an_error_not_an_empty_list(self):
        class Broken(Recorder):
            def __call__(self, cmd):
                if cmd[:2] == ["gh", "run"]:
                    return 0, "not json", ""
                return super().__call__(cmd)

        with self.assertRaises(ToolError):
            runs_for(Broken(), "cd.yml", "b" * 40)

    def test_a_failed_query_is_an_error_not_an_empty_list(self):
        class Broken(Recorder):
            def __call__(self, cmd):
                if cmd[:2] == ["gh", "run"]:
                    return 1, "", "HTTP 403: API rate limit exceeded"
                return super().__call__(cmd)

        with self.assertRaises(ToolError) as caught:
            runs_for(Broken(), "cd.yml", "b" * 40)
        self.assertIn("rate limit", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
