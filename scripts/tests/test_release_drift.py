"""Regression proof for scripts/release_drift.py.

The detector exists because of a real silence. `cd.yml` failed on every run
between 2026-07-31 and 2026-08-04 and ~46 merged commits piled up unreleased
behind it, while CI stayed green and every PR check list stayed green. v1.11.0
finally shipped by pull request; nothing had ever said the releases had stopped.

So the property under test is not "does it notice drift" — it is **it must never
report clean when it could not look**. Every command whose answer feeds the
verdict is driven here in its failing form (shallow clone, git-cliff exiting
non-zero, git-cliff printing nothing, an unreadable issue list, a commit stamp
that is not an epoch) and each one must raise ToolError rather than return a
non-drifting report. That inversion — a tool that could not run reading as
"nothing to release" — is the same false pass the run-error classification in
src/quality and src/security exists to prevent, one level up.

The one command allowed to degrade is `gh run list`: the CD-run summary is
context printed into the issue body, not an input to the verdict.

Every command is served by a fake runner, so these tests touch no git repository,
no network, no clock and no GitHub issue.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "release_drift.py"

_spec = importlib.util.spec_from_file_location("release_drift", MODULE_PATH)
assert _spec and _spec.loader
rd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rd)

# 2026-08-04T00:00:00Z — fixed so no test depends on the wall clock.
NOW = 1785801600
DAY = 86400

OK = (0, "", "")


def result(stdout: str = "", code: int = 0, stderr: str = "") -> rd.CommandResult:
    return (code, stdout, stderr)


class FakeRunner:
    """Serves canned results by longest-listed-first command prefix.

    An unlisted command is an assertion failure rather than a default, so a test
    cannot accidentally pass because the code under test asked something the test
    never anticipated.
    """

    def __init__(self, table) -> None:
        self.table = list(table.items()) if isinstance(table, dict) else list(table)
        self.calls: list = []

    def __call__(self, cmd):
        cmd = list(cmd)
        self.calls.append(cmd)
        for key, res in self.table:
            key = list(key)
            if cmd[: len(key)] == key:
                return res
        raise AssertionError("unexpected command: {}".format(" ".join(cmd)))

    def ran(self, *prefix) -> bool:
        prefix = list(prefix)
        return any(call[: len(prefix)] == prefix for call in self.calls)

    def call_matching(self, *prefix):
        prefix = list(prefix)
        for call in self.calls:
            if call[: len(prefix)] == prefix:
                return call
        raise AssertionError("no call matching {}".format(" ".join(prefix)))


def git_table(
    *,
    shallow: str = "false",
    tag: rd.CommandResult = result("v1.11.0"),
    cliff: rd.CommandResult = result("v1.12.0"),
    count: rd.CommandResult = result("12"),
    log: rd.CommandResult = None,
) -> dict:
    if log is None:
        # newest first, as git log emits it; the oldest is 3 days old
        log = result("\n".join(str(NOW - n * DAY) for n in (1, 2, 3)))
    return {
        ("git", "rev-parse", "--is-shallow-repository"): result(shallow),
        ("git", "describe", "--tags", "--abbrev=0"): tag,
        ("git", "cliff", "--unreleased", "--bumped-version"): cliff,
        ("git", "rev-list", "--count"): count,
        ("git", "log", "--format=%ct"): log,
    }


def gh_table(*, issues: str = "[]", runs: rd.CommandResult = None) -> dict:
    if runs is None:
        runs = result(
            '[{"conclusion":"failure","status":"completed",'
            '"url":"https://github.com/context-and-oss/cicd/actions/runs/1",'
            '"createdAt":"2026-08-03T06:00:00Z"}]'
        )
    return {
        ("gh", "issue", "list"): result(issues),
        ("gh", "run", "list"): runs,
        ("gh", "label", "create"): OK,
        ("gh", "issue", "create"): result("https://github.com/context-and-oss/cicd/issues/14"),
        ("gh", "issue", "edit"): OK,
        ("gh", "issue", "close"): OK,
    }


def drift(
    latest_tag: str = "v1.11.0",
    next_version: str = "v1.12.0",
    commits_ahead: int = 12,
    oldest: int = NOW - 3 * DAY,
) -> rd.Drift:
    return rd.Drift(latest_tag, next_version, commits_ahead, oldest)


class TestVersionComparison(unittest.TestCase):
    def test_v_prefix_is_not_a_difference(self):
        """A tag spelled without the v must not read as permanent drift.

        git describe emits `v1.11.0`; cd.yml strips the v in places and a
        hand-pushed tag may never have carried one. A false alarm that can never
        be cleared trains people to ignore the issue, which is worse than none.
        """
        self.assertEqual(rd.normalise_version("v1.11.0"), rd.normalise_version("1.11.0"))
        self.assertFalse(rd.is_drifting(drift(latest_tag="1.11.0", next_version="v1.11.0")))
        self.assertFalse(rd.is_drifting(drift(latest_tag="V1.11.0", next_version="1.11.0")))

    def test_whitespace_is_stripped(self):
        self.assertEqual(rd.normalise_version("  v1.2.3\n"), "1.2.3")


class TestIsDrifting(unittest.TestCase):
    def test_drift_needs_both_a_new_version_and_commits(self):
        self.assertTrue(rd.is_drifting(drift(next_version="v1.12.0", commits_ahead=12)))

    def test_commits_that_bump_nothing_are_not_drift(self):
        """A chore-only backlog releases to the same version, so no issue is due.

        Flagging it would open an issue that no release could ever close.
        """
        self.assertFalse(rd.is_drifting(drift(next_version="v1.11.0", commits_ahead=12)))

    def test_no_commits_is_not_drift_whatever_cliff_computes(self):
        self.assertFalse(rd.is_drifting(drift(next_version="v9.9.9", commits_ahead=0)))
        self.assertFalse(rd.is_drifting(drift(commits_ahead=-1)))

    def test_repository_with_no_tag_and_commits_is_drift(self):
        self.assertTrue(rd.is_drifting(drift(latest_tag="", next_version="v0.1.0", commits_ahead=3)))


class TestDriftAge(unittest.TestCase):
    def test_age_in_days(self):
        self.assertAlmostEqual(rd.drift_age_days(NOW - 3 * DAY, NOW), 3.0)
        self.assertAlmostEqual(rd.drift_age_days(NOW - DAY // 2, NOW), 0.5)

    def test_future_commit_date_clamps_to_zero(self):
        """A skewed clock or a rebased future date must not produce a negative age.

        A negative age reads as below every threshold, so real drift would be
        hidden by a timestamp the committer controls.
        """
        self.assertEqual(rd.drift_age_days(NOW + 10 * DAY, NOW), 0.0)

    def test_no_commits_has_no_age(self):
        self.assertEqual(rd.drift_age_days(None, NOW), 0.0)


class TestDecideAction(unittest.TestCase):
    def test_truth_table(self):
        cases = [
            # drifting, age, threshold, has_issue -> action
            (True, 3.0, 2.0, False, rd.ACTION_OPEN),
            (True, 2.0, 2.0, False, rd.ACTION_OPEN),  # threshold is inclusive
            (True, 1.9, 2.0, False, rd.ACTION_NONE),  # inside the normal window
            (True, 3.0, 2.0, True, rd.ACTION_UPDATE),
            (True, 0.1, 2.0, True, rd.ACTION_UPDATE),  # keep an open issue accurate
            (False, 0.0, 2.0, True, rd.ACTION_CLOSE),
            (False, 0.0, 2.0, False, rd.ACTION_NONE),
            (False, 9.0, 2.0, True, rd.ACTION_CLOSE),  # released: age is irrelevant
        ]
        for drifting, age, threshold, has_issue, expected in cases:
            with self.subTest(drifting=drifting, age=age, has_issue=has_issue):
                self.assertEqual(
                    rd.decide_action(drifting, age, threshold, has_issue), expected
                )

    def test_zero_threshold_reports_immediately(self):
        self.assertEqual(rd.decide_action(True, 0.0, 0.0, False), rd.ACTION_OPEN)


class TestPickIssue(unittest.TestCase):
    def test_no_issues(self):
        self.assertEqual(rd.pick_issue([]), (None, []))

    def test_lowest_number_wins_and_extras_are_reported(self):
        """A human's second issue under the label must not make this flip.

        Lowest-number-wins is stable across runs, and the extras are named rather
        than silently ignored — the same "no silent caps" rule the gates follow.
        """
        number, duplicates = rd.pick_issue([{"number": 29}, {"number": 14}, {"number": 300}])
        self.assertEqual(number, 14)
        self.assertEqual(duplicates, [29, 300])

    def test_string_numbers_are_accepted(self):
        self.assertEqual(rd.pick_issue([{"number": "14"}]), (14, []))


class TestRendering(unittest.TestCase):
    def test_title_states_the_gap(self):
        self.assertEqual(
            rd.render_title(drift(commits_ahead=12)),
            "release drift: main is 12 commits ahead of v1.11.0",
        )

    def test_title_singular(self):
        self.assertIn("1 commit ahead", rd.render_title(drift(commits_ahead=1)))
        self.assertNotIn("1 commits", rd.render_title(drift(commits_ahead=1)))

    def test_title_without_a_tag(self):
        self.assertIn("(no tag yet)", rd.render_title(drift(latest_tag="")))

    def test_body_carries_the_marker_and_the_numbers(self):
        body = rd.render_body(drift(), 3.0, 2.0, "completed / failure on 2026-08-03", "http://run")
        self.assertTrue(body.startswith(rd.MARKER))
        self.assertIn("**12**", body)
        self.assertIn("v1.11.0", body)
        self.assertIn("v1.12.0", body)
        self.assertIn("3.0 days old", body)
        self.assertIn("2 days", body)  # %g, not "2.0"
        self.assertIn("completed / failure", body)
        self.assertIn("http://run", body)
        self.assertIn("closes itself", body)

    def test_body_points_at_the_spec_that_explains_the_release_path(self):
        """The issue must say how to release, not just that a release is due.

        A release cannot be pushed to main here, and someone reading this issue for
        the first time will otherwise try exactly that.
        """
        body = rd.render_body(drift(), 3.0, 2.0, "none found", "http://run")
        self.assertIn("release-by-pull-request.md", body)
        spec = REPO_ROOT / "specs" / "release-by-pull-request.md"
        self.assertTrue(spec.is_file(), "the spec the issue body links to must exist")

    def test_body_without_commits_says_the_date_is_unknown(self):
        body = rd.render_body(
            rd.Drift("v1.11.0", "v1.11.0", 0, None), 0.0, 2.0, "none found", "http://run"
        )
        self.assertIn("unknown", body)

    def test_close_comment_names_the_tag(self):
        self.assertIn("v1.11.0", rd.close_comment(drift()))


class TestMeasure(unittest.TestCase):
    def test_happy_path(self):
        runner = FakeRunner(git_table())
        d = rd.measure(runner)
        self.assertEqual(d.latest_tag, "v1.11.0")
        self.assertEqual(d.next_version, "v1.12.0")
        self.assertEqual(d.commits_ahead, 12)
        self.assertEqual(d.oldest_unreleased_epoch, NOW - 3 * DAY)

    def test_range_is_scoped_to_the_newest_tag(self):
        runner = FakeRunner(git_table())
        rd.measure(runner)
        self.assertIn("v1.11.0..HEAD", runner.call_matching("git", "rev-list", "--count"))
        self.assertIn("v1.11.0..HEAD", runner.call_matching("git", "log", "--format=%ct"))

    def test_repository_with_no_tags_counts_all_history(self):
        """`git describe` exiting non-zero is a legitimate pre-first-release state.

        It is the only command here allowed to fail, and it must widen the range to
        all history rather than abort or count zero.
        """
        runner = FakeRunner(git_table(tag=result("", 128, "fatal: No names found"), cliff=result("v0.1.0")))
        d = rd.measure(runner)
        self.assertEqual(d.latest_tag, "")
        self.assertIn("HEAD", runner.call_matching("git", "rev-list", "--count"))
        self.assertTrue(rd.is_drifting(d))

    def test_shallow_clone_is_refused(self):
        """Every number a shallow clone yields is wrong in the direction that hides
        drift: no tags reachable, a truncated count, and an "oldest" commit that is
        merely the oldest one fetched."""
        runner = FakeRunner(git_table(shallow="true"))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.measure(runner)
        self.assertIn("shallow", str(ctx.exception))
        self.assertIn("fetch-depth: 0", str(ctx.exception))

    def test_git_cliff_failing_is_never_no_drift(self):
        runner = FakeRunner(git_table(cliff=result("", 1, "error: no configuration")))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.measure(runner)
        self.assertIn("cliff", str(ctx.exception))

    def test_git_cliff_printing_nothing_is_never_no_drift(self):
        """Exit 0 with empty output is the shape a silent false pass takes."""
        runner = FakeRunner(git_table(cliff=result("")))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.measure(runner)
        self.assertIn("no version", str(ctx.exception))

    def test_unreadable_commit_count_is_refused(self):
        runner = FakeRunner(git_table(count=result("lots")))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.measure(runner)
        self.assertIn("not a number", str(ctx.exception))

    def test_count_and_log_disagreeing_is_refused(self):
        """Counted commits with no log lines means one of the two lied; refuse."""
        runner = FakeRunner(git_table(count=result("12"), log=result("")))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.measure(runner)
        self.assertIn("listed none", str(ctx.exception))

    def test_non_epoch_timestamp_is_refused(self):
        runner = FakeRunner(git_table(log=result("2026-08-01T00:00:00Z")))
        with self.assertRaises(rd.ToolError):
            rd.measure(runner)

    def test_clean_tree_has_no_oldest_commit(self):
        runner = FakeRunner(git_table(cliff=result("v1.11.0"), count=result("0")))
        d = rd.measure(runner)
        self.assertEqual(d.commits_ahead, 0)
        self.assertIsNone(d.oldest_unreleased_epoch)
        self.assertFalse(runner.ran("git", "log", "--format=%ct"))


class TestCdSummary(unittest.TestCase):
    def test_reports_status_and_url(self):
        summary = rd.latest_cd_summary(FakeRunner(gh_table()))
        self.assertIn("failure", summary)
        self.assertIn("actions/runs/1", summary)

    def test_gh_failing_degrades_to_a_note(self):
        """This one command may degrade: it is context in the body, not a verdict."""
        runner = FakeRunner(gh_table(runs=result("", 1, "gh: could not authenticate")))
        self.assertEqual(rd.latest_cd_summary(runner), rd.CD_SUMMARY_UNAVAILABLE)

    def test_unreadable_json_degrades_to_a_note(self):
        runner = FakeRunner(gh_table(runs=result("not json")))
        self.assertIn("unavailable", rd.latest_cd_summary(runner))

    def test_no_runs_at_all(self):
        """No CD run ever is itself the symptom worth naming in the body."""
        self.assertEqual(rd.latest_cd_summary(FakeRunner(gh_table(runs=result("[]")))), "none found")


class TestOpenDriftIssues(unittest.TestCase):
    def test_parses_the_list(self):
        runner = FakeRunner(gh_table(issues='[{"number":14,"title":"release drift: ..."}]'))
        self.assertEqual(rd.open_drift_issues(runner)[0]["number"], 14)

    def test_query_is_scoped_to_the_label_and_open_state(self):
        runner = FakeRunner(gh_table())
        rd.open_drift_issues(runner)
        call = runner.call_matching("gh", "issue", "list")
        self.assertIn(rd.LABEL, call)
        self.assertIn("open", call)

    def test_gh_failing_is_fatal(self):
        """Without the issue list there is no dedup, so proceeding would open a
        second issue on every run. Fail instead."""
        runner = FakeRunner(gh_table(issues=""))
        runner.table = [(("gh", "issue", "list"), result("", 1, "HTTP 403"))]
        with self.assertRaises(rd.ToolError):
            rd.open_drift_issues(runner)

    def test_unreadable_json_is_fatal(self):
        runner = FakeRunner(gh_table(issues="{oops"))
        with self.assertRaises(rd.ToolError):
            rd.open_drift_issues(runner)

    def test_non_list_json_is_fatal(self):
        runner = FakeRunner(gh_table(issues='{"number": 1}'))
        with self.assertRaises(rd.ToolError) as ctx:
            rd.open_drift_issues(runner)
        self.assertIn("expected a list", str(ctx.exception))


class TestCheck(unittest.TestCase):
    def runner(self, **kwargs) -> FakeRunner:
        table = dict(git_table(**{k: v for k, v in kwargs.items() if k in
                                 ("shallow", "tag", "cliff", "count", "log")}))
        table.update(gh_table(**{k: v for k, v in kwargs.items() if k in ("issues", "runs")}))
        return FakeRunner(table)

    def test_opens_one_issue_past_the_threshold(self):
        runner = self.runner()
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0, run_url="http://run")
        self.assertEqual(report.action, rd.ACTION_OPEN)
        self.assertTrue(report.performed)
        create = runner.call_matching("gh", "issue", "create")
        self.assertIn(rd.LABEL, create)
        self.assertIn(rd.MARKER, "".join(create))
        # the label must be ensured first, or create fails on a missing label
        self.assertTrue(runner.ran("gh", "label", "create"))
        self.assertIn("opened", report.detail)

    def test_stays_quiet_inside_the_normal_release_window(self):
        runner = self.runner(log=result(str(NOW - 3600)))
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0)
        self.assertEqual(report.action, rd.ACTION_NONE)
        self.assertTrue(report.drifting)
        self.assertFalse(runner.ran("gh", "issue", "create"))
        self.assertFalse(runner.ran("gh", "issue", "close"))

    def test_updates_the_existing_issue_instead_of_opening_a_second(self):
        runner = self.runner(issues='[{"number":14}]')
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0)
        self.assertEqual(report.action, rd.ACTION_UPDATE)
        self.assertEqual(report.issue_number, 14)
        self.assertFalse(runner.ran("gh", "issue", "create"))
        self.assertIn("14", runner.call_matching("gh", "issue", "edit"))

    def test_closes_the_issue_when_a_release_lands(self):
        """The issue closing itself is the signal that a release happened."""
        runner = self.runner(cliff=result("v1.11.0"), count=result("0"), issues='[{"number":14}]')
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0)
        self.assertEqual(report.action, rd.ACTION_CLOSE)
        close = runner.call_matching("gh", "issue", "close")
        self.assertIn("14", close)
        self.assertIn("Drift cleared", "".join(close))
        self.assertFalse(runner.ran("gh", "issue", "create"))

    def test_nothing_to_do_on_a_released_tree(self):
        runner = self.runner(cliff=result("v1.11.0"), count=result("0"))
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0)
        self.assertEqual(report.action, rd.ACTION_NONE)
        self.assertFalse(report.drifting)
        self.assertFalse(runner.ran("gh", "issue", "create"))

    def test_duplicate_issues_are_named_not_swallowed(self):
        runner = self.runner(issues='[{"number":29},{"number":14}]')
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0)
        self.assertEqual(report.issue_number, 14)
        self.assertEqual(report.duplicates, [29])
        self.assertTrue(any("#29" in line for line in report.lines()))

    def test_dry_run_touches_no_issue(self):
        runner = self.runner()
        report = rd.check(runner, now_epoch=NOW, threshold_days=2.0, dry_run=True)
        self.assertEqual(report.action, rd.ACTION_OPEN)
        self.assertFalse(report.performed)
        self.assertFalse(any(call[0] == "gh" for call in runner.calls))
        self.assertIn("dry run", report.detail)

    def test_a_tool_failure_raises_instead_of_reporting_clean(self):
        """The property this whole module exists for.

        A detector that could not look must never produce a report at all, because
        every report reads as a verdict.
        """
        for name, broken in [
            ("shallow", {"shallow": "true"}),
            ("cliff-failed", {"cliff": result("", 1, "boom")}),
            ("cliff-empty", {"cliff": result("")}),
            ("bad-count", {"count": result("many")}),
            ("bad-stamp", {"log": result("yesterday")}),
            ("issue-list-unreadable", {"issues": "{oops"}),
        ]:
            with self.subTest(failure=name):
                with self.assertRaises(rd.ToolError):
                    rd.check(self.runner(**broken), now_epoch=NOW, threshold_days=2.0)

    def test_report_lines_state_the_verdict(self):
        runner = self.runner()
        lines = rd.check(runner, now_epoch=NOW, threshold_days=2.0).lines()
        self.assertTrue(lines[0].startswith("tag=v1.11.0 next=v1.12.0 ahead=12"))
        self.assertIn("drift reported", lines[-1])


class TestCliContract(unittest.TestCase):
    """The workflow calls the dashed entry point, so it has to keep working."""

    def test_entry_point_exists_and_is_executable(self):
        entry = REPO_ROOT / "scripts" / "check-release-drift.py"
        self.assertTrue(entry.is_file())
        self.assertTrue(entry.stat().st_mode & 0o111, "entry point must be executable")

    def test_negative_threshold_is_rejected(self):
        import subprocess

        proc = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "check-release-drift.py"),
             "--threshold-days", "-1", "--dry-run"],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("must not be negative", proc.stderr)


if __name__ == "__main__":
    unittest.main()
