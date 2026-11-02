"""Regression proof for scripts/ci/wait-for-release-merge.sh.

Only `release.yml` blocks on a merge, and it does so to cut a tag in the run the
operator started. So the one thing that must never happen here is exit 0 on
anything but a real merge: the caller tags on 0, and a tag cut against an
unmerged or unknown state points at the wrong tree.

The states that need distinguishing, and why each gets its own exit code:

  0  MERGED                    the only path that may lead to a tag
  1  still OPEN at the budget   auto-merge is still armed; the bump is not lost
  2  CLOSED, or DIRTY          waiting cannot fix either; a conflict fails fast
                               rather than hiding under a timeout message
  3  unreadable, or a state    unknown is not unmerged — say so instead of
     this script does not know  guessing in either direction

`gh` and `sleep` are stubs on PATH; `gh` answers from a scripted sequence, so a
transient read failure followed by a merge is drivable, and `sleep` returns
immediately so the real polling budget costs no wall-clock here.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "ci" / "wait-for-release-merge.sh"

# Serves one line of the scenario file per call, then repeats the last line
# forever, so "OPEN until the budget runs out" needs one line, not a hundred.
GH_STUB = r"""#!/usr/bin/env bash
printf '%s\n' "gh $*" >> "$CALL_LOG"
n=$(cat "$STUB_STATE/n" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" > "$STUB_STATE/n"
total=$(wc -l < "$STUB_SCENARIO" | tr -d ' ')
if [ "$n" -gt "$total" ]; then n="$total"; fi
line=$(sed -n "${n}p" "$STUB_SCENARIO")
case "$line" in
  FAIL*) printf '%s\n' "${line#FAIL }" >&2; exit 1 ;;
esac
printf '%s\n' "$line"
exit 0
"""

SLEEP_STUB = "#!/usr/bin/env bash\nexit 0\n"


class Harness:
    def __init__(self, tmp: str, scenario: list) -> None:
        self.root = pathlib.Path(tmp)
        self.bin = self.root / "stubbin"
        self.state = self.root / "state"
        self.log = self.root / "calls.log"
        for d in (self.bin, self.state):
            d.mkdir(parents=True, exist_ok=True)

        scenario_file = self.root / "scenario.txt"
        scenario_file.write_text("\n".join(scenario) + "\n")

        for name, body in (("gh", GH_STUB), ("sleep", SLEEP_STUB)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)

        self.env = dict(os.environ)
        self.env.update(
            PATH="{}:{}".format(self.bin, os.environ["PATH"]),
            CALL_LOG=str(self.log),
            STUB_STATE=str(self.state),
            STUB_SCENARIO=str(scenario_file),
            GH_TOKEN="stub-token",
        )

    def run(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPT)] + list(args),
            capture_output=True, text=True, cwd=str(self.root), env=self.env,
        )

    def calls(self) -> list:
        return self.log.read_text().splitlines() if self.log.is_file() else []


def snapshot(state, merged_at="-", merge_state="CLEAN"):
    return "\t".join([state, merged_at, merge_state])


def harness(scenario):
    return Harness(tempfile.mkdtemp(), scenario)


class TestMerged(unittest.TestCase):
    def test_a_merged_pull_request_exits_zero(self):
        h = harness([snapshot("MERGED", "2026-08-04T11:00:00Z")])
        proc = h.run("chore/release-v1.12.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("merged at 2026-08-04T11:00:00Z", proc.stdout)

    def test_it_waits_through_open_polls_then_succeeds(self):
        h = harness([
            snapshot("OPEN", merge_state="UNKNOWN"),
            snapshot("OPEN", merge_state="BLOCKED"),
            snapshot("MERGED", "2026-08-04T11:00:00Z"),
        ])
        proc = h.run("chore/release-v1.12.0", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len([c for c in h.calls() if c.startswith("gh pr view")]), 3)

    def test_blocked_is_not_treated_as_a_failure(self):
        """BLOCKED is the normal state of a pull request whose required check has
        not finished — which is every release pull request for its first minutes."""
        h = harness([snapshot("OPEN", merge_state="BLOCKED"), snapshot("MERGED", "t")])
        self.assertEqual(h.run("b", "--interval-seconds", "1").returncode, 0)

    def test_unknown_mergeability_is_not_treated_as_a_failure(self):
        """GitHub reports UNKNOWN while it computes mergeability; reading that as
        unmergeable would fail every release in its first seconds."""
        h = harness([snapshot("OPEN", merge_state="UNKNOWN"), snapshot("MERGED", "t")])
        self.assertEqual(h.run("b", "--interval-seconds", "1").returncode, 0)


class TestNeverExitsZeroWithoutAMerge(unittest.TestCase):
    """The caller tags on exit 0 — nothing else may produce it."""

    def test_every_non_merged_outcome_is_non_zero(self):
        cases = [
            ("still open", [snapshot("OPEN")], 1),
            ("closed", [snapshot("CLOSED")], 2),
            ("conflict", [snapshot("OPEN", merge_state="DIRTY")], 2),
            ("unreadable", ["FAIL gh: not found"], 3),
            ("unknown state", [snapshot("LOCKED")], 3),
        ]
        for name, scenario, expected in cases:
            with self.subTest(case=name):
                h = harness(scenario)
                proc = h.run("b", "--timeout-seconds", "2", "--interval-seconds", "1")
                self.assertEqual(proc.returncode, expected, proc.stderr)


class TestTimeout(unittest.TestCase):
    def test_a_timeout_says_the_bump_is_not_lost(self):
        """Auto-merge stays armed after this run gives up, so the message must not
        read as 'the release failed' — the pull request may still land."""
        h = harness([snapshot("OPEN", merge_state="BLOCKED")])
        proc = h.run("chore/release-v1.12.0", "--timeout-seconds", "2", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("still armed", proc.stderr)
        self.assertIn("BLOCKED", proc.stderr)

    def test_it_polls_more_than_once_within_the_budget(self):
        h = harness([snapshot("OPEN")])
        h.run("b", "--timeout-seconds", "5", "--interval-seconds", "1")
        polls = len([c for c in h.calls() if c.startswith("gh pr view")])
        self.assertGreaterEqual(polls, 5, "the budget was not actually spent polling")


class TestConflict(unittest.TestCase):
    def test_a_conflict_fails_immediately_not_at_the_budget(self):
        """Burning the budget on a conflict buries the real reason under a
        timeout message, and no amount of waiting resolves one."""
        h = harness([snapshot("OPEN", merge_state="DIRTY")])
        proc = h.run("b", "--timeout-seconds", "600", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("conflicts with main", proc.stderr)
        self.assertEqual(len([c for c in h.calls() if c.startswith("gh pr view")]), 1)


class TestReadFailures(unittest.TestCase):
    def test_one_transient_failure_does_not_abandon_the_release(self):
        """A single API blip during a release must not abandon a pull request that
        is seconds from merging."""
        h = harness([
            "FAIL HTTP 502",
            "FAIL HTTP 502",
            snapshot("MERGED", "2026-08-04T11:00:00Z"),
        ])
        proc = h.run("b", "--timeout-seconds", "600", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("could not read", proc.stdout + proc.stderr)

    def test_persistent_failure_reports_unknown_not_unmerged(self):
        """An unreadable pull request is an unknown state. Reporting it as
        'not merged' would be a guess, and the tag depends on the answer."""
        h = harness(["FAIL HTTP 401 Bad credentials"])
        proc = h.run("b", "--timeout-seconds", "600", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("merge state is unknown", proc.stderr)
        self.assertIn("not the same as unmerged", proc.stderr)

    def test_the_budget_expiring_mid_failure_reports_unknown_not_unmerged(self):
        """Caught by the test above before it ever ran: a short budget spent
        entirely on failed reads used to fall through to the timeout exit, which
        says 'not merged, auto-merge still armed'. That is a verdict about a pull
        request the run never read. Unknown gets its own code."""
        h = harness(["FAIL HTTP 502"])
        proc = h.run("b", "--timeout-seconds", "2", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("unknown, not unmerged", proc.stderr)
        self.assertNotIn("still armed", proc.stderr)

    def test_the_failure_counter_is_consecutive_not_cumulative(self):
        """Five scattered blips across a long wait are not the same signal as five
        in a row, and only the latter means the credential or API is gone."""
        scenario = []
        for _ in range(4):
            scenario += ["FAIL HTTP 502", snapshot("OPEN")]
        scenario.append(snapshot("MERGED", "t"))
        h = harness(scenario)
        proc = h.run("b", "--timeout-seconds", "600", "--interval-seconds", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestArguments(unittest.TestCase):
    def test_a_missing_branch_is_refused(self):
        h = harness([snapshot("MERGED")])
        self.assertNotEqual(h.run().returncode, 0)

    def test_a_non_numeric_budget_is_refused(self):
        h = harness([snapshot("MERGED")])
        for bad in ["abc", "-5", "0", "1.5"]:
            with self.subTest(value=bad):
                proc = h.run("b", "--timeout-seconds", bad)
                self.assertEqual(proc.returncode, 3, proc.stderr)
                self.assertIn("positive integers", proc.stderr)

    def test_an_unknown_argument_is_refused(self):
        h = harness([snapshot("MERGED")])
        proc = h.run("b", "--wait-forever")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("unknown argument", proc.stderr)


if __name__ == "__main__":
    unittest.main()
