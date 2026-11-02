"""Regression proof for scripts/commit_subjects.py.

The gate exists because of a real silence. A `fix(quality):` commit landed on
`main` with its subject mangled into free text ("Second-pass review follow-up on
the gate. One real gap, two wording corrections, one decline."). git-cliff dropped it,
`--bumped-version` printed the version already tagged, CD found "nothing to bump"
and reported success, and no tag was cut. Nothing was red. `release-drift.yml`
could not see it either: it defines drift as newest-tag vs `git cliff
--bumped-version`, which is the same answer from the same source that had already
dropped the commit.

So the property under test is the asymmetry. Every subject cliff **does** release
must pass (a false failure here blocks a good release), and every subject cliff
**drops** must fail (a false pass here loses one silently). The accept/reject
tables below are not invented from the Conventional Commits spec — they are the
measured output of git-cliff 2.13.1 against this repository's own cliff.toml, one
commit at a time after a v1.0.0 tag, recorded in
specs/refuse-a-commit-git-cliff-cannot-release.md.

Pure logic: no git, no subprocess, no clock.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "commit_subjects.py"

_spec = importlib.util.spec_from_file_location("commit_subjects", MODULE_PATH)
assert _spec and _spec.loader
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


# Measured: git-cliff bumps a version for each of these.
RELEASED = [
    "fix(quality): a real fix",
    "feat: a feature",
    "feat(x)!: breaking feature",
    "fix!: breaking fix",
    "docs: documentation",
    "refactor: shuffling",
    "perf: faster",
    "build: build system",
    "revert: undo a thing",
    "wip: unknown type",
    "FIX: uppercase type",
    # Measured as skipped by cliff's parsers on purpose — they release nothing by
    # design and must not be reported as a defect.
    "chore: housekeeping",
    "ci: pipeline tweak",
    "test: more tests",
    "style: formatting",
    # Shapes the grammar allows that no probe covered individually.
    "fix(a/b-c): nested-looking scope",
    "chore(): empty scope",
    "fix: subject with: an inner colon",
    "feat(deps)!: bump everything",
]

# Measured: git-cliff drops each of these with a parse error, or cannot parse it.
DROPPED = {
    "Second-pass review follow-up on the gate. One real gap.": "free text",
    'Revert "fix(quality): a real fix"': "revert",
    "Merge pull request #11 from example-org/branch": "merge subject",
    "fix : space before colon": "space before colon",
    # Not measured against cliff as a drop — cliff accepts it and bumps. Rejected
    # here on purpose (see the module docstring): stricter can only cost an author
    # an amend, while more lenient costs a release.
    "fix:no space after colon": "no space after colon",
}


class TestAcceptsWhatCliffReleases(unittest.TestCase):
    def test_every_released_subject_passes(self):
        for subject in RELEASED:
            with self.subTest(subject=subject):
                self.assertIsNone(
                    cs.subject_problem(subject),
                    "cliff releases this subject, so the gate must not block it",
                )


class TestRejectsWhatCliffDrops(unittest.TestCase):
    def test_every_dropped_subject_fails(self):
        for subject, label in DROPPED.items():
            with self.subTest(subject=subject, kind=label):
                self.assertIsNotNone(
                    cs.subject_problem(subject),
                    "cliff drops this subject silently, so the gate must reject it",
                )

    def test_the_real_incident_subject_is_named_specifically(self):
        reason = cs.subject_problem(
            "Second-pass review follow-up on the gate. One real gap, two wording "
            "corrections, one decline."
        )
        self.assertIn("free text", reason)

    def test_near_misses_name_the_actual_mistake(self):
        cases = {
            "fix(quality) missing colon entirely": "no colon",
            "fix(quality:) unclosed scope": "no colon",
            "fix(quality": "unclosed scope",
            "fix:": "description after the colon is empty",
            "fix:   ": "description after the colon is empty",
            "fix-it: hyphenated type": "other than a letter",
            'Revert "chore: seed"': "revert",
        }
        for subject, fragment in cases.items():
            with self.subTest(subject=subject):
                reason = cs.subject_problem(subject)
                self.assertIsNotNone(reason, subject)
                self.assertIn(fragment, reason)

    def test_empty_and_whitespace_subjects(self):
        for subject in ("", "   ", "\n", "\t"):
            with self.subTest(subject=repr(subject)):
                self.assertEqual(cs.subject_problem(subject), "the subject is empty")

    def test_surrounding_whitespace_is_not_the_authors_mistake(self):
        self.assertIsNone(cs.subject_problem("  fix: a real fix  "))


class TestReview(unittest.TestCase):
    def test_input_order_is_preserved_and_only_problems_are_returned(self):
        commits = [
            cs.Commit("aaaaaaaa", "fix: fine"),
            cs.Commit("bbbbbbbb", "broken subject"),
            cs.Commit("cccccccc", "chore: also fine"),
            cs.Commit("dddddddd", "another broken one"),
        ]
        problems = cs.review(commits)
        self.assertEqual([p.sha for p in problems], ["bbbbbbbb", "dddddddd"])

    def test_a_clean_range_has_no_problems(self):
        self.assertEqual(cs.review([cs.Commit("a", "feat: x")]), [])

    def test_no_commits_yields_no_problems(self):
        # The "examined nothing" judgement belongs to the CLI, which knows whether
        # an empty range is legitimate; the pure review must not invent a verdict.
        self.assertEqual(cs.review([]), [])


class TestRenderReport(unittest.TestCase):
    def test_clean_report_states_what_was_examined(self):
        commits = [cs.Commit("a" * 40, "fix: x"), cs.Commit("b" * 40, "chore: y")]
        lines = cs.render_report(commits, [], "v1.0.0..HEAD")
        text = "\n".join(lines)
        self.assertIn("examined 2 commit(s) in v1.0.0..HEAD", text)
        self.assertIn("OK", text)

    def test_failing_report_names_the_subject_the_reason_and_the_remedy(self):
        commits = [cs.Commit("a" * 40, "fix: x"), cs.Commit("b" * 40, "oops")]
        problems = cs.review(commits)
        text = "\n".join(cs.render_report(commits, problems, "abc..HEAD"))
        self.assertIn("examined 2 commit(s)", text)
        self.assertIn("oops", text)
        self.assertIn("bbbbbbbb", text)  # short sha, not the full 40
        self.assertIn("free text", text)
        self.assertIn("1 of 2 commit(s) would be dropped", text)
        # The consequence has to be in the message: the author's instinct is that
        # a subject is cosmetic, and the reason it is not is that CD stays green.
        self.assertIn("CD would report success", text)
        self.assertIn("git commit --amend", text)

    def test_clean_report_never_claims_more_than_it_examined(self):
        lines = cs.render_report([], [], "v1.2.3..HEAD")
        self.assertIn("examined 0 commit(s)", lines[0])


if __name__ == "__main__":
    unittest.main()
