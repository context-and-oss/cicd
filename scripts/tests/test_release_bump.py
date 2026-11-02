"""Regression proof for scripts/release_bump.py and scripts/check-release-bump.py.

The silence under test shipped twice. `git cliff --bumped-version` partitions
history by commit date, so `feat(quality): witness every language with test legs`
— merged from a branch that stayed open across v1.14.1 — was filed under a release
that had already shipped, and v1.14.2 went out as a patch. v1.14.3 repeated it.
Both features sit behind their tags permanently: no later bump can account for a
commit cliff has already assigned to a shipped release.

The property is the asymmetry, as everywhere else in this repository. A release
whose bump kind matches its history must pass, because a false failure blocks every
release until someone rewrites a subject. A release whose bump kind does not match
must fail, because a feature released as a patch is byte-for-byte indistinguishable
from a release that shipped no features — well-formed tag, complete release notes
(they come from `--unreleased`, which saw the feature), green CI, and a
`release-drift.yml` whose two sides both come from the cliff that dropped it.

The classification tables below are not read off the Conventional Commits spec.
They are the measured output of git-cliff 2.13.1 — the version
.github/actions/install-git-cliff pins — against this repository's own cliff.toml,
one commit at a time after a v1.0.0 tag. See
specs/prove-the-bump-matches-its-history.md.

Pure logic: no git, no subprocess, no clock. The one test that touches the
filesystem reads the real cliff.toml on purpose, to fail when its skip rule drifts
away from what this check assumes.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rb = _load("release_bump", "release_bump.py")
crb = _load("check_release_bump", "check-release-bump.py")

# cliff.toml's one `skip = true` rule, as this repository writes it today. The
# guard test below reads the real file and fails if it has moved.
SKIP = ["^chore|^ci|^test|^style"]


def commit(subject: str, body: str = "", sha: str = "0123456789abcdef") -> "rb.Commit":
    return rb.Commit(sha=sha, subject=subject, body=body)


def kind_of(subject: str, body: str = ""):
    return rb.classify_commit(commit(subject, body), SKIP).kind


class TestClassifyAgainstMeasuredCliff(unittest.TestCase):
    """Every row here was measured: base v1.0.0, one commit, this cliff.toml."""

    def test_feat_is_minor(self):
        # measured: v1.1.0
        for subject in ("feat: a feature", "feat(quality): witness every language"):
            with self.subTest(subject=subject):
                self.assertEqual(rb.MINOR, kind_of(subject))

    def test_ordinary_types_are_patch(self):
        # measured: v1.0.1 for each
        for ctype in ("fix", "docs", "refactor", "perf", "revert", "build"):
            with self.subTest(type=ctype):
                self.assertEqual(rb.PATCH, kind_of("{}: something".format(ctype)))

    def test_unknown_but_parseable_type_is_patch(self):
        # cliff's default parser releases a patch for a type it has no group for,
        # and guessing "nothing" here would let a real release through as no-op.
        self.assertEqual(rb.PATCH, kind_of("wip: half a thing"))

    def test_skipped_types_release_nothing(self):
        # measured: v1.0.0 — no bump at all
        for ctype in ("chore", "ci", "test", "style"):
            with self.subTest(type=ctype):
                self.assertIsNone(kind_of("{}: something".format(ctype)))

    def test_bang_is_major_and_beats_skip(self):
        # measured: v2.0.0 for all four. cliff.toml lists the breaking-subject
        # parser before the skip rule, so `!` wins.
        for subject in ("fix!: x", "feat!: x", "chore!: x", "ci!: x"):
            with self.subTest(subject=subject):
                self.assertEqual(rb.MAJOR, kind_of(subject))

    def test_bang_with_scope_is_major(self):
        self.assertEqual(rb.MAJOR, kind_of("feat(api)!: drop the old surface"))

    def test_breaking_footer_in_body_is_major(self):
        # measured: v2.0.0
        for footer in ("BREAKING CHANGE: gone", "BREAKING-CHANGE: gone"):
            with self.subTest(footer=footer):
                self.assertEqual(rb.MAJOR, kind_of("fix: x", "some prose\n\n" + footer))

    def test_breaking_footer_must_start_a_line(self):
        # Prose mentioning the phrase is not a footer. Treating it as one would
        # refuse a correct patch release over a sentence.
        self.assertEqual(
            rb.PATCH, kind_of("fix: x", "this is not a BREAKING CHANGE: honestly")
        )

    def test_unparseable_subject_contributes_nothing(self):
        # cliff drops it under filter_unconventional. Refusing it belongs to
        # scripts/check-commit-subjects.py, on the pull request.
        for subject in (
            "Second-pass review follow-up on the gate.",
            "fix:no space after the colon",
            "Merge pull request #14 from example-org/chore/release-v1.14.2",
            "",
        ):
            with self.subTest(subject=subject):
                self.assertIsNone(kind_of(subject))

    def test_type_recognition_ignores_case_but_the_skip_regex_does_not(self):
        # Measured, and an asymmetry worth knowing before touching either half:
        #   FEAT: x     -> v1.1.0   type matching is case-insensitive
        #   Feat(x): y  -> v1.1.0
        #   Chore: x    -> v1.0.1   `^chore` is a case-SENSITIVE regex, so a
        #   CHORE: x    -> v1.0.1   capitalised chore releases a patch
        # So the type is lowercased for the feat test and the skip patterns are
        # applied to the subject verbatim. Lowercasing before the skip match would
        # drop a release cliff does perform.
        self.assertEqual(rb.MINOR, kind_of("FEAT: shouting"))
        self.assertEqual(rb.MINOR, kind_of("Feat(x): shouting"))
        self.assertEqual(rb.PATCH, kind_of("Chore: shouting"))
        self.assertEqual(rb.PATCH, kind_of("CHORE: shouting"))

    def test_skip_regex_prefix_behaviour_is_reproduced(self):
        # `^ci` matches `citizen:` for cliff, so it matches here. Translating the
        # rule into a list of type names would silently disagree with cliff on
        # exactly the commits nobody writes on purpose.
        self.assertIsNone(kind_of("citizen: an odd type"))


class TestSkipDefect(unittest.TestCase):
    """chore: + BREAKING CHANGE body releases nothing at all — measured v1.0.0."""

    def test_reported_as_a_defect(self):
        contribution = rb.classify_commit(
            commit("chore: tidy", "BREAKING CHANGE: the API is gone"), SKIP
        )
        self.assertIsNone(contribution.kind)
        self.assertIsNotNone(contribution.defect)
        self.assertIn("releases nothing at all", contribution.defect)
        self.assertIn("chore!:", contribution.defect)

    def test_skipped_type_without_a_footer_is_no_defect(self):
        contribution = rb.classify_commit(commit("chore: tidy"), SKIP)
        self.assertIsNone(contribution.kind)
        self.assertIsNone(contribution.defect)

    def test_a_defect_refuses_the_release_on_its_own(self):
        # Even a range whose bump kind is otherwise correct: the breaking change
        # in it ships to nobody, and the version says nothing about that.
        contributions = rb.classify(
            [
                commit("chore: tidy", "BREAKING CHANGE: gone", sha="aaaaaaaa"),
                commit("fix: a real fix", sha="bbbbbbbb"),
            ],
            SKIP,
        )
        problems = rb.review("1.0.0", "1.0.1", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("aaaaaaaa", problems[0])


class TestRequiredBump(unittest.TestCase):
    def test_highest_rank_wins(self):
        contributions = rb.classify(
            [commit("fix: a"), commit("feat: b"), commit("docs: c")], SKIP
        )
        self.assertEqual(rb.MINOR, rb.required_bump(contributions))

    def test_major_beats_minor(self):
        contributions = rb.classify([commit("feat: a"), commit("fix!: b")], SKIP)
        self.assertEqual(rb.MAJOR, rb.required_bump(contributions))

    def test_nothing_releasable_is_none(self):
        contributions = rb.classify(
            [commit("chore: a"), commit("Merge branch 'main'"), commit("ci: b")], SKIP
        )
        self.assertIsNone(rb.required_bump(contributions))

    def test_empty_range_is_none(self):
        self.assertIsNone(rb.required_bump([]))


class TestObservedBump(unittest.TestCase):
    def test_each_kind(self):
        self.assertEqual(rb.MAJOR, rb.observed_bump("1.14.3", "2.0.0"))
        self.assertEqual(rb.MINOR, rb.observed_bump("1.14.3", "1.15.0"))
        self.assertEqual(rb.PATCH, rb.observed_bump("1.14.3", "1.14.4"))
        self.assertEqual(rb.NONE, rb.observed_bump("1.14.3", "1.14.3"))

    def test_leading_v_is_accepted_on_either_side(self):
        self.assertEqual(rb.MINOR, rb.observed_bump("v1.14.3", "V1.15.0"))

    def test_pre_one_zero_needs_no_special_case(self):
        # measured: v0.1.0 + feat -> v0.2.0, v0.1.0 + fix! -> v1.0.0
        self.assertEqual(rb.MINOR, rb.observed_bump("0.1.0", "0.2.0"))
        self.assertEqual(rb.MAJOR, rb.observed_bump("0.1.0", "1.0.0"))

    def test_multi_step_and_backwards_are_irregular(self):
        # cliff never produces these, so reading a two-minor jump as "minor" would
        # let a hand-edited or truncated version through as agreement.
        for current, nxt in (
            ("1.14.3", "1.16.0"),
            ("1.14.3", "1.14.6"),
            ("1.14.3", "3.0.0"),
            ("1.14.3", "1.14.2"),
            ("1.14.3", "2.0.1"),
            ("1.14.3", "1.15.1"),
        ):
            with self.subTest(step=(current, nxt)):
                self.assertEqual(rb.IRREGULAR, rb.observed_bump(current, nxt))

    def test_non_semver_is_unclassifiable(self):
        for current, nxt in (
            ("1.14.3", "1.15"),
            ("not-a-version", "1.15.0"),
            ("1.14.3", "1.15.0-rc1"),
            ("1.14.3", ""),
        ):
            with self.subTest(step=(current, nxt)):
                self.assertIsNone(rb.observed_bump(current, nxt))


class TestReview(unittest.TestCase):
    def test_a_matching_bump_has_no_problems(self):
        contributions = rb.classify([commit("feat: a"), commit("fix: b")], SKIP)
        self.assertEqual([], rb.review("1.14.3", "1.15.0", contributions))

    def test_nothing_releasable_and_no_release_agrees(self):
        contributions = rb.classify([commit("chore: a")], SKIP)
        self.assertEqual([], rb.review("1.14.3", "1.14.3", contributions))

    def test_the_shipped_regression_is_refused(self):
        # The exact shape of v1.14.2: a feat in the range, a patch computed.
        contributions = rb.classify([commit("feat(quality): witness"), commit("fix: x")], SKIP)
        problems = rb.review("1.14.1", "1.14.2", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("requires a minor bump", problems[0])
        self.assertIn("permanent", problems[0])

    def test_over_release_is_refused_too(self):
        contributions = rb.classify([commit("fix: x")], SKIP)
        problems = rb.review("1.14.3", "1.15.0", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("Over-releasing", problems[0])
        self.assertIn("spent", problems[0])

    def test_a_releasable_range_that_releases_nothing_is_refused(self):
        # The sibling of the patch-for-a-feat case: cliff finds nothing to bump while a feat sits in range.
        contributions = rb.classify([commit("feat: a")], SKIP)
        problems = rb.review("1.14.3", "1.14.3", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("ship to nobody", problems[0])

    def test_a_version_computed_from_an_empty_range_is_refused(self):
        contributions = rb.classify([commit("chore: a"), commit("Merge x")], SKIP)
        problems = rb.review("1.14.3", "1.14.4", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("changelog is empty", problems[0])

    def test_an_irregular_step_short_circuits(self):
        contributions = rb.classify([commit("feat: a")], SKIP)
        problems = rb.review("1.14.3", "1.16.0", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("not a single semver increment", problems[0])

    def test_a_non_semver_version_is_not_a_pass(self):
        contributions = rb.classify([commit("feat: a")], SKIP)
        problems = rb.review("1.14.3", "1.15.0-rc1", contributions)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("not semver", problems[0])

    def test_an_empty_range_with_no_release_agrees(self):
        self.assertEqual([], rb.review("1.14.3", "1.14.3", []))


class TestRealHistory(unittest.TestCase):
    """The range after v1.14.1 as CD actually saw it: subjects verbatim, merge
    numbers and branch names replaced with stand-ins."""

    RANGE = [
        "Merge pull request #11 from example-org/feat/witness-every-language",
        "docs(guides): align the use-without-dockerfile pin with the released version",
        "Merge branch 'main' into feat/witness-every-language",
        "Merge pull request #12 from example-org/docs/dotnet-sdk-guidance",
        "Merge pull request #13 from example-org/fix/detect-slnx",
        "docs(intent): name the changed files in the CAPS-008 capsule",
        "fix(ci): assert the composite gate passed, not that the field exists",
        "docs(dotnet): document SDK band selection and retire the inert remedies",
        "feat(quality): witness every language with test legs",
        "fix(quality): pin a .NET SDK image per band and select it from the repo",
        "fix(detect): recognise .slnx as a .NET language marker",
    ]

    def _contributions(self):
        commits = [
            commit(subject, sha="{:08x}".format(i))
            for i, subject in enumerate(self.RANGE)
        ]
        return rb.classify(commits, SKIP)

    def test_the_range_requires_a_minor(self):
        self.assertEqual(rb.MINOR, rb.required_bump(self._contributions()))

    def test_the_tag_that_shipped_is_refused(self):
        self.assertNotEqual([], rb.review("1.14.1", "1.14.2", self._contributions()))

    def test_the_tag_that_should_have_shipped_passes(self):
        self.assertEqual([], rb.review("1.14.1", "1.15.0", self._contributions()))

    def test_the_four_merge_subjects_contribute_nothing(self):
        silent = [c for c in self._contributions() if c.kind is None]
        self.assertEqual(4, len(silent))
        self.assertTrue(all(c.commit.subject.startswith("Merge") for c in silent))


class TestBaseFromTag(unittest.TestCase):
    """No reachable tag is two states, and only one of them is pre-release."""

    def test_a_tag_sets_the_range_and_the_current_version(self):
        self.assertEqual(("v1.2.3..HEAD", "v1.2.3..HEAD", "1.2.3"), crb.base_from_tag("v1.2.3", True))

    def test_no_tag_and_no_pins_is_a_repository_before_its_first_release(self):
        rng, scope, current = crb.base_from_tag("", pins_present=False)
        self.assertEqual(("HEAD", "0.0.0"), (rng, current))
        self.assertIn("no tags yet", scope)

    def test_no_tag_but_pins_is_an_unbootstrapped_copy_and_cannot_be_asked(self):
        """The import of this tree into a fresh repository, before anyone tagged
        it: every pin says v5.0.0 and git says nothing. 0.0.0 is a base nobody
        chose, and the bumper would rewrite every pin from it."""
        with self.assertRaises(crb.AskError) as ctx:
            crb.base_from_tag("", pins_present=True)
        self.assertIn("Bootstrapping a fresh copy", str(ctx.exception))

    def test_this_tree_carries_pins(self):
        """The scanner reads the real inventory, so a copy of this repository
        is always on the refusing side of the fork above."""
        self.assertTrue(crb.tree_carries_pins(REPO_ROOT))

    def test_a_tree_without_an_inventory_cannot_be_asked(self):
        import tempfile
        with self.assertRaises(crb.AskError):
            crb.tree_carries_pins(pathlib.Path(tempfile.mkdtemp()))


class TestRenderReport(unittest.TestCase):
    def _render(self, current, nxt, subjects):
        contributions = rb.classify(
            [commit(s, sha="{:08x}".format(i)) for i, s in enumerate(subjects)], SKIP
        )
        problems = rb.review(current, nxt, contributions)
        return "\n".join(
            rb.render_report(current, nxt, contributions, problems, "v{}..HEAD".format(current))
        )

    def test_a_refusal_names_the_deciding_commit_and_says_nothing_was_tagged(self):
        out = self._render("1.14.1", "1.14.2", ["feat: witness", "fix: x", "chore: y"])
        self.assertIn("RELEASE REFUSED", out)
        self.assertIn("requires a minor bump:", out)
        self.assertIn("feat: witness", out)
        self.assertIn("Nothing has been tagged", out)

    def test_a_pass_says_which_bump_and_why(self):
        out = self._render("1.14.3", "1.15.0", ["feat: witness"])
        self.assertNotIn("REFUSED", out)
        self.assertIn("OK: a minor bump is what the history requires.", out)

    def test_a_no_release_pass_says_so_explicitly(self):
        out = self._render("1.14.3", "1.14.3", ["chore: tidy"])
        self.assertIn("OK: nothing in this range releases", out)

    def test_non_contributing_commits_are_collapsed_into_a_count(self):
        out = self._render(
            "1.14.3", "1.15.0", ["feat: a", "Merge one", "Merge two", "chore: x"]
        )
        self.assertIn("3 commit(s) contribute nothing", out)
        self.assertNotIn("Merge one", out)
        self.assertIn("check-commit-subjects.py", out)

    def test_lower_rank_commits_are_listed_separately(self):
        out = self._render("1.14.3", "1.15.0", ["feat: a", "fix: b"])
        self.assertIn("also releasable, lower rank:", out)
        self.assertIn("fix: b", out)

    def test_an_unclassifiable_version_is_labelled_not_blank(self):
        out = self._render("1.14.3", "1.15.0-rc1", ["feat: a"])
        self.assertIn("computed=unclassifiable", out)


class TestSplitSubjectBody(unittest.TestCase):
    def test_subject_and_body_are_separated(self):
        subject, body = rb.split_subject_body("feat: a\n\nBREAKING CHANGE: gone\n")
        self.assertEqual("feat: a", subject)
        self.assertEqual("BREAKING CHANGE: gone", body)

    def test_a_subject_only_message_has_an_empty_body(self):
        self.assertEqual(("feat: a", ""), rb.split_subject_body("feat: a\n"))

    def test_the_body_keeps_its_internal_blank_lines(self):
        # The footer branches read the body with a multiline regex, so a body that
        # arrives flattened would silently stop matching a footer after prose.
        _, body = rb.split_subject_body("fix: a\n\nprose\n\nBREAKING CHANGE: gone")
        self.assertIn("\n\nBREAKING CHANGE: gone", body)


class TestReadSkipPatterns(unittest.TestCase):
    """cliff.toml is read with a regex, not tomllib — 3.9 has no tomllib."""

    def _write(self, body: str) -> pathlib.Path:
        import tempfile

        directory = tempfile.mkdtemp()
        path = pathlib.Path(directory) / "cliff.toml"
        path.write_text(body, encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def test_the_real_cliff_toml_still_holds_the_rule_this_check_assumes(self):
        # A drift guard, not a unit test. If cliff.toml's skip rule changes, the
        # classification above is describing a cliff that no longer exists.
        patterns = crb.read_skip_patterns(REPO_ROOT / "cliff.toml")
        self.assertEqual(SKIP, patterns)

    def test_only_skip_parsers_are_collected(self):
        path = self._write(
            'commit_parsers = [\n'
            '  { message = "^feat", group = "Features" },\n'
            '  { message = "^chore|^ci", skip = true },\n'
            '  { message = "^wip", skip = true },\n'
            ']\n'
        )
        self.assertEqual(["^chore|^ci", "^wip"], crb.read_skip_patterns(path))

    def test_single_quoted_patterns_are_read(self):
        path = self._write(
            "commit_parsers = [\n  { message = '^chore', skip = true },\n]\n"
        )
        self.assertEqual(["^chore"], crb.read_skip_patterns(path))

    def test_a_missing_file_cannot_be_asked(self):
        with self.assertRaises(crb.ConfigError):
            crb.read_skip_patterns(REPO_ROOT / "no-such-cliff.toml")

    def test_no_commit_parsers_is_refused(self):
        path = self._write('[changelog]\nheader = ""\n')
        with self.assertRaises(crb.ConfigError):
            crb.read_skip_patterns(path)

    def test_an_unclosed_array_is_refused(self):
        # Truncation would silently drop the skip rules that follow, and an empty
        # skip list reclassifies every chore: commit as a patch.
        path = self._write(
            'commit_parsers = [\n  { message = "^chore", skip = true },\n'
        )
        with self.assertRaises(crb.ConfigError):
            crb.read_skip_patterns(path)

    def test_a_skip_rule_with_no_message_is_refused(self):
        # A skip keyed on a body or a field cannot be applied to a subject here.
        path = self._write(
            'commit_parsers = [\n  { body = "^ignore", skip = true },\n]\n'
        )
        with self.assertRaises(crb.ConfigError):
            crb.read_skip_patterns(path)

    def test_no_skip_rule_at_all_is_refused(self):
        # Without one, every chore: reads as releasable and the check would refuse
        # every release. Refusing to guess is the honest answer.
        path = self._write(
            'commit_parsers = [\n  { message = "^feat", group = "Features" },\n]\n'
        )
        with self.assertRaises(crb.ConfigError):
            crb.read_skip_patterns(path)

    def test_a_config_error_is_an_ask_error(self):
        # main() maps AskError to exit 2, so ConfigError must be one or a malformed
        # config would escape as a traceback and a non-2 exit.
        self.assertTrue(issubclass(crb.ConfigError, crb.AskError))


if __name__ == "__main__":
    unittest.main()
