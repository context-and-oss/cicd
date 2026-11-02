"""Regression proof for scripts/ci/write-release-intent.py.

A release pin bump reaches `main` by pull request, and every change to `main` in
this repository must carry an intent artifact — the gate in
`src/cross-cutting/intent` fails a diff that touches none. Widening the gate's
`dependabotActionsPin` machine-origin exemption to cover the release identity was
rejected (it would hand the identity that writes `.github/workflows/` a documented
way past the gate), so the release generates a real artifact instead.

That makes this template load-bearing: if it stops satisfying the gate's rules,
releases stop merging. The rules are Go, in src/cross-cutting/intent/rules.go, and
cannot be imported here — so the checks below encode each rule's *requirement*
against the rendered text, and the pairing is asserted deliberately:

  no-tbd (error)              no TBD/TODO/FIXME/??? token
  min-causal-language (error) at least one causal marker
  refs-infer-coupling (error) at least one named path is really in the diff
  no-weasel-words (warn)      none of the 20 listed qualifiers as a whole word
  min-length (warn)           at least 30 words

The word lists are duplicated from rules.go on purpose: a copy that drifts fails
here loudly, whereas no copy at all means nothing notices until a release cannot
merge. The real gate was also run against this template's output for a genuine
28-file v1.12.0 bump and reported zero findings; that run is recorded in
specs/deliver-release-pins-by-pull-request.md.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "ci" / "write-release-intent.py"

_spec = importlib.util.spec_from_file_location("write_release_intent", SCRIPT)
assert _spec and _spec.loader
wri = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wri)

# Verbatim from src/cross-cutting/intent/rules.go.
TBD_PATTERN = re.compile(r"(?i)\b(?:TBD|TODO|FIXME)\b|\?\?\?")
WEASEL_WORDS = [
    "scalable", "robust", "fast", "easy", "simple", "better", "improved",
    "optimized", "seamless", "intuitive", "best practice", "world-class",
    "cutting-edge", "state-of-the-art", "efficient", "powerful", "flexible",
    "lightweight", "comprehensive", "elegant",
]
CAUSAL_MARKERS = [
    "because", "since", "in order to", "so that", "therefore", "as a result",
    "due to", "given that", "the reason", "this is why", "we chose",
    "we decided", "instead of", "rather than",
]

# A real bump: what scripts/bump-version.py rewrites for both scopes.
CHANGED = [
    ".github/workflows/commit.yml",
    ".github/workflows/precommit.yml",
    "README.md",
    "src/quality/README.md",
    "src/security/README.md",
    "templates/azure-devops/commit.yml",
    "templates/github-actions/commit.yml",
    "templates/local/scripts/cicd-prepush",
]


def prose_without_code(text: str) -> str:
    """Strip fenced blocks and code spans, as checkNoWeaselWords does.

    The rule judges the author's own prose: a path or a flag in backticks is a
    quotation, not a claim.
    """
    text = re.sub(r"(?s)```.*?```", " | ", text)
    return re.sub(r"`[^`]*`", " | ", text)


class TestArtifactPath(unittest.TestCase):
    def test_path_is_fixed_whatever_the_version(self):
        """One artifact, overwritten: a file per release left 76 stubs in specs/."""
        self.assertEqual(wri.artifact_path("1.12.0"), "specs/release-latest.md")
        self.assertEqual(wri.artifact_path("2.0.0"), wri.artifact_path("1.12.0"))

    def test_path_lands_in_a_scanned_glob(self):
        """specs/*.md is one of the intent module's default globs.

        Nested trees are excluded by design (src/cross-cutting/intent/main.go), so
        an artifact one directory deeper would be invisible to the gate and the
        release would fail the presence rule while carrying a perfectly good
        rationale.
        """
        path = wri.artifact_path("2.0.0")
        self.assertTrue(path.startswith("specs/"))
        self.assertEqual(path.count("/"), 1)
        self.assertTrue(path.endswith(".md"))


class TestGrouping(unittest.TestCase):
    def test_paths_are_grouped_and_sorted(self):
        grouped = wri.group_changed(CHANGED)
        self.assertEqual(
            grouped["Workflow pins"],
            [".github/workflows/commit.yml", ".github/workflows/precommit.yml"],
        )
        self.assertIn("templates/github-actions/commit.yml", grouped["GitHub Actions templates"])
        self.assertIn("README.md", grouped["Module and repository docs"])

    def test_an_unrecognised_path_is_not_dropped(self):
        """No silent caps: a pin in a place the grouping never anticipated still
        has to appear in the artifact, or the artifact under-reports the change."""
        grouped = wri.group_changed(CHANGED + ["some/new/place/pinned.yml"])
        listed = [p for paths in grouped.values() for p in paths]
        self.assertIn("some/new/place/pinned.yml", listed)
        self.assertEqual(len(listed), len(CHANGED) + 1)


class TestGateRules(unittest.TestCase):
    def setUp(self):
        self.body = wri.render("1.12.0", CHANGED, "cd.yml")

    def test_no_placeholder_tokens(self):
        self.assertIsNone(TBD_PATTERN.search(self.body))

    def test_has_causal_language(self):
        lower = self.body.lower()
        self.assertTrue(
            any(marker in lower for marker in CAUSAL_MARKERS),
            "no causal marker: the gate reads this as WHY being missing",
        )

    def test_no_weasel_words_in_prose(self):
        haystack = " " + " ".join(
            re.split(r"\s+", re.sub(r"[^\w\s-]+", " | ", prose_without_code(self.body).lower()))
        ) + " "
        found = [w for w in WEASEL_WORDS if " " + w + " " in haystack]
        self.assertEqual(found, [], "unmeasurable qualifiers in the template: {}".format(found))

    def test_well_over_the_word_floor(self):
        self.assertGreater(len(self.body.split()), 300)

    def test_every_named_path_group_is_really_in_the_change(self):
        """refs-infer-coupling: the paths come from the bump, never assumed.

        An artifact naming files that are not in the diff is an artifact describing
        some other change, which is exactly what the rule exists to catch.
        """
        for path in CHANGED:
            self.assertIn(path, self.body)

    def test_mentions_the_human_spec_and_it_exists(self):
        self.assertIn(wri.HUMAN_SPEC, self.body)
        self.assertTrue((REPO_ROOT / wri.HUMAN_SPEC).is_file())


class TestHonesty(unittest.TestCase):
    def setUp(self):
        self.body = wri.render("1.12.0", CHANGED, "release.yml")

    def test_says_it_is_machine_written(self):
        self.assertIn("machine-written", self.body)

    def test_names_the_delivering_workflow(self):
        self.assertIn("release.yml", self.body)

    def test_does_not_invent_review_or_destination_policy(self):
        """A fixed template cannot observe approvals or effective branch rules."""
        self.assertNotIn("No human reviewed this pull request", self.body)
        self.assertNotIn("Two branch rulesets govern", self.body)
        self.assertIn("does not know whether a human reviewed", self.body)
        self.assertIn("destination's chosen policy", self.body)
        self.assertIn("neither supply approval nor prove a merge occurred", self.body)
        self.assertIn("not a substitute for required review", self.body)

    def test_states_that_the_tag_comes_later(self):
        self.assertIn("after this merges", self.body)

    def test_points_at_the_drift_detector_for_a_merged_bump_with_no_tag(self):
        self.assertIn("release_drift.py", self.body)

    def test_reports_the_real_file_count(self):
        self.assertIn("{} file(s)".format(len(CHANGED)), self.body)


class TestRefusals(unittest.TestCase):
    def test_an_empty_change_is_refused(self):
        """An artifact describing no files would claim a change that did not
        happen — and the caller reaching here with nothing staged means the bump
        produced no diff, which is a different code path entirely."""
        with self.assertRaises(ValueError):
            wri.render("1.12.0", [], "cd.yml")

    def test_a_non_semver_version_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            listing = pathlib.Path(tmp) / "changed.txt"
            listing.write_text("README.md\n")
            proc = subprocess.run(
                ["python3", str(SCRIPT), "v1.12", "--changed-from", str(listing)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("not semver", proc.stderr)

    def test_a_missing_listing_is_refused(self):
        proc = subprocess.run(
            ["python3", str(SCRIPT), "1.12.0", "--changed-from", "/nonexistent/changed.txt"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no such file", proc.stderr)


class TestCli(unittest.TestCase):
    def test_writes_the_artifact_and_prints_its_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            listing = root / "changed.txt"
            listing.write_text("\n".join(CHANGED) + "\n")
            proc = subprocess.run(
                ["python3", str(SCRIPT), "1.12.0", "--changed-from", str(listing),
                 "--source", "cd.yml", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "specs/release-latest.md")
            written = root / "specs" / "release-latest.md"
            self.assertTrue(written.is_file())
            self.assertIn("v1.12.0", written.read_text())

    def test_a_second_release_overwrites_the_artifact(self):
        """The fixed path is the design: the gate reads a modified file as a
        changed path, so the second release's rationale must replace the first
        rather than append to it or refuse because the file exists."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            listing = root / "changed.txt"
            listing.write_text("README.md\n")
            for version in ("1.12.0", "1.12.1"):
                proc = subprocess.run(
                    ["python3", str(SCRIPT), version, "--changed-from", str(listing),
                     "--root", str(root)],
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            body = (root / "specs" / "release-latest.md").read_text()
            self.assertIn("v1.12.1", body)
            self.assertNotIn("v1.12.0", body)

    def test_blank_lines_in_the_listing_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            listing = root / "changed.txt"
            listing.write_text("README.md\n\n  \ntemplates/github-actions/commit.yml\n")
            proc = subprocess.run(
                ["python3", str(SCRIPT), "1.12.0", "--changed-from", str(listing),
                 "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("2 file(s)", (root / "specs" / "release-latest.md").read_text())


if __name__ == "__main__":
    unittest.main()
