"""Tests for the capsule YAML typo check.

The positive case is the measured one: the CAPS-003 capsule as first written,
whose `work: anyone` cost a four-minute dogfood run and reported itself as
`line 24` of `/inputs/f0000`. The negative controls matter more than usual —
capsules are prose, prose is full of colons, and a check that fires on legal
folded text would be abandoned within a week.

The quoted-scalar-tail cases are measured too, and from the worst possible
source: the CAPS-017 capsule written for the change *this* check was being
prepared alongside passed `check-capsules.py`, reached CI, and took the dogfood
policy scan down at `line 90: did not find expected '-' indicator`.
`test_the_measured_quoted_scalar_tail` is that line verbatim.

The identity cases below are measured too, from the other direction: three
branches cut off the same `main` each sealed a `CAPS-017`, and the check as it
then stood printed `OK (18 capsule(s))` over the merged tree. `test_the_measured
_three_branch_collision` is those three files, and
`test_a_collision_has_no_yaml_fault_to_find` states why no amount of work on
`scan_text` could ever have reached it.
"""

from __future__ import annotations

import sys
import importlib.util
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capsules import CAPSULE_GLOB, check_capsules, check_identity, scan_text  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestScanText(unittest.TestCase):
    def test_measured_failure_is_caught(self) -> None:
        """The exact shape that broke conftest: a colon on a continuation line."""
        text = (
            "impact:\n"
            "  risk:\n"
            "    - No loss of permission coverage, because each deleted rule had an\n"
            "      identical Read twin in the same list. The risk is a future\n"
            "      reader assuming Glob rules work: anyone excluding a path\n"
            "      or Grep must express it as Read.\n"
        )
        findings = scan_text(text)
        self.assertEqual(len(findings), 1, findings)
        lineno, rule, _ = findings[0]
        self.assertEqual(lineno, 5)
        self.assertEqual(rule, "plain-scalar-colon")

    def test_trailing_colon_on_continuation_is_caught(self) -> None:
        text = "risk:\n  - some prose that continues\n    and ends like this:\n"
        findings = scan_text(text)
        self.assertEqual([f[1] for f in findings], ["plain-scalar-colon"])

    def test_mapping_value_with_colon_is_caught(self) -> None:
        """`a: b: c` is 'mapping values are not allowed here' too."""
        findings = scan_text("choice: delete the rules: right now\n")
        self.assertEqual([f[1] for f in findings], ["plain-scalar-colon"])

    def test_tab_indentation_is_caught(self) -> None:
        findings = scan_text("impact:\n\tvisibility: internal\n")
        self.assertEqual([f[1] for f in findings], ["tab-indent"])

    # --- negative controls: legal prose that must never fire ---

    def test_folded_block_scalar_may_contain_colons(self) -> None:
        text = (
            "intent: >\n"
            "  Remove the rules because Claude Code never consults them: file\n"
            "  access is checked one way: against Read rules only.\n"
            "impact:\n"
            "  visibility: internal\n"
        )
        self.assertEqual(scan_text(text), [])

    def test_literal_block_scalar_may_contain_colons(self) -> None:
        text = "notes: |\n  key: value\n  other: thing\n"
        self.assertEqual(scan_text(text), [])

    def test_url_in_plain_prose_does_not_fire(self) -> None:
        """`://` is not `: ` and never starts a mapping."""
        text = "risk:\n  - see https://example.com/x for the measured table\n"
        self.assertEqual(scan_text(text), [])

    def test_quoted_value_may_contain_a_colon(self) -> None:
        self.assertEqual(scan_text('choice: "delete the rules: right now"\n'), [])
        self.assertEqual(scan_text("choice: 'a: b'\n"), [])

    def test_sequence_of_mappings_is_not_a_continuation(self) -> None:
        """`- id: x` then a sibling key is structure, not prose."""
        text = (
            "decisions:\n"
            "  - id: d01\n"
            "    choice: delete the rules\n"
            "    confidence: high\n"
            "  - id: d02\n"
            "    choice: keep them\n"
        )
        self.assertEqual(scan_text(text), [])

    def test_nested_mapping_under_bare_key_is_not_a_continuation(self) -> None:
        text = "impact:\n  visibility: internal\n  compatibility: unchanged\n"
        self.assertEqual(scan_text(text), [])

    def test_comment_with_a_colon_does_not_fire(self) -> None:
        self.assertEqual(scan_text("# note: this is a comment\nkind: change-capsule\n"), [])

    def test_blank_line_inside_a_block_scalar_stays_inside(self) -> None:
        text = "intent: >\n  first paragraph\n\n  second: still folded text\nkind: x\n"
        self.assertEqual(scan_text(text), [])

    # --- rule 3: a quoted scalar with content after its closing quote ---

    def test_the_measured_quoted_scalar_tail(self) -> None:
        """CAPS-017 line 90 verbatim. Rule 1 could not see it: `_MAPPING_RE`
        reads the line as a legal mapping whose key is `"artifact`."""
        text = 'options:\n  - "artifact: NOT ATTESTED — no artifact was built" (rejected)\n'
        findings = scan_text(text)
        self.assertEqual(len(findings), 1, findings)
        lineno, rule, message = findings[0]
        self.assertEqual(lineno, 2)
        self.assertEqual(rule, "quoted-scalar-tail")
        self.assertIn("(rejected)", message)

    def test_mapping_value_quoted_then_text(self) -> None:
        findings = scan_text('choice: "quoted" then more\n')
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0][1], "quoted-scalar-tail")

    def test_a_fully_quoted_sequence_item_is_silent(self) -> None:
        self.assertEqual(scan_text('options:\n  - "fully quoted, colon and all"\n'), [])

    def test_an_escaped_single_quote_is_silent(self) -> None:
        """`''` is YAML's escaped quote, not the end of the scalar."""
        self.assertEqual(scan_text("options:\n  - 'it''s quoted, all of it'\n"), [])

    def test_an_escaped_double_quote_is_silent(self) -> None:
        self.assertEqual(scan_text('options:\n  - "a \\" inside, and: a colon"\n'), [])

    def test_no_closing_quote_on_the_line_is_silent(self) -> None:
        """A quoted scalar may legally span lines, and this walk cannot tell
        that from an unterminated quote — so it must not guess."""
        self.assertEqual(scan_text('options:\n  - "opens here\n    and closes there"\n'), [])

    def test_a_comment_after_a_quoted_scalar_is_silent(self) -> None:
        self.assertEqual(scan_text('kind: "change-capsule"  # still legal\n'), [])


class TestReservedFirstCharacter(unittest.TestCase):
    """The rule CAPS-049 bought. Every case here was run against PyYAML first:
    the position of the backtick decides whether the file parses, so a rule
    guessed rather than measured would either miss the fault or fail prose."""

    def test_a_sequence_item_opening_with_a_backtick_is_named(self) -> None:
        """The shipped line, verbatim."""
        text = "options:\n  - `== 'pr-open' || == 'released'` (chosen)\n"
        findings = scan_text(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0][0], 2)
        self.assertEqual(findings[0][1], "reserved-first-char")

    def test_a_mapping_value_opening_with_a_backtick_is_named(self) -> None:
        findings = scan_text("choice: `git reset --hard` moves HEAD\n")
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0][1], "reserved-first-char")

    def test_an_at_sign_is_named_too(self) -> None:
        """YAML reserves `@` alongside the backtick, and a capsule quoting a
        handle or an `actions/foo@v1` pin lands on it the same way."""
        findings = scan_text("options:\n  - @v4 pinned by sha (rejected)\n")
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0][1], "reserved-first-char")

    def test_a_backtick_after_the_first_character_is_prose(self) -> None:
        """The false positive that would make this rule worse than nothing:
        capsules are full of mid-sentence backticks and every one of them parses."""
        self.assertEqual(scan_text("options:\n  - leave `!= 'x'` alone (rejected)\n"), [])
        self.assertEqual(scan_text("choice: keep `HEAD` where it was\n"), [])

    def test_a_continuation_line_may_open_with_a_backtick(self) -> None:
        """Measured: the reserved-indicator restriction applies to the first
        character of the scalar, not to each line of a multi-line one. Flagging
        these would fail legal YAML, which is how a prose check gets abandoned."""
        text = "because: >\n  the reset moves HEAD\n  `git tag` then tags it\n"
        self.assertEqual(scan_text(text), [])
        plain = "because: the reset moves HEAD\n  `git tag` then tags it\n"
        self.assertEqual(scan_text(plain), [])

    def test_a_quoted_value_may_open_with_a_backtick(self) -> None:
        """The remedy the finding tells the author to apply must itself pass."""
        self.assertEqual(scan_text('options:\n  - "`== \'a\' || == \'b\'` (chosen)"\n'), [])

    def test_block_scalar_openers_are_not_reserved(self) -> None:
        """`>` and `|` open a scalar legally; only `@` and the backtick never do.
        A rule that swept in every indicator character would fail every capsule."""
        self.assertEqual(scan_text("intent: >\n  prose\n"), [])
        self.assertEqual(scan_text("intent: |\n  prose\n"), [])


class TestAgainstARealParser(unittest.TestCase):
    """`scan_text` is deliberately not a YAML validator and cannot depend on
    PyYAML — but the tests can, and this is the check that would have caught
    CAPS-049 before the dogfood run rather than after it. It cannot prove the
    scanner catches everything; it proves the scanner is never *wrong about a
    shipped capsule*, which is the failure mode that costs four minutes."""

    def test_every_shipped_capsule_parses_and_the_scanner_agrees(self) -> None:
        yaml = importlib.util.find_spec("yaml")
        if yaml is None:
            self.skipTest("PyYAML absent; the scanner deliberately does not need it")
        import yaml as pyyaml  # noqa: PLC0415

        paths = sorted(REPO_ROOT.glob(CAPSULE_GLOB))
        self.assertTrue(paths)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            with self.subTest(capsule=path.name):
                try:
                    pyyaml.safe_load(text)
                except pyyaml.YAMLError as exc:
                    self.fail(f"{path.name} does not parse: {exc}")
                self.assertEqual(
                    scan_text(text),
                    [],
                    f"{path.name} parses, so the scanner must not flag it",
                )


class TestCheckCapsules(unittest.TestCase):
    def test_shipped_capsules_all_pass(self) -> None:
        """Regression proof against the real files, not only synthetic ones."""
        self.assertEqual(check_capsules(REPO_ROOT), [])

    def test_repo_actually_has_capsules_to_check(self) -> None:
        """Guards the guard: zero files would make the case above vacuous."""
        self.assertTrue(sorted(REPO_ROOT.glob(CAPSULE_GLOB)))

    def test_missing_capsules_is_a_failure_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            problems = check_capsules(Path(tmp))
        self.assertEqual(len(problems), 1)
        self.assertIn("no capsules matched", problems[0])

    def test_problem_names_the_file_and_line(self) -> None:
        """The whole point: conftest says `/inputs/f0000`, this says the path."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".capsules").mkdir()
            (root / ".capsules" / "CAPS-999-broken.capsule.yaml").write_text(
                "id: CAPS-999\nrisk:\n  - prose that continues\n    and breaks here: badly\n"
            )
            problems = check_capsules(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(".capsules/CAPS-999-broken.capsule.yaml:4:", problems[0])


class TestCheckIdentity(unittest.TestCase):
    """A capsule number has to resolve to one capsule. See the module docstring."""

    @staticmethod
    def _write(root: Path, *capsules: tuple[str, str]) -> list[Path]:
        (root / ".capsules").mkdir(exist_ok=True)
        paths = []
        for name, body in capsules:
            path = root / ".capsules" / name
            path.write_text(body, encoding="utf-8")
            paths.append(path)
        return sorted(paths)

    def test_the_measured_three_branch_collision(self) -> None:
        """Two branches, two slugs, one number — and no filename collided."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(
                root,
                ("CAPS-017-detect-the-dotnet-test-runner.capsule.yaml", "id: CAPS-017\n"),
                ("CAPS-017-say-what-no-artifact-left-unattested.capsule.yaml", "id: CAPS-017\n"),
            )
            problems = check_identity(paths, root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("[duplicate]", problems[0])
        # Both claimants are named: a message saying only "duplicate" leaves the
        # reader to find the other file by hand.
        self.assertIn("CAPS-017-detect-the-dotnet-test-runner", problems[0])
        self.assertIn("CAPS-017-say-what-no-artifact-left-unattested", problems[0])

    def test_a_collision_has_no_yaml_fault_to_find(self) -> None:
        """Why this lives beside `scan_text` rather than inside it."""
        body = "kind: change-capsule\nid: CAPS-017\nstatus: sealed\n"
        self.assertEqual(scan_text(body), [])

    def test_a_gap_is_legal(self) -> None:
        """Branches merge in review order, so 018 may land after 019."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(
                root,
                ("CAPS-017-one.capsule.yaml", "id: CAPS-017\n"),
                ("CAPS-019-three.capsule.yaml", "id: CAPS-019\n"),
            )
            self.assertEqual(check_identity(paths, root), [])

    def test_renaming_the_file_does_not_move_the_field(self) -> None:
        """A `git mv` with no edit to `id:`. Measured on this very change."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(root, ("CAPS-019-renamed.capsule.yaml", "id: CAPS-017\n"))
            problems = check_identity(paths, root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("[id]", problems[0])
        self.assertIn("CAPS-017", problems[0])
        self.assertIn("CAPS-019", problems[0])

    def test_no_id_field_at_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(root, ("CAPS-020-silent.capsule.yaml", "kind: change-capsule\n"))
            problems = check_identity(paths, root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("[id]", problems[0])

    def test_two_id_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(
                root, ("CAPS-021-twice.capsule.yaml", "id: CAPS-021\nkind: x\nid: CAPS-021\n")
            )
            problems = check_identity(paths, root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("[id]", problems[0])

    def test_a_nested_id_is_not_the_capsule_identity(self) -> None:
        """`^id:` is column-anchored: an inner node's own id must not be read."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(
                root,
                (
                    "CAPS-022-nested.capsule.yaml",
                    "id: CAPS-022\nrefs:\n  - id: CAPS-001\n",
                ),
            )
            self.assertEqual(check_identity(paths, root), [])

    def test_an_unnumbered_filename_is_named_as_such(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._write(root, ("notes.yaml", "id: CAPS-001\n"))
            problems = check_identity(paths, root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("[name]", problems[0])

    def test_shipped_capsule_numbers_are_unique(self) -> None:
        """The real files, not synthetic ones — this is the case that failed."""
        paths = sorted(REPO_ROOT.glob(CAPSULE_GLOB))
        self.assertTrue(paths)
        self.assertEqual(check_identity(paths, REPO_ROOT), [])


if __name__ == "__main__":
    unittest.main()
