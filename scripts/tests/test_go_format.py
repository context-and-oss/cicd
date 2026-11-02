"""Tests for scripts/go_format.py and scripts/check-go-format.py.

The three answers are all covered end to end, because the one that matters here
is exit 2 — a formatter that never ran must not read as a formatted tree, and
that is not something the unit-level classifier can prove on its own.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))

from go_format import (  # noqa: E402
    EXIT_CANNOT_ASK,
    EXIT_OK,
    EXIT_UNFORMATTED,
    parse_gofmt_list,
    verdict,
)

UNFORMATTED_GO = "package main\n\nfunc main()  {\n\tx :=  1\n\t_ = x\n}\n"
FORMATTED_GO = "package main\n\nfunc main() {\n\tx := 1\n\t_ = x\n}\n"


class ParseListTests(unittest.TestCase):
    def test_empty_stdout_is_an_empty_list(self):
        self.assertEqual(parse_gofmt_list(""), [])
        self.assertEqual(parse_gofmt_list("\n\n  \n"), [])

    def test_paths_are_sorted_and_deduplicated(self):
        out = "src/b.go\nsrc/a.go\nsrc/b.go\n"
        self.assertEqual(parse_gofmt_list(out), ["src/a.go", "src/b.go"])

    def test_surrounding_whitespace_is_stripped(self):
        self.assertEqual(parse_gofmt_list("  src/a.go  \n"), ["src/a.go"])


class VerdictTests(unittest.TestCase):
    def test_clean_tree_passes_and_names_the_count(self):
        result = verdict("/usr/bin/gofmt", ["a.go", "b.go"], "")
        self.assertEqual(result.exit_code, EXIT_OK)
        self.assertIn("2 tracked Go file(s)", "\n".join(result.lines))

    def test_unformatted_files_fail_and_are_listed(self):
        result = verdict("/usr/bin/gofmt", ["a.go", "b.go"], "b.go\n")
        self.assertEqual(result.exit_code, EXIT_UNFORMATTED)
        text = "\n".join(result.lines)
        self.assertIn("1 of 2 tracked Go file(s)", text)
        self.assertIn("  b.go", text)
        self.assertIn("make fmt", text)

    def test_missing_gofmt_is_exit_2_and_says_why_it_is_not_a_skip(self):
        result = verdict(None, [], None, "nothing on PATH")
        self.assertEqual(result.exit_code, EXIT_CANNOT_ASK)
        text = "\n".join(result.lines)
        self.assertIn("nothing on PATH", text)
        self.assertIn("exactly like a formatted tree", text)

    def test_missing_gofmt_without_detail_still_explains_itself(self):
        result = verdict(None, [], None, None)
        self.assertEqual(result.exit_code, EXIT_CANNOT_ASK)
        self.assertIn("no further detail", "\n".join(result.lines))

    def test_a_failed_gofmt_run_is_exit_2_not_a_pass(self):
        result = verdict("/usr/bin/gofmt", ["a.go"], None, "gofmt exited 2: boom")
        self.assertEqual(result.exit_code, EXIT_CANNOT_ASK)
        self.assertIn("boom", "\n".join(result.lines))

    def test_zero_files_with_a_working_gofmt_is_exit_2(self):
        # "0 of 0 files are unformatted" is vacuously true, which is the shape
        # this repository refuses everywhere else it appears.
        result = verdict("/usr/bin/gofmt", [], "")
        self.assertEqual(result.exit_code, EXIT_CANNOT_ASK)
        self.assertIn("broken file list", "\n".join(result.lines))


class CLITests(unittest.TestCase):
    """Drive check-go-format.py against throwaway git repositories."""

    def make_repo(self, files: dict, commit: bool = True) -> pathlib.Path:
        import tempfile

        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root, True)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for rel, body in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        if commit:
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        return root

    def run_cli(self, root: pathlib.Path, *args, env=None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "check-go-format.py"), "--root", str(root), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_a_formatted_repository_passes(self):
        root = self.make_repo({"main.go": FORMATTED_GO})
        proc = self.run_cli(root)
        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("OK", proc.stdout)

    def test_an_unformatted_file_fails_and_is_named(self):
        root = self.make_repo({"main.go": FORMATTED_GO, "bad/x.go": UNFORMATTED_GO})
        proc = self.run_cli(root)
        self.assertEqual(proc.returncode, EXIT_UNFORMATTED)
        self.assertIn("bad/x.go", proc.stderr)
        self.assertNotIn("main.go", proc.stderr.replace("bad/x.go", ""))

    def test_an_untracked_file_is_not_graded(self):
        # Generated SDKs are gitignored, and grading generated Go would make the
        # check report a codegen's output as this repository's debt.
        root = self.make_repo({"main.go": FORMATTED_GO})
        (root / "dagger.gen.go").write_text(UNFORMATTED_GO)
        proc = self.run_cli(root)
        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)

    def test_write_formats_in_place_and_then_passes(self):
        root = self.make_repo({"bad/x.go": UNFORMATTED_GO})
        proc = self.run_cli(root, "--write")
        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("bad/x.go", proc.stdout)
        self.assertEqual((root / "bad" / "x.go").read_text(), FORMATTED_GO)
        self.assertEqual(self.run_cli(root).returncode, EXIT_OK)

    def test_a_directory_that_is_not_a_git_repository_is_exit_2(self):
        import tempfile

        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root, True)
        proc = self.run_cli(root)
        self.assertEqual(proc.returncode, EXIT_CANNOT_ASK)
        self.assertIn("cannot list tracked Go files", proc.stderr)

    def test_a_repository_with_no_go_files_is_exit_2_not_a_pass(self):
        root = self.make_repo({"README.md": "# x\n"})
        proc = self.run_cli(root)
        self.assertEqual(proc.returncode, EXIT_CANNOT_ASK)
        self.assertIn("no Go files were found", proc.stderr)

    def test_no_gofmt_on_path_is_exit_2(self):
        root = self.make_repo({"main.go": FORMATTED_GO})
        env = dict(os.environ, PATH="/nonexistent")
        proc = self.run_cli(root, env=env)
        self.assertEqual(proc.returncode, EXIT_CANNOT_ASK)
        self.assertIn("gofmt could not be found", proc.stderr)

    def test_a_gofmt_that_fails_is_exit_2_and_never_a_clean_report(self):
        root = self.make_repo({"main.go": FORMATTED_GO})
        fake = root / "fakebin"
        fake.mkdir()
        (fake / "gofmt").write_text('#!/bin/sh\necho "boom" >&2\nexit 2\n')
        (fake / "gofmt").chmod(0o755)
        # git must stay reachable: the point is a gofmt that fails, not a
        # missing git, which is a different exit-2 path already covered above.
        import shutil as _shutil

        (fake / "git").symlink_to(_shutil.which("git"))
        env = dict(os.environ, PATH=str(fake))
        proc = self.run_cli(root, env=env)
        self.assertEqual(proc.returncode, EXIT_CANNOT_ASK)
        self.assertIn("boom", proc.stderr)
        self.assertNotIn("OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
