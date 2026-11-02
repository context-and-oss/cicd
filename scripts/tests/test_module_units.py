"""
Regression tests for the canonical module-unit runner (scripts/test-module-units.sh).

Every test builds a throwaway module tree under a temp directory and points the
runner at it via --root + TEST_MODULE_UNITS_MODULES, so nothing here depends on
which modules the live inventory happens to list today. The suite pins the
exact false-pass class this runner exists to catch: `go test` exits 0 with
"[no test files]" when every *_test.go in a package is excluded by a build
constraint, which looks identical to a healthy green run unless something
counts how many tests actually ran.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS.parent
RUNNER = SCRIPTS / "test-module-units.sh"

GO_MOD = "module fixture\n\ngo 1.24.0\n"

LIB_GO = "package fixture\n\nfunc Add(a, b int) int { return a + b }\n"

REAL_TEST_GO = """package fixture

import "testing"

func TestAdd(t *testing.T) {
\tif Add(2, 3) != 5 {
\t\tt.Fatal("wrong sum")
\t}
}
"""

EXCLUDED_TEST_GO = """//go:build never

package fixture

import "testing"

func TestNeverRuns(t *testing.T) {}
"""

FAILING_TEST_GO = """package fixture

import "testing"

func TestAlwaysFails(t *testing.T) {
\tt.Fatal("intentional failure")
}
"""


def _run(
    root: pathlib.Path, modules: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["TEST_MODULE_UNITS_MODULES"] = modules
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", str(RUNNER), "--root", str(root)],
        capture_output=True,
        text=True,
        env=env,
    )


class ModuleUnitsRunnerTests(unittest.TestCase):
    def test_zero_discovered_tests_fails(self) -> None:
        """A *_test.go excluded entirely by a build constraint must fail, not
        report the package's harmless 'ok ... [no test files]' as success."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            mod = root / "fixture-module"
            mod.mkdir()
            (mod / "go.mod").write_text(GO_MOD)
            (mod / "lib.go").write_text(LIB_GO)
            (mod / "main_test.go").write_text(EXCLUDED_TEST_GO)

            result = _run(root, "fixture-module")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("zero tests", (result.stdout + result.stderr).lower())

    def test_no_modules_with_test_files_fails(self) -> None:
        """An inventory whose listed module carries no test files at all must
        fail loudly instead of reporting an empty, vacuous success."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            mod = root / "empty-module"
            mod.mkdir()
            (mod / "go.mod").write_text(GO_MOD)
            (mod / "lib.go").write_text(LIB_GO)

            result = _run(root, "empty-module")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failing_test_propagates(self) -> None:
        """A real test failure must fail the runner, not be swallowed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            mod = root / "fixture-module"
            mod.mkdir()
            (mod / "go.mod").write_text(GO_MOD)
            (mod / "lib.go").write_text(LIB_GO)
            (mod / "main_test.go").write_text(FAILING_TEST_GO)

            result = _run(root, "fixture-module")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_healthy_module_passes(self) -> None:
        """A module with a genuine, passing test must succeed and report a
        nonzero executed-test count — the negative-direction pin."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            mod = root / "fixture-module"
            mod.mkdir()
            (mod / "go.mod").write_text(GO_MOD)
            (mod / "lib.go").write_text(LIB_GO)
            (mod / "main_test.go").write_text(REAL_TEST_GO)

            result = _run(root, "fixture-module")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("1 test(s) executed", result.stdout)

    def test_nested_package_tests_are_discovered(self) -> None:
        """A module whose only suite is in a nested package must run because
        the execution boundary is go test ./..., not only the module root."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            mod = root / "fixture-module"
            nested = mod / "nested"
            nested.mkdir(parents=True)
            (mod / "go.mod").write_text(GO_MOD)
            (nested / "lib.go").write_text(LIB_GO)
            (nested / "main_test.go").write_text(REAL_TEST_GO)

            result = _run(root, "fixture-module")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("1 test(s) executed", result.stdout)

    def test_ambient_go_workspace_cannot_break_the_run(self) -> None:
        """The runner must resolve every module against its own go.mod.

        This repository has "no shared Go module": the root go.work lists only
        ./src/internal, and some Dagger modules ship a module-local go.work with
        `use .` while others (risk, intent, contract) do not. A runner that
        inherits workspace resolution from the environment therefore passes or
        fails depending on where it is invoked from and whether the caller
        happens to export GOWORK=off. Reproduce that hostile shape — a workspace
        that exists but excludes the module under test — and require a pass.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "unrelated").mkdir()
            (root / "unrelated" / "go.mod").write_text("module unrelated\n\ngo 1.24.0\n")
            (root / "go.work").write_text("go 1.24.0\n\nuse ./unrelated\n")

            mod = root / "fixture-module"
            mod.mkdir()
            (mod / "go.mod").write_text(GO_MOD)
            (mod / "lib.go").write_text(LIB_GO)
            (mod / "main_test.go").write_text(REAL_TEST_GO)

            result = _run(root, "fixture-module", {"GOWORK": str(root / "go.work")})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("1 test(s) executed", result.stdout)

    def test_live_repository_passes(self) -> None:
        """The real repository tree must pass end to end — the runner is
        wired to the live defended inventory, not just fixtures."""
        result = subprocess.run(
            ["bash", str(RUNNER)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unit test(s) executed across", result.stdout)


if __name__ == "__main__":
    unittest.main()
