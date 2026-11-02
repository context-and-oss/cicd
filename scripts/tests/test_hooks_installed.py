"""Regression proof for scripts/check-hooks-installed.py.

The defect: `git config core.hooksPath` was unset in a working clone of this
repository and there was no `.git/hooks/pre-push`, so `git push` ran no gate at
all — and nothing said so, because a skipped gate and a passing gate look
identical from the terminal. `make install-hooks` sets the config, but it is a
one-time manual step, so a fresh clone starts ungated.

These tests drive real git repositories rather than a mocked git, because the
property under test is *what git would actually do* on push. A test that stubbed
git's answer would prove only that the stub agrees with the assertion.

Two environment facts the tests must control, both of which would otherwise make
them lie:

  * The developer's own global config. A global `core.hooksPath` leaks into a
    fresh `git init`, so the ungated baseline would find a hook and the failure
    assertions would never fire. Every repo here is built with
    GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM pointed away.
  * `CI`. The script deliberately skips when CI is set, so under GitHub Actions
    every assertion about a failing exit code would pass for the wrong reason.
    The runner strips CI from the child environment unless a test asks for it.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-hooks-installed.py"

_spec = importlib.util.spec_from_file_location("check_hooks_installed", SCRIPT)
assert _spec and _spec.loader
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

HOOK_BODY = "#!/bin/sh\nexit 0\n"


class HookCheckCase(unittest.TestCase):
    """A temp repository per test, isolated from the developer's git config."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        # An empty file, not /dev/null: git writes to GIT_CONFIG_GLOBAL in some
        # code paths and a read-only device would fail for the wrong reason.
        self.global_config = self.root / "gitconfig-global"
        self.global_config.write_text("")
        self.system_config = self.root / "gitconfig-system"
        self.system_config.write_text("")
        self.git("init", "-q")

    def env(self, *, ci: str | None = None) -> dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in {"CI", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
        }
        env["GIT_CONFIG_GLOBAL"] = str(self.global_config)
        env["GIT_CONFIG_SYSTEM"] = str(self.system_config)
        if ci is not None:
            env["CI"] = ci
        return env

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=self.repo,
            env=self.env(),
            check=True,
            capture_output=True,
            text=True,
        )

    def run_check(
        self,
        *args: str,
        cwd: pathlib.Path | None = None,
        ci: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd or self.repo,
            env=self.env(ci=ci),
            capture_output=True,
            text=True,
        )

    def install_hook(self, directory: pathlib.Path, *, executable: bool = True) -> pathlib.Path:
        directory.mkdir(parents=True, exist_ok=True)
        hook = directory / "pre-push"
        hook.write_text(HOOK_BODY)
        hook.chmod(0o755 if executable else 0o644)
        return hook


class UngatedCloneTests(HookCheckCase):
    def test_a_fresh_clone_fails_and_names_the_fix(self) -> None:
        """The measured starting state of this repository's own clone."""
        result = self.run_check()
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("would run no pre-push hook", result.stderr)
        self.assertIn("make install-hooks", result.stderr)

    def test_hooks_path_pointing_at_an_empty_directory_fails(self) -> None:
        """The direction a config-only check calls installed.

        `git config --get core.hooksPath` answers with the path, so a check that
        compared that string to ".githooks" would report this clone gated while
        every push sails through.
        """
        empty = self.root / "no-hooks-here"
        empty.mkdir()
        self.git("config", "core.hooksPath", str(empty))
        result = self.run_check()
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("does not exist", result.stderr)

    @unittest.skipUnless(os.name == "posix", "the file-mode bit is irrelevant on Windows")
    def test_a_hook_that_is_not_executable_fails(self) -> None:
        """git silently declines to run a non-executable hook, which is the same
        observable outcome as no hook at all."""
        hooks = self.root / "hooks-noexec"
        self.install_hook(hooks, executable=False)
        self.git("config", "core.hooksPath", str(hooks))
        result = self.run_check()
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("not executable", result.stderr)


class GatedCloneTests(HookCheckCase):
    def test_a_relative_hooks_path_passes(self) -> None:
        self.install_hook(self.repo / ".githooks")
        self.git("config", "core.hooksPath", ".githooks")
        result = self.run_check()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_an_absolute_hooks_path_passes(self) -> None:
        hooks = self.root / "elsewhere"
        self.install_hook(hooks)
        self.git("config", "core.hooksPath", str(hooks))
        self.assertEqual(0, self.run_check().returncode)

    def test_the_default_git_hooks_directory_passes(self) -> None:
        """A developer who dropped a pre-push into .git/hooks and never touched
        core.hooksPath is gated, and the check must say so. Demanding
        ".githooks" specifically would report that working clone as broken."""
        self.install_hook(self.repo / ".git" / "hooks")
        self.assertEqual(0, self.run_check().returncode)

    def test_a_global_hooks_path_passes(self) -> None:
        """Proves the question is asked of git rather than of the local config.
        A developer who wired hooks globally is gated; reading `git config
        --local` would have called them ungated."""
        hooks = self.root / "global-hooks"
        self.install_hook(hooks)
        self.global_config.write_text(f"[core]\n\thooksPath = {hooks}\n")
        self.assertEqual(0, self.run_check().returncode)


class WarnModeTests(HookCheckCase):
    def test_warn_never_fails_and_writes_to_stderr(self) -> None:
        """--warn is what the developer-facing make targets use. It must not
        break `make test` over a local preference, and it must not pollute
        stdout, which callers pipe."""
        result = self.run_check("--warn")
        self.assertEqual(0, result.returncode)
        self.assertIn("warning:", result.stderr)
        self.assertEqual("", result.stdout)

    def test_warn_is_silent_when_the_hook_is_installed(self) -> None:
        """A warning that prints on every target regardless of state is noise,
        and noise gets filtered out along with the signal."""
        self.install_hook(self.repo / ".githooks")
        self.git("config", "core.hooksPath", ".githooks")
        result = self.run_check("--warn")
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)


class NotApplicableTests(HookCheckCase):
    def test_ci_is_skipped_rather_than_failed(self) -> None:
        """core.hooksPath is per-clone local config CI cannot see, and a CI
        clone is gated by the required `ci` check. Failing there over an
        inherently local fact is how a check like this gets deleted."""
        result = self.run_check(ci="true")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("skipped (CI)", result.stdout)

    def test_outside_a_work_tree_it_does_not_claim_to_be_gated(self) -> None:
        """The bug found in this script's own first version: "not applicable"
        was folded into "gated" by returning None for both, so running it
        outside a work tree printed "OK (git would run the pre-push hook)" — a
        false claim, and the same absent-check-reads-as-passing failure the
        script exists to close."""
        outside = self.root / "not-a-repo"
        outside.mkdir()
        probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=outside,
            env=self.env(),
            capture_output=True,
            text=True,
        )
        if probe.stdout.strip() == "true":
            self.skipTest("the temp directory is itself inside a git work tree")
        result = self.run_check(cwd=outside)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("not inside a git work tree", result.stdout)
        self.assertNotIn("would run", result.stdout)

    def test_the_three_states_are_distinct_values(self) -> None:
        """Guards the fix for the bug above. Collapsing any two of these back
        into one value reintroduces it."""
        self.assertEqual(3, len({mod.GATED, mod.UNGATED, mod.NOT_APPLICABLE}))


if __name__ == "__main__":
    unittest.main()
