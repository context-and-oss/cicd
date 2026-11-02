"""Exercise the smoke's real fixture producer without starting Dagger."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NonRunIntentFixtureTests(unittest.TestCase):
    def test_control_diff_matches_the_supplied_after_tree(self):
        script = (ROOT / "scripts/smoke/non-run-matrix.sh").read_text()
        # Extract the producer, not a second copy of its commands. Fail if its
        # boundaries disappear: an empty extraction is never fixture proof.
        start = script.index('tree="$work/intent-src"')
        end = script.index('expect_refusal "intent: no-prefix diff"', start)
        producer = script[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ["bash", "-c", 'set -euo pipefail\nfail() { echo "$*" >&2; exit 1; }\n' + producer],
                cwd=tmp,
                env={**os.environ, "work": tmp},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            source = Path(tmp) / "intent-src"
            self.assertFalse((source / ".git").exists())
            patch = Path(tmp) / "spec.diff"
            self.assertGreater(patch.stat().st_size, 0)
            # git apply can check a plain exported directory too. Reverse
            # application verifies the after-side, exactly the side Check reads.
            check = subprocess.run(
                ["git", "apply", "--reverse", "--check", str(patch)],
                cwd=source,
                text=True,
                capture_output=True,
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            refusal = (Path(tmp) / "noprefix.diff").read_text()
            self.assertIn("diff --git main.go main.go", refusal)
            self.assertNotIn("diff --git a/", refusal)


if __name__ == "__main__":
    unittest.main()
