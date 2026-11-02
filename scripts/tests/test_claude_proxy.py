"""Runs src/risk/claude-proxy.test.js, the proxy's loopback suite, inside the
script suite — so `make test-scripts` and CI's lint-repo job execute it rather
than leaving a JavaScript test nothing runs.

The suite starts the real proxy on 127.0.0.1 with a fake Claude CLI on PATH; it
needs Node and nothing else. A missing `node` is a failure, not a skip: a proxy
suite that could not run must not read as one that passed.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUITE = ROOT / "src" / "risk" / "claude-proxy.test.js"


class ClaudeProxyLoopbackSuite(unittest.TestCase):
    def test_suite_runs_and_passes(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "node is required to run the claude-proxy loopback suite")
        result = subprocess.run(
            [node, "--test", "--test-reporter=tap", str(SUITE)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output[-4000:])
        passed = re.search(r"^# pass (\d+)$", output, re.MULTILINE)
        failed = re.search(r"^# fail (\d+)$", output, re.MULTILINE)
        self.assertIsNotNone(passed, "the node test runner reported no summary:\n" + output[-2000:])
        self.assertGreater(int(passed.group(1)), 0, "the proxy suite executed zero tests")
        self.assertEqual(failed.group(1) if failed else None, "0")


if __name__ == "__main__":
    unittest.main()
