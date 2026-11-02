"""Executable HTML must not inherit documentation-only CI exemptions."""
import fnmatch
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from repo_surface import _run_block_bodies  # noqa: E402


class HTMLClassificationTests(unittest.TestCase):
    def test_actual_classifier_runs_executable_validation_for_html(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        body = next(body for _, body in _run_block_bodies(workflow) if 'docs_only=false' in body)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = root / 'git'
            git.write_text('#!/bin/sh\nprintf "%s\\n" "$CHANGED_PATH"\n')
            git.chmod(0o755)
            for changed, docs_only in [('README.md', True), ('docs/guide.md', True),
                                       ('docs/example.html', False),
                                       ('src/cross-cutting/pages/template.html', False),
                                       ('src/site/page.htm', False), ('src/security/sast.go', False)]:
                output = root / 'output'
                output.write_text('')
                env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                       'CHANGED_PATH': changed, 'GITHUB_OUTPUT': str(output),
                       'EVENT_NAME': 'pull_request', 'BASE_SHA': 'local'}
                result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text().strip(), 'docs_only=' + str(docs_only).lower(), changed)

    def test_dogfood_does_not_ignore_html_changes(self):
        workflow = (ROOT / '.github/workflows/dogfood-precommit.yml').read_text()
        block = workflow.split('paths-ignore:', 1)[1].split('  push:', 1)[0]
        patterns = re.findall(r"^\s+- '([^']+)'", block, re.M)
        self.assertTrue(patterns)
        for path in ['docs/example.html', 'src/cross-cutting/pages/template.html', 'src/site/page.htm']:
            self.assertFalse(any(fnmatch.fnmatch(path, pattern) for pattern in patterns), path)


if __name__ == '__main__':
    unittest.main()
