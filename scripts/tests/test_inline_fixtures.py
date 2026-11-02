"""Positive scanner controls remain data until the smoke stages real inputs."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InlineFixtureTests(unittest.TestCase):
    def test_actual_smoke_stages_all_sources_without_changing_bytes(self):
        script = (ROOT / 'scripts/smoke/semgrep-inline.sh').read_text()
        marker = 'python3 - testdata/semgrep-inline-html "$fixtures" <<\'PY\'\n'
        body = script.split(marker, 1)[1].split('\nPY\n', 1)[0]
        source = ROOT / 'testdata/semgrep-inline-html'
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixtures'
            result = subprocess.run([sys.executable, '-c', body, str(source), str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for original in source.rglob('*'):
                if not original.is_file():
                    continue
                relative = original.relative_to(source)
                if relative.name.endswith('.fixture'):
                    relative = relative.with_suffix('')
                self.assertEqual((target / relative).read_bytes(), original.read_bytes(), str(relative))
            for relative in ['unsafe/page.html', 'unsafe/module.htm', 'unsafe/standalone.js',
                             'unsafe/template.html', 'unsafe/.semgrepignore',
                             'unsafe/ignored/excluded.html', 'safe/page.html']:
                self.assertTrue((target / relative).is_file(), relative)
            self.assertFalse(list(target.rglob('*.fixture')))


if __name__ == '__main__':
    unittest.main()
