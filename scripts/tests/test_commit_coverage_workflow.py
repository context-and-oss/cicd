"""Exercise the actual workflow's report-path argument forwarding."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SENTINEL = b"--parallelism\x003\x00"


class CommitCoverageWorkflow(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/commit.yml").read_text()

    def test_optional_input_and_environment_binding(self):
        declaration = self.workflow.split("      coverage-path:\n", 1)[1].split("      test-legs:", 1)[0]
        self.assertIn("required: false", declaration)
        self.assertIn("type: string", declaration)
        self.assertIn("default: ''", declaration)
        self.assertIn("COVERAGE_PATH: ${{ inputs.coverage-path }}", self.workflow)
        commit_step = self.workflow.split("      - name: Run commit composite\n", 1)[1].split("\n      - ", 1)[0]
        commit_run = commit_step.split("        run: |\n", 1)[1]
        self.assertIn('--coverage-path "$COVERAGE_PATH"', commit_run)
        self.assertNotIn("${{ inputs.coverage-path }}", commit_run)

    def test_caller_checkout_cannot_shadow_the_module_reader(self):
        checkout = self.workflow.split("      - name: Checkout\n", 1)[1].split("\n      - ", 1)[0]
        self.assertIn("          persist-credentials: false\n", checkout)
        self.assertIn("          fetch-depth: 0\n", checkout)
        diff = self.workflow.split("      - name: Compute change diff", 1)[1].split("\n      - ", 1)[0]
        self.assertNotIn("git fetch", diff)

    def test_actual_shell_preserves_path_as_one_argument_and_omits_empty(self):
        block = re.search(r'          if \[ -n "\$COVERAGE_PATH" \]; then\n.*?          fi', self.workflow, re.S)
        self.assertIsNotNone(block)
        script = 'set -eu\nextra=(--parallelism 3)\n' + block.group() + '\nprintf "%s\\0" "${extra[@]}"'
        for value in ("", "coverage/coverage-summary.json", "reports with spaces/summary.json", '$(exit 99); "quoted"/*.json'):
            with self.subTest(path=value):
                result = subprocess.run(["bash", "-c", script], env={**os.environ, "COVERAGE_PATH": value}, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = b"--parallelism\x003\x00" + (("--coverage-path\0" + value + "\0").encode() if value else b"")
                self.assertEqual(result.stdout, expected)

    def _ratchet_script(self):
        block = re.search(r'          case "\$RATCHET_MODE" in\n.*?          esac', self.workflow, re.S)
        self.assertIsNotNone(block)
        return 'set -eu\nextra=(--parallelism 3)\n' + re.sub(r"(?m)^          ", "", block.group()) + '\nprintf "%s\\0" "${extra[@]}"'

    def _run_ratchet(self, **env):
        base = {"RATCHET_MODE": "", "RATCHET_TOLERANCE": "1.0", "RATCHET_BASELINE": "", "TEST_CMD": "npm test", "TEST_LEGS": ""}
        return subprocess.run(["bash", "-c", self._ratchet_script()], env={**os.environ, **base, **env}, capture_output=True)

    def test_ratchet_is_opt_in_and_forwards_only_a_real_baseline(self):
        self.assertEqual(self._run_ratchet().stdout, SENTINEL)
        self.assertEqual(self._run_ratchet(RATCHET_MODE="gate", TEST_CMD="").stdout, SENTINEL)
        warn = self._run_ratchet(RATCHET_MODE="warn", RATCHET_TOLERANCE="0.5", RATCHET_BASELINE="/nonexistent")
        self.assertEqual(warn.stdout, SENTINEL + b"--coverage-gate\0warn\0--tolerance\x000.5\0")
        with tempfile.NamedTemporaryFile() as baseline:
            gate = self._run_ratchet(RATCHET_MODE="gate", RATCHET_BASELINE=baseline.name)
            self.assertEqual(gate.stdout, SENTINEL + b"--coverage-gate\0gate\0--tolerance\x001.0\0--baseline\0" + baseline.name.encode() + b"\0")

    def test_unknown_ratchet_mode_is_refused(self):
        for value in ("Gate", "off", "gate; true"):
            with self.subTest(value=value):
                result = self._run_ratchet(RATCHET_MODE=value)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"coverage-gate must be empty", result.stdout)

    def test_inputs_default_to_off_and_bind_through_env(self):
        gate = self.workflow.split("      coverage-gate:\n", 1)[1].split("      coverage-tolerance:", 1)[0]
        self.assertIn("default: ''", gate)
        self.assertIn("RATCHET_MODE: ${{ inputs.coverage-gate }}", self.workflow)
        self.assertIn("RATCHET_BASELINE: ${{ steps.baseline.outputs.file }}", self.workflow)
        fetch = self.workflow.split("      - name: Fetch coverage ratchet baseline\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: inputs.coverage-gate != ''", fetch)
        self.assertIn("continue-on-error: true", fetch)
        self.assertNotIn("${{ inputs.", fetch.split("run: |", 1)[1])

    def _fetch_script(self):
        fetch = self.workflow.split("      - name: Fetch coverage ratchet baseline\n", 1)[1].split("\n      - name:", 1)[0]
        return re.sub(r"(?m)^          ", "", fetch.split("        run: |\n", 1)[1])

    def _run_fetch(self, gh_body):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin"); bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text("#!/usr/bin/env bash\n" + gh_body)
            gh.chmod(0o755)
            out = Path(tmp, "out")
            env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "RUNNER_TEMP": tmp, "GITHUB_OUTPUT": str(out),
                   "REPO": "o/r", "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/nightly.yml@refs/heads/main", "GH_TOKEN": "t"}
            result = subprocess.run(["bash", "-c", self._fetch_script()], env=env, capture_output=True, text=True)
            return result, out.read_text() if out.exists() else "", tmp

    def test_fetch_uses_the_caller_workflows_default_branch_evidence(self):
        gh = '''case "$*" in
  "api repos/o/r --jq .default_branch") echo main ;;
  *"workflows/nightly.yml/runs?branch=main&status=success"*) printf '11\\n12\\n' ;;
  "api repos/o/r/actions/runs/11/artifacts"*) echo "" ;;
  "api repos/o/r/actions/runs/12/artifacts"*) echo commit-evidence-abc ;;
  "run download 12 -R o/r --name commit-evidence-abc --dir "*) d="${@: -1}"; echo '{}' > "$d/combined-evidence.json" ;;
  *) echo "unexpected: $*" >&2; exit 9 ;;
esac
'''
        result, out, tmp = self._run_fetch(gh)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("commit-evidence-abc (run 12 on main)", result.stdout)
        self.assertEqual(out, f"file={tmp}/coverage-baseline/combined-evidence.json\n")

    def test_fetch_fails_open_without_a_baseline(self):
        result, out, _ = self._run_fetch("exit 1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("BOOTSTRAP MODE", result.stdout)
        self.assertEqual(out, "file=\n")

    def test_no_obsolete_reachability_exemption(self):
        import json
        inventory = json.loads((ROOT / "scripts/repo-inventory.json").read_text())
        entries = inventory["composite_reach"]["unreachable"]
        for entry in entries:
            if entry["param"] in ("coverage-path", "baseline", "tolerance", "coverage-gate"):
                self.assertNotIn(".github/workflows/commit.yml", entry["sites"])
