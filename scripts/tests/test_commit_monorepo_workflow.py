"""Check the app workflow's evidence-only boundary and failure-output contract."""
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest


class ApplicationWorkflow(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(__file__).resolve().parents[2]
        self.workflow = (self.root / ".github/workflows/commit-monorepo.yml").read_text()
        # Assert the checked-in contract without requiring a YAML dependency.
        # Syntax validation remains the repository's workflow validator's job.
        self.steps = re.split(r"(?m)^      - ", self.workflow.split("    steps:\n", 1)[1])[1:]

    def step(self, identity):
        return next(s for s in self.steps if f"        id: {identity}\n" in s)

    def test_evidence_only_permissions_and_actions(self):
        self.assertRegex(self.workflow, r"(?m)^permissions:\n  contents: read\n\n")
        actions = re.findall(r"(?:^|\n)\s*(?:- )?uses: ([^@\s]+)@", self.workflow)
        self.assertEqual(actions, ["actions/checkout", "actions/upload-artifact", "actions/upload-artifact"])
        # The modules are fetched from the public repository: no token is
        # minted, and nothing writes ~/.git-credentials.
        self.assertNotIn("create-github-app-token", self.workflow)
        self.assertNotIn(".git-credentials", self.workflow)
        body = "\n".join(self.steps)
        for publishing in ("GITHUB_STEP_SUMMARY", "upload-sarif", "deploy-pages", "teams-webhook"):
            self.assertNotIn(publishing, body)

    def test_deployable_requires_passed_gate_and_separate_upload(self):
        upload = self.step("build-artifact")
        self.assertIn("if: success() && steps.gate.outputs.passed == 'true' && inputs.artifact != 'none'", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn("!${{ steps.execute.outputs.evidence-path }}/artifacts/**", self.step("upload"))
        self.assertIn("steps.build-artifact.outcome == 'success'", self.workflow)
        self.assertIn("github.run_attempt", upload)

    def test_input_values_are_data_and_every_scope_reaches_the_composite(self):
        execute = self.step("execute").split("        run: |\n", 1)[1]
        self.assertNotIn("${{ inputs.", execute)
        for flag in ("--app-id", "--source-paths", "--lint-legs", "--test-legs"):
            self.assertIn(flag, execute)
        self.assertIn("mktemp -d", execute)
        self.assertIn('export --path "$evidence_dir"', execute)

    def test_application_workflow_has_no_sbom_execution_path(self):
        self.assertNotIn("sbom-legs", self.workflow)
        template = (self.root / "templates/github-actions/commit-monorepo.yml").read_text()
        self.assertNotIn("sbom-legs", template)
        app = (self.root / "src/composites/commit/app.go").read_text()
        for call in (".Sbom(", ".ScanSbom(", ".ScanImage("):
            self.assertNotIn(call, app)
        self.assertIn("CodeOnly: true", app)
        self.assertIn("ArtifactOnly: true", app)
        self.assertIn("SourceOnly: true", app)
        self.assertIn("OmitSbom: true", app)
        self.assertIn('Collect(src, "lint",', app)
        wrap = (self.root / "src/cross-cutting/evidence/wrap.go").read_text()
        self.assertIn('if !omitSbom {\n\t\tif err := writeBundleFile("sbom.cdx.json", cdxJSON)', wrap)
        self.assertIn("deferredAppDependencies(envs, repo, start)", wrap)
        regular = (self.root / "src/composites/commit/main.go").read_text()
        self.assertIn("dag.Build().Sbom(", regular)

    def test_failed_gate_still_exposes_the_uploaded_evidence(self):
        ids = re.findall(r"(?m)^        id: (.+)$", self.workflow)
        self.assertLess(ids.index("upload"), ids.index("gate"))
        gate = self.step("gate")
        self.assertIn("        if: always()\n", gate)
        self.assertLess(gate.index("passed=false"), gate.index("exit 1"))
        self.assertIn("if: always() && steps.upload.outcome == 'success'", self.step("identity"))
        upload = self.step("upload")
        self.assertIn("if: always() && steps.execute.outcome == 'success'", upload)
        self.assertIn("name: commit-evidence-${{ inputs.app-id }}", upload)

    def test_command_log_preserves_the_captured_exit_and_fresh_output(self):
        source = (self.root / "src/quality/appcommand.go").read_text()
        script = re.search(r'WithExec\(\[\]string\{"sh", "-c", `([^`]+)`', source).group(1)
        for code in (0, 1, 2, 7):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as folder:
                base = pathlib.Path(folder)
                report = base / "report with spaces.json"
                report.write_text("stale")
                isolated = script.replace("/tmp/app-command", str(base / "command"))
                command = f"test ! -e {shlex.quote(str(report))} || exit 99; printf 'diagnostic'; exit {code}"
                result = subprocess.run(["sh", "-c", isolated, "app-command", command, str(report)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((base / "command.exit").read_text(), str(code))
                self.assertFalse(report.exists())
                self.assertEqual(result.stderr, "diagnostic" if code else "")

    def test_cannot_hide_report_cleanup_failure_with_log_output(self):
        source = (self.root / "src/quality/appcommand.go").read_text()
        script = re.search(r'WithExec\(\[\]string\{"sh", "-c", `([^`]+)`', source).group(1)
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            report = base / "directory-not-report"
            report.mkdir()
            isolated = script.replace("/tmp/app-command", str(base / "command"))
            result = subprocess.run(["sh", "-c", isolated, "app-command", "exit 0", str(report)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((base / "command.exit").exists())
