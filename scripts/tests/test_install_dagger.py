"""Tests for .github/actions/install-dagger and its inline copies.

Two claims. The reusable workflows cannot `uses:` a local action, so each
carries the action's step body inline, and the first test refuses the drift
between them. The second drives the body itself, with a fake `curl` serving a
release directory on disk, so a tampered tarball, a checksums.txt that omits
the asset, and a binary of the wrong version are each proven to fail the step
rather than to install something.
"""

import hashlib
import io
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "install-dagger" / "action.yml"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
INLINE_COPIES = ["commit.yml", "precommit.yml", "dast.yml", "commit-monorepo.yml"]
VERSION = "0.20.8"

FAKE_CURL = """#!/usr/bin/env bash
# Serves $FAKE_RELEASE_DIR/<basename of the URL> into the -o target.
out=; url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
echo "$url" >> "$FAKE_LOG"
src="$FAKE_RELEASE_DIR/$(basename "$url")"
[ -f "$src" ] || { echo "curl: (22) not found: $url" >&2; exit 22; }
cp "$src" "$out"
"""

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"
[ "${FAKE_DOCKER_FAILS:-}" = 1 ] && exit 1
exit 0
"""

FAKE_SLEEP = "#!/usr/bin/env bash\nexit 0\n"

FAKE_DAGGER = """#!/usr/bin/env bash
echo "dagger v%s (image://registry.dagger.io/engine:v%s) linux/amd64"
"""


def action_body() -> str:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"][0]["run"]


ADO_TEMPLATES = sorted((REPO_ROOT / "templates" / "azure-devops").rglob("*.yml"))


def shared_block() -> str:
    """The download-verify-install-check lines every copy must carry verbatim."""
    lines = action_body().splitlines()
    return "\n".join(lines[1 : lines.index("esac") + 1]) + "\n"


def ado_install_steps(template: pathlib.Path):
    doc = yaml.safe_load(template.read_text(encoding="utf-8"))
    for step in doc.get("steps", []):
        if step.get("displayName", "").startswith("Install Dagger"):
            yield step


def install_steps(workflow: pathlib.Path):
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name", "").startswith("Install Dagger"):
                yield step


class InlineCopiesTests(unittest.TestCase):
    def test_every_reusable_workflow_carries_the_action_body_verbatim(self):
        body = action_body()
        for name in INLINE_COPIES:
            steps = list(install_steps(WORKFLOWS / name))
            self.assertTrue(steps, f"{name} has no Install Dagger step")
            for step in steps:
                with self.subTest(workflow=name):
                    self.assertEqual(step.get("run"), body, f"{name} drifted from the action")
                    self.assertEqual(step.get("env", {}).get("VERSION"), "${{ env.DAGGER_VERSION }}")

    def test_no_workflow_pipes_the_installer_into_a_shell(self):
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            with self.subTest(workflow=workflow.name):
                self.assertNotIn("dagger/install.sh", workflow.read_text(encoding="utf-8"))

    def test_internal_workflows_use_the_local_action(self):
        for name in ["ci.yml", "cd.yml", "release.yml", "dogfood-precommit.yml"]:
            steps = list(install_steps(WORKFLOWS / name))
            self.assertTrue(steps, f"{name} has no Install Dagger step")
            for step in steps:
                with self.subTest(workflow=name):
                    self.assertEqual(step.get("uses"), "./.github/actions/install-dagger")
                    self.assertEqual(step.get("with", {}).get("version"), "${{ env.DAGGER_VERSION }}")

    def test_every_dagger_version_across_the_workflows_is_identical(self):
        versions = {}
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            found = re.findall(r'^\s*DAGGER_VERSION: "([^"]+)"', workflow.read_text(encoding="utf-8"), re.M)
            if found:
                versions[workflow.name] = set(found)
        self.assertTrue(versions)
        self.assertEqual(len(set().union(*versions.values())), 1, versions)

    def test_the_action_declares_no_version_of_its_own(self):
        # The version is the caller's env.DAGGER_VERSION, which Renovate already
        # rewrites; a default on the input or a constant in the body would be the
        # copy the bump misses. The description may name one as an example.
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        self.assertNotIn("default", doc["inputs"]["version"])
        step = doc["runs"]["steps"][0]
        self.assertNotRegex(step["run"], r"\d+\.\d+\.\d+")
        self.assertEqual(step["env"], {"VERSION": "${{ inputs.version }}"})


class StepBodyTests(unittest.TestCase):
    """Drives the action's run body with a release directory on disk."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, text in (("curl", FAKE_CURL), ("docker", FAKE_DOCKER), ("sleep", FAKE_SLEEP)):
            path = self.bin / name
            path.write_text(text)
            path.chmod(0o755)
        self.release = self.tmp / "release"
        self.release.mkdir()
        self.install_dir = self.tmp / "installed"
        self.install_dir.mkdir()
        self.github_env = self.tmp / "github.env"
        self.log = self.tmp / "fake.log"
        self.script = self.tmp / "step.sh"
        self.script.write_text(action_body())

    def publish(self, version=VERSION, binary_version=VERSION, checksum_for=None, tamper=False):
        asset = f"dagger_v{version}_linux_amd64.tar.gz"
        binary = (FAKE_DAGGER % (binary_version, binary_version)).encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("dagger")
            info.size = len(binary)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(binary))
        data = buf.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        if tamper:
            data = data + b"\0"
        (self.release / asset).write_bytes(data)
        listed = checksum_for if checksum_for is not None else asset
        (self.release / "checksums.txt").write_text(
            f"{'0' * 64}  dagger_v{version}_darwin_arm64.tar.gz\n{digest}  {listed}\n"
        )

    def run_step(self, version=VERSION, docker_fails=False):
        env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ['PATH']}",
            VERSION=version,
            GITHUB_ENV=str(self.github_env),
            DAGGER_INSTALL_DIR=str(self.install_dir),
            FAKE_RELEASE_DIR=str(self.release),
            FAKE_LOG=str(self.log),
            FAKE_DOCKER_FAILS="1" if docker_fails else "",
        )
        return subprocess.run(["bash", str(self.script)], env=env, capture_output=True, text=True)

    def installed(self) -> bool:
        return (self.install_dir / "dagger").exists()

    def test_an_intact_download_installs_and_records_the_engine_host(self):
        self.publish()
        res = self.run_step()
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertTrue(self.installed())
        self.assertIn(f"_EXPERIMENTAL_DAGGER_RUNNER_HOST=docker-image://ghcr.io/dagger/engine:v{VERSION}",
                      self.github_env.read_text())
        self.assertIn(f"docker pull ghcr.io/dagger/engine:v{VERSION}", self.log.read_text())
        self.assertIn(f"releases/{VERSION}/dagger_v{VERSION}_linux_amd64.tar.gz", self.log.read_text())

    def test_a_tampered_tarball_fails_before_anything_is_installed(self):
        self.publish(tamper=True)
        res = self.run_step()
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(self.installed())
        self.assertFalse(self.github_env.exists())
        self.assertNotIn("docker pull", self.log.read_text())

    def test_a_checksums_file_that_omits_the_asset_verifies_nothing_and_fails(self):
        self.publish(checksum_for="dagger_v0.20.8_linux_arm64.tar.gz")
        res = self.run_step()
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(self.installed())

    def test_a_binary_of_another_version_is_refused_after_install(self):
        self.publish(binary_version="0.20.7")
        res = self.run_step()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(f"installed dagger is not v{VERSION}", res.stderr)
        self.assertFalse(self.github_env.exists())

    def test_an_unreachable_engine_mirror_is_red_after_eight_attempts(self):
        self.publish()
        res = self.run_step(docker_fails=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("::error::Failed to pull", res.stdout)
        self.assertEqual(self.log.read_text().count("docker pull"), 8)
        self.assertFalse(self.github_env.exists())


class AdoTemplateTests(unittest.TestCase):
    """The ADO templates cannot `uses:` the action either, so they carry the block.

    They differ from the GitHub copies only around it: an install directory on
    the agent instead of /usr/local/bin (no sudo assumed on a self-hosted
    agent), and ##vso logging commands instead of GITHUB_ENV.
    """

    def test_every_ado_template_carries_the_verified_block_verbatim(self):
        self.assertTrue(ADO_TEMPLATES)
        block = shared_block()
        for template in ADO_TEMPLATES:
            steps = list(ado_install_steps(template))
            with self.subTest(template=template.name):
                self.assertEqual(len(steps), 1, f"{template} has no single Install Dagger step")
                self.assertIn(block, steps[0]["bash"])
                self.assertEqual(steps[0]["env"]["VERSION"], "$(DAGGER_VERSION)")

    def test_no_ado_template_pipes_the_installer_into_a_shell(self):
        for template in ADO_TEMPLATES:
            with self.subTest(template=template.name):
                self.assertNotRegex(template.read_text(encoding="utf-8"), r"install\.sh\s*\|")

    def run_ado(self, tamper=False):
        harness = StepBodyTests("test_an_intact_download_installs_and_records_the_engine_host")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        body = next(ado_install_steps(ADO_TEMPLATES[0]))["bash"]
        harness.script.write_text(body)
        harness.publish(tamper=tamper)
        return harness, harness.run_step()

    def test_the_ado_body_installs_an_intact_download_onto_the_path(self):
        harness, res = self.run_ado()
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertTrue(harness.installed())
        self.assertIn(f"##vso[task.prependpath]{harness.install_dir}", res.stdout)
        self.assertIn("##vso[task.setvariable variable=_EXPERIMENTAL_DAGGER_RUNNER_HOST]", res.stdout)

    def test_the_ado_body_refuses_a_tampered_tarball(self):
        harness, res = self.run_ado(tamper=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(harness.installed())
        self.assertNotIn("##vso[task.prependpath]", res.stdout)


if __name__ == "__main__":
    unittest.main()
