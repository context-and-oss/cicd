"""The deployment handoff refuses bytes or provenance not bound by the verdict."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("build_artifact", Path(__file__).parents[1] / "verify-build-artifact.py")
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


class BuildArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.provenance = {"repoUrl": "https://example.test/repo", "commitSha": "abc123", "branch": "main", "appId": "web"}
        self.evidence = {"repo": self.provenance, "passed": True}
        (self.root / "application.tar.gz").write_bytes(b"exact assessed payload")
        self.manifest = {"schemaVersion": "1.0", "repo": self.provenance, "passed": True, "runUrl": "https://example.test/runs/42",
                         "artifacts": [{"kind": "archive", "path": "application.tar.gz", "sha256": artifact.digest(self.root / "application.tar.gz")}]}
        self.write_evidence()
        self.write_manifest()

    def write_evidence(self):
        path = self.root / "combined-evidence.json"
        path.write_text(json.dumps(self.evidence))
        self.manifest["evidenceSha256"] = artifact.digest(path)

    def write_manifest(self):
        (self.root / "artifact-manifest.json").write_text(json.dumps(self.manifest))

    def verify(self, **overrides):
        kwargs = dict(repo=self.provenance["repoUrl"], commit="abc123", branch="main", app_id="web", run_url=self.manifest["runUrl"])
        kwargs.update(overrides)
        return artifact.verify(self.root, **kwargs)

    def test_valid_archive_and_container(self):
        self.assertEqual(self.verify().name, "application.tar.gz")
        (self.root / "application.tar.gz").rename(self.root / "image.tar")
        self.manifest["artifacts"][0].update(kind="container", path="image.tar")
        self.write_manifest()
        self.assertEqual(self.verify().name, "image.tar")

    def test_wrong_source_or_run(self):
        for key in ("repo", "commit", "branch", "app_id", "run_url"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(**{key: "wrong"})

    def test_changed_payload_or_evidence(self):
        for name in ("application.tar.gz", "combined-evidence.json"):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"tampered")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "checksum"):
                self.verify()
            path.write_bytes(original)

    def test_false_missing_or_string_verdict(self):
        for value in (False, None, "true", 1):
            with self.subTest(value=value):
                self.evidence["passed"] = value
                self.write_evidence()
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_no_payload(self):
        self.manifest["artifacts"] = []
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.verify()

    def test_traversing_path_is_refused_even_with_a_valid_external_payload(self):
        # Otherwise-valid entry: the external file exists and its checksum
        # matches, so only path containment can reject it.
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        external = Path(outside.name) / "application.tar.gz"
        external.write_bytes(b"bytes nobody assessed")
        relative = os.path.relpath(external, self.root)
        self.assertTrue(relative.startswith(".."))
        for path in (relative, str(external)):
            with self.subTest(path=path):
                self.manifest["artifacts"] = [{"kind": "archive", "path": path, "sha256": artifact.digest(external)}]
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, "transport path"):
                    self.verify()

    def test_symlink_is_not_a_payload(self):
        path = self.root / "application.tar.gz"
        path.rename(self.root / "elsewhere")
        path.symlink_to("elsewhere")
        with self.assertRaises(ValueError):
            self.verify()

    def test_matching_hash_cannot_hide_wrong_evidence_provenance(self):
        self.evidence["repo"] = dict(self.provenance, commitSha="different")
        self.write_evidence()
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.verify()

    def test_failed_manifest_is_not_deployable(self):
        self.manifest["passed"] = False
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.verify()
