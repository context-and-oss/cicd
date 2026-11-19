"""Guard the reusable commit workflow's caller permissions and evidence delivery."""
import pathlib
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]


class CommitWorkflow(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(
            (ROOT / ".github/workflows/commit.yml").read_text(), Loader=yaml.BaseLoader
        )
        self.template = yaml.load(
            (ROOT / "templates/github-actions/commit.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_caller_does_not_need_publishing_permissions(self):
        # GitHub validates every nested job's permissions before evaluating its if.
        grant = self.template["permissions"]
        levels = {"none": 0, "read": 1, "write": 2}
        forbidden = {"pages", "id-token"}
        self.assertTrue(forbidden.isdisjoint(grant))
        requests = {name: job.get("permissions", {}) for name, job in self.workflow["jobs"].items()}
        requests["workflow defaults"] = self.workflow["permissions"]
        for name, permissions in requests.items():
            with self.subTest(job=name):
                self.assertTrue(forbidden.isdisjoint(permissions))
                for scope, access in permissions.items():
                    self.assertLessEqual(levels[access], levels[grant.get(scope, "none")], scope)

    def test_legacy_input_remains_accepted_without_a_deploy_job(self):
        legacy = self.workflow["on"]["workflow_call"]["inputs"]["deploy-pages"]
        self.assertEqual((legacy["type"], legacy["default"]), ("boolean", "false"))
        self.assertIn("Deprecated and ignored", legacy["description"])
        jobs = self.workflow["jobs"]
        self.assertNotIn("pages", jobs)
        for job in jobs.values():
            for step in job.get("steps", []):
                self.assertNotIn(step.get("uses", "").split("@")[0], {
                    "actions/deploy-pages", "actions/upload-pages-artifact",
                })
        steps = jobs["commit"]["steps"]
        evidence = next(step for step in steps if step.get("name") == "Upload evidence")
        self.assertTrue(evidence["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(evidence["if"], "always()")
