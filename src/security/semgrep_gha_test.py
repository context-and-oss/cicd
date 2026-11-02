"""Synthetic adapter contracts; no upstream rule body is redistributed here."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import semgrep_gha as adapter


def fixture():
    return {"rules": [{
        "id": adapter.SOURCE_ID, "languages": ["yaml"], "severity": "ERROR",
        "message": "Synthetic upstream message.",
        "metadata": {"copyright": "Example licensor", "license": "fixture-only", "other": [1, 2]},
        "patterns": [
            {"pattern": "synthetic_marker: $VALUE"},
            {"metavariable-pattern": {"language": "bash", "metavariable": "$SHELL",
                                      "patterns": [{"pattern": "synthetic_command"}]}},
        ],
    }]}


class AdapterTests(unittest.TestCase):
    def test_only_the_matcher_identity_and_explanation_change(self):
        before = fixture()
        frozen = copy.deepcopy(before)
        result = adapter.adapt(before)
        self.assertEqual(before, frozen)
        rule = result["rules"][0]
        self.assertEqual(rule["patterns"][0], before["rules"][0]["patterns"][0])
        self.assertEqual(rule["metadata"], before["rules"][0]["metadata"])
        self.assertEqual(rule["id"], adapter.RULE_ID)
        self.assertEqual(rule["message"], adapter.MESSAGE)
        self.assertEqual(rule["languages"], ["yaml"])
        self.assertEqual(rule["severity"], "ERROR")
        self.assertEqual(rule["patterns"][1], {"metavariable-regex": {
            "metavariable": "$SHELL", "regex": adapter.SHELL_REGEX}})

    def test_unexpected_contracts_are_refused(self):
        cases = [None, {}, {"rules": []}, {"rules": [None]},
                 {"rules": fixture()["rules"] * 2}]
        for key, value in [("id", "other"), ("languages", ["bash"]),
                           ("severity", "WARNING"), ("metadata", None),
                           ("patterns", []), ("patterns", [None, None])]:
            case = fixture()
            case["rules"][0][key] = value
            cases.append(case)
        for key, value in [("language", "python"), ("metavariable", "$OTHER"),
                           ("patterns", []), ("patterns", None)]:
            case = fixture()
            case["rules"][0]["patterns"][1]["metavariable-pattern"][key] = value
            cases.append(case)
        case = fixture()
        case["rules"][0]["patterns"].append(copy.deepcopy(case["rules"][0]["patterns"][1]))
        cases.append(case)
        case = fixture()
        case["rules"][0]["patterns"][1] = {"pattern": "no matcher"}
        cases.append(case)
        case = fixture()
        case["rules"][0]["patterns"][1]["unexpected"] = True
        cases.append(case)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                adapter.adapt(case)

    def prepare(self, root):
        source = root / adapter.SOURCE_PATH
        source.parent.mkdir(parents=True)
        raw = json.dumps(fixture(), indent=2) + "\n"
        source.write_text(raw)
        (root / "LICENSE").write_text("Semgrep Rules License v1.0\nSynthetic fixture notice.\n")
        (root / "NOTICE").write_text("Synthetic retained notice.\n")
        return source, raw

    def test_runtime_copy_retains_complete_source_and_licensor_notices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, raw = self.prepare(root)
            output = root / "generated" / "rule.yml"
            adapter.generate(root, output)
            rendered = output.read_text()
            self.assertTrue(rendered.startswith("# " + adapter.MODIFIED_NOTICE))
            for block in [raw, (root / "LICENSE").read_text(), (root / "NOTICE").read_text()]:
                self.assertIn("\n".join("# " + line for line in block.splitlines()), rendered)
            loaded = json.loads("\n".join(line for line in rendered.splitlines() if not line.startswith("#")))
            self.assertEqual(loaded, adapter.adapt(fixture()))
            self.assertEqual(source.read_text(), raw)

    def test_optional_notice_is_not_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.prepare(root)
            (root / "NOTICE").unlink()
            adapter.generate(root, root / "out.yml")
            self.assertTrue((root / "out.yml").is_file())

    def test_failure_removes_a_stale_output_and_never_exposes_config_text(self):
        for failure in ["missing-source", "missing-license", "changed-license", "malformed", "bad-shape"]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, _ = self.prepare(root)
                if failure == "missing-source":
                    source.unlink()
                elif failure == "missing-license":
                    (root / "LICENSE").unlink()
                elif failure == "changed-license":
                    (root / "LICENSE").write_text("Unreviewed fixture licence")
                elif failure == "malformed":
                    source.write_text("{ not valid: [ synthetic-canary")
                else:
                    source.write_text("{}")
                output = root / "out.yml"
                output.write_text("stale config")
                proc = subprocess.run([sys.executable, str(Path(adapter.__file__)),
                                       "--upstream", str(root), "--output", str(output)],
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 2)
                self.assertFalse(output.exists())
                self.assertNotIn("synthetic-canary", proc.stderr)
                self.assertIn("adaptation failed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
