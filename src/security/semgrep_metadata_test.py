"""First-party fixtures; no upstream rule bodies are redistributed."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from semgrep_metadata import PROPERTY, enrich_sarif, project

FIXTURE = Path(__file__).resolve().parents[2] / "testdata/semgrep-finding-metadata"


class MetadataTests(unittest.TestCase):
    def test_real_pinned_report(self):
        native = json.loads((FIXTURE / "native.json").read_text())
        original = json.loads((FIXTURE / "native.sarif").read_text())
        enriched = enrich_sarif(native, copy.deepcopy(original))
        rows = {r["ruleId"]: r for r in enriched["runs"][0]["results"]}
        self.assertEqual(rows["synthetic-security-audit"]["properties"][PROPERTY], {
            "concern": "sast", "category": "security", "subcategories": ["audit"],
            "confidence": "LOW", "weaknessIds": ["CWE-79"],
            "classificationSource": "scanner-metadata",
        })
        self.assertEqual(rows["synthetic-style"]["properties"][PROPERTY]["category"], "style")
        self.assertEqual(rows["synthetic-unknown"]["properties"][PROPERTY], {"concern": "sast"})
        # No finding, severity, suppression or native field is altered.
        for run in enriched["runs"]:
            for row in run["results"]:
                del row["properties"][PROPERTY]
        self.assertEqual(enriched, original)

    def test_allowlist_never_copies_source_or_verification(self):
        self.assertEqual(project({
            "category": "style", "subcategory": ["audit", "audit", "matched source"],
            "confidence": "low", "cwe": ["CWE-79: prose", "CWE-89", "CWE-invalid", "secret"],
            "precision": "very-high", "severity": "CRITICAL", "confirmed": True,
            "source": "source text", "fix": "matched text",
        }), {"category": "style", "subcategories": ["audit"], "confidence": "LOW",
             "weaknessIds": ["CWE-79", "CWE-89"], "classificationSource": "scanner-metadata"})
        for malformed in [None, [], "security", {"category": []}, {"confidence": "certain"},
                          {"category": "best-practice"}, {"precision": "very-high"},
                          {"subcategory": [False, {}]}, {"cwe": [{"id": "CWE-79"}]}]:
            self.assertEqual(project(malformed), {})

    def test_conflicting_rules_are_unknown(self):
        profile = {"results": [
            {"check_id": "same", "extra": {"metadata": {"category": "security"}}},
            {"check_id": "same", "extra": {"metadata": {"category": "style"}}},
        ]}
        sarif = {"runs": [{"results": [{"ruleId": "same"}]}]}
        row = enrich_sarif(profile, sarif)["runs"][0]["results"][0]
        self.assertEqual(row["properties"][PROPERTY], {"concern": "sast"})

    def test_rule_index_and_exact_identity(self):
        profile = {"results": [{"check_id": "exact", "extra": {"metadata": {"confidence": "LOW"}}}]}
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "exact"}]}},
                           "results": [{"ruleIndex": 0}, {"ruleId": "EXACT"}]}]}
        rows = enrich_sarif(profile, sarif)["runs"][0]["results"]
        self.assertEqual(rows[0]["properties"][PROPERTY]["confidence"], "LOW")
        self.assertEqual(rows[1]["properties"][PROPERTY], {"concern": "sast"})

    def test_unreadable_optional_json_keeps_original_sarif_and_is_silent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sarif = root / "report.sarif"
            native = root / "report.json"
            original = (FIXTURE / "native.sarif").read_bytes()
            sarif.write_bytes(original)
            native.write_text("invalid synthetic report")
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("semgrep_metadata.py")),
                                     "--json", str(native), "--sarif", str(sarif)], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout + result.stderr, b"")
            self.assertEqual(sarif.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
