"""
Coverage tests for the bounded update configuration (renovate.json).

The pins this repository maintains by hand — the static runtime tool images and
the Dagger version — only stay maintainable if something actually proposes bumps
for them. But an update robot pointed at the whole tree is worse than none: it
would rewrite the consumer copy-paste templates, chase unrelated version prose in
docs, and start proposing GitHub Action bumps that Dependabot already owns (and
that the intent gate's approved machine-origin path recognises by actor name).

So this suite asserts both directions against the *real* files in the tree:

  positive  every image declared in scripts/runtime-images.json is matched by a
            custom manager, in the file that declares it, extracting exactly the
            depName, tag and digest the inventory records — and the Dagger version
            is matched in this repository's own workflows and module dagger.json
  negative  consumer templates, docs, changelog prose, non-images.go Go sources
            and the Dependabot config produce no matches at all, and a synthetic
            images.go without the `// renovate-image:` declaration is not matched
            either, so a family cannot be silently half-added

The regexes are evaluated with Python's `re` after a single translation of the
named-group spelling (`(?<x>)` → `(?P<x>)`); see `_js_regex_to_python`. Keeping the
translation that small is deliberate — the further these tests drift from what
Renovate itself runs, the less they prove.

Installing or activating the Renovate App is a separate human action. Nothing in
ordinary CI reads renovate.json to fetch versions.
"""
from __future__ import annotations

import copy
import pathlib
import re
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from runtime_images import (  # noqa: E402
    InventoryError,
    check_update_config,
    custom_managers,
    load_inventory,
    load_update_config,
    update_group_of,
    update_matches_for,
)

CONFIG_PATH = REPO_ROOT / "renovate.json"
INVENTORY_PATH = SCRIPTS / "runtime-images.json"

# Files that legitimately carry version-shaped text the update config must leave
# alone. Consumer templates are copy-paste starters owned by the release pin
# rewrite (scripts/bump-version.py), not by an update robot; the rest is prose or
# an unrelated package version.
UNTOUCHED_FILES = (
    "templates/azure-devops/commit.yml",
    "templates/azure-devops/precommit.yml",
    "templates/github-actions/commit.yml",
    "templates/azure-devops/shared/precommit.yml",
    "docs/decisions/ADR-004-toolchain-resolution.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "src/quality/lint.go",
    "src/quality/schema.go",
    "src/security/sast.go",
    ".github/dependabot.yml",
)


class ConfigShapeTests(unittest.TestCase):
    def setUp(self):
        self.config = load_update_config(CONFIG_PATH)

    def test_config_is_valid_json_with_a_schema_reference(self):
        self.assertIn("$schema", self.config)
        self.assertIn("renovate-schema.json", self.config["$schema"])

    def test_only_the_custom_regex_manager_is_enabled(self):
        """Everything else — gomod, npm, docker, github-actions — stays off.

        GitHub Actions remain SHA-pinned by Dependabot (.github/dependabot.yml),
        and the intent gate's approved machine-origin path is scoped to
        dependabot[bot] by name, so a second robot proposing action bumps would
        arrive without that approval.
        """
        self.assertEqual(self.config.get("enabledManagers"), ["custom.regex"])

    def test_dependabot_still_owns_github_actions(self):
        dependabot = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("github-actions", dependabot)

    def test_every_manager_uses_an_explicit_anchored_file_regex(self):
        for index, manager in enumerate(custom_managers(self.config)):
            with self.subTest(manager=index):
                patterns = manager.get("managerFilePatterns") or []
                self.assertTrue(patterns, "manager declares no managerFilePatterns")
                for pattern in patterns:
                    self.assertTrue(pattern.startswith("/") and pattern.endswith("/"), pattern)
                    self.assertTrue(pattern[1:].startswith("^"), pattern)

    def test_no_manager_is_pointed_at_templates_docs_or_testdata(self):
        for index, manager in enumerate(custom_managers(self.config)):
            for pattern in manager.get("managerFilePatterns") or []:
                with self.subTest(manager=index, pattern=pattern):
                    for forbidden in ("templates", "docs", "testdata"):
                        self.assertNotIn(forbidden, pattern)


class ImageCoverageTests(unittest.TestCase):
    """Positive coverage: every maintained pin is recognised."""

    def setUp(self):
        self.config = load_update_config(CONFIG_PATH)
        self.inventory = load_inventory(INVENTORY_PATH)

    def test_the_shipped_config_covers_every_declared_image(self):
        self.assertEqual(
            check_update_config(self.inventory, self.config, REPO_ROOT), []
        )

    def test_each_image_is_matched_with_its_exact_tag_and_digest(self):
        for entry in self.inventory["images"]:
            with self.subTest(image=f"{entry['repository']}:{entry['tag']}"):
                extracted = [
                    (m.dep_name, m.current_value, m.current_digest)
                    for source in entry["sources"]
                    for m in update_matches_for(self.config, REPO_ROOT, source)
                ]
                self.assertIn(
                    (entry["repository"], entry["tag"], entry["digest"]),
                    extracted,
                )

    def test_every_family_has_its_own_revertable_group(self):
        groups = {
            rule["groupName"]: rule.get("matchDepNames") or []
            for rule in self.config["packageRules"]
            if rule.get("groupName")
        }
        for entry in self.inventory["images"]:
            with self.subTest(family=entry["family"]):
                group = update_group_of(entry)
                self.assertIn(group, groups)
                self.assertIn(entry["repository"], groups[group])

    def test_families_are_not_merged_into_one_group(self):
        """One family per group — otherwise a bad bump cannot be reverted alone."""
        families = {entry["family"] for entry in self.inventory["images"]}
        image_groups = {
            rule["groupName"]
            for rule in self.config["packageRules"]
            if str(rule.get("groupName", "")).startswith("runtime image: ")
        }
        self.assertEqual(len(image_groups), len(families))

    def test_dropping_a_family_group_is_detected(self):
        """The coverage check must fail when a maintained family loses its group."""
        broken = copy.deepcopy(self.config)
        broken["packageRules"] = [
            rule
            for rule in broken["packageRules"]
            if rule.get("groupName") != "runtime image: trivy"
        ]
        problems = check_update_config(self.inventory, broken, REPO_ROOT)
        self.assertTrue(any("runtime image: trivy" in p for p in problems), problems)

    def test_dropping_the_images_manager_is_detected(self):
        broken = copy.deepcopy(self.config)
        broken["customManagers"] = [
            m
            for m in broken["customManagers"]
            if not any("images" in p for p in m.get("managerFilePatterns") or [])
        ]
        problems = check_update_config(self.inventory, broken, REPO_ROOT)
        self.assertTrue(
            any("not matched by any renovate.json custom manager" in p for p in problems),
            problems,
        )

    def test_a_config_with_no_managers_at_all_is_refused(self):
        broken = copy.deepcopy(self.config)
        broken["customManagers"] = []
        with self.assertRaises(InventoryError):
            check_update_config(self.inventory, broken, REPO_ROOT)


class ConsumerPresetTests(unittest.TestCase):
    """default.json is the preset consumers extend; it is proven against the
    real templates they copy, not against prose in its own description."""

    PRESET = REPO_ROOT / "default.json"

    def setUp(self):
        self.config = load_update_config(self.PRESET)

    def test_the_preset_uses_no_deprecated_manager_keys(self):
        text = self.PRESET.read_text(encoding="utf-8")
        self.assertNotIn('"regexManagers"', text)
        self.assertNotIn('"fileMatch"', text)
        for manager in self.config["customManagers"]:
            self.assertEqual(manager.get("customType"), "regex", manager)

    def test_the_ado_commit_template_pin_is_matched(self):
        rel = "templates/azure-devops/commit.yml"
        matches = [m for m in update_matches_for(self.config, REPO_ROOT, rel)
                   if m.dep_name == "context-and-oss/cicd"]
        self.assertTrue(matches, f"the preset would propose no bump for {rel}")
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        declared = set(re.findall(r"github\.com/context-and-oss/cicd/[^@\s]+@(v[0-9]+\.[0-9]+\.[0-9]+)", text))
        self.assertEqual({m.current_value for m in matches}, declared)

    def test_a_consumer_dagger_json_source_pin_is_matched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "dagger.json").write_text(
                '{"name": "pipeline", "dependencies": [{"name": "quality", '
                '"source": "github.com/context-and-oss/cicd/src/quality@v4.5.0"}]}\n',
                encoding="utf-8",
            )
            matches = update_matches_for(self.config, root, "dagger.json")
        self.assertEqual([(m.dep_name, m.current_value) for m in matches],
                         [("context-and-oss/cicd", "v4.5.0")])


class DaggerVersionCoverageTests(unittest.TestCase):
    def setUp(self):
        self.config = load_update_config(CONFIG_PATH)

    def test_workflow_dagger_version_is_matched(self):
        matches = update_matches_for(self.config, REPO_ROOT, ".github/workflows/ci.yml")
        dagger = [m for m in matches if m.dep_name == "dagger/dagger"]
        self.assertTrue(dagger, "no manager matched DAGGER_VERSION in ci.yml")
        declared = [
            line.split('"')[1]
            for line in (REPO_ROOT / ".github/workflows/ci.yml")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip().startswith("DAGGER_VERSION:")
        ]
        self.assertEqual({m.current_value for m in dagger}, set(declared))

    def test_every_repository_workflow_with_a_dagger_version_is_matched(self):
        workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            rel = workflow.relative_to(REPO_ROOT).as_posix()
            if "DAGGER_VERSION:" not in workflow.read_text(encoding="utf-8"):
                continue
            with self.subTest(workflow=rel):
                matches = update_matches_for(self.config, REPO_ROOT, rel)
                self.assertTrue(any(m.dep_name == "dagger/dagger" for m in matches))

    def test_module_engine_version_is_matched(self):
        matches = update_matches_for(self.config, REPO_ROOT, "src/quality/dagger.json")
        engine = [m for m in matches if m.dep_name == "dagger/dagger"]
        self.assertTrue(engine, "no manager matched engineVersion in src/quality/dagger.json")
        self.assertTrue(all((m.current_value or "").startswith("v") for m in engine))

    def test_dagger_updates_travel_as_one_group(self):
        groups = [
            rule.get("groupName")
            for rule in self.config["packageRules"]
            if "dagger/dagger" in (rule.get("matchDepNames") or [])
        ]
        self.assertEqual(groups, ["dagger"])


class UnrelatedProseIsIgnoredTests(unittest.TestCase):
    """Negative coverage: nothing outside the maintained pins is matched."""

    def setUp(self):
        self.config = load_update_config(CONFIG_PATH)

    def test_consumer_templates_and_prose_produce_no_matches(self):
        for rel in UNTOUCHED_FILES:
            with self.subTest(path=rel):
                self.assertTrue(
                    (REPO_ROOT / rel).is_file(),
                    f"{rel} is missing — this negative test would pass vacuously",
                )
                self.assertEqual(update_matches_for(self.config, REPO_ROOT, rel), [])

    def test_a_consumer_template_declares_a_dagger_version_that_stays_untouched(self):
        """Proves the previous test is not vacuous: the text really is there."""
        template = (REPO_ROOT / "templates/azure-devops/commit.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("DAGGER_VERSION:", template)

    def test_an_images_go_outside_src_is_not_matched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "testdata" / "go-app").mkdir(parents=True)
            (root / "testdata" / "go-app" / "images.go").write_text(
                'package main\n\n// renovate-image: acme/tool\nconst v = "1.0.0"\n'
                'const i = "acme/tool:" + v + "@sha256:' + "d" * 64 + '"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                update_matches_for(self.config, root, "testdata/go-app/images.go"), []
            )

    def test_an_images_go_without_the_declaration_comment_is_not_matched(self):
        """A half-added family must not look covered."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src" / "newtool").mkdir(parents=True)
            (root / "src" / "newtool" / "images.go").write_text(
                'package main\n\nconst toolVersion = "1.0.0"\n'
                'const toolImage = "acme/tool:" + toolVersion + "@sha256:' + "d" * 64 + '"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                update_matches_for(self.config, root, "src/newtool/images.go"), []
            )

    def test_a_correctly_declared_new_images_go_is_matched(self):
        """The mirror of the two negatives above — the marker is what does the work."""
        digest = "sha256:" + "d" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src" / "newtool").mkdir(parents=True)
            (root / "src" / "newtool" / "images.go").write_text(
                "package main\n\nconst (\n\t// renovate-image: acme/tool\n"
                '\ttoolVersion = "1.0.0"\n'
                f'\ttoolImage   = "acme/tool:" + toolVersion + "@{digest}"\n)\n',
                encoding="utf-8",
            )
            matches = update_matches_for(self.config, root, "src/newtool/images.go")
            self.assertEqual(
                [(m.dep_name, m.current_value, m.current_digest) for m in matches],
                [("acme/tool", "1.0.0", digest)],
            )

    def test_a_schema_version_constant_is_not_mistaken_for_an_image(self):
        # The constant's VALUE is deliberately not asserted here. It used to be
        # ("1.0.0"), and this test failed the first time the evidence schema
        # version moved -- a test about renovate's image matching, broken by a
        # change to a version it has no opinion about. What matters is that a
        # bare semver-shaped constant exists in this file at all, since that is
        # the shape that could be mistaken for an image tag.
        text = (REPO_ROOT / "src" / "quality" / "schema.go").read_text(encoding="utf-8")
        self.assertRegex(text, r'evidenceSchemaVersion = "\d+\.\d+\.\d+"')
        self.assertEqual(
            update_matches_for(self.config, REPO_ROOT, "src/quality/schema.go"), []
        )


class InventoryAgreementTests(unittest.TestCase):
    """renovate.json and the inventory must describe the same set of families."""

    def test_no_package_rule_names_a_family_the_inventory_does_not_declare(self):
        config = load_update_config(CONFIG_PATH)
        inventory = load_inventory(INVENTORY_PATH)
        declared = {update_group_of(entry) for entry in inventory["images"]}
        for rule in config["packageRules"]:
            group = rule.get("groupName", "")
            if not group.startswith("runtime image: "):
                continue
            with self.subTest(group=group):
                self.assertIn(group, declared)

    def test_every_manager_declares_a_datasource(self):
        for index, manager in enumerate(custom_managers(load_update_config(CONFIG_PATH))):
            with self.subTest(manager=index):
                self.assertIn(
                    manager.get("datasourceTemplate"), ("docker", "github-releases")
                )


if __name__ == "__main__":
    unittest.main()
