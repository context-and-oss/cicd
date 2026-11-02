"""
Regression tests for the ADR-004 runtime image pin gate (scripts/runtime_images.py
and scripts/check-runtime-image-pins.py).

Every test builds a throwaway repository in a temp directory, so nothing here
depends on the state of the real working tree — the checker has to be provable
independently of whether today's tree happens to be clean.

The suite is written against the failure modes that actually shipped, and against
the ways a checker can look like it defends them without doing so:

  * a scanner image left on a mutable tag — the v1.7.2 state of every scanner
    except the build module's Trivy pin;
  * a digest that is present but malformed, or a digest with the readable tag
    stripped off;
  * a brand new static `From(...)` call nobody listed anywhere — the case a
    hardcoded allowlist cannot see, which is why discovery is source-driven;
  * a literal laundered through a local variable before being handed to `From`,
    which must still count as static;
  * the ADR-004 consumer toolchain path — an explicit `--toolchain-image` or a
    tag derived from `.nvmrc` / `global.json` — which must be accepted, never
    reported as a mutable tool image;
  * an inventory entry that outlives the code that referenced it, or names a file
    where the pin is not written;
  * a pin that no update manager would ever match, so it silently rots.

It also pins the negative direction — a clean fixture passes, and an empty
inventory is refused rather than silently satisfied — because a checker that
always fails defends nothing either.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from runtime_images import (  # noqa: E402
    InventoryError,
    check_all,
    check_inventory_entries_used,
    check_references_declared,
    check_static_references_pinned,
    check_update_config,
    discover_go_references,
    discover_make_references,
    discover_references,
    load_inventory,
    load_update_config,
    parse_reference,
    update_group_of,
)

SCANNER_DIGEST = "sha256:" + "a" * 64
HELPER_DIGEST = "sha256:" + "b" * 64
NEW_DIGEST = "sha256:" + "c" * 64

# A module that pins its scanner the way this repository does: a readable tag in a
# version constant, an immutable digest in the image constant, and the `From` call
# reading the constant rather than a literal.
SCANNER_IMAGES_GO = f"""package main

const (
	// renovate-image: acme/scanner
	scannerVersion = "1.2.3"
	scannerImage   = "acme/scanner:" + scannerVersion + "@{SCANNER_DIGEST}"
)
"""

SCANNER_MAIN_GO = """//go:build !unit_test

package main

func scan(ctx context.Context, src *dagger.Directory) error {
	_, err := dag.Container().
		From(scannerImage).
		WithMountedDirectory("/src", src).
		Stdout(ctx)
	return err
}
"""

# The ADR-004 toolchain path: an explicit consumer image wins, otherwise a tag is
# derived from the consumer's version files. Neither can be digest-pinned here.
TOOLCHAIN_GO = """//go:build !unit_test

package main

func buildArchive(ctx context.Context, src *dagger.Directory, toolchainImage string) error {
	image, err := resolveToolchain(ctx, src, toolchainImage)
	if err != nil {
		return err
	}
	_, err = dag.Container().
		From(image).
		WithMountedDirectory("/src", src).
		Stdout(ctx)
	return err
}
"""

UPDATE_CONFIG = {
    "enabledManagers": ["custom.regex"],
    "customManagers": [
        {
            "customType": "regex",
            "managerFilePatterns": ["/^src/.+/images\\.go$/"],
            "matchStrings": [
                "// renovate-image: (?<depName>[^\\s]+)[ \\t]*\\n[ \\t]*\\w+[ \\t]*="
                "[ \\t]*\"(?<currentValue>[^\"]+)\"[ \\t]*\\n[ \\t]*\\w+[ \\t]*=[ \\t]*"
                "\"[^\\n]*@(?<currentDigest>sha256:[0-9a-f]{64})\""
            ],
            "datasourceTemplate": "docker",
        }
    ],
    "packageRules": [
        {"matchDepNames": ["acme/scanner"], "groupName": "runtime image: scanner"},
        {"matchDepNames": ["acme/helper"], "groupName": "runtime image: helper"},
    ],
}


def scanner_entry(**overrides) -> dict:
    entry = {
        "family": "scanner",
        "role": "scanner",
        "repository": "acme/scanner",
        "tag": "1.2.3",
        "digest": SCANNER_DIGEST,
        "purpose": "SAST scan of consumer source",
        "sources": ["src/security/images.go"],
    }
    entry.update(overrides)
    return entry


def inventory_doc(images: list[dict] | None = None, **overrides) -> dict:
    doc = {
        "version": 1,
        "platforms": ["linux/amd64", "linux/arm64"],
        "discovery": {"go_roots": ["src"], "make_files": []},
        "images": images if images is not None else [scanner_entry()],
    }
    doc.update(overrides)
    return doc


class FixtureRepo:
    """A throwaway repository tree with a runtime image inventory and update config."""

    def __init__(self, stack: unittest.TestCase) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp())
        stack.addCleanup(self._cleanup)
        self.write("src/security/images.go", SCANNER_IMAGES_GO)
        self.write("src/security/main.go", SCANNER_MAIN_GO)
        self.inventory = inventory_doc()
        self.config = json.loads(json.dumps(UPDATE_CONFIG))

    def _cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel: str, text: str) -> pathlib.Path:
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def materialise(self) -> tuple[pathlib.Path, pathlib.Path]:
        inv = self.dir / "runtime-images.json"
        cfg = self.dir / "renovate.json"
        inv.write_text(json.dumps(self.inventory, indent=2), encoding="utf-8")
        cfg.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        return inv, cfg

    def run_checks(self) -> list[str]:
        inv, cfg = self.materialise()
        problems, _ = check_all(self.dir, load_inventory(inv), load_update_config(cfg))
        return problems

    def run_cli(self) -> subprocess.CompletedProcess:
        inv, cfg = self.materialise()
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "check-runtime-image-pins.py"),
                "--root",
                str(self.dir),
                "--inventory",
                str(inv),
                "--update-config",
                str(cfg),
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class CleanFixtureTests(unittest.TestCase):
    """A correctly pinned repository must pass — otherwise nothing below means much."""

    def test_clean_fixture_has_no_problems(self):
        repo = FixtureRepo(self)
        self.assertEqual(repo.run_checks(), [])

    def test_clean_fixture_passes_the_cli_with_exit_zero(self):
        repo = FixtureRepo(self)
        result = repo.run_cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("acme/scanner:1.2.3@" + SCANNER_DIGEST, result.stdout)


class MutableTagTests(unittest.TestCase):
    """The v1.7.2 pattern: a scanner image on a bare tag."""

    def test_tag_only_scanner_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            'package main\n\nconst scannerImage = "acme/scanner:1.2.3"\n',
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("pinned by mutable tag" in p and "src/security/main.go" in p for p in problems),
            problems,
        )

    def test_tag_only_scanner_fails_the_cli_with_exit_one(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            'package main\n\nconst scannerImage = "acme/scanner:1.2.3"\n',
        )
        result = repo.run_cli()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("mutable tag", result.stderr)

    def test_inline_latest_literal_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/main.go",
            SCANNER_MAIN_GO.replace("From(scannerImage)", 'From("acme/scanner:latest")'),
        )
        problems = repo.run_checks()
        self.assertTrue(any("acme/scanner:latest" in p for p in problems), problems)


class MalformedDigestTests(unittest.TestCase):
    def test_short_digest_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            'package main\n\nconst scannerImage = "acme/scanner:1.2.3@sha256:abc123"\n',
        )
        problems = repo.run_checks()
        self.assertTrue(any("invalid digest" in p for p in problems), problems)

    def test_uppercase_digest_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            f'package main\n\nconst scannerImage = "acme/scanner:1.2.3@sha256:{"A" * 64}"\n',
        )
        problems = repo.run_checks()
        self.assertTrue(any("invalid digest" in p for p in problems), problems)

    def test_digest_without_a_readable_tag_fails(self):
        """Immutability must not cost legibility: tool metadata still names a version."""
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            f'package main\n\nconst scannerImage = "acme/scanner@{SCANNER_DIGEST}"\n',
        )
        problems = repo.run_checks()
        self.assertTrue(any("digest-only" in p for p in problems), problems)

    def test_inventory_with_a_malformed_digest_is_refused(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = [scanner_entry(digest="sha256:nope")]
        inv, _ = repo.materialise()
        with self.assertRaises(InventoryError) as ctx:
            load_inventory(inv)
        self.assertIn("64 lowercase hex", str(ctx.exception))


class UnlistedStaticImageTests(unittest.TestCase):
    """A checker built from an allowlist cannot see a new static From() call."""

    def test_new_pinned_but_undeclared_image_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/images.go",
            f'package main\n\nconst toolImage = "acme/newtool:9.9.9@{NEW_DIGEST}"\n',
        )
        repo.write(
            "src/newtool/main.go",
            "package main\n\nfunc run() { dag.Container().From(toolImage) }\n",
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("acme/newtool:9.9.9" in p and "not declared" in p for p in problems),
            problems,
        )

    def test_a_new_static_from_call_is_discovered_at_all(self):
        """The discovery half, asserted directly: an allowlist-only checker fails here."""
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            'package main\n\nfunc run() { dag.Container().From("acme/newtool:9.9.9") }\n',
        )
        found = {
            ref.value for ref in discover_go_references(repo.dir, ["src"]) if ref.is_static
        }
        self.assertIn("acme/newtool:9.9.9", found)

    def test_a_literal_laundered_through_a_local_variable_is_still_static(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            "package main\n\nfunc run() {\n"
            '\timg := "acme/newtool:latest"\n'
            "\tdag.Container().From(img)\n}\n",
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("acme/newtool:latest" in p and "mutable tag" in p for p in problems),
            problems,
        )

    def test_from_on_a_continuation_line_is_discovered(self):
        """Dagger chains put `From(` on its own line — matching only `.From(` misses it."""
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            "package main\n\nfunc run() {\n\tdag.Container().\n"
            '\t\tFrom("acme/newtool:latest").\n\t\tWithExec(nil)\n}\n',
        )
        found = {
            ref.value for ref in discover_go_references(repo.dir, ["src"]) if ref.is_static
        }
        self.assertIn("acme/newtool:latest", found)


class CommentsAreNotSelectionsTests(unittest.TestCase):
    """Prose about an image is not a selection of it."""

    def test_a_line_comment_mentioning_from_is_ignored(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            "package main\n\n"
            '// Historically this called From("acme/newtool:latest") — do not restore it.\n'
            "func run() {}\n",
        )
        self.assertEqual(repo.run_checks(), [])

    def test_a_block_comment_mentioning_from_is_ignored(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            'package main\n\n/*\n\tdag.Container().From("acme/newtool:latest")\n*/\n'
            "func run() {}\n",
        )
        self.assertEqual(repo.run_checks(), [])

    def test_a_commented_out_constant_cannot_satisfy_a_reference(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/images.go",
            f'package main\n\n// const toolImage = "acme/newtool:9.9.9@{NEW_DIGEST}"\n',
        )
        repo.write(
            "src/newtool/main.go",
            "package main\n\nfunc run() { dag.Container().From(toolImage) }\n",
        )
        refs = discover_go_references(repo.dir, ["src"])
        self.assertIn("toolImage", [r.expression for r in refs if not r.is_static])

    def test_line_numbers_survive_comment_blanking(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            "package main\n\n// a comment\n/* a block\n   comment */\n"
            'func run() { dag.Container().From("acme/newtool:latest") }\n',
        )
        refs = [r for r in discover_go_references(repo.dir, ["src"]) if r.is_static]
        target = [r for r in refs if r.value == "acme/newtool:latest"]
        self.assertEqual([r.line for r in target], [6])


class DynamicConsumerToolchainTests(unittest.TestCase):
    """ADR-004: consumer-resolved toolchains are not repository-selected tools."""

    def test_dynamic_consumer_image_is_accepted(self):
        repo = FixtureRepo(self)
        repo.write("src/build/archive.go", TOOLCHAIN_GO)
        self.assertEqual(repo.run_checks(), [])

    def test_dynamic_consumer_image_is_classified_dynamic_not_mutable(self):
        repo = FixtureRepo(self)
        repo.write("src/build/archive.go", TOOLCHAIN_GO)
        refs = discover_go_references(repo.dir, ["src"])
        dynamic = [r for r in refs if not r.is_static]
        self.assertEqual([r.expression for r in dynamic], ["image"])
        self.assertEqual(check_static_references_pinned(refs), [])

    def test_version_file_derived_tag_is_dynamic(self):
        """`.nvmrc` → node:<major>-alpine is computed at run time, so unpinnable."""
        repo = FixtureRepo(self)
        repo.write(
            "src/build/toolchain.go",
            "package main\n\nfunc run(ctx context.Context, src *dagger.Directory) {\n"
            "\timage := resolveToolchain(nvmrcMajor(ctx, src))\n"
            "\tdag.Container().From(image)\n}\n",
        )
        refs = discover_go_references(repo.dir, ["src"])
        self.assertEqual(
            [r.expression for r in refs if not r.is_static], ["image"]
        )
        self.assertEqual(repo.run_checks(), [])

    def test_an_explicit_toolchain_parameter_is_dynamic(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/quality/byotest.go",
            "package main\n\nfunc run(toolchainImage string) {\n"
            "\tdag.Container().From(toolchainImage)\n}\n",
        )
        self.assertEqual(repo.run_checks(), [])


class InventoryAccuracyTests(unittest.TestCase):
    def test_entry_nobody_references_any_more_fails(self):
        repo = FixtureRepo(self)
        repo.inventory["images"].append(
            scanner_entry(
                family="ghost",
                repository="acme/ghost",
                tag="0.1.0",
                digest=HELPER_DIGEST,
                sources=["src/security/images.go"],
            )
        )
        repo.config["packageRules"].append(
            {"matchDepNames": ["acme/ghost"], "groupName": "runtime image: ghost"}
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("acme/ghost" in p and "no source references it" in p for p in problems),
            problems,
        )

    def test_entry_naming_a_file_where_the_pin_is_not_written_fails(self):
        repo = FixtureRepo(self)
        repo.write("src/security/other.go", "package main\n")
        repo.inventory["images"] = [
            scanner_entry(sources=["src/security/images.go", "src/security/other.go"])
        ]
        problems = repo.run_checks()
        self.assertTrue(
            any("src/security/other.go" in p and "not written there" in p for p in problems),
            problems,
        )

    def test_entry_naming_a_missing_file_fails(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = [scanner_entry(sources=["src/security/gone.go"])]
        problems = repo.run_checks()
        self.assertTrue(any("missing source file" in p for p in problems), problems)

    def test_empty_inventory_is_refused(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = []
        inv, _ = repo.materialise()
        with self.assertRaises(InventoryError):
            load_inventory(inv)

    def test_empty_inventory_exits_two_not_zero(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = []
        self.assertEqual(repo.run_cli().returncode, 2)

    def test_entry_missing_a_required_field_is_refused(self):
        for field in ("family", "role", "repository", "tag", "digest", "purpose", "sources"):
            with self.subTest(field=field):
                repo = FixtureRepo(self)
                entry = scanner_entry()
                del entry[field]
                repo.inventory["images"] = [entry]
                inv, _ = repo.materialise()
                with self.assertRaises(InventoryError):
                    load_inventory(inv)

    def test_inventory_without_declared_platforms_is_refused(self):
        repo = FixtureRepo(self)
        del repo.inventory["platforms"]
        inv, _ = repo.materialise()
        with self.assertRaises(InventoryError) as ctx:
            load_inventory(inv)
        self.assertIn("platforms", str(ctx.exception))

    def test_unknown_role_is_refused(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = [scanner_entry(role="mystery")]
        inv, _ = repo.materialise()
        with self.assertRaises(InventoryError):
            load_inventory(inv)

    def test_duplicate_entry_is_refused(self):
        repo = FixtureRepo(self)
        repo.inventory["images"] = [scanner_entry(), scanner_entry()]
        inv, _ = repo.materialise()
        with self.assertRaises(InventoryError):
            load_inventory(inv)

    def test_discovery_root_that_does_not_exist_is_an_error(self):
        repo = FixtureRepo(self)
        repo.inventory["discovery"]["go_roots"] = ["nope"]
        inv, cfg = repo.materialise()
        with self.assertRaises(InventoryError):
            check_all(repo.dir, load_inventory(inv), load_update_config(cfg))

    def test_a_tree_with_no_static_reference_at_all_is_reported(self):
        """Broken discovery must fail loudly instead of passing vacuously."""
        repo = FixtureRepo(self)
        repo.write("src/security/main.go", "package main\n")
        repo.inventory["images"] = [scanner_entry()]
        problems = repo.run_checks()
        self.assertTrue(
            any("no static image reference was discovered" in p for p in problems), problems
        )


class UpdateCoverageTests(unittest.TestCase):
    def test_pin_no_manager_matches_fails(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/security/images.go",
            SCANNER_IMAGES_GO.replace("// renovate-image: acme/scanner\n\t", ""),
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("not matched by any renovate.json custom manager" in p for p in problems),
            problems,
        )

    def test_family_without_its_own_group_fails(self):
        repo = FixtureRepo(self)
        repo.config["packageRules"] = []
        problems = repo.run_checks()
        self.assertTrue(
            any("runtime image: scanner" in p and "packageRule" in p for p in problems),
            problems,
        )

    def test_group_matching_a_different_dependency_does_not_count(self):
        repo = FixtureRepo(self)
        repo.config["packageRules"] = [
            {"matchDepNames": ["acme/something-else"], "groupName": "runtime image: scanner"}
        ]
        problems = repo.run_checks()
        self.assertTrue(any("packageRule" in p for p in problems), problems)

    def test_config_without_custom_managers_is_refused(self):
        repo = FixtureRepo(self)
        repo.config["customManagers"] = []
        inv, cfg = repo.materialise()
        with self.assertRaises(InventoryError):
            check_update_config(load_inventory(inv), load_update_config(cfg), repo.dir)

    def test_glob_style_file_pattern_is_refused(self):
        """Only the explicit /regex/ form is evaluated, so the test matches Renovate."""
        repo = FixtureRepo(self)
        repo.config["customManagers"][0]["managerFilePatterns"] = ["**/images.go"]
        inv, cfg = repo.materialise()
        with self.assertRaises(InventoryError):
            check_update_config(load_inventory(inv), load_update_config(cfg), repo.dir)

    def test_update_group_is_derived_from_the_family(self):
        self.assertEqual(update_group_of(scanner_entry(family="trivy")), "runtime image: trivy")


class MakefileDiscoveryTests(unittest.TestCase):
    def test_tag_only_makefile_image_fails(self):
        repo = FixtureRepo(self)
        repo.write("Makefile", "TOOL_IMAGE := acme/tool:1.0.0\n\ncheck:\n\techo hi\n")
        repo.inventory["discovery"]["make_files"] = ["Makefile"]
        problems = repo.run_checks()
        self.assertTrue(
            any("acme/tool:1.0.0" in p and "mutable tag" in p for p in problems), problems
        )

    def test_unnamespaced_image_variable_is_still_discovered(self):
        repo = FixtureRepo(self)
        repo.write("Makefile", "HELPER_IMAGE := busybox:1.36\n")
        refs = discover_make_references(repo.dir, ["Makefile"])
        self.assertEqual([r.value for r in refs], ["busybox:1.36"])

    def test_expanded_variable_reference_is_resolved(self):
        repo = FixtureRepo(self)
        repo.write(
            "Makefile",
            f"TOOL_VERSION := 1.0.0\nTOOL_IMAGE := acme/tool:$(TOOL_VERSION)@{HELPER_DIGEST}\n",
        )
        refs = discover_make_references(repo.dir, ["Makefile"])
        self.assertEqual([r.value for r in refs], [f"acme/tool:1.0.0@{HELPER_DIGEST}"])

    def test_a_file_path_variable_is_not_mistaken_for_an_image(self):
        repo = FixtureRepo(self)
        repo.write(
            "Makefile",
            "SCHEMA_SRC := src/internal/evidence/schema.go\nMODULES := $(shell echo a b)\n",
        )
        self.assertEqual(discover_make_references(repo.dir, ["Makefile"]), [])

    def test_recipe_lines_are_not_treated_as_assignments(self):
        repo = FixtureRepo(self)
        repo.write("Makefile", "run:\n\tFOO_IMAGE := acme/tool:1.0.0\n")
        self.assertEqual(discover_make_references(repo.dir, ["Makefile"]), [])


class ReferenceParsingTests(unittest.TestCase):
    def test_registry_host_and_path_are_parsed(self):
        self.assertEqual(
            parse_reference(f"ghcr.io/zaproxy/zaproxy:2.17.0@{HELPER_DIGEST}"),
            ("ghcr.io/zaproxy/zaproxy", "2.17.0", HELPER_DIGEST),
        )

    def test_unparseable_reference_is_reported_as_such(self):
        self.assertIsNone(parse_reference("not a reference at all"))

    def test_an_unparseable_static_value_is_named_in_the_problem(self):
        repo = FixtureRepo(self)
        repo.write(
            "src/newtool/main.go",
            'package main\n\nfunc run() { dag.Container().From("Not An Image") }\n',
        )
        problems = repo.run_checks()
        self.assertTrue(
            any("not a parseable container image reference" in p for p in problems), problems
        )


class ShippedTreeTests(unittest.TestCase):
    """The checker must actually pass against the repository it ships in."""

    def test_the_live_tree_passes(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "check-runtime-image-pins.py")],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_declared_role_class_is_represented(self):
        """scanner, linter, policy and helper images are all actually covered."""
        inventory = load_inventory(REPO_ROOT / "scripts" / "runtime-images.json")
        roles = {entry["role"] for entry in inventory["images"]}
        self.assertLessEqual({"scanner", "linter", "policy", "helper"}, roles)

    def test_the_live_tree_still_has_the_adr_004_dynamic_paths(self):
        """If these ever become static, ADR-004's consumer escape hatch is gone."""
        inventory = load_inventory(REPO_ROOT / "scripts" / "runtime-images.json")
        dynamic = [
            ref.file
            for ref in discover_references(REPO_ROOT, inventory)
            if not ref.is_static
        ]
        # Archive builds now delegate their dynamic command container to
        # quality.Prepare; keep the consumer override visible through that path.
        self.assertIn("src/quality/prepare.go", dynamic)
        archive = (REPO_ROOT / "src/build/archive.go").read_text()
        self.assertIn("resolveArchiveToolchain(ctx, src, toolchainImage)", archive)
        self.assertIn('dag.Quality().Prepare(src, ":", image, repoUrl', archive)
        self.assertIn("src/quality/byotest.go", dynamic)

    def test_every_live_static_reference_is_declared_and_pinned(self):
        inventory = load_inventory(REPO_ROOT / "scripts" / "runtime-images.json")
        references = discover_references(REPO_ROOT, inventory)
        self.assertEqual(check_static_references_pinned(references), [])
        self.assertEqual(check_references_declared(references, inventory), [])
        self.assertEqual(
            check_inventory_entries_used(references, inventory, REPO_ROOT), []
        )

    def test_every_live_digest_is_lowercase_sha256_of_the_right_length(self):
        inventory = load_inventory(REPO_ROOT / "scripts" / "runtime-images.json")
        for entry in inventory["images"]:
            with self.subTest(image=entry["repository"]):
                self.assertRegex(entry["digest"], r"^sha256:[0-9a-f]{64}$")

    def test_the_declared_platforms_cover_ci_and_local_development(self):
        inventory = load_inventory(REPO_ROOT / "scripts" / "runtime-images.json")
        self.assertIn("linux/amd64", inventory["platforms"])
        self.assertIn("linux/arm64", inventory["platforms"])


if __name__ == "__main__":
    unittest.main()
