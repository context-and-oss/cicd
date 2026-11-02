"""
ADR-004 runtime image pins — discovery, classification and validation.

Everything here is deterministic and offline. It reads files already in the
working tree and never resolves a tag against a registry, never shells out to
dagger, and never asks what "latest" is. Proposing a newer version is update
automation's job (renovate.json); this module's job is to prove that whatever
version is pinned is pinned *immutably*, is declared, and is maintainable.

Why discovery instead of a list
-------------------------------
The drift this defends against is someone adding a new tool container. A checker
built from a hardcoded allowlist of known images cannot see that: the new
`From("some/tool:latest")` is simply not in the list, so the check passes and the
mutable tag ships. So the reference set is *discovered from source* —
`discover_references()` parses every `.From(...)` argument in the module sources
and resolves it through package constants and local literal assignments. The
inventory (scripts/runtime-images.json) is then checked against what was
discovered, in both directions: an undeclared static image is an error, and a
declared image nobody references any more is an error too.

Static vs dynamic (the ADR-004 line)
------------------------------------
A reference is STATIC when its argument resolves, through constants and local
string literals, to a literal image reference — i.e. *this repository* chose it.
Those are the scanner / linter / policy / helper images, and every one of them
must be `tag@sha256:<64 hex>`.

A reference is DYNAMIC when the argument cannot be resolved to a literal: it
comes from a parameter, a function result, or anything else computed at run time.
That is exactly the ADR-004 toolchain path — an explicit `--toolchain-image`, or
a tag derived from the consumer's `.nvmrc` / `global.json`. Those are consumer
controlled, cannot be digest-pinned ahead of time, and are NOT violations. They
are reported as classified-dynamic, never failed.

Resolution is what makes that line hold: assigning a literal to a local variable
first (`img := "tool:latest"; ...From(img)`) still resolves, so it is still
static. Only genuinely run-time-computed values land in the dynamic bucket.

Makefile references
-------------------
Not every tool container is launched through Dagger — `make policy-test` runs
conftest directly, and it claims to run "the same image" the real gate does. A
tag-only reference there would break that claim, so Makefile-style assignments
are discovered too (see `discover_make_references` for the exact rule).

Checks (each returns a list of human-readable problems; empty means clean)
-------------------------------------------------------------------------
  check_static_references_pinned    every static reference is tag@sha256:<digest>
  check_references_declared         every static reference is in the inventory,
                                    and the inventory's `sources` are accurate
  check_inventory_entries_used      no inventory entry describes an image the
                                    source no longer references
  check_update_config               every inventory entry is matched by a
                                    renovate.json custom manager, so no
                                    maintained pin is left without an update path

`check_all` runs the lot. `load_inventory` refuses a manifest that would make the
checks vacuous — an empty image list defends nothing.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Iterable, Sequence

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# repository[:tag][@digest] — the shape of a container image reference. The
# repository half allows a registry host with an optional port.
REFERENCE_RE = re.compile(
    r"^(?P<repository>[a-z0-9][a-z0-9._\-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._\-]*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._\-]*))?"
    r"(?:@(?P<digest>[A-Za-z0-9]+:[A-Za-z0-9]+))?$"
)

# What kind of tool the image is. Purely descriptive, but declared so a reviewer
# can see at a glance that every scanner / linter / policy / helper class the
# brief names is actually represented.
VALID_ROLES = ("scanner", "linter", "policy", "helper", "language-runtime")

# Generated Dagger SDK trees are not authored source; they define From(), they do
# not call it with an image this repository chose.
GENERATED_DIR_PARTS = ("internal/dagger", "internal/querybuilder", "internal/telemetry")


class InventoryError(Exception):
    """The runtime-image inventory itself is unusable."""


@dataclasses.dataclass(frozen=True)
class ImageReference:
    """One discovered image selection site."""

    file: str  # repository-relative path
    line: int  # 1-based
    expression: str  # the source text that selects the image
    value: str | None  # resolved literal reference, or None when dynamic

    @property
    def is_static(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #


def default_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def default_inventory_path(root: pathlib.Path | None = None) -> pathlib.Path:
    return (root or default_root()) / "scripts" / "runtime-images.json"


def default_update_config_path(root: pathlib.Path | None = None) -> pathlib.Path:
    return (root or default_root()) / "renovate.json"


def load_inventory(path: pathlib.Path) -> dict:
    """Load and validate scripts/runtime-images.json.

    Raises InventoryError rather than returning something a check could pass
    vacuously against.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InventoryError(f"runtime image inventory not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InventoryError(f"{path}: invalid JSON: {exc}") from exc

    images = raw.get("images")
    if not isinstance(images, list) or not images:
        raise InventoryError(
            f"{path}: 'images' must be a non-empty list — an empty runtime image "
            "inventory would make every coverage check vacuous"
        )

    go_roots = raw.get("discovery", {}).get("go_roots")
    if not isinstance(go_roots, list) or not go_roots:
        raise InventoryError(f"{path}: 'discovery.go_roots' must be a non-empty list")

    platforms = raw.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise InventoryError(
            f"{path}: 'platforms' must list the architectures every digest was "
            "verified to resolve on — an unstated claim is not a verified one"
        )

    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(images):
        where = f"{path}: images[{index}]"
        for field in ("family", "role", "repository", "tag", "digest", "purpose", "sources"):
            if not entry.get(field):
                raise InventoryError(f"{where}: missing required field '{field}'")
        if entry["role"] not in VALID_ROLES:
            raise InventoryError(
                f"{where}: role {entry['role']!r} is not one of {', '.join(VALID_ROLES)}"
            )
        if not DIGEST_RE.match(entry["digest"]):
            raise InventoryError(
                f"{where}: digest {entry['digest']!r} is not sha256:<64 lowercase hex>"
            )
        if not isinstance(entry["sources"], list):
            raise InventoryError(f"{where}: 'sources' must be a list")
        key = (entry["repository"], entry["tag"], entry["digest"])
        if key in seen:
            raise InventoryError(f"{where}: duplicate entry for {reference_of(entry)}")
        seen.add(key)

    return raw


def reference_of(entry: dict) -> str:
    return f"{entry['repository']}:{entry['tag']}@{entry['digest']}"


def update_group_of(entry: dict) -> str:
    """The renovate.json groupName that must own this image's updates.

    Derived from the family rather than declared separately: one tool family, one
    group, one revertable pull request. Two entries of the same family (the two
    Trivy pins, say) travel together; unrelated families never do.
    """
    return f"runtime image: {entry['family']}"


# --------------------------------------------------------------------------- #
# Go source discovery
# --------------------------------------------------------------------------- #

_GO_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
# A single-name string assignment. Covers the three Go spellings that can hold an
# image reference: a line inside a `const (...)`/`var (...)` block, a one-line
# `const x = "..."` / `var x = "..."`, and a local `x := "..."`.
_ASSIGN = re.compile(
    r"^\s*(?:(?:const|var)\s+)?(?P<name>[A-Za-z_]\w*)\s*(?P<op>:?=)\s*(?P<rhs>\S.*?)\s*$"
)


def _is_generated(rel: str) -> bool:
    return any(part in rel for part in GENERATED_DIR_PARTS)


def _unquote(literal: str) -> str:
    # Go string escapes we could plausibly meet in an image reference. Anything
    # exotic simply stays as written, which can only make a reference fail to
    # match the inventory — never silently pass.
    return (
        literal.replace('\\"', '"')
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
    )


def _blank_go_comments(text: str) -> str:
    """Replace comment bodies with spaces, preserving every byte offset and newline.

    A prose mention of `From("some/tool:latest")` in a doc comment is not an image
    selection, and must not be reported as one. Blanking rather than deleting keeps
    reported line numbers pointing at the real source line.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            literal = _GO_STRING.match(text, i)
            i = literal.end() if literal else i + 1
            continue
        if ch == "`":
            end = text.find("`", i + 1)
            i = n if end == -1 else end + 1
            continue
        if text[i : i + 2] == "//":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if text[i : i + 2] == "/*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                if text[j] != "\n":
                    out[j] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def _split_top_level_plus(expr: str) -> list[str] | None:
    """Split a Go expression on top-level `+`. None when it is not a flat concat."""
    parts: list[str] = []
    current = ""
    depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == '"':
            match = _GO_STRING.match(expr, i)
            if not match:
                return None
            current += match.group(0)
            i = match.end()
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return None
        if ch == "+" and depth == 0:
            parts.append(current)
            current = ""
            i += 1
            continue
        current += ch
        i += 1
    parts.append(current)
    return [p.strip() for p in parts]


def _resolve_expression(expr: str, symbols: dict[str, set[str]], seen: frozenset[str]) -> set[str]:
    """Resolve a Go expression to the set of literal strings it can be.

    Returns an empty set when the expression is not statically resolvable — that
    is the dynamic (ADR-004 consumer toolchain) case. A set with more than one
    member means the same identifier is defined with different literals in the
    package; every candidate is then validated, so ambiguity cannot hide a
    mutable reference.
    """
    expr = expr.strip()
    if not expr:
        return set()
    parts = _split_top_level_plus(expr)
    if parts is None or not all(parts):
        return set()

    resolved: list[set[str]] = []
    for part in parts:
        literal = _GO_STRING.fullmatch(part)
        if literal:
            resolved.append({_unquote(literal.group(1))})
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", part) and part in symbols and part not in seen:
            candidates: set[str] = set()
            for definition in symbols[part]:
                candidates |= _resolve_expression(definition, symbols, seen | {part})
            if not candidates:
                return set()
            resolved.append(candidates)
            continue
        return set()

    out = {""}
    for options in resolved:
        out = {prefix + option for prefix in out for option in options}
    return out


def _collect_go_symbols(paths: Iterable[pathlib.Path]) -> dict[str, set[str]]:
    """Package-level and local single-assignment string expressions, by name."""
    symbols: dict[str, set[str]] = {}
    for path in paths:
        blanked = _blank_go_comments(path.read_text(encoding="utf-8"))
        for raw_line in blanked.splitlines():
            match = _ASSIGN.match(raw_line)
            if not match:
                continue
            rhs = match.group("rhs")
            if rhs.startswith("="):  # a `==` comparison, not an assignment
                continue
            if _split_top_level_plus(rhs) is None:
                continue
            symbols.setdefault(match.group("name"), set()).add(rhs)
    return symbols


# `From(` as a *call*, not as part of a longer identifier. Dagger chains routinely
# put the call on its own continuation line, so the selector dot sits at the end of
# the previous line — matching only `.From(` would miss almost every real one.
_FROM_CALL = re.compile(r"(?<![A-Za-z0-9_])From\(")


def _from_call_arguments(text: str) -> list[tuple[int, str]]:
    """Every `From(<arg>)` call argument in `text`, as (1-based line, source text)."""
    out: list[tuple[int, str]] = []
    for match in _FROM_CALL.finditer(text):
        if text[: match.start()].rstrip().endswith("func"):
            continue  # a declaration of From, not a call to it
        start = match.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == '"':
                literal = _GO_STRING.match(text, i)
                if not literal:
                    break
                i = literal.end()
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue
        out.append((text.count("\n", 0, match.start()) + 1, text[start:i]))
    return out


def discover_go_references(root: pathlib.Path, go_roots: Sequence[str]) -> list[ImageReference]:
    """Every `.From(...)` image selection in the authored Go sources under go_roots."""
    references: list[ImageReference] = []
    for go_root in go_roots:
        base = root / go_root
        if not base.is_dir():
            raise InventoryError(f"discovery.go_roots names a missing directory: {go_root}")
        files = [
            p
            for p in sorted(base.rglob("*.go"))
            if not _is_generated(p.relative_to(root).as_posix())
        ]
        by_dir: dict[pathlib.Path, list[pathlib.Path]] = {}
        for path in files:
            by_dir.setdefault(path.parent, []).append(path)
        for directory, paths in by_dir.items():
            symbols = _collect_go_symbols(paths)
            for path in paths:
                rel = path.relative_to(root).as_posix()
                text = _blank_go_comments(path.read_text(encoding="utf-8"))
                for line, expression in _from_call_arguments(text):
                    values = _resolve_expression(expression, symbols, frozenset())
                    if not values:
                        references.append(
                            ImageReference(rel, line, expression.strip(), None)
                        )
                        continue
                    for value in sorted(values):
                        references.append(
                            ImageReference(rel, line, expression.strip(), value)
                        )
    return references


# --------------------------------------------------------------------------- #
# Makefile-style discovery
# --------------------------------------------------------------------------- #

_MAKE_ASSIGN = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[:?+]?=\s*(?P<value>.*?)\s*$")
_MAKE_VAR = re.compile(r"\$[({](?P<name>[A-Za-z_][A-Za-z0-9_]*)[)}]")


def discover_make_references(root: pathlib.Path, files: Sequence[str]) -> list[ImageReference]:
    """Image references assigned in Makefile-style files.

    An assignment counts as an image selection when, after `$(VAR)` expansion,
    either the variable name ends in `_IMAGE` (an explicit declaration of intent)
    or the value looks like a namespaced image reference (`ns/name:tag`, with an
    optional digest). Both rules are shape-based, so a brand new tool image is
    discovered without being listed anywhere first.
    """
    references: list[ImageReference] = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            raise InventoryError(f"discovery.make_files names a missing file: {rel}")
        values: dict[str, str] = {}
        for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if raw_line.startswith("\t") or raw_line.lstrip().startswith("#"):
                continue
            match = _MAKE_ASSIGN.match(raw_line)
            if not match:
                continue
            name, value = match.group("name"), match.group("value")
            expanded = _MAKE_VAR.sub(lambda m: values.get(m.group("name"), m.group(0)), value)
            values[name] = expanded
            if "$" in expanded or " " in expanded:
                continue
            namespaced = "/" in expanded and ":" in expanded
            if not (name.endswith("_IMAGE") or namespaced):
                continue
            if not REFERENCE_RE.match(expanded.split("@")[0]):
                continue
            references.append(ImageReference(rel, number, f"{name} = {value}", expanded))
    return references


def discover_references(root: pathlib.Path, inventory: dict) -> list[ImageReference]:
    discovery = inventory.get("discovery", {})
    return discover_go_references(root, discovery["go_roots"]) + discover_make_references(
        root, discovery.get("make_files", [])
    )


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


def parse_reference(value: str) -> tuple[str, str | None, str | None] | None:
    """Split an image reference into (repository, tag, digest); None if unparseable."""
    match = REFERENCE_RE.match(value)
    if not match:
        return None
    return match.group("repository"), match.group("tag"), match.group("digest")


def check_static_references_pinned(references: Sequence[ImageReference]) -> list[str]:
    """Every statically selected image is `tag@sha256:<64 lowercase hex>`."""
    problems: list[str] = []
    for ref in references:
        if not ref.is_static:
            continue
        parsed = parse_reference(ref.value or "")
        if parsed is None:
            problems.append(
                f"{ref}: static image {ref.value!r} is not a parseable container image "
                "reference (expected repository:tag@sha256:<digest>)"
            )
            continue
        repository, tag, digest = parsed
        if digest is None:
            problems.append(
                f"{ref}: static image {ref.value!r} is pinned by mutable tag — "
                "repository-selected images must be tag@sha256:<digest> (ADR-004)"
            )
            continue
        if not DIGEST_RE.match(digest):
            problems.append(
                f"{ref}: static image {ref.value!r} has an invalid digest {digest!r} — "
                "expected sha256:<64 lowercase hex>"
            )
            continue
        if not tag:
            problems.append(
                f"{ref}: static image {ref.value!r} is digest-only — keep the readable "
                "tag so emitted tool metadata and review still name a version"
            )
        if not repository:
            problems.append(f"{ref}: static image {ref.value!r} has no repository")
    return problems


def check_references_declared(
    references: Sequence[ImageReference], inventory: dict
) -> list[str]:
    """Every static reference is declared, and each entry's `sources` are accurate."""
    problems: list[str] = []
    by_key = {
        (e["repository"], e["tag"], e["digest"]): e for e in inventory["images"]
    }
    for ref in references:
        if not ref.is_static:
            continue
        parsed = parse_reference(ref.value or "")
        if parsed is None:
            continue  # already reported by check_static_references_pinned
        repository, tag, digest = parsed
        if digest is None or not DIGEST_RE.match(digest):
            continue  # already reported by check_static_references_pinned
        if (repository, tag, digest) not in by_key:
            problems.append(
                f"{ref}: static image {ref.value!r} is not declared in the runtime "
                "image inventory (scripts/runtime-images.json) — an undeclared image "
                "has no update path, so it would never be bumped or rolled back"
            )
    return problems


def check_inventory_entries_used(
    references: Sequence[ImageReference], inventory: dict, root: pathlib.Path
) -> list[str]:
    """No inventory entry outlives the code that used it, and `sources` are real.

    `sources` names the files where the pin literal is *written* — a module's
    images.go or the Makefile — not every call site that consumes it. That is what
    update automation has to rewrite, so that is what has to be accurate.
    """
    problems: list[str] = []
    used = {
        parsed
        for ref in references
        if ref.is_static and (parsed := parse_reference(ref.value or "")) is not None
    }
    for entry in inventory["images"]:
        key = (entry["repository"], entry["tag"], entry["digest"])
        if key not in used:
            problems.append(
                f"scripts/runtime-images.json: {reference_of(entry)} is declared but no "
                "source references it — delete the entry or restore the reference"
            )
            continue
        for source in entry["sources"]:
            path = root / source
            if not path.is_file():
                problems.append(
                    f"scripts/runtime-images.json: {reference_of(entry)} lists a missing "
                    f"source file {source}"
                )
                continue
            text = path.read_text(encoding="utf-8")
            if not (
                entry["digest"] in text
                and entry["repository"] in text
                and entry["tag"] in text
            ):
                problems.append(
                    f"scripts/runtime-images.json: {reference_of(entry)} lists {source} "
                    "as a source but the pin is not written there"
                )
    return problems


# --------------------------------------------------------------------------- #
# Update configuration (renovate.json)
# --------------------------------------------------------------------------- #


def _js_regex_to_python(pattern: str) -> re.Pattern[str]:
    """Translate a Renovate matchString to a Python regex.

    Renovate evaluates these with JavaScript/RE2 semantics. The only syntax
    difference that matters for the patterns this repository uses is the named
    group spelling — `(?<name>…)` in JS, `(?P<name>…)` in Python — so that is the
    single translation applied. Keeping the translation this small is deliberate:
    the further these tests drift from what Renovate itself would run, the less
    they prove.
    """
    translated = re.sub(r"\(\?<(?![=!])", "(?P<", pattern)
    return re.compile(translated, re.MULTILINE)


def _file_pattern_to_python(pattern: str) -> re.Pattern[str]:
    if not (pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2):
        raise InventoryError(
            f"renovate.json: managerFilePatterns entry {pattern!r} must use the "
            "explicit /regex/ form so the coverage test evaluates exactly what "
            "Renovate matches"
        )
    return re.compile(pattern[1:-1])


@dataclasses.dataclass(frozen=True)
class UpdateMatch:
    manager: int
    dep_name: str | None
    current_value: str | None
    current_digest: str | None


def load_update_config(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InventoryError(f"update configuration not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InventoryError(f"{path}: invalid JSON: {exc}") from exc


def custom_managers(config: dict) -> list[dict]:
    managers = config.get("customManagers") or []
    if not managers:
        raise InventoryError(
            "renovate.json declares no customManagers — nothing would keep the "
            "runtime image pins or the Dagger version updatable"
        )
    return managers


def update_matches_for(config: dict, root: pathlib.Path, rel: str) -> list[UpdateMatch]:
    """Every custom-manager match this configuration would extract from `rel`."""
    path = root / rel
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    matches: list[UpdateMatch] = []
    for index, manager in enumerate(custom_managers(config)):
        patterns = manager.get("managerFilePatterns") or []
        if not any(_file_pattern_to_python(p).search(rel) for p in patterns):
            continue
        for match_string in manager.get("matchStrings") or []:
            for found in _js_regex_to_python(match_string).finditer(text):
                groups = found.groupdict()
                matches.append(
                    UpdateMatch(
                        manager=index,
                        dep_name=groups.get("depName") or manager.get("depNameTemplate"),
                        current_value=groups.get("currentValue"),
                        current_digest=groups.get("currentDigest"),
                    )
                )
    return matches


def check_update_config(
    inventory: dict, config: dict, root: pathlib.Path
) -> list[str]:
    """Every declared image is recognised by the update configuration."""
    problems: list[str] = []
    grouped: dict[str, list[dict]] = {}
    for rule in config.get("packageRules") or []:
        if rule.get("groupName"):
            grouped.setdefault(rule["groupName"], []).append(rule)
    for entry in inventory["images"]:
        covered = False
        for source in entry["sources"]:
            for match in update_matches_for(config, root, source):
                if (
                    match.dep_name == entry["repository"]
                    and match.current_value == entry["tag"]
                    and match.current_digest == entry["digest"]
                ):
                    covered = True
                    break
            if covered:
                break
        if not covered:
            problems.append(
                f"scripts/runtime-images.json: {reference_of(entry)} is not matched by "
                "any renovate.json custom manager — the pin would never be proposed "
                "for update, so it silently rots"
            )
        expected_group = update_group_of(entry)
        if not any(
            entry["repository"] in (rule.get("matchDepNames") or [])
            for rule in grouped.get(expected_group, [])
        ):
            problems.append(
                f"renovate.json: no packageRule declares groupName {expected_group!r} "
                f"matching depName {entry['repository']!r} — without a per-family group "
                "a bad bump cannot be reviewed or rolled back on its own"
            )
    return problems


# --------------------------------------------------------------------------- #
# Aggregate
# --------------------------------------------------------------------------- #


def check_all(
    root: pathlib.Path, inventory: dict, config: dict
) -> tuple[list[str], list[ImageReference]]:
    """Run every check. Returns (problems, discovered references)."""
    references = discover_references(root, inventory)
    problems: list[str] = []
    problems += check_static_references_pinned(references)
    problems += check_references_declared(references, inventory)
    problems += check_inventory_entries_used(references, inventory, root)
    problems += check_update_config(inventory, config, root)
    if not [r for r in references if r.is_static]:
        problems.append(
            "no static image reference was discovered at all — discovery is broken or "
            "misconfigured, which would make every check above vacuous"
        )
    return problems, references
