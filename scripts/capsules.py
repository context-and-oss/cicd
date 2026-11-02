"""Catch the YAML typos in `.capsules/*.yaml` that stop conftest from parsing.

A capsule is prose in YAML, and prose grows colons. An unquoted `: ` inside a
plain scalar starts a mapping where YAML does not allow one, so the file stops
parsing — and the way that failure surfaces is the problem this module exists
for. conftest ingests capsules through the infra policy scan, renames every
input, and reports:

    parse configurations: parser unmarshal: unmarshal yaml:
    error converting YAML to JSON: yaml: line 24: mapping values are not
    allowed in this context, path: /inputs/f0000

Line 24 of `/inputs/f0000`. Not a filename, not a hint that a capsule is
involved, from a job named "Precommit on self" that reads like a code scan —
and only after Dagger has spun up and run the chain, four minutes in. The
information needed to fix a one-character typo is exactly the information the
error drops.

Scope, stated plainly because a checker that overstates itself is the failure
this repository refuses everywhere else: **this is not a YAML validator.** It
cannot be one without PyYAML, which `ado_templates.py` and `repo_surface.py`
both decline to depend on for the same reason (not guaranteed on a bare runner
or in the release sandbox). It recognises two specific classes that are always
invalid YAML and are what prose files actually get wrong:

  1. An unquoted `: ` (or a trailing `:`) in a plain scalar — the measured
     failure above.
  2. A tab in leading whitespace, which YAML forbids for indentation.
  3. A quoted scalar with content after its closing quote. Measured, and the
     reason this third rule exists at all — CAPS-017 shipped this line:

         - "artifact: NOT ATTESTED — no artifact was built" (rejected)

     which is the same instinct as rule 1 (quote the prose holding the colon)
     applied one word too narrowly. YAML ends the scalar at the closing quote
     and then expects a new node, so it reports `line 90: did not find expected
     '-' indicator` — and rule 1 could not see it, because `_MAPPING_RE` reads
     the line as a perfectly legal `key: value` whose key happens to be
     `"artifact`. It cost a four-minute dogfood run to find, in exactly the way
     described above.
  4. A plain scalar opening with `@` or a backtick. YAML reserves both and
     allows neither to start a scalar in any context, so a line walk can judge
     them without a parser — unlike every other indicator, which is contextual.
     Also measured, and by the same route the docstring keeps describing:
     CAPS-049 shipped this line:

         - `== 'pr-open' || == 'released'` (chosen)

     which is rule 1's instinct (put the syntax in backticks so it reads as
     code) applied where the backtick lands first instead of mid-sentence. Rules
     1 and 3 both passed it — there is no colon and no quote — and the dogfood
     run reported `line 118 ... path: /inputs/f0000`. The position is the whole
     rule: a backtick anywhere after the first character, including opening a
     continuation line of a multi-line plain scalar, is ordinary prose and must
     not be flagged.

A capsule that passes this check is therefore *not* proven to parse. It is
proven to be free of those three. Anything else still surfaces downstream, in
conftest, the slow way — so treat a pass as "the common typo is absent", never
as "the file is valid". Rule 3 is the standing proof that the caveat is not
boilerplate: it was added *after* a capsule this module had already called
clean took the policy scan down.

The second thing this module checks is not about parsing at all: **a capsule
number has to resolve to one capsule.** The number is the whole handle — it is
what a doctrine paragraph, an ADR or a spec cites, and it is not derivable from
anything else in the file. Three branches authored off the same `main` each
claimed `CAPS-017`, and because the slugs differed no filename collided, no
merge conflicted, and `check_capsules` printed `OK (18 capsule(s))` over a tree
holding two capsules numbered 017. Nothing was mis-scanned, so this is not the
"could not run reads as clean" class the rest of this repository is built
around — it is weaker and worth saying so: the cost is a citation that resolves
to whichever of the two files the reader happens to open, and a renumber owed
later, on `main`, where the capsule is already sealed.

`check_identity` therefore asks three questions the glob cannot: the filename
carries a readable `CAPS-<NNN>`, the top-level `id:` inside agrees with it (the
two are edited separately — a `git mv` alone leaves the field behind), and no
number is claimed twice. Uniqueness only: **a gap is legal.** Branches merge in
whatever order review finishes, so requiring 017 to exist before 019 would fail
`main` for the ordinary case this check was written in response to.
"""

from __future__ import annotations

import re
from pathlib import Path

# Capsules are the intent artifacts the dogfood pipeline gates on
# (`.capsules/*.yaml` is one of intent.Check's default globs).
CAPSULE_GLOB = ".capsules/*.yaml"

# A line whose value opens a block scalar: `key: >`, `key: |-`, `- >`, `|2`.
# Everything indented past such a line is literal text, where a colon is legal
# prose and must not be reported.
_BLOCK_OPEN_RE = re.compile(r"^(?:-\s+)?(?:[^\s:#][^:]*:\s*)?[|>][-+]?\d*\s*$")

# `key: value` or a bare `key:`. The key may not contain a colon, which is what
# makes the *second* colon on a line detectable as the mistake.
_MAPPING_RE = re.compile(r"^(?P<key>[^\s:#][^:]*):(?:\s+(?P<val>\S.*))?\s*$")

_SEQ_RE = re.compile(r"^-\s+(?=\S)")

# `CAPS-017-say-what-no-artifact-left-unattested.capsule.yaml`. The number is
# matched as digits rather than exactly three, so passing 999 needs no edit here.
_CAPSULE_NAME_RE = re.compile(r"^CAPS-(?P<num>\d+)-[^.]+\.capsule\.yaml$")

# Top-level only: `^id:` at column 0. A nested `id:` deeper in the document
# belongs to some inner node and is not the capsule's identity.
_ID_RE = re.compile(r"^id:[ \t]*(?P<id>\S+)[ \t]*$", re.MULTILINE)


def _is_quoted(value: str) -> bool:
    """A fully quoted scalar may hold any colon it likes."""
    value = value.strip()
    if len(value) < 2:
        return False
    return (value[0] == value[-1]) and value[0] in "\"'"


def _colon_fault(value: str) -> str | None:
    """The colon that would start a mapping, or None if the scalar is safe."""
    if _is_quoted(value):
        return None
    stripped = value.rstrip()
    if stripped.endswith(":"):
        return "value ends with ':'"
    # `://` in a URL is not `: ` and never starts a mapping.
    if ": " in stripped:
        return "value contains an unquoted ': '"
    return None


# YAML's two reserved indicators. Every other indicator character is contextual
# -- `>` and `|` open block scalars, `-` opens a sequence entry, `?` and `:` are
# legal mid-scalar -- so those cannot be judged from one line without a parser.
# These two are never legal as the first character of a plain scalar, in any
# context, which is what makes the rule safe to apply from a line walk.
_RESERVED_FIRST = "@`"


def _reserved_first(value: str) -> str | None:
    """The reserved indicator opening this plain scalar, or None if it is safe.

    Measured, because the position matters and guessing it would either miss the
    fault or fail legal prose: a sequence item or a mapping value opening with a
    backtick both stop the parser, while one anywhere after the first character
    -- including the first
    character of a *continuation* line of a multi-line plain scalar -- is
    ordinary text. So this is called only where a scalar begins.
    """
    value = value.lstrip()
    if not value or _is_quoted(value):
        return None
    return value[0] if value[0] in _RESERVED_FIRST else None


def _quoted_tail(value: str) -> str | None:
    """What follows a quoted scalar's closing quote, or None if there is no fault.

    Deliberately silent when no closing quote is found on the line: a quoted
    scalar may legally span lines, and this walk has no state to tell that from
    an unterminated quote. Reporting the ambiguous case would put a false
    failure on legal YAML, which the module docstring argues is the one thing
    that gets a prose check abandoned.
    """
    value = value.rstrip()
    if not value or value[0] not in "\"'":
        return None
    quote = value[0]
    i, n = 1, len(value)
    while i < n:
        char = value[i]
        # Only double quotes take backslash escapes; in single quotes a
        # backslash is an ordinary character and '' is the escaped quote.
        if quote == '"' and char == "\\":
            i += 2
            continue
        if char == quote:
            if quote == "'" and i + 1 < n and value[i + 1] == "'":
                i += 2
                continue
            break
        i += 1
    else:
        return None
    tail = value[i + 1:].strip()
    if not tail or tail.startswith("#"):
        return None
    return tail


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Findings in one capsule as (line number, rule, message).

    Hand-rolled for the same reason as `_run_block_bodies` in repo_surface:
    no third-party dependency, and the shape needed is narrow. The walk tracks
    two regions so a colon is judged in the right context — inside a block
    scalar it is prose, and on a continuation line of a plain scalar it is the
    bug.
    """
    findings: list[tuple[int, str, str]] = []
    block_indent: int | None = None
    plain_indent: int | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\n")
        indent = len(line) - len(line.lstrip(" \t"))

        if line.strip() and "\t" in line[:indent]:
            findings.append(
                (lineno, "tab-indent", "leading whitespace contains a tab; YAML forbids tabs for indentation")
            )
            continue

        if not line.strip():
            continue  # A blank line ends nothing: block scalars may contain them.

        if block_indent is not None:
            if indent > block_indent:
                continue  # Literal text. Colons here are prose.
            block_indent = None

        if line.lstrip().startswith("#"):
            continue

        # A continuation line of a multi-line plain scalar: pure prose, so any
        # colon on it is the fault. This is where the measured failure landed.
        if plain_indent is not None and indent > plain_indent:
            fault = _colon_fault(line.strip())
            if fault is not None:
                findings.append(
                    (lineno, "plain-scalar-colon", f"continuation line of a plain scalar {fault}")
                )
            continue
        plain_indent = None

        content = line.lstrip()
        offset = indent
        seq = _SEQ_RE.match(content)
        if seq is not None:
            # `- key: value` anchors continuations at the key; `- bare text`
            # anchors them at the dash, since a bare scalar has no children.
            content = content[seq.end():]
            offset = indent + seq.end()

        # Before _MAPPING_RE, which would read `- "artifact: X" (rejected)` as a
        # legal mapping whose key is `"artifact`. That misreading is why rule 1
        # could not see the measured failure; see the module docstring.
        tail = _quoted_tail(content)
        if tail is not None:
            findings.append(
                (
                    lineno,
                    "quoted-scalar-tail",
                    f"a quoted scalar is followed by {tail!r} on the same line; YAML ends "
                    f"the scalar at the closing quote and then expects a new node",
                )
            )
            plain_indent = None
            continue

        reserved = _reserved_first(content)
        if reserved is not None:
            findings.append(
                (
                    lineno,
                    "reserved-first-char",
                    f"a plain scalar starts with {reserved!r}, which YAML reserves and "
                    f"never allows to open a scalar; quote the value",
                )
            )
            plain_indent = None
            continue

        if _BLOCK_OPEN_RE.match(line.strip()):
            block_indent = indent
            continue

        mapping = _MAPPING_RE.match(content)
        if mapping is None:
            # A bare plain scalar (`- some prose`). Continuations follow.
            plain_indent = indent if seq is not None else offset
            continue

        value = mapping.group("val")
        if value is None:
            plain_indent = None  # Children are nested nodes, not continuations.
            continue

        tail = _quoted_tail(value)
        if tail is not None:
            findings.append(
                (
                    lineno,
                    "quoted-scalar-tail",
                    f"mapping value is a quoted scalar followed by {tail!r} on the same "
                    f"line; YAML ends the scalar at the closing quote",
                )
            )
            plain_indent = None
            continue

        reserved = _reserved_first(value)
        if reserved is not None:
            findings.append(
                (
                    lineno,
                    "reserved-first-char",
                    f"mapping value starts with {reserved!r}, which YAML reserves and "
                    f"never allows to open a scalar; quote the value",
                )
            )
            plain_indent = None
            continue

        fault = _colon_fault(value)
        if fault is not None:
            findings.append((lineno, "plain-scalar-colon", f"mapping value {fault}"))
        plain_indent = offset

    return findings


def check_identity(paths: list[Path], root: Path) -> list[str]:
    """Problems with *which capsule a capsule is*, as opposed to whether it parses.

    Reports the filename it cannot read a number from, the `id:` field that
    disagrees with the filename holding it, and any number claimed more than
    once. Deliberately silent about gaps: see the module docstring.
    """
    problems: list[str] = []
    by_number: dict[str, list[str]] = {}

    for path in paths:
        rel = path.relative_to(root)
        name = _CAPSULE_NAME_RE.match(path.name)
        if name is None:
            problems.append(
                f"{rel}: [name] not CAPS-<NNN>-<slug>.capsule.yaml, so this file "
                f"has no number anything can cite it by"
            )
            continue

        number = name.group("num")
        by_number.setdefault(number, []).append(str(rel))

        declared = _ID_RE.findall(path.read_text())
        if not declared:
            problems.append(
                f"{rel}: [id] no top-level `id:` field — the filename claims "
                f"CAPS-{number} and the file itself claims nothing"
            )
        elif len(declared) > 1:
            problems.append(
                f"{rel}: [id] {len(declared)} top-level `id:` fields "
                f"({', '.join(declared)}); a capsule has one identity"
            )
        elif declared[0] != f"CAPS-{number}":
            problems.append(
                f"{rel}: [id] declares `id: {declared[0]}` but is named CAPS-{number} "
                f"— renaming the file does not move the field"
            )

    for number, claimants in sorted(by_number.items()):
        if len(claimants) > 1:
            problems.append(
                f"CAPS-{number}: [duplicate] claimed by {len(claimants)} capsules "
                f"({', '.join(claimants)}) — a capsule number is a citation "
                f"target, so it has to resolve to exactly one file. Renumber all "
                f"but one to the next free number; a gap is fine, a collision is not."
            )

    return problems


def check_capsules(root: Path) -> list[str]:
    """Every capsule, or a loud problem if there are none to check.

    Zero files is a failure, not a pass. A glob that silently matches nothing
    reports OK over no work, which is the same false clean this repository
    refuses from a scanner that never ran — and the directory moving is exactly
    how it would happen.
    """
    paths = sorted(root.glob(CAPSULE_GLOB))
    if not paths:
        return [f"no capsules matched {CAPSULE_GLOB} — the glob or the directory moved"]

    problems: list[str] = []
    for path in paths:
        rel = path.relative_to(root)
        for lineno, rule, message in scan_text(path.read_text()):
            problems.append(f"{rel}:{lineno}: [{rule}] {message}")
    problems.extend(check_identity(paths, root))
    return problems
