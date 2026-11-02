"""
Behavioural validation for the active Azure DevOps templates.

Why this exists
---------------
`scripts/check-workflow-pins.py` proves an ADO template's `@vX.Y.Z` pins agree
and that a pinned `call <cmd>` exists. That is *static* checking of two tokens.
Nothing checked what the template actually does, so all of the following could
ship green:

  * a template that no longer parses as YAML at all (ADO only tells you at
    queue time, in the consumer's repo, after they copied the file);
  * a step that splices a consumer-supplied pipeline variable straight into a
    bash script as an ADO `$(VAR)` macro — macro expansion happens *before* bash
    parses the line, so quoting cannot save it and a value containing a quote or
    a newline injects shell;
  * a template that writes a credential into `~/.git-credentials` and never
    removes it (harmless on a hosted agent, a credential left on disk on a
    self-hosted one). No shipped template writes one any more; the rule stays
    so the next one that does cannot ship without the clearing step;
  * a `--token`/`--webhook`/`--api-key` flag given a literal or a macro instead
    of the `env:NAME` form, i.e. a secret on a command line;
  * a reference to a removed surface (`run-archive`, `commit-archive`) in prose
    or in a command, telling a consumer to use something ADR-005 deleted.

Everything here is deterministic and offline: it reads
scripts/repo-inventory.json for the declared template list and the files already
in the working tree. No network, no `dagger`, no ADO API.

YAML parsing
------------
PyYAML is not available in every environment this runs in (the release sandbox
has no pip packages at all), and ADO's dialect is a *subset* of YAML anyway, so
`parse_ado_yaml` implements that subset directly: block mappings, block
sequences, block scalars (`|`, `|-`, `>`), plain and quoted scalars, and
comments. Anything outside the subset is reported as a parse error rather than
guessed at — a template we cannot parse is a template we cannot vouch for.

Check surface (each returns a list of human-readable problem strings; empty means
clean, so callers can aggregate):

  check_templates_declared     declared ADO templates exist; no active template
                               on disk is undeclared
  check_templates_parse        every template parses and has the ADO skeleton
                               (pool / variables / steps, steps non-empty)
  check_step_shape             every step names exactly one action, and bash
                               steps carry a displayName
  check_removed_surfaces       no reference to a removed archive surface
  check_dagger_invocations     each composite call uses its supported entry
                               point with the flags the pipeline depends on
  check_secret_flags           every secret-bearing flag uses `env:NAME`, and
                               NAME is declared in that step's `env:` mapping
  check_value_interpolation    no consumer-supplied `$(VAR)` macro is spliced
                               into a bash body
  check_shell_quoting          every expansion of an `env:`-provided value is
                               double-quoted
  check_secret_handling        no secret env var is echoed, and a template that
                               writes ~/.git-credentials clears them again
  check_evidence_verdict       every template either reads `passed` from
                               combined-evidence.json or carries the banner
                               declaring that it does not gate

`check_all` runs the lot.
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass

INVENTORY_FILENAME = "repo-inventory.json"

# Every active ADO template lives here. Used both to filter the inventory's
# `templates` group and to discover an undeclared template on disk.
ADO_TEMPLATE_DIR = "templates/azure-devops"

# ── ADO variable trust boundary ──────────────────────────────────────────────
#
# ADO expands `$(Name)` macros into the script body *before* the shell parses
# it. So for any value a consumer controls, `"$(VAR)"` is not quoting — it is
# textual splicing, and a value containing `"` ends the string early. The safe
# shape is to pass the value through the step's `env:` mapping (where ADO does
# not shell-interpolate) and reference it as `"$VAR"`.
#
# Agent/system variables are exempt only when ADO itself mints the value: an id,
# a sha, a path on the agent, the organisation's own URL. A name a pusher chooses
# is not exempt, however system-looking its macro. A git ref may legally carry
# `$(`, `;`, `|` and a backtick, and ADO builds GitHub fork PRs, so
# Build.SourceBranch[Name] and System.PullRequest.{Source,Target}Branch are
# attacker-shaped text; Build.BuildNumber is too, because a consumer's `name:`
# format may embed the branch. ADO already exports every one of them to the
# step's environment (BUILD_SOURCEBRANCHNAME, SYSTEM_PULLREQUEST_TARGETBRANCH),
# so the safe form costs nothing: "$BUILD_SOURCEBRANCHNAME".
TRUSTED_SYSTEM_VARIABLES = frozenset(
    {
        "Agent.BuildDirectory",
        "Agent.TempDirectory",
        "Agent.WorkFolder",
        "Build.ArtifactStagingDirectory",
        "Build.BuildId",
        "Build.Reason",
        "Build.Repository.ID",
        "Build.Repository.Name",
        "Build.Repository.Uri",
        "Build.SourceVersion",
        "Build.StagingDirectory",
        "System.AccessToken",
        "System.CollectionUri",
        "System.DefaultWorkingDirectory",
        "System.JobId",
        "System.PullRequest.PullRequestId",
        "System.TeamFoundationCollectionUri",
        "System.TeamProject",
        "System.TeamProjectId",
    }
)

# The one template-owned variable allowed inline in a bash body.
#
# DAGGER_VERSION is only ever used to build the CLI download URL and the engine
# image tag, both of which the consumer already fully controls by editing the
# template. Every other variable — including ones the template declares with a
# literal default, because an ADO pipeline variable set in the UI *overrides* a
# `variables:` block — must arrive via `env:`.
TEMPLATE_OWNED_INLINE = frozenset({"DAGGER_VERSION"})

# ── removed surfaces (ADR-005) ───────────────────────────────────────────────
#
# The commit composite exposes a single `Run` with `--artifact
# container|archive|none`. These identifiers named the per-shape entry points and
# the separate pipeline file that ADR-005 removed; an active template naming one
# is telling a consumer to use something that no longer exists.
REMOVED_SURFACES = ("run-archive", "commit-archive", "RunArchive", "runArchive")

# A flag whose value is a credential. Matched on the flag name.
SECRET_FLAG = re.compile(r"--[a-z0-9-]*(?:token|webhook|api-key|apikey|password|secret)\b")

# An environment variable name that holds a credential.
SECRET_ENV_NAME = re.compile(r"(?:TOKEN|SECRET|PASSWORD|WEBHOOK|API_?KEY|ACCESSTOKEN)")

# The only accepted shape for a secret flag's value: Dagger's `env:NAME` form.
# Leading quotes are tolerated; a trailing `)` from a bash array append is not
# part of the name.
ENV_SECRET_REF = re.compile(r"""^["']?env:(?P<name>[A-Za-z_][A-Za-z0-9_]*)""")

# `dagger [flags] -m github.com/context-and-oss/cicd/<path>@vX.Y.Z call <cmd>`
COMPOSITE_CALL = re.compile(
    r"-m\s+github\.com/context-and-oss/cicd/(?P<path>[A-Za-z0-9/_\-]+)@v\d+\.\d+\.\d+"
    r"\s+call\s+(?P<cmd>[a-z][a-z0-9\-]*)"
)

# ── template kinds ───────────────────────────────────────────────────────────
#
# A template's filename prefix decides which composite its `dagger call` must
# name and which flags that call must carry. This was a BOOLEAN — commit, or
# not-commit meaning pre-commit — until an ADO DAST template had to ship, and
# widening it is a real change rather than a rename because the required flag
# list is not universal. `dast.Scan --app url` scans an address and has no
# source tree at all, so asserting `--src` against it would force the template
# to carry a flag it does not use in order to satisfy the checker: the same
# class of lie the flag list exists to prevent, one level up in the harness.
#
# `commit` is tested before the fallback, so `precommit.yml` classifies the way
# it always did. A filename matching no prefix is a pre-commit template, which
# is the historical default and deliberately not an error — the classification
# decides *which* flags are demanded, and demanding the wrong set is louder
# than demanding none.
TEMPLATE_KIND_PREFIXES = ("commit", "dast")
DEFAULT_TEMPLATE_KIND = "precommit"

COMPOSITE_BY_KIND = {
    "commit": "src/composites/commit",
    "dast": "src/composites/dast",
    "precommit": "src/composites/precommit",
}

# Flags the composite invocation must always pass. Without --fail-on the gate
# threshold silently becomes the module default; without the repo triple the
# evidence loses its provenance.
REQUIRED_COMPOSITE_FLAGS = ("--src", "--fail-on", "--commit-sha", "--branch", "--repo-url")

# The DAST composite keeps the threshold and the provenance triple, and then
# diverges in both directions. It has no --src on two of its three shapes, and
# it gains two selectors whose absence is a *downgrade* rather than a missing
# input, because Dagger's generated client drops any optional argument holding
# its zero value: an unset --mode buys the weakest of the three scans, and an
# unset --app resolves to the shape that needs the least from the caller.
# `validateApp` refuses both, and the template is asked to pass them so that
# refusal never has to fire on a consumer's first run.
DAST_COMPOSITE_FLAGS = (
    "--mode",
    "--fail-on",
    "--commit-sha",
    "--branch",
    "--repo-url",
)

DAST_PACKAGE_FLAGS = (
    "--evidence",
    "--commit-sha",
    "--branch",
    "--repo-url",
)

REQUIRED_FLAGS_BY_KIND = {
    "commit": REQUIRED_COMPOSITE_FLAGS,
    "dast": DAST_COMPOSITE_FLAGS,
    "precommit": REQUIRED_COMPOSITE_FLAGS,
}

# Flags the step must pass, but which the invocation *line* cannot be asked to
# carry. This splits WHERE the checker looks and nothing else: a flag in this
# table is exactly as mandatory as one in the table above, and a template
# passing it in neither place still fails.
#
# `--app` is here because its value pairs with a different second flag in each
# of the three shapes — `--target`, `--service`, `--src` — so the shape has to
# be resolved in shell before the call is composed, and every template that
# covers more than one shape assembles it into the argument array. Demanding it
# on the line would demand a template that supports exactly one shape, which is
# a template covering a third of the feature in order to satisfy the checker:
# the same trade the kind comment above already refuses, arriving through the
# location of a check rather than through its contents.
#
# Comments do not count, for the reason `check_container_shape_flags` gives —
# a flag named in prose reaches no dagger call.
DAST_BODY_SCOPED_FLAGS = ("--app",)

BODY_SCOPED_FLAGS_BY_KIND = {
    "commit": (),
    "dast": DAST_BODY_SCOPED_FLAGS,
    "precommit": (),
}

# Container-shape overrides `commit.Run` accepts and the templates shipped
# without. `--dockerfile` and `--platform` were reachable from a direct
# `dagger call` and from nowhere else, so an ADO consumer could build exactly
# `./Dockerfile` for exactly linux/amd64. A capability the composite
# has and the harness cannot reach is invisible from both ends — the module
# signature reads complete and the template runs green — so the templates are
# asked whether the flags are there, and whether their values arrive from the
# step's `env:` mapping rather than from a spliced ADO macro.
#
# `dast.Run --app container` builds from the same two, so the question is asked
# of a DAST template too. It is NOT asked of a pre-commit template, which
# builds nothing.
CONTAINER_SHAPE_FLAGS = ("--dockerfile", "--platform")
CONTAINER_SHAPE_KINDS = frozenset({"commit", "dast"})

# The only accepted shape for a container-shape override's value: a double-quoted
# expansion of an `env:`-provided variable, `"$NAME"` or `"${NAME:-}"`.
ENV_VALUE_REF = re.compile(r"""^"\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)""")

# ADO step keys that name what the step *does*, as opposed to configuring it
# (displayName, condition, env, continueOnError, ...).
STEP_ACTION_KEYS = frozenset({"bash", "script", "pwsh", "powershell", "task", "checkout", "publish", "download", "template"})

# `$(Name)` — an ADO macro. The identifier restriction matters: bash command
# substitution shares this syntax, and `$(git rev-parse HEAD)` contains spaces so
# it cannot be confused with a macro. A single-word substitution such as `$(pwd)`
# is genuinely ambiguous in an ADO template and is reported.
ADO_MACRO = re.compile(r"\$\((?P<name>[A-Za-z_][A-Za-z0-9_.]*)\)")

# `$NAME`, `${NAME}`, `${NAME:-default}`, `${NAME[@]}`
SHELL_EXPANSION = re.compile(r"\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)")


class TemplateError(Exception):
    """The manifest or a template is unusable, as opposed to merely wrong."""


class YamlSubsetError(TemplateError):
    """A template is outside the ADO YAML subset this module parses."""


# ─────────────────────────────────────────────────────────────────────────────
# YAML subset parser
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Line:
    number: int
    indent: int
    text: str  # content with indentation stripped, comments already handled


def _split_key(text: str) -> tuple[str, str] | None:
    """Split `key: value` on the first structural colon, honouring quotes.

    Returns (key, rest) or None when the line is not a mapping entry. `rest` is
    "" for `key:` with nothing after it.
    """
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1 :].strip()
    return None


def _strip_comment(text: str) -> str:
    """Drop a trailing YAML comment. A `#` inside quotes is data, not a comment."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _scalar(raw: str) -> object:
    """Interpret a plain or quoted YAML scalar."""
    text = raw.strip()
    if not text:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    if text in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def parse_ado_yaml(source: str) -> dict:
    """Parse the block-YAML subset ADO pipelines use.

    Raises YamlSubsetError on anything outside the subset: tab indentation, a
    line that is neither a mapping entry nor a sequence item, an unterminated
    quote, or a document whose root is not a mapping.
    """
    raw_lines = source.splitlines()
    lines: list[_Line] = []
    for number, raw in enumerate(raw_lines, 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlSubsetError(f"line {number}: tab indentation is invalid YAML")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in ("---", "..."):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append(_Line(number, indent, raw[indent:]))

    if not lines:
        raise YamlSubsetError("document is empty")

    # Block scalars are consumed against the *raw* lines, so keep them around.
    value, index = _parse_block(lines, 0, lines[0].indent, raw_lines)
    if index != len(lines):
        raise YamlSubsetError(
            f"line {lines[index].number}: unexpected indentation — "
            f"expected indent {lines[0].indent}, got {lines[index].indent}"
        )
    if not isinstance(value, dict):
        raise YamlSubsetError("an ADO pipeline document must be a mapping at the root")
    return value


def _parse_block(
    lines: list[_Line], index: int, indent: int, raw_lines: list[str]
) -> tuple[object, int]:
    if lines[index].text.startswith("- ") or lines[index].text == "-":
        return _parse_sequence(lines, index, indent, raw_lines)
    return _parse_mapping(lines, index, indent, raw_lines)


def _parse_mapping(
    lines: list[_Line], index: int, indent: int, raw_lines: list[str]
) -> tuple[dict, int]:
    result: dict[str, object] = {}
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if line.text.startswith("- "):
            break
        split = _split_key(_strip_comment(line.text) or line.text)
        if split is None:
            raise YamlSubsetError(
                f"line {line.number}: expected 'key: value' or '- item', got {line.text!r}"
            )
        key, rest = split
        if key.startswith(("'", '"')):
            key = str(_scalar(key))
        index += 1

        if rest in ("|", "|-", "|+", ">", ">-", ">+"):
            block, index = _consume_block_scalar(lines, index, indent, raw_lines, line.number)
            result[key] = block
            continue
        if rest == "":
            if (
                index < len(lines)
                and lines[index].indent == indent
                and (lines[index].text.startswith("- ") or lines[index].text == "-")
            ):
                # YAML permits a block sequence to be indented at the same
                # level as its parent mapping key (`steps:\n- checkout: self`).
                nested, index = _parse_sequence(lines, index, indent, raw_lines)
                result[key] = nested
            elif index < len(lines) and lines[index].indent > indent:
                nested, index = _parse_block(lines, index, lines[index].indent, raw_lines)
                result[key] = nested
            else:
                result[key] = None
            continue
        result[key] = _scalar(rest)
    return result, index


def _parse_sequence(
    lines: list[_Line], index: int, indent: int, raw_lines: list[str]
) -> tuple[list, int]:
    items: list[object] = []
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if not (line.text.startswith("- ") or line.text == "-"):
            break
        inline = line.text[2:] if line.text.startswith("- ") else ""
        item_indent = indent + 2
        if not inline.strip():
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                item, index = _parse_block(lines, index, lines[index].indent, raw_lines)
                items.append(item)
            else:
                items.append(None)
            continue

        split = _split_key(_strip_comment(inline) or inline)
        if split is None:
            items.append(_scalar(_strip_comment(inline)))
            index += 1
            continue

        # `- key: value` opens a mapping whose remaining keys sit at item_indent.
        # Re-present the dash line as a mapping line at that indent and parse on.
        synthetic = [_Line(line.number, item_indent, inline)]
        rest_index = index + 1
        while rest_index < len(lines) and lines[rest_index].indent >= item_indent:
            if lines[rest_index].indent == item_indent and lines[rest_index].text.startswith("- "):
                break
            synthetic.append(lines[rest_index])
            rest_index += 1
        mapping, consumed = _parse_mapping(synthetic, 0, item_indent, raw_lines)
        if consumed != len(synthetic):
            raise YamlSubsetError(
                f"line {synthetic[consumed].number}: unexpected indentation inside a sequence item"
            )
        items.append(mapping)
        index = rest_index
    return items, index


def _consume_block_scalar(
    lines: list[_Line], index: int, indent: int, raw_lines: list[str], key_line: int
) -> tuple[str, int]:
    """Collect a block scalar's body verbatim, dedented by its own indentation.

    Read from `raw_lines`, not from the tokenised `lines`: the tokeniser drops
    blank and `#`-comment lines, which are *content* inside a block scalar. A
    bash body that opens with a comment — every long step in these templates does
    — would otherwise lose those lines, and with them any unsafe interpolation
    or removed-surface reference they contain.

    `key_line` is the 1-based line number of the `key: |` line, so the body
    starts at raw index `key_line`.
    """
    block_indent: int | None = None
    body_raw: list[str] = []
    cursor = key_line
    while cursor < len(raw_lines):
        raw = raw_lines[cursor]
        if not raw.strip():
            body_raw.append("")
            cursor += 1
            continue
        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent <= indent:
            break
        if block_indent is None:
            block_indent = current_indent
        body_raw.append(raw)
        cursor += 1

    # Trailing blank lines belong to whatever follows, not to the block.
    while body_raw and not body_raw[-1].strip():
        body_raw.pop()
        cursor -= 1

    if block_indent is None:
        return "", index

    body = "\n".join(
        raw[block_indent:] if len(raw) > block_indent else raw.strip() for raw in body_raw
    )
    # Advance past every tokenised line the block consumed (1-based numbers up
    # to and including `cursor`).
    while index < len(lines) and lines[index].number <= cursor:
        index += 1
    return body, index


# ─────────────────────────────────────────────────────────────────────────────
# shell scanning
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ShellRef:
    kind: str  # "macro" | "expansion"
    name: str
    quoted: bool
    in_comment: bool


def scan_shell(body: str) -> list[ShellRef]:
    """Find every ADO macro and shell expansion in a bash body, with its quoting.

    Tracks single quotes (no expansion at all), double quotes (expansion, but
    word-splitting suppressed) and `#` comments. Command substitutions are
    scanned recursively with fresh quote state so their inner quoting does not
    corrupt the outer scan — `echo "x $(grep -c '^+' "$f")"` must not leave the
    scanner believing it is inside a single-quoted string.
    """
    refs: list[ShellRef] = []
    _scan(body, refs, in_comment_allowed=True)
    return refs


def _scan(body: str, refs: list[ShellRef], *, in_comment_allowed: bool) -> None:
    i, n = 0, len(body)
    quote = ""  # "" | "'" | '"'
    while i < n:
        ch = body[i]

        if quote == "'":
            if ch == "'":
                quote = ""
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                quote = ""
                i += 1
                continue
            # fall through so expansions inside double quotes are still seen
        else:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch in "\"'":
                quote = ch
                i += 1
                continue
            if (
                in_comment_allowed
                and ch == "#"
                and (i == 0 or body[i - 1] in " \t\n")
            ):
                end = body.find("\n", i)
                end = n if end == -1 else end
                # ADO expands macros even inside a shell comment, so they still
                # count; an unquoted *shell* expansion in a comment does not run.
                for match in ADO_MACRO.finditer(body[i:end]):
                    refs.append(ShellRef("macro", match.group("name"), False, True))
                i = end
                continue

        if ch == "$" and i + 1 < n and body[i + 1] == "(":
            macro = ADO_MACRO.match(body, i)
            if macro:
                refs.append(ShellRef("macro", macro.group("name"), quote == '"', False))
                i = macro.end()
                continue
            inner_start = i + 2
            depth, j = 1, inner_start
            while j < n and depth:
                if body[j] == "(":
                    depth += 1
                elif body[j] == ")":
                    depth -= 1
                j += 1
            _scan(body[inner_start : j - 1], refs, in_comment_allowed=False)
            i = j
            continue

        if ch == "$":
            expansion = SHELL_EXPANSION.match(body, i)
            if expansion:
                refs.append(ShellRef("expansion", expansion.group("name"), quote == '"', False))
                i = expansion.end()
                continue

        i += 1


# ─────────────────────────────────────────────────────────────────────────────
# template model
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Template:
    rel: str
    text: str
    document: dict

    @property
    def steps(self) -> list[dict]:
        steps = self.document.get("steps")
        return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []

    @property
    def kind(self) -> str:
        """Which composite this template is a pipeline for, by filename prefix."""
        name = pathlib.PurePosixPath(self.rel).name
        for prefix in TEMPLATE_KIND_PREFIXES:
            if name.startswith(prefix):
                return prefix
        return DEFAULT_TEMPLATE_KIND

    @property
    def is_commit(self) -> bool:
        return self.kind == "commit"


@dataclass(frozen=True)
class TemplateSet:
    root: pathlib.Path
    declared: tuple[str, ...]
    templates: tuple[Template, ...]
    parse_errors: tuple[tuple[str, str], ...]  # (rel, message)
    missing: tuple[str, ...]
    undeclared: tuple[str, ...]


def default_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def default_inventory_path() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / INVENTORY_FILENAME


def declared_ado_templates(inventory_path: pathlib.Path) -> tuple[str, ...]:
    """The ADO templates the defended inventory declares active."""
    try:
        data = json.loads(inventory_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise TemplateError(f"cannot read inventory {inventory_path}: {exc}") from exc
    group = data.get("active_surfaces", {}).get("templates")
    if not isinstance(group, list) or not group:
        raise TemplateError(
            f"{inventory_path} declares no active_surfaces.templates — an empty "
            f"template list would make every check below vacuous"
        )
    declared = tuple(
        rel for rel in group if isinstance(rel, str) and rel.startswith(ADO_TEMPLATE_DIR + "/")
    )
    if not declared:
        raise TemplateError(
            f"{inventory_path} declares no template under {ADO_TEMPLATE_DIR}/ — "
            f"refusing to validate nothing"
        )
    return declared


def discover_ado_templates(root: pathlib.Path) -> tuple[str, ...]:
    """Every ADO template file on disk, whether the inventory knows it or not."""
    base = root / ADO_TEMPLATE_DIR
    if not base.is_dir():
        return ()
    found = [
        path.relative_to(root).as_posix()
        for path in sorted(base.rglob("*"))
        if path.is_file() and path.suffix in (".yml", ".yaml")
    ]
    return tuple(found)


def load_templates(root: pathlib.Path, inventory_path: pathlib.Path) -> TemplateSet:
    declared = declared_ado_templates(inventory_path)
    discovered = discover_ado_templates(root)

    missing, templates, parse_errors = [], [], []
    for rel in declared:
        path = root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        text = path.read_text()
        try:
            templates.append(Template(rel, text, parse_ado_yaml(text)))
        except YamlSubsetError as exc:
            parse_errors.append((rel, str(exc)))

    undeclared = tuple(rel for rel in discovered if rel not in set(declared))
    return TemplateSet(
        root=root,
        declared=declared,
        templates=tuple(templates),
        parse_errors=tuple(parse_errors),
        missing=tuple(missing),
        undeclared=undeclared,
    )


# ─────────────────────────────────────────────────────────────────────────────
# checks
# ─────────────────────────────────────────────────────────────────────────────


def check_templates_declared(ts: TemplateSet) -> list[str]:
    """A declared template must exist; a template on disk must be declared."""
    problems = [
        f"{rel}  declared active in the inventory but missing from the tree"
        for rel in ts.missing
    ]
    problems += [
        f"{rel}  is an active ADO template but is not declared in "
        f"scripts/repo-inventory.json's active_surfaces.templates, so nothing "
        f"pin-checks or validates it"
        for rel in ts.undeclared
    ]
    return problems


def check_templates_parse(ts: TemplateSet) -> list[str]:
    """Every template parses and carries the ADO skeleton the runner needs."""
    problems = [f"{rel}  does not parse: {message}" for rel, message in ts.parse_errors]
    for t in ts.templates:
        for key in ("pool", "variables", "steps"):
            if key not in t.document:
                problems.append(f"{t.rel}  has no top-level '{key}:' — ADO cannot run it")
        if "steps" not in t.document:
            continue  # already reported as a missing top-level key
        steps = t.document["steps"]
        # `steps:` with nothing under it parses to None. That is a template with
        # no work in it, not an absent key, so it must fail rather than skip.
        if not isinstance(steps, list) or not steps:
            problems.append(
                f"{t.rel}  'steps:' must be a non-empty list, got {type(steps).__name__}"
            )
            continue
        if not t.steps:
            problems.append(f"{t.rel}  'steps:' contains no step mappings")
    return problems


def check_step_shape(ts: TemplateSet) -> list[str]:
    """Each step names exactly one action; bash steps carry a displayName."""
    problems = []
    for t in ts.templates:
        for position, step in enumerate(t.steps, 1):
            actions = sorted(set(step) & STEP_ACTION_KEYS)
            if not actions:
                problems.append(
                    f"{t.rel}  step {position} names no action "
                    f"(one of {', '.join(sorted(STEP_ACTION_KEYS))}); keys: {sorted(step)}"
                )
                continue
            if len(actions) > 1:
                problems.append(
                    f"{t.rel}  step {position} names {len(actions)} actions ({', '.join(actions)}) — "
                    f"ADO accepts exactly one per step"
                )
            if "bash" in step:
                if not isinstance(step["bash"], str) or not step["bash"].strip():
                    problems.append(f"{t.rel}  step {position} has an empty bash body")
                if not step.get("displayName"):
                    problems.append(
                        f"{t.rel}  step {position} is a bash step with no displayName — "
                        f"the ADO log shows an unnamed script"
                    )
    return problems


def check_removed_surfaces(ts: TemplateSet) -> list[str]:
    """No active template may name a surface ADR-005 removed."""
    problems = []
    for t in ts.templates:
        for lineno, line in enumerate(t.text.splitlines(), 1):
            for token in REMOVED_SURFACES:
                if token in line:
                    problems.append(
                        f"{t.rel}:{lineno}  names removed surface '{token}' — the commit "
                        f"composite exposes one `run` with "
                        f"--artifact container|archive|none (ADR-005)"
                    )
    return problems


def _bash_bodies(t: Template):
    """Yield (position, step, body) for every bash step."""
    for position, step in enumerate(t.steps, 1):
        body = step.get("bash")
        if isinstance(body, str) and body.strip():
            yield position, step, body


def _logical_lines(body: str) -> list[str]:
    """Join backslash continuations so a multi-line `dagger call` reads as one."""
    joined, buffer = [], ""
    for line in body.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
            continue
        joined.append(buffer + line)
        buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def check_dagger_invocations(ts: TemplateSet) -> list[str]:
    """Composite calls must use their supported entry points and required flags."""
    problems = []
    for t in ts.templates:
        expected_module = COMPOSITE_BY_KIND[t.kind]
        expected_commands = {"scan", "package"} if t.kind == "dast" else {"run"}
        found_commands: set[str] = set()
        for _, _, body in _bash_bodies(t):
            live = [
                line
                for line in _logical_lines(body)
                if not line.lstrip().startswith("#")
            ]
            for line in _logical_lines(body):
                for match in COMPOSITE_CALL.finditer(line):
                    module, cmd = match.group("path"), match.group("cmd")
                    if not module.startswith("src/composites/"):
                        continue  # a domain-module call (e.g. notify ado)
                    found_commands.add(cmd)
                    if module != expected_module:
                        problems.append(
                            f"{t.rel}  calls composite '{module}', expected "
                            f"'{expected_module}' for this template"
                        )
                    if cmd not in expected_commands:
                        problems.append(
                            f"{t.rel}  calls '{module} {cmd}' — supported entry points "
                            f"for this template are {', '.join(sorted(expected_commands))}"
                        )
                    if t.kind == "dast" and cmd == "package":
                        required_flags = DAST_PACKAGE_FLAGS
                        body_flags = ()
                    else:
                        required_flags = REQUIRED_FLAGS_BY_KIND[t.kind]
                        body_flags = BODY_SCOPED_FLAGS_BY_KIND[t.kind]
                    missing = [f for f in required_flags if f not in line]
                    missing += [
                        f
                        for f in body_flags
                        if not any(f in other for other in live)
                    ]
                    if missing:
                        problems.append(
                            f"{t.rel}  composite call omits {', '.join(missing)}"
                        )
                    if t.is_commit and "--artifact" not in line:
                        problems.append(
                            f"{t.rel}  commit composite call omits --artifact — the "
                            f"artifact shape is always explicit, never auto-detected "
                            f"(ADR-005)"
                        )
        missing_commands = expected_commands - found_commands
        if missing_commands:
            problems.append(
                f"{t.rel}  contains no pinned invocation for "
                f"{', '.join(sorted(missing_commands))} on {expected_module}"
            )
    return problems


def check_container_shape_flags(ts: TemplateSet) -> list[str]:
    """A building template can override the Dockerfile path and the target platform."""
    problems = []
    for t in ts.templates:
        if t.kind not in CONTAINER_SHAPE_KINDS:
            continue
        for flag in CONTAINER_SHAPE_FLAGS:
            reached = False
            for position, step, body in _bash_bodies(t):
                env = step.get("env") if isinstance(step.get("env"), dict) else {}
                for line in _logical_lines(body):
                    if line.lstrip().startswith("#"):
                        continue  # a mention in prose reaches no dagger call
                    index = line.find(flag + " ")
                    if index < 0:
                        continue
                    tail = line[index + len(flag) :].lstrip()
                    token = tail.split()[0] if tail else ""
                    ref = ENV_VALUE_REF.match(token)
                    if ref is None:
                        problems.append(
                            f"{t.rel}  step {position} passes {flag} as "
                            f"{token.rstrip(')')!r} — a consumer-supplied value must arrive "
                            f'from the step\'s env: mapping as "$NAME" or "${{NAME:-}}", '
                            f"because ADO expands a $(MACRO) before the shell parses the line"
                        )
                        continue
                    name = ref.group("name")
                    if name not in env:
                        problems.append(
                            f"{t.rel}  step {position} passes {flag} as ${name} but the "
                            f"step's env: mapping does not declare {name}, so the flag would "
                            f"carry an empty value"
                        )
                        continue
                    reached = True
            if not reached:
                problems.append(
                    f"{t.rel}  never passes {flag} to the {t.kind} composite. "
                    f"`{t.kind}.Run` "
                    f"accepts it, so leaving it out of the template makes the module default "
                    f"the only reachable value: a Dockerfile away from the repository root, "
                    f"or an image for any platform but linux/amd64, cannot be built from "
                    f"this pipeline at all"
                )
    return problems


def check_secret_flags(ts: TemplateSet) -> list[str]:
    """A credential reaches a Dagger flag as `env:NAME`, never as a value."""
    problems = []
    for t in ts.templates:
        for position, step, body in _bash_bodies(t):
            env = step.get("env") if isinstance(step.get("env"), dict) else {}
            for line in _logical_lines(body):
                for match in SECRET_FLAG.finditer(line):
                    flag = match.group(0)
                    tail = line[match.end() :].lstrip()
                    # The flag may sit inside a bash array append, so the token
                    # can carry surrounding quotes and a closing paren:
                    #   extra+=(--npm-token env:NPM_FEED_TOKEN)
                    token = tail.split()[0] if tail else ""
                    env_ref = ENV_SECRET_REF.match(token)
                    if env_ref is None:
                        problems.append(
                            f"{t.rel}  step {position} passes {flag} as "
                            f"{token.rstrip(')') !r} — a credential must be handed to "
                            f"Dagger as `env:NAME` so it never appears on a command line"
                        )
                        continue
                    name = env_ref.group("name")
                    if name not in env:
                        problems.append(
                            f"{t.rel}  step {position} passes {flag} env:{name} but the "
                            f"step's env: mapping does not declare {name} — Dagger would "
                            f"read an unset variable and the secret would be empty"
                        )
    return problems


def check_value_interpolation(ts: TemplateSet) -> list[str]:
    """No consumer-supplied `$(VAR)` macro may be spliced into a bash body."""
    problems = []
    for t in ts.templates:
        for position, step, body in _bash_bodies(t):
            for ref in scan_shell(body):
                if ref.kind != "macro":
                    continue
                if ref.name in TRUSTED_SYSTEM_VARIABLES or ref.name in TEMPLATE_OWNED_INLINE:
                    continue
                # A dotted name is a predefined variable ADO already exports to
                # the step's environment; name that variable rather than "$A.B".
                safe = ref.name.upper().replace(".", "_") if "." in ref.name else ref.name
                problems.append(
                    f"{t.rel}  step {position} splices $({ref.name}) into a bash body. "
                    f"ADO expands macros before the shell parses the line, so quoting "
                    f"does not contain the value: pass it through the step's env: "
                    f'mapping and reference it as "${safe}". (If this was meant as '
                    f"shell command substitution, use the `$(cmd arg)` form or backticks "
                    f"— a single bare word is indistinguishable from an ADO macro.)"
                )
    return problems


def check_shell_quoting(ts: TemplateSet) -> list[str]:
    """Every expansion of an `env:`-provided value must be double-quoted."""
    problems = []
    for t in ts.templates:
        for position, step, body in _bash_bodies(t):
            env = step.get("env") if isinstance(step.get("env"), dict) else {}
            if not env:
                continue
            for ref in scan_shell(body):
                if ref.kind != "expansion" or ref.in_comment:
                    continue
                if ref.name not in env or ref.quoted:
                    continue
                problems.append(
                    f"{t.rel}  step {position} expands ${ref.name} unquoted. It carries a "
                    f'consumer-supplied value, so it must be written "${ref.name}" or '
                    f'"${{{ref.name}:-}}" — otherwise a value with whitespace or a glob '
                    f"splits into several arguments"
                )
    return problems


def check_secret_handling(ts: TemplateSet) -> list[str]:
    """Secrets are not echoed, and written credentials are cleared again."""
    problems = []
    for t in ts.templates:
        writes_credentials = False
        clears_credentials = False
        for position, step, body in _bash_bodies(t):
            env = step.get("env") if isinstance(step.get("env"), dict) else {}
            secret_names = {name for name in env if SECRET_ENV_NAME.search(name)}
            for line in _logical_lines(body):
                bare = line.strip()
                if "~/.git-credentials" in bare or ".git-credentials" in bare:
                    if bare.startswith("rm ") or " rm " in bare:
                        clears_credentials = True
                    else:
                        writes_credentials = True
                if not bare.startswith(("echo ", "printf ")) or "> " in bare:
                    continue
                for name in secret_names:
                    if f"${name}" in bare or f"${{{name}" in bare:
                        problems.append(
                            f"{t.rel}  step {position} echoes ${name} to the pipeline log: "
                            f"{bare!r}"
                        )
        if writes_credentials and not clears_credentials:
            problems.append(
                f"{t.rel}  writes a credential into ~/.git-credentials but never removes "
                f"it. Add a final step that runs `rm -f ~/.git-credentials` with "
                f"`condition: always()`, so a self-hosted agent does not keep the "
                f"credential on disk after the run"
            )
        if clears_credentials:
            for step in t.steps:
                body = step.get("bash")
                if isinstance(body, str) and "rm -f ~/.git-credentials" in body:
                    if step.get("condition") != "always()":
                        problems.append(
                            f"{t.rel}  the credential-clearing step must carry "
                            f"`condition: always()`, or a failing gate leaves the credential "
                            f"on disk"
                        )
    return problems

# The exact banner a template uses to declare, on purpose, that it does not read
# the verdict. Deliberately shouty and deliberately a single fixed string: the
# check below matches it verbatim, so a template can only be fail-open by saying
# so in the one place a reader of the file cannot miss.
FAIL_OPEN_ACK = "THIS PIPELINE DOES NOT GATE"

VERDICT_FILE = "combined-evidence.json"


def _reads_verdict(t: Template) -> bool:
    """True if an ACTIVE step reads `passed` out of the evidence file.

    Only real steps count. A gate shipped commented out is YAML comment text, so
    it never becomes a step and never satisfies this — which is the point: the
    paste-ready snippet the templates carry must not read as a gate that exists.
    Lines commented inside a live bash body are skipped for the same reason.
    """
    for _position, _step, body in _bash_bodies(t):
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if ".passed" in stripped:
                return True
    return False


def check_evidence_verdict(ts: TemplateSet) -> list[str]:
    """Every template either gates on the evidence verdict or admits it does not.

    Both composites are producers: since v1.16.1 they exit 0 on a tripped gate
    exactly as on a clean run, and the verdict lives only in `passed` inside
    combined-evidence.json. A template that never reads it runs the scanners and
    then reports success whatever they found — false assurance, which is worse
    than no scan, and invisible from outside because the build is green either
    way.

    This does not force a gate. An advisory pipeline is a legitimate choice, and
    forcing the gate on here would turn green builds red in every repository
    that copied a template. What it forces is that the choice is WRITTEN DOWN in
    the file that gets copied. Silence is the one state rejected, because silence
    cannot be told apart from an oversight — and it was an oversight, in all four
    templates, from v1.16.1 until CAPS-042.

    The converse is checked too: a template that gates must not still carry the
    banner, or the acknowledgement outlives the gap it described and the file
    lies in the other direction.
    """
    problems = []
    for t in ts.templates:
        gates = _reads_verdict(t)
        admits = FAIL_OPEN_ACK in t.text
        if not gates and not admits:
            problems.append(
                f"{t.rel}  never reads `passed` from {VERDICT_FILE} and does not "
                f"carry the '{FAIL_OPEN_ACK}' banner — the composite exits 0 on a "
                f"tripped gate, so this pipeline reports success whatever it finds. "
                f"Add the verdict read, or declare the gap in the banner"
            )
        if gates and admits:
            problems.append(
                f"{t.rel}  reads `passed` from {VERDICT_FILE} but still carries the "
                f"'{FAIL_OPEN_ACK}' banner — drop the banner, it now describes a gap "
                f"that is closed"
            )
    return problems


# The lanes a merge depends on. check_evidence_verdict accepts a declared
# advisory pipeline because advisory is a legitimate choice — for a scan that
# is not a merge gate. The commit and precommit templates ARE the merge gate on
# Azure DevOps (there is no reusable workflow on that side; the template is the
# pipeline), and both precommit templates shipped for eleven releases with the
# gate step present, correct, and commented out, under a banner that admitted
# it. The banner satisfied the verdict check. Nothing asked whether a starter
# that exists to gate a merge actually does.
#
# DAST is the one template allowed to stay advisory: it runs on its own cadence
# against a running application and is wired into no merge gate by design
# (src/composites/dast). The allowance carries that reason so that a new
# template is a gate until someone writes down why it is not.
ADVISORY_ALLOWED: dict[str, str] = {
    "templates/azure-devops/dast.yml": "DAST runs on its own cadence and is not a merge gate (src/composites/dast)",
}


def check_merge_lanes_gate(ts: TemplateSet) -> list[str]:
    """Every template that is not declared advisory in ADVISORY_ALLOWED gates.

    check_evidence_verdict lets a template choose between a gate and a banner.
    This one removes the choice for the templates whose purpose is to gate a
    merge: a starter copied as "the precommit pipeline" that goes green over
    its own findings is the failure the whole repository exists to prevent,
    and a paste-ready step beside it is documentation, not a gate.
    """
    problems = []
    for t in ts.templates:
        if t.rel in ADVISORY_ALLOWED:
            continue
        if not _reads_verdict(t):
            problems.append(
                f"{t.rel}  is a merge-lane starter and has no active step that reads "
                f"`passed` from {VERDICT_FILE}. A commented-out gate is YAML comment "
                f"text and gates nothing; make the step live, or add the template to "
                f"ADVISORY_ALLOWED with the reason it is not a merge gate"
            )
    return problems


def check_run_collapsing(ts: TemplateSet) -> list[str]:
    """A precommit PR build cancels when superseded; a commit build is never batched.

    Both values are ADO's defaults, so a template that omits them behaves
    correctly today — and reads identically to one that a copy edited to the
    opposite. The check requires them stated. Templates that declare no
    trigger (the shared `extends` templates) leave it to the application
    repository and are not graded here.
    """
    problems = []
    for t in ts.templates:
        if t.kind == "precommit" and "pr" in t.document:
            pr = t.document.get("pr")
            if not isinstance(pr, dict) or pr.get("autoCancel") is not True:
                problems.append(
                    f"{t.rel}  declares `pr:` without `autoCancel: true`. A build for a "
                    f"commit the PR no longer points at keeps running and posts a verdict "
                    f"nobody needs; state autoCancel: true so the copy cannot drift"
                )
        if t.kind == "commit" and "trigger" in t.document:
            trigger = t.document.get("trigger")
            if not isinstance(trigger, dict) or trigger.get("batch") is not False:
                problems.append(
                    f"{t.rel}  declares `trigger:` without `batch: false`. A batched build "
                    f"runs only the newest of the commits pushed while it waited, and the "
                    f"commits in between never get commit-stage evidence"
                )
    return problems


CHECKS = (
    ("templates declared", check_templates_declared),
    ("templates parse", check_templates_parse),
    ("step shape", check_step_shape),
    ("removed surfaces", check_removed_surfaces),
    ("dagger invocations", check_dagger_invocations),
    ("container shape overrides are reachable", check_container_shape_flags),
    ("secret flags", check_secret_flags),
    ("value interpolation", check_value_interpolation),
    ("shell quoting", check_shell_quoting),
    ("secret handling", check_secret_handling),
    ("evidence verdict read or its absence declared", check_evidence_verdict),
    ("merge-lane templates gate", check_merge_lanes_gate),
    ("superseded runs: PR builds cancel, commit builds never batch", check_run_collapsing),
)


def check_all(ts: TemplateSet) -> list[tuple[str, list[str]]]:
    """Run every check. A parse failure suppresses the checks that need a document."""
    return [(name, check(ts)) for name, check in CHECKS]
