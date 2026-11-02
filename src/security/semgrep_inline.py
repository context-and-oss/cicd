"""Inline JavaScript adapter for the pinned Semgrep image (stdlib, plus its PyYAML).

Never execute consumer code. Inputs come from Semgrep's original selected-file
inventory, not a second filesystem walk that could bypass its ignore rules.
Offsets are UTF-8 bytes internally and UTF-16 columns in the exported SARIF.
"""
import argparse
import bisect
import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote, unquote, urlparse

DOM_ID = "cicd-rules.cicd.javascript.dom-text-to-html"
JS_TYPES = frozenset({
    "", "application/ecmascript", "application/javascript",
    "application/x-ecmascript", "application/x-javascript", "text/ecmascript",
    "text/javascript", "text/javascript1.0", "text/javascript1.1",
    "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
    "text/javascript1.5", "text/jscript", "text/livescript",
    "text/x-ecmascript", "text/x-javascript",
})


class InlineError(Exception):
    """Messages are authored here, never copied from consumer source/stderr."""


class Scripts(HTMLParser):
    # HTMLParser otherwise treats fake tags in textarea/title as markup.
    CDATA_CONTENT_ELEMENTS = (
        "script", "style", "textarea", "title", "xmp", "iframe", "noembed",
        "noframes", "noscript",
    )

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.lines = [0] + [m.end() for m in re.finditer("\n", text)]
        self.active = None
        self.blocks = []
        self.issues = set()
        self.templates = 0
        self.foreign = 0
        self.plaintext = False
        self.last_char = 0
        self.last_byte = 0

    def byte_offset(self, index):
        self.last_byte += len(self.text[self.last_char:index].encode("utf-8"))
        self.last_char = index
        return self.last_byte

    def char_offset(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        if self.plaintext:
            return
        if tag == "plaintext":
            self.plaintext = True
        if tag == "template":
            self.templates += 1
        if tag in {"svg", "math"}:
            self.foreign += 1
        if tag != "script":
            return
        if self.foreign:
            self.issues.add("scripts in foreign SVG/MathML content are not analysed")
            return
        attributes = {}
        for key, value in attrs:
            attributes.setdefault(key, value or "")  # Browser keeps first duplicate.
        if "src" in attributes:
            return  # Its body is not executed. Local JS files get the ordinary scan.
        typ = attributes.get("type", "").strip(" \t\r\n\f")
        if "type" not in attributes and attributes.get("language"):
            typ = "text/" + attributes["language"]
        module = typ == "module"
        if not module and typ.lower() not in JS_TYPES:
            return  # Inert data/import-map/template block, not JavaScript.
        self.active = (self.char_offset() + len(self.get_starttag_text()), module or bool(self.templates))

    def handle_startendtag(self, tag, attrs):
        if tag == "script":
            self.issues.add("self-closing script markup is not analysed")
        elif tag in self.CDATA_CONTENT_ELEMENTS:
            self.handle_starttag(tag, attrs)
            self.set_cdata_mode(tag)  # In HTML, the self-closing slash is ignored.
        elif tag == "template":
            self.handle_starttag(tag, attrs)
        elif tag not in {"svg", "math"}:
            self.handle_starttag(tag, attrs)
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.plaintext:
            return
        if tag == "template":
            self.templates = max(0, self.templates - 1)
        if tag in {"svg", "math"}:
            self.foreign = max(0, self.foreign - 1)
        if tag != "script" or self.active is None:
            return
        start, module = self.active
        body = self.text[start:self.char_offset()]
        if "<!--" in body and re.search(r"<script\b", body, re.I):
            self.issues.add("escaped/nested HTML script states are not analysed")
        elif body.strip():
            self.blocks.append((self.byte_offset(start), body.encode("utf-8"), module))
        self.active = None

    def extract(self):
        self.feed(self.text)
        self.close()
        if self.active is not None:
            self.issues.add("unterminated script is not analysed")
        return self.blocks


class SourceMap:
    def __init__(self, original, source, blocks, source_lines=None):
        self.original, self.source = original, source
        self.segments, chunks, size = [], [], 0
        for start, body, _ in blocks:
            self.segments.append((size, size + len(body), start))
            chunks.extend([body, b"\n;\n"])  # Separate // comments and statements.
            size += len(body) + 3
        self.generated = b"".join(chunks)
        self.lines = [0] + [m.end() for m in re.finditer(b"\n", self.generated)]
        self.source_lines = source_lines if source_lines is not None else [0] + [m.end() for m in re.finditer(b"\n", source)]
        self.starts = [segment[0] for segment in self.segments]

    def original_offset(self, offset):
        index = bisect.bisect_right(self.starts, offset) - 1
        if index >= 0:
            start, end, original = self.segments[index]
            if offset <= end:
                return original + offset - start
        raise InlineError("inline result points outside an extracted script")

    def position(self, offset):
        original = self.original_offset(offset)
        line = bisect.bisect_right(self.source_lines, original)
        text = self.source[self.source_lines[line - 1]:original].decode("utf-8")
        return line, len(text.encode("utf-16-le")) // 2 + 1

    def region(self, region):
        # Semgrep's pinned SARIF emitter uses byte columns; converting through
        # offsets avoids guessing about non-ASCII source or a same-line tag.
        for prefix in ("start", "end"):
            line_key, col_key = prefix + "Line", prefix + "Column"
            if line_key not in region:
                continue
            line = region[line_key]
            column = region.get(col_key, 1)
            if not 1 <= line <= len(self.lines) or column < 1:
                raise InlineError("inline result has an invalid source location")
            offset = self.lines[line - 1] + column - 1
            region[line_key], region[col_key] = self.position(offset)
        # These optional offsets would otherwise still describe the synthetic file.
        for key in ("byteOffset", "byteLength", "charOffset", "charLength"):
            region.pop(key, None)


def extract(selected, root, output):
    maps, warnings = {}, []
    root = root.resolve()
    for relative in selected:
        if Path(relative).suffix.lower() not in {".html", ".htm"}:
            continue
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise InlineError("selected HTML path escapes the source root")
        source = path.read_bytes()
        try:
            parser = Scripts(source.decode("utf-8"))
            blocks = parser.extract()
        except UnicodeDecodeError:
            warnings.append("semgrep: PARTIAL INLINE SCAN — " + json.dumps(relative) + ": non-UTF-8 HTML is not analysed")
            continue
        for issue in sorted(parser.issues):
            warnings.append("semgrep: PARTIAL INLINE SCAN — " + json.dumps(relative) + ": " + issue)
        source_lines = [0] + [m.end() for m in re.finditer(b"\n", source)]
        groups = [[b for b in blocks if not b[2]]]
        groups.extend([[b] for b in blocks if b[2]])  # Modules/template scripts stay independent.
        for group in groups:
            if not group:
                continue
            name = f"inline-{len(maps):04}.js"
            mapping = SourceMap(relative, source, group, source_lines)
            (output / name).write_bytes(mapping.generated)
            maps[name] = mapping
    return maps, warnings


def rules_for_inline(plan, pack_root, dom_path):
    import yaml  # Already part of the digest-pinned Semgrep image; never consumer code.

    floor, rules = set(plan["floor"]), []
    for relative in plan["files"]:
        if not relative.startswith(("javascript/", "typescript/")):
            continue
        prefix = relative.rsplit(".", 1)[0].replace("/", ".") + "."
        for rule in yaml.safe_load((pack_root / relative).read_text())["rules"]:
            identifier = prefix + rule["id"]
            if identifier.lower() not in floor:
                continue
            if not set(rule.get("languages", [])) & {"javascript", "typescript", "js", "ts"}:
                continue
            if rule.get("paths"):
                raise InlineError("pinned inline rule has path restrictions that need an explicit mapping")
            rule["id"] = identifier
            rules.append(rule)
    dom = yaml.safe_load(dom_path.read_text())["rules"][0]
    dom["id"] = DOM_ID
    rules.append(dom)
    if DOM_ID not in floor:
        raise InlineError("inline DOM rule is absent from the defended membership")
    expected = {identifier for identifier in floor if identifier.startswith(("javascript.", "typescript."))}
    if expected != {rule["id"].lower() for rule in rules if rule["id"] != DOM_ID}:
        raise InlineError("pinned JavaScript/TypeScript membership changed; inline selection needs review")
    return rules


def remap_sarif(document, maps, original_bases):
    def mapping_for(uri):
        path = unquote(urlparse(uri).path)
        return maps.get(Path(path).name)

    indices = {}

    def artifact_mapping(artifact):
        return mapping_for(artifact.get("uri", "")) or indices.get(artifact.get("index"))

    def walk(value):
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, dict):
            physical = value.get("physicalLocation")
            if isinstance(physical, dict):
                artifact = physical.get("artifactLocation", {})
                mapping = artifact_mapping(artifact)
                if mapping:
                    if "region" in physical:
                        mapping.region(physical["region"])
                    # Optional context may include generated separators; it is
                    # not a finding location and its source text is withheld.
                    physical.pop("contextRegion", None)
            # All locations, including code-flow/related locations and artifact
            # catalogues, use the original URI. No temporary filename is exported.
            artifact = value.get("artifactLocation")
            if isinstance(artifact, dict):
                mapping = artifact_mapping(artifact)
                if mapping:
                    artifact.update(uri=quote(mapping.original, safe="/"), uriBaseId="%SRCROOT%")
            if "uri" in value:
                mapping = mapping_for(value["uri"])
                if mapping:
                    value.update(uri=quote(mapping.original, safe="/"), uriBaseId="%SRCROOT%")
            for child in value.values():
                walk(child)

    pattern = re.compile(r"(?:(?:file://)?[\w./%+-]*/)?(inline-\d+\.js)(?::(\d+))?")

    def notification(match):
        mapping = maps.get(match[1])
        if not mapping:
            raise InlineError("notification names an unknown extracted script")
        suffix = ""
        if match[2]:
            line = int(match[2])
            if not 1 <= line <= len(mapping.lines):
                raise InlineError("notification has an invalid extracted line")
            offset = mapping.lines[line - 1]
            # A parser may point at the separator between two classic scripts.
            for start, end, _ in mapping.segments:
                if offset <= end:
                    offset = max(offset, start)
                    break
            suffix = ":" + str(mapping.position(offset)[0])
        return mapping.original + suffix

    for run in document["runs"]:
        indices = {index: mapping_for(artifact.get("location", {}).get("uri", ""))
                   for index, artifact in enumerate(run.get("artifacts", []))}
        for artifact in run.get("artifacts", []):
            artifact.pop("contents", None)
        walk(run)
        run["columnKind"] = "utf16CodeUnits"
        run["originalUriBaseIds"] = copy.deepcopy(original_bases)
        run["automationDetails"] = {"id": "semgrep-inline-javascript"}
        for invocation in run.get("invocations", []):
            invocation.pop("workingDirectory", None)
            for note in invocation.get("toolExecutionNotifications", []):
                message = note.get("message", {})
                if "text" in message:
                    text = message["text"]
                    first, last = text.find("`"), text.rfind("`")
                    if first >= 0 and last > first:
                        text = text[:first] + "[source withheld]" + text[last + 1:]
                    message["text"] = pattern.sub(notification, text)
    return document


def analyse(plan_path, source_root, report_path, sarif_path, warnings_path):
    plan = json.loads(plan_path.read_text())
    original_json = json.loads(report_path.read_text())
    selected = original_json["paths"]["scanned"]
    if not isinstance(selected, list) or not all(isinstance(p, str) for p in selected):
        raise InlineError("original scan did not supply a selected-file inventory")
    original = json.loads(sarif_path.read_text())
    if not isinstance(original.get("runs"), list) or not original["runs"]:
        raise InlineError("original scan did not supply a SARIF run")
    warnings = []
    with tempfile.TemporaryDirectory(prefix="cicd-inline-") as temporary:
        work = Path(temporary)
        scripts = work / "scripts"
        scripts.mkdir()
        maps, warnings = extract(selected, source_root, scripts)
        if maps:
            rules = rules_for_inline(plan, Path("/cicd-semgrep-pack/src"), Path("/cicd-rules/dom-text-to-html.yml"))
            config = work / "rules.json"
            config.write_text(json.dumps({"rules": rules}))
            with (work / "stderr").open("wb") as stderr:
                result = subprocess.run([
                    "semgrep", "scan", "--no-rewrite-rule-ids", "--metrics=off",
                    "--config", str(config), "--json-output", str(work / "report.json"),
                    "--sarif-output", str(work / "report.sarif"), "scripts",
                ], cwd=work, stdout=subprocess.DEVNULL, stderr=stderr, timeout=300)
            if result.returncode not in (0, 1):
                raise InlineError("inline JavaScript scanner did not complete")
            scanned = json.loads((work / "report.json").read_text())["paths"]["scanned"]
            if {Path(p).name for p in scanned} != set(maps):
                raise InlineError("inline JavaScript scanner omitted an extracted input")
            inline = json.loads((work / "report.sarif").read_text())
            if not inline.get("runs"):
                raise InlineError("inline JavaScript scanner produced no SARIF run")
            loaded = {r["id"].lower() for run in inline["runs"] for r in run["tool"]["driver"]["rules"]}
            if not {r["id"].lower() for r in rules} <= loaded:
                raise InlineError("inline JavaScript scanner did not load its selected rules")
            bases = original["runs"][0].get("originalUriBaseIds", {})
            original["runs"].extend(remap_sarif(inline, maps, bases)["runs"])
            files = len({mapping.original for mapping in maps.values()})
            warnings.append(f"semgrep: INLINE JAVASCRIPT — analysed {len(maps)} script scope(s) in {files} HTML file(s) with selected pinned JavaScript/TypeScript rules and cicd's DOM rule; custom/live rules and event-handler attributes are not included")
    # Publish only after the complete inline pass and all location mapping succeed.
    warnings_path.write_text(json.dumps(warnings))
    staged = sarif_path.with_name(sarif_path.name + ".inline")
    staged.write_text(json.dumps(original))
    staged.replace(sarif_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--warnings", type=Path, required=True)
    args = parser.parse_args()
    try:
        analyse(args.plan, args.source, args.json, args.sarif, args.warnings)
    except Exception as exc:
        # A decoder/parser/OS exception can quote consumer code. Never print it.
        detail = str(exc) if isinstance(exc, InlineError) else type(exc).__name__
        print("semgrep: inline JavaScript analysis failed: " + detail, file=sys.stderr)
        return 125
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
