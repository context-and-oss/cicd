"""Adapt the pinned workflow rule inside the scan container, never vendor it.

Only the Bash metavariable matcher changes. YAML structural matching and all
upstream metadata come from the runtime checkout under its own licence.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

SOURCE_PATH = "yaml/github-actions/security/gha-curl-pipe-shell.yaml"
SOURCE_ID = "gha-curl-pipe-shell"
RULE_ID = "cicd.yaml.github-actions.security.gha-curl-pipe-shell"
MESSAGE = (
    "Network-delivered bytes become executable input in this workflow. "
    "Separate retrieval from execution, and check the downloaded bytes against "
    "a trusted digest or signature before launching an interpreter."
)
# First-party compatibility matcher: command boundary, downloader, optional
# continued arguments, pipe and interpreter. Keep the established scope rather
# than claiming this is a full shell parser.
SHELL_REGEX = r"(?ms).*(?:^|[\n;])\s*(?:curl|wget)\b[^\n;|]*(?:\\\n[^\n;|]*)*\|\s*(?:bash|sh|python3?|ruby|perl)\b.*"
MODIFIED_NOTICE = (
    "Modified by cicd: the Bash metavariable matcher is replaced with a "
    "parser-safe regex; the finding identity and explanation are changed. "
    "The upstream rule remains under its own licence, not Apache-2.0."
)


def adapt(document):
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError("upstream document must contain a rules array")
    rules = document["rules"]
    if len(rules) != 1 or not isinstance(rules[0], dict):
        raise ValueError("expected exactly one upstream workflow rule")
    rule = copy.deepcopy(rules[0])
    if rule.get("id") != SOURCE_ID or rule.get("languages") != ["yaml"]:
        raise ValueError("unexpected upstream rule identity or language")
    if rule.get("severity") != "ERROR" or not isinstance(rule.get("metadata"), dict):
        raise ValueError("unexpected upstream severity or metadata")
    patterns = rule.get("patterns")
    if not isinstance(patterns, list) or len(patterns) < 2:
        raise ValueError("upstream structural patterns are missing")
    candidates = []
    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, dict):
            raise ValueError("invalid upstream pattern entry")
        if "metavariable-pattern" in pattern:
            node = pattern["metavariable-pattern"]
            if (set(pattern) != {"metavariable-pattern"}
                    or not isinstance(node, dict)
                    or node.get("language") != "bash"
                    or node.get("metavariable") != "$SHELL"
                    or not isinstance(node.get("patterns"), list)
                    or not node["patterns"]):
                raise ValueError("unexpected upstream metavariable matcher")
            candidates.append(index)
    if len(candidates) != 1:
        raise ValueError("expected exactly one Bash metavariable matcher")
    patterns[candidates[0]] = {
        "metavariable-regex": {"metavariable": "$SHELL", "regex": SHELL_REGEX}
    }
    rule["id"] = RULE_ID
    rule["message"] = MESSAGE
    return {"rules": [rule]}


def read_document(raw):
    # JSON is a YAML subset and keeps synthetic host-side unit fixtures free
    # of a new dependency. The existing pinned Semgrep image supplies PyYAML
    # for the real upstream YAML; import failure is a non-run, never a fallback.
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        import yaml
        return yaml.safe_load(raw)


def generate(upstream, output):
    # A failed regeneration must never leave a formerly valid config usable.
    output.unlink(missing_ok=True)
    raw = (upstream / SOURCE_PATH).read_text(encoding="utf-8")
    licence = (upstream / "LICENSE").read_text(encoding="utf-8")
    if "Semgrep Rules License v1.0" not in licence:
        raise ValueError("pinned upstream licence must be reviewed")
    notice_path = upstream / "NOTICE"
    notice = notice_path.read_text(encoding="utf-8") if notice_path.exists() else ""
    adapted = adapt(read_document(raw))
    # Retain the COMPLETE original text, including inline comments and notices,
    # in the runtime copy. Parsing/dumping alone would silently drop comments.
    sections = [MODIFIED_NOTICE, "Upstream LICENSE:\n" + licence]
    if notice:
        sections.append("Upstream NOTICE:\n" + notice)
    sections.append("Unmodified upstream source (retained for notices):\n" + raw)
    header = "\n".join("# " + line for part in sections for line in part.splitlines())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header + "\n" + json.dumps(adapted, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        generate(args.upstream, args.output)
    except Exception:
        # Neither malformed config text nor exception messages need to escape
        # into the scan evidence. Source/adapter failure must fail closed.
        print("workflow rule adaptation failed: pinned source, notices or matcher contract unavailable", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
