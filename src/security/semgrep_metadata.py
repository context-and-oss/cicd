"""Allowlisted finding metadata from the same Semgrep invocation's native JSON.

No matched text, arbitrary metadata, severity or verification status is copied.
Missing or malformed optional metadata must not change findings or the scan gate.
"""
import argparse
import json
from pathlib import Path
import re

PROPERTY = "cicdFindingMetadata"
CATEGORIES = frozenset({"security", "correctness", "maintainability", "style", "unknown"})


def project(metadata):
    if not isinstance(metadata, dict):
        return {}
    result = {}
    category = metadata.get("category")
    if isinstance(category, str) and category.lower() in CATEGORIES:
        result["category"] = category.lower()
    subcategories = metadata.get("subcategory", [])
    if isinstance(subcategories, str):
        subcategories = [subcategories]
    if isinstance(subcategories, list):
        values = sorted({v.lower() for v in subcategories
                         if isinstance(v, str) and v.lower() in {"audit", "vuln"}})
        if values:
            result["subcategories"] = values
    confidence = metadata.get("confidence")
    if isinstance(confidence, str) and confidence.upper() in {"HIGH", "MEDIUM", "LOW"}:
        result["confidence"] = confidence.upper()
    weaknesses = metadata.get("cwe", [])
    if isinstance(weaknesses, str):
        weaknesses = [weaknesses]
    if isinstance(weaknesses, list):
        values = set()
        for value in weaknesses:
            if isinstance(value, str):
                match = re.match(r"^(CWE-[1-9][0-9]*)(?:$|:|\s)", value)
                if match:
                    values.add(match[1])
        if values:
            result["weaknessIds"] = sorted(values)
    if result:
        result["classificationSource"] = "scanner-metadata"
    return result


def enrich_sarif(profile, document):
    """Join by exact rule identity, within this invocation only.

    Conflicting metadata for one identity is unknown, not first/last-writer wins.
    Rule confidence never comes from SARIF's hardcoded precision property.
    """
    by_rule, conflicts = {}, set()
    rows = profile.get("results", []) if isinstance(profile, dict) else []
    if not isinstance(rows, list):
        rows = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("check_id"), str):
            continue
        extra = row.get("extra")
        metadata = project(extra.get("metadata")) if isinstance(extra, dict) else {}
        identity = row["check_id"]
        if identity in by_rule and by_rule[identity] != metadata:
            conflicts.add(identity)
        by_rule[identity] = metadata
    for run in document.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for row in run.get("results", []):
            identity = row.get("ruleId")
            index = row.get("ruleIndex")
            if not identity and type(index) is int and 0 <= index < len(rules):
                identity = rules[index].get("id")
            metadata = dict(by_rule.get(identity, {})) if identity not in conflicts else {}
            metadata["concern"] = "sast"
            properties = row.get("properties")
            if not isinstance(properties, dict):
                properties = row["properties"] = {}
            properties[PROPERTY] = metadata
    return document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--sarif", type=Path, required=True)
    args = parser.parse_args()
    try:
        profile = json.loads(args.json.read_text())
        document = enrich_sarif(profile, json.loads(args.sarif.read_text()))
        staged = args.sarif.with_name(args.sarif.name + ".metadata")
        staged.write_text(json.dumps(document))
        staged.replace(args.sarif)
    except Exception:
        # Optional enrichment: keep the original report. Exceptions can quote
        # source text; never print them or export the native JSON wholesale.
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
