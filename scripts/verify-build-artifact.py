#!/usr/bin/env python3
"""Verify a downloaded cicd bundle before importing or deploying its payload.

Download by immutable artifact ID from a trusted producing run first. Checksums
bind the bundle's contents; they do not authenticate its publisher.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or non-regular bundle file: {path.name}")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_object(path: Path) -> dict:
    digest(path)  # Refuse symlinks and missing files before reading metadata.
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be a JSON object")
    return value


def verify(bundle: Path, *, repo: str, commit: str, branch: str, run_url: str, app_id: str = "") -> Path:
    manifest = read_object(bundle / "artifact-manifest.json")
    if manifest.get("schemaVersion") != "1.0" or manifest.get("passed") is not True:
        raise ValueError("unsupported manifest or artifact gate did not pass")
    provenance = manifest.get("repo")
    if not isinstance(provenance, dict):
        raise ValueError("missing artifact provenance")
    for key, expected in (("repoUrl", repo), ("commitSha", commit), ("branch", branch), ("appId", app_id)):
        if provenance.get(key, "") != expected:
            raise ValueError(f"artifact provenance mismatch: {key}")
    if not repo or not commit or not run_url or manifest.get("runUrl") != run_url:
        raise ValueError("artifact producing run does not match")
    evidence_path = bundle / "combined-evidence.json"
    if digest(evidence_path) != manifest.get("evidenceSha256"):
        raise ValueError("evidence checksum mismatch")
    evidence = read_object(evidence_path)
    if evidence.get("passed") is not True or evidence.get("repo") != provenance:
        raise ValueError("evidence verdict or provenance does not match")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict):
        raise ValueError("expected exactly one deployable artifact")
    entry = artifacts[0]
    if (entry.get("kind"), entry.get("path")) not in (("archive", "application.tar.gz"), ("container", "image.tar")):
        raise ValueError("invalid artifact kind or transport path")
    payload = bundle / entry["path"]
    if digest(payload) != entry.get("sha256"):
        raise ValueError("payload checksum mismatch")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    for arg in ("repo", "commit", "branch", "run-url"):
        parser.add_argument("--" + arg, required=True)
    parser.add_argument("--app-id", default="")
    args = parser.parse_args()
    try:
        payload = verify(args.bundle, repo=args.repo, commit=args.commit, branch=args.branch,
                         run_url=args.run_url, app_id=args.app_id)
    except (ValueError, OSError) as exc:
        print(f"artifact verification failed: {exc}", file=sys.stderr)
        return 1
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
