#!/usr/bin/env python3
"""Fail when a tracked Go file is not gofmt-clean, or when gofmt could not run.

Reasoning, the scope this deliberately does not cover, and why gofmt rather than
gofumpt: scripts/go_format.py.

    python3 scripts/check-go-format.py                 # audit the tree
    python3 scripts/check-go-format.py --write         # format in place, then audit
    python3 scripts/check-go-format.py --root <dir>    # audit another checkout

Exit 0 clean, 1 unformatted, 2 the question could not be put to gofmt.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from go_format import EXIT_CANNOT_ASK, verdict  # noqa: E402

# gofmt takes a file list; 152 paths is nowhere near ARG_MAX, but the chunk keeps
# a growing repository from turning this into an E2BIG that reads as a run error.
CHUNK = 200


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def find_gofmt() -> Tuple[Optional[str], Optional[str]]:
    """Locate gofmt. GOROOT first: it is the gofmt matching the toolchain in use.

    Returns (path, error). Exactly one is None.
    """
    try:
        proc = subprocess.run(
            ["go", "env", "GOROOT"], capture_output=True, text=True, timeout=60
        )
        if proc.returncode == 0:
            candidate = Path(proc.stdout.strip()) / "bin" / "gofmt"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate), None
    except (OSError, subprocess.SubprocessError) as exc:
        # Not fatal on its own — gofmt may still be on PATH without `go` being.
        pass

    found = shutil.which("gofmt")
    if found:
        return found, None
    return None, "neither `go env GOROOT`/bin/gofmt nor `gofmt` on PATH resolved."


def tracked_go_files(root: Path) -> Tuple[Optional[List[str]], Optional[str]]:
    """List tracked *.go paths. A git failure is an error, never an empty list."""
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", "--", "*.go"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"`git ls-files` could not be run: {exc}"
    if proc.returncode != 0:
        return None, f"`git ls-files` exited {proc.returncode}: {proc.stderr.strip()}"
    return [p for p in proc.stdout.split("\0") if p], None


def run_gofmt(
    gofmt: str, root: Path, files: List[str], write: bool
) -> Tuple[Optional[str], Optional[str]]:
    """Run `gofmt -l` (plus -w when asked). Returns (stdout, error)."""
    flags = ["-l", "-w"] if write else ["-l"]
    out: List[str] = []
    for start in range(0, len(files), CHUNK):
        batch = files[start : start + CHUNK]
        try:
            proc = subprocess.run(
                [gofmt, *flags, *batch],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"gofmt could not be run: {exc}"
        if proc.returncode != 0:
            # A file gofmt cannot parse lands here. Its stdout is then an
            # incomplete answer, so it must not be read as one.
            return None, (
                f"gofmt exited {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}"
            )
        out.append(proc.stdout)
    return "".join(out), None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", default=None, help="repository root (default: this checkout)"
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite unformatted files in place (gofmt -w) and report what changed",
    )
    args = parser.parse_args(argv)

    root = Path(args.root) if args.root else repo_root()
    gofmt, probe_error = find_gofmt()
    if gofmt is None:
        result = verdict(None, [], None, probe_error)
        print("\n".join(result.lines), file=sys.stderr)
        return result.exit_code

    files, list_error = tracked_go_files(root)
    if files is None:
        print(f"cannot list tracked Go files.\n  {list_error}", file=sys.stderr)
        return EXIT_CANNOT_ASK

    listing, run_error = run_gofmt(gofmt, root, files, args.write)
    result = verdict(gofmt, files, listing, run_error)

    if args.write and result.exit_code == 1:
        # -w already fixed them, so the listing is what changed, not what is broken.
        changed = [line for line in result.lines if line.startswith("  ")]
        print(f"gofmt -w rewrote {len(changed)} file(s):")
        print("\n".join(changed))
        return 0

    stream = sys.stdout if result.exit_code == 0 else sys.stderr
    print("\n".join(result.lines), file=stream)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
