"""Copy a fixture tree, restoring every `*.fixture` file's real name.

Fixtures that a repository walker would otherwise act on — buildable projects,
GitHub Actions workflows, a .gitignore, a zizmor.yml — are stored with a
`.fixture` suffix, so nothing that scans or builds this repository treats them
as its own. A smoke materialises one in a temporary directory and points the
scanner under test at that copy.

Usage: python3 -I scripts/smoke/materialise-fixtures.py <source> <target>
"""

from pathlib import Path
import shutil
import sys


def materialise(source: Path, target: Path) -> int:
    copied = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if relative.name.endswith(".fixture"):
            relative = relative.with_name(relative.name[: -len(".fixture")])
        output = target / relative
        if output.exists():
            raise SystemExit(f"two fixture files materialise to {relative}")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, output)
        copied += 1
    if copied == 0:
        raise SystemExit(f"no fixture files under {source}")
    return copied


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    materialise(Path(sys.argv[1]), Path(sys.argv[2]))
