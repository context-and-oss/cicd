#!/usr/bin/env python3
"""Write the intent artifact for a release pin bump.

Every change to `main` in this repository must carry an intent artifact — the
gate in `src/cross-cutting/intent` rejects a diff that touches none. A release
pin bump is a change to `main` like any other, so it needs one too.

The alternative was to widen the gate's one machine-origin exemption
(`dependabotActionsPin`) to cover the release identity. That was rejected when
v1.11.0 shipped and it is rejected here for the same reason: it would hand the
identity that can write to `.github/workflows/` a documented way past the gate,
and that trust decision would be made where nobody is looking for it. Generating
a real artifact costs one file and leaves the reasoning in the tree.

The prose is fixed, so it is honest about being machine-written and points at the
human document for the reasoning it cannot restate. The file list is read from the
actual bump rather than assumed, which is also what satisfies the gate's
`refs-infer-coupling` rule — an artifact naming paths that are not in the diff is
an artifact describing some other change.

Usage:
  python3 scripts/ci/write-release-intent.py 1.12.0 --changed-from <file> \
      --source cd.yml [--out <path>]

--changed-from names a file holding one changed path per line, which is how the
caller passes `git diff --name-only` without argv limits or quoting games.
Prints the artifact path it wrote.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Dict, List, Sequence

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

# The human document this artifact defers to for the reasoning it does not
# restate. Asserted to exist by the caller's test, not just referenced.
HUMAN_SPEC = "specs/release-by-pull-request.md"

# Ordered: the first group whose prefix matches wins, so the fallback is last.
GROUPS = [
    ("Workflow pins", (".github/workflows/",)),
    ("GitHub Actions templates", ("templates/github-actions/",)),
    ("Azure DevOps templates", ("templates/azure-devops/",)),
    ("Local templates", ("templates/local/",)),
    ("Module and repository docs", ("src/", "docs/", "README.md", "CLAUDE.md")),
]
FALLBACK_GROUP = "Other managed pins"


ARTIFACT = "specs/release-latest.md"


def artifact_path(version: str) -> str:
    """One fixed artifact, overwritten by every release.

    The intent gate counts a modified file as a changed path
    (src/cross-cutting/intent/extract.go), so an overwrite satisfies the
    presence rule as well as a new file would. A file per release was the first
    shape, and it left seventy-six machine-written stubs in `specs/` that said
    the same thing with a different number, each one indistinguishable from a
    human spec in a listing. The history of what each release changed is in
    git, in the pull request body and in the release notes git-cliff writes;
    the artifact's job is only to put the rationale in front of the gate.

    Two concurrent release runs would both rewrite this file and the second
    would conflict — which they already do on every pin they bump, and which
    `deliver-release-pins.sh` reports as `superseded` rather than retrying.

    The version argument is kept so the caller's signature does not change;
    the path does not depend on it.
    """
    del version
    return ARTIFACT


def group_changed(changed: Sequence[str]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for path in changed:
        label = FALLBACK_GROUP
        for name, prefixes in GROUPS:
            if any(path.startswith(prefix) for prefix in prefixes):
                label = name
                break
        grouped.setdefault(label, []).append(path)
    for paths in grouped.values():
        paths.sort()
    return grouped


def render(version: str, changed: Sequence[str], source: str) -> str:
    """Build the artifact.

    Every rule the gate applies is satisfied deliberately, not by luck: causal
    language ("because", "rather than"), no placeholder tokens, well over the
    30-word floor, no unmeasurable qualifiers, and at least one named path that is
    genuinely in the diff — every path below comes from the bump itself.
    """
    if not changed:
        raise ValueError(
            "no changed files: an artifact must describe a real bump, and an "
            "empty one would claim a change that did not happen"
        )

    grouped = group_changed(changed)
    lines = [
        "# Intent: bump version pins to v{}".format(version),
        "",
        "## Why",
        "",
        "This release bumps every managed version pin in this repository from the",
        "previous tag to `v{}`. The version is not chosen by hand:".format(version),
        "`git cliff --bumped-version` derives it from the conventional-commit history",
        "on `main`, and the release run fails rather than guessing when git-cliff",
        "cannot answer.",
        "",
        "The bump arrives as a pull request because release changes must satisfy",
        "the destination's effective pull-request, status-check and review policy.",
        "A direct workflow push does not establish those requirements or prove that",
        "they were satisfied. The delivery design and its verification boundary are",
        "written up in",
        # Root-relative, so the link survives --out putting this artifact
        # somewhere other than specs/.
        "[`{}`](/{}), which is the".format(HUMAN_SPEC, HUMAN_SPEC),
        "document to read for the reasoning this file does not restate.",
        "",
        "This artifact exists because the intent gate requires one for every change",
        "to `main`, and a release is a change to `main`. Widening the gate's",
        "machine-origin exemption to cover the release identity was rejected: it",
        "would hand the identity that can write to `.github/workflows/` a way past",
        "the gate, which is a larger trust decision than a pin bump warrants.",
        "",
        "## What changed",
        "",
        "Version pins only — {} file(s) carrying a pin, plus this artifact. No".format(
            len(changed)
        ),
        "source, module contract or workflow logic. The set is derived from the",
        "defended inventory in",
        "`scripts/repo-inventory.json` by `scripts/_pin_targets.py`, which is shared",
        "with the coherence gate so the bumper and the guard cannot drift apart.",
        "",
    ]

    for name, _ in GROUPS + [(FALLBACK_GROUP, ())]:
        paths = grouped.get(name)
        if not paths:
            continue
        lines.append("**{}**".format(name))
        lines.append("")
        for path in paths:
            lines.append("- `{}`".format(path))
        lines.append("")

    lines += [
        "## Proof",
        "",
        "Written and delivered by `{}` through".format(source),
        "`scripts/ci/deliver-release-pins.sh`, which refuses to open this pull",
        "request unless every step below succeeded first:",
        "",
        "- `python3 scripts/bump-version.py {}` and the same command with".format(version),
        "  `--scope workflows`, so consumer-facing pins and workflow pins move",
        "  together. The workflow scope is separate because GitHub refuses a push",
        "  touching `.github/workflows/` unless the credential carries the",
        "  `workflow` scope, which no `permissions:` key can grant.",
        "- `python3 scripts/check-workflow-pins.py` — the release-blocking coherence",
        "  gate. It is what caught the historical `commit-archive@v1.0.0` skew,",
        "  where a pin advanced past a command that no longer existed. It runs",
        "  against the live tip of `main`, so a merge landing during the release",
        "  cannot slip past it.",
        "- the bump is re-derived against the live tip on each attempt rather than",
        "  rebased from a stale tree, so newly merged pinned content is bumped too.",
        "",
        "## Decisions",
        "",
        "**This file is machine-written.** The prose is a fixed template in",
        "`scripts/ci/write-release-intent.py`; only the version and the file list",
        "above vary, and the file list is read from the bump that actually happened",
        "rather than assumed. Nothing here is a human's judgement about this",
        "release — the judgement is in the commits being released and in the gates",
        "that ran before this pull request opened.",
        "",
        "**The tag is cut after this merges, not here.** Once this lands, CI runs on",
        "`main`, the release run finds the pins already at `v{}`, and cuts the".format(version),
        "tag and the GitHub release with notes generated by git-cliff. So a merged",
        "pin bump with no tag means the run that should have tagged did not — the",
        "scheduled detector in `scripts/release_drift.py` reports that state rather",
        "than letting it pass as a repository with nothing to release.",
        "",
        "## Known residue",
        "",
        "This template does not know whether a human reviewed this pull request.",
        "Required approvals and other effective branch requirements must be",
        "satisfied under the destination's chosen policy. The release preflight",
        "checks its configured prerequisites; bypass eligibility and an armed",
        "auto-merge request neither supply approval nor prove a merge occurred.",
        "The automated checks listed above are not a substitute for required review.",
        "",
    ]
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a release pin bump's intent artifact.")
    parser.add_argument("version", help="release version, semver without a leading v")
    parser.add_argument(
        "--changed-from",
        required=True,
        help="file holding one changed path per line (e.g. from git diff --name-only)",
    )
    parser.add_argument("--source", default="cd.yml", help="workflow delivering this release")
    parser.add_argument("--out", default=None, help="override the artifact path")
    parser.add_argument(
        "--root", default=None, help="repository root (default: this checkout)"
    )
    args = parser.parse_args(argv)

    if not SEMVER.match(args.version):
        print(
            "ERROR: {!r} is not semver X.Y.Z".format(args.version), file=sys.stderr
        )
        return 2

    root = (
        pathlib.Path(args.root)
        if args.root
        else pathlib.Path(__file__).resolve().parents[2]
    )
    listing = pathlib.Path(args.changed_from)
    if not listing.is_file():
        print("ERROR: no such file: {}".format(listing), file=sys.stderr)
        return 2

    changed = [line.strip() for line in listing.read_text().splitlines() if line.strip()]
    rel = args.out or artifact_path(args.version)

    try:
        body = render(args.version, changed, args.source)
    except ValueError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1

    out = root / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    print(rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
