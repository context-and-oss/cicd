"""Refuse a release whose bump kind disagrees with the history it ships.

`cd.yml` asks `git cliff --bumped-version` what to tag, and asks
`git cliff --unreleased` what to write in the release notes. Those are two
different questions to the same binary, and **cliff answers them over two
different partitions of history**.

`--unreleased` partitions by reachability: the commits after the newest tag that
HEAD can reach. The bare bump computation partitions by *commit date*: cliff walks
history chronologically and cuts at tag boundaries. A commit authored on a branch
that was open across a release therefore lands in a release that already shipped,
because its commit date precedes that release's tag commit — even though no tag
reaches it.

Measured on git-cliff 2.13.1 (the version .github/actions/install-git-cliff pins),
this repository's cliff.toml, at the two commits CD actually checked out:

    CD ran at            base       --bumped-version   + --unreleased   correct
    tag v1.14.2          v1.14.1    v1.14.2  WRONG     v1.15.0          minor
    tag v1.14.3          v1.14.2    v1.14.3  WRONG     v1.15.0          minor
    later (no feat)      v1.14.2    v1.14.3            v1.14.3          patch

`git cliff --context` at the v1.14.3 commit shows where the feature went: filed under
release **v1.14.1**, which had already shipped, alongside the other feat that
v1.14.2 mis-tagged. The unreleased bucket held only a fix and a docs commit, so
the bump was a patch. Both features are behind their tags permanently; no later
`--bumped-version` can ever bump minor for them.

So the flag closes the known cause. This module exists for the next cause, because
the flag alone leaves the question unasked. **A feature released as a patch reads
exactly like a release that shipped no features**: the tag is well-formed, the
release notes are complete (they came from `--unreleased`, which saw the feature),
CI passed on every commit, and `release-drift.yml` compares the newest tag against
the same cliff that dropped the commit, so both sides of its comparison agree.
Only the ordering of a tag against its own history separates the two states, and
nothing was asking about it.

The comparison here is deliberately **not** a re-implementation of cliff. It
derives the bump the range requires from `git log`, whose range is reachability-
based, and fails the release when cliff's answer differs. That is independent on
exactly the axis that broke: two computations that disagree about which commits
are in the release cannot both be right, and the release stops rather than tagging.

Reading the rendered notes for a `### Features` heading was rejected as the
comparison: cliff.toml sets `header = ""` and the body template emits no version
heading, so the notes carry group names only — and a group name is a label
`commit_parsers` derived from the same commit. Asking about the label is asking
cliff twice.

The classification below matches cliff's measured behaviour, so it produces no
false failures on histories cliff gets right (base v1.0.0, one commit, this
repository's cliff.toml):

    feat: x                          v1.1.0    minor
    fix: x / docs: / refactor: /
      perf: / revert: / build: x     v1.0.1    patch
    chore: / ci: / test: / style: x  v1.0.0    nothing to release
    fix!: x / feat!: x               v2.0.0    major
    chore!: x / ci!: x               v2.0.0    major   (! beats skip)
    fix: x  + BREAKING CHANGE body   v2.0.0    major
    chore: x + BREAKING CHANGE body  v1.0.0    NOTHING  <-- see below
    FEAT: x / Feat(s): x             v1.1.0    minor   (type match ignores case)
    Chore: x / CHORE: x              v1.0.1    patch   <-- and this one does not

The last two rows are an asymmetry, not a typo. cliff recognises the conventional
*type* case-insensitively, but `commit_parsers` entries are plain case-sensitive
regexes, so `^chore` does not match `Chore:` and a capitalised chore releases a
patch. `classify_commit` therefore lowercases the type for the `feat` test and
matches the skip patterns against the subject verbatim — lowercasing first would
suppress a release cliff does perform.

Note the chore-plus-footer row, which is why `classify_commit` reports a defect rather than a
kind. A `chore:`-typed commit carrying a `BREAKING CHANGE` footer is removed by
cliff's `skip = true` parser *before* the footer is read, so the breaking change
releases nothing at all. That is the same class of silence as this module's
subject, one type further along, and it is always a real defect when it occurs —
the remedy is to put the `!` in the subject, where the first parser sees it.

At pre-1.0 versions cliff bumps the same way (v0.1.0 + `feat:` -> v0.2.0,
v0.1.0 + `fix!:` -> v1.0.0), so no special case is needed for a 0.x major.

Pure logic only: no git, no subprocess, no clock, no file reads.
`scripts/check-release-bump.py` supplies the commits and the skip patterns, and
`scripts/tests/test_release_bump.py` drives every branch here directly.
"""

from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

# Conventional Commits 1.0.0 §1: `<type>[optional scope][!]: <description>`.
# Type is letters only, matching cliff's own parsers (`^[A-Za-z]+`).
CONVENTIONAL = re.compile(r"^(?P<type>[A-Za-z]+)(?:\((?P<scope>[^()]*)\))?(?P<bang>!)?:\s")

# Conventional Commits 1.0.0 §16 allows BREAKING-CHANGE as a synonym in a footer.
BREAKING_FOOTER = re.compile(r"(?m)^BREAKING[ -]CHANGE\s*:")

MAJOR = "major"
MINOR = "minor"
PATCH = "patch"

# Higher wins when a range mixes kinds.
RANK: Dict[str, int] = {PATCH: 1, MINOR: 2, MAJOR: 3}

SEMVER = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")

# What `observed_bump` reports when the two versions are equal: no release.
NONE = "none"
# What it reports when the step from one to the other is not a single semver bump.
IRREGULAR = "irregular"

SKIP_DEFECT = (
    "declares a BREAKING CHANGE footer under a commit type cliff skips, so the "
    "breaking change releases nothing at all. Put the `!` in the subject "
    "(`{type}!: …`) — cliff's `skip = true` parser removes the commit before it "
    "reads the footer, but the breaking-subject parser runs first"
)


class Commit(NamedTuple):
    """One commit in the range under release."""

    sha: str
    subject: str
    body: str = ""

    @property
    def short(self) -> str:
        return self.sha[:8]


class Contribution(NamedTuple):
    """What one commit requires of the version, and why."""

    commit: Commit
    kind: Optional[str]  # None: contributes nothing to the version
    reason: str
    defect: Optional[str] = None  # a declaration cliff will silently ignore


def commit_type(subject: str) -> Optional[str]:
    """The conventional type of subject, lowercased, or None if it does not parse."""
    match = CONVENTIONAL.match(subject)
    if match is None:
        return None
    return match.group("type").lower()


def classify_commit(commit: Commit, skip_patterns: Sequence[str]) -> Contribution:
    """What this one commit requires of the next version.

    Precedence follows cliff.toml's parser order, which is also what the measured
    table in this module's docstring shows: the breaking-subject parser is listed
    first and therefore beats `skip = true`, and a skipped type is removed before
    its body is examined.

    skip_patterns are cliff.toml's own `skip = true` message regexes, passed
    through rather than translated into a list of type names. Matching the regex
    the way cliff matches it keeps the two from drifting when a type is added to
    that rule, and it reproduces the prefix behaviour exactly: `^ci` matches
    `citizen: x` for cliff, so it matches it here.
    """
    match = CONVENTIONAL.match(commit.subject)
    if match is None:
        # An unparseable subject contributes nothing, which is exactly what cliff
        # does with it under `filter_unconventional = true`. Refusing it is
        # scripts/check-commit-subjects.py's job, on the pull request, where it is
        # still cheap to amend; duplicating that verdict here would fail every
        # release over the merge commits every release in this history carries.
        return Contribution(commit, None, "not a conventional commit — contributes nothing")

    ctype = match.group("type").lower()

    if match.group("bang"):
        return Contribution(commit, MAJOR, "`!` in the subject declares a breaking change")

    if any(re.search(pattern, commit.subject) for pattern in skip_patterns):
        if BREAKING_FOOTER.search(commit.body):
            return Contribution(
                commit,
                None,
                "type `{}` is skipped by cliff.toml".format(ctype),
                defect=SKIP_DEFECT.format(type=ctype),
            )
        return Contribution(
            commit, None, "type `{}` is skipped by cliff.toml".format(ctype)
        )

    if BREAKING_FOOTER.search(commit.body):
        return Contribution(commit, MAJOR, "a BREAKING CHANGE footer in the body")

    if ctype == "feat":
        return Contribution(commit, MINOR, "type `feat` adds functionality")

    return Contribution(commit, PATCH, "type `{}` releases a patch".format(ctype))


def classify(
    commits: Sequence[Commit], skip_patterns: Sequence[str]
) -> List[Contribution]:
    return [classify_commit(c, skip_patterns) for c in commits]


def required_bump(contributions: Sequence[Contribution]) -> Optional[str]:
    """The highest bump the range requires, or None when nothing in it releases."""
    kinds = [c.kind for c in contributions if c.kind is not None]
    if not kinds:
        return None
    return max(kinds, key=lambda k: RANK[k])


def observed_bump(current: str, next_version: str) -> Optional[str]:
    """Classify the step from current to next_version.

    Returns one of major/minor/patch, NONE when they are equal, IRREGULAR when the
    step is not a single semver increment, or None when either version is not
    semver at all. A jump of two minors is IRREGULAR rather than "minor": it is
    not something cliff produces, so reading it as a minor would let a
    hand-edited or truncated version through as agreement.
    """
    cur = SEMVER.match(current.strip().lstrip("vV"))
    nxt = SEMVER.match(next_version.strip().lstrip("vV"))
    if cur is None or nxt is None:
        return None

    c = (int(cur.group("major")), int(cur.group("minor")), int(cur.group("patch")))
    n = (int(nxt.group("major")), int(nxt.group("minor")), int(nxt.group("patch")))

    if c == n:
        return NONE
    if n == (c[0] + 1, 0, 0):
        return MAJOR
    if n == (c[0], c[1] + 1, 0):
        return MINOR
    if n == (c[0], c[1], c[2] + 1):
        return PATCH
    return IRREGULAR


def review(
    current: str,
    next_version: str,
    contributions: Sequence[Contribution],
) -> List[str]:
    """Every reason this release must not proceed. Empty means the bump agrees."""
    problems: List[str] = []

    for contribution in contributions:
        if contribution.defect is not None:
            problems.append(
                "{} {!r}\n  ^ {}".format(
                    contribution.commit.short,
                    contribution.commit.subject,
                    contribution.defect,
                )
            )

    required = required_bump(contributions)
    observed = observed_bump(current, next_version)

    if observed is None:
        problems.append(
            "cannot compare v{} with v{}: one of them is not semver, so whether "
            "the bump matches the history is unknown".format(current, next_version)
        )
        return problems

    if observed == IRREGULAR:
        problems.append(
            "v{} -> v{} is not a single semver increment. cliff never produces "
            "such a step, so the computed version did not come from the history "
            "this release is about to ship.".format(current, next_version)
        )
        return problems

    if required is None and observed != NONE:
        problems.append(
            "the range requires no release — every commit in it is a type "
            "cliff.toml skips, or does not parse — yet a {} bump to v{} was "
            "computed. Tagging here would ship a version whose changelog is "
            "empty.".format(observed, next_version)
        )
    elif required is not None and observed == NONE:
        problems.append(
            "the range requires a {} bump but no release was computed, so the "
            "commits named above would ship to nobody while CD reports success."
            .format(required)
        )
    elif required is not None and observed != required:
        if RANK[observed] < RANK[required]:
            problems.append(
                "the range requires a {req} bump and a {obs} bump to v{next} was "
                "computed. Under-releasing is permanent: the commits named above "
                "end up behind the tag, so no later bump can ever account for "
                "them, and a consumer reading the tag list has no way to learn "
                "they shipped.".format(req=required, obs=observed, next=next_version)
            )
        else:
            problems.append(
                "the range requires a {req} bump and a {obs} bump to v{next} was "
                "computed. Over-releasing claims something the range does not "
                "contain: a consumer who pins by {obs} upgrades expecting the "
                "change that rank implies and does not get it, and the version "
                "that should have carried it is now spent.".format(
                    req=required, obs=observed, next=next_version
                )
            )

    return problems


def render_report(
    current: str,
    next_version: str,
    contributions: Sequence[Contribution],
    problems: Sequence[str],
    scope: str,
) -> List[str]:
    """The whole verdict, evidence included, as lines to print."""
    required = required_bump(contributions)
    observed = observed_bump(current, next_version)
    lines = [
        "range        {}".format(scope),
        "current      v{}".format(current),
        "computed     {}".format("v" + next_version if next_version else "(no release)"),
        "bump kind    computed={}  required by history={}".format(
            observed if observed is not None else "unclassifiable",
            required if required is not None else "nothing releasable",
        ),
        "",
    ]

    # The deciding commits come first. In a forty-commit range the one feat that
    # sets the required bump is the only line a reader needs, and it would
    # otherwise sit somewhere in the middle.
    deciding = [c for c in contributions if required is not None and c.kind == required]
    lesser = [c for c in contributions if c.kind is not None and c not in deciding]
    silent = [c for c in contributions if c.kind is None]

    if deciding:
        lines.append("requires a {} bump:".format(required))
        for c in deciding:
            lines.append("  {}  {}".format(c.commit.short, c.commit.subject))
            lines.append("            ^ {}".format(c.reason))
    if lesser:
        lines.append("also releasable, lower rank:")
        for c in lesser:
            lines.append("  {}  {}  [{}]".format(c.commit.short, c.commit.subject, c.kind))

    # Collapsed rather than listed: every one of these is a merge subject or a
    # subject that does not parse, so none of them can change the verdict, and
    # listing twenty merges pushes the deciding commit off a reviewer's screen.
    # Refusing an unparseable subject belongs to scripts/check-commit-subjects.py,
    # which asks on the pull request while an amend is still possible.
    if silent:
        lines.append(
            "{} commit(s) contribute nothing: a merge subject, a type cliff.toml "
            "skips, or a subject that does not parse. None can change the bump; "
            "scripts/check-commit-subjects.py is what refuses the last kind.".format(
                len(silent)
            )
        )

    lines.append("")
    if problems:
        lines.append(
            "RELEASE REFUSED — the tag would disagree with the history it ships:"
        )
        for problem in problems:
            lines.append("  - {}".format(problem))
        lines.append("")
        lines.append(
            "Nothing has been tagged. A wrong tag cannot be withdrawn, so this "
            "exits non-zero rather than releasing and reporting success."
        )
    elif observed == NONE:
        lines.append(
            "OK: nothing in this range releases, and no version was computed."
        )
    else:
        lines.append("OK: a {} bump is what the history requires.".format(observed))
    return lines


def format_problem_count(problems: Sequence[str]) -> str:
    return "{} problem{}".format(len(problems), "" if len(problems) == 1 else "s")


def split_subject_body(message: str) -> Tuple[str, str]:
    """Split a raw commit message into its subject and the rest.

    Kept here rather than in the CLI so the tests exercise the same split the
    release does; a body that never arrives would silently disable the
    BREAKING-CHANGE-footer branches above.
    """
    subject, _, body = message.partition("\n")
    return subject.strip(), body.strip()
