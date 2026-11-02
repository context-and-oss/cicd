"""Refuse a commit subject git-cliff cannot release.

`cd.yml` decides what to release by asking `git cliff --bumped-version`. cliff's
config here sets `conventional_commits = true` and `filter_unconventional = true`,
so a commit whose subject does not parse as a conventional commit is **silently
dropped**: it contributes nothing to the version, appears in no changelog section,
and produces no error anywhere.

Measured with the exact binary CI pins (git-cliff 2.13.1, this repository's
cliff.toml, one commit after tag v1.0.0):

    subject                                   git cliff --bumped-version
    fix(quality): a real fix                  v1.0.1
    feat: a feature                           v1.1.0
    fix!: breaking fix                        v2.0.0
    chore: housekeeping                       v1.0.0  + "There is nothing to bump"
    Second-pass review follow-up on the gate. v1.0.0  + "1 commit(s) were skipped
                                                        due to parse error(s)"

Note the last two lines. **An unparseable commit and a deliberately non-releasing
`chore:` sweep are indistinguishable from the outside**: both exit 0 and both
print the version that is already tagged. That is not a hypothetical — a
`fix(quality):` commit landed on `main` with a subject mangled into free text, CD
ran, found "nothing to bump", and reported success. No tag, no error, no signal.
`release-drift.yml` could not see it either, because it defines drift as
newest-tag vs `git cliff --bumped-version` — the same answer, from the same
source that had already dropped the commit.

So the question has to be asked where the commit is still cheap to fix, and it
has to be asked about the *subject*, not about the resulting version: the version
cannot tell the two cases apart, and no downstream check can either.

Deliberately stricter than cliff in one respect. cliff accepts `fix:no space` and
bumps it; this rejects it and demands `fix: no space`. Being stricter can only
produce a false *failure* an author fixes in seconds, never a false pass that
loses a release — and the asymmetry is the whole point. Every rejection names the
remedy.

Pure logic only: no git, no subprocess, no clock. `scripts/check-commit-subjects.py`
supplies the commits and `scripts/tests/test_commit_subjects.py` drives every
branch here directly.
"""

from __future__ import annotations

import re
from typing import List, NamedTuple, Optional, Sequence

# Conventional Commits 1.0.0 §1: `<type>[optional scope][!]: <description>`.
# Type is letters only, which is what cliff's own parsers match (`^[A-Za-z]+`).
CONVENTIONAL = re.compile(r"^[A-Za-z]+(\([^()]*\))?!?: \S")

# Shapes worth naming separately, because "not a conventional commit" is useless
# advice when the author is one character away. Order matters: first match wins.
# A subject is judged against these in order, so the more specific shapes come
# first: "Revert \"chore: seed\"" also has no colon directly after its first word,
# and the free-text incident subject ("Second-pass review …") also begins with a
# hyphenated word — matching either of those broader rules first would print a
# true-but-useless reason.
NEAR_MISSES = (
    (re.compile(r"^Revert\s+\""), "a git-generated revert subject, which cliff cannot parse"),
    # The subject is stripped before matching, so a trailing-space-only
    # description arrives here as a bare colon.
    (re.compile(r"^[A-Za-z]+(\([^()]*\))?!?:$"), "the description after the colon is empty"),
    (re.compile(r"^[A-Za-z]+(\([^()]*\))?!?:\S"), "no space after the colon"),
    (re.compile(r"^[A-Za-z]+(\([^()]*\))?!?:\s\s"), "the description starts with whitespace"),
    (re.compile(r"^[A-Za-z]+(\([^()]*\))?!?\s+:"), "a space before the colon"),
    # Only a mis-typed *type* counts here, so the colon must be present: without
    # it, any ordinary English sentence starting with a hyphenated word matches.
    (
        re.compile(r"^[A-Za-z]+[-_.][A-Za-z0-9]*(\([^()]*\))?!?:"),
        "a type containing a character other than a letter",
    ),
    (re.compile(r"^[A-Za-z]+\([^()]*$"), "an unclosed scope parenthesis"),
    (re.compile(r"^[A-Za-z]+(\([^()]*\))?!?\s"), "no colon after the type"),
)

REMEDY = (
    "Rewrite the subject as `type(optional-scope): description` — for example "
    "`fix(quality): stop dropping the feed token`. Use `chore:`, `ci:`, `test:` or "
    "`style:` for a change that deliberately releases nothing; those are skipped on "
    "purpose and pass this check. `git commit --amend` (or an interactive rebase for "
    "an older commit) then force-push the branch."
)


class Commit(NamedTuple):
    """One commit to judge. `sha` is display-only; only `subject` is parsed."""

    sha: str
    subject: str


class Problem(NamedTuple):
    sha: str
    subject: str
    reason: str


def subject_problem(subject: str) -> Optional[str]:
    """Why git-cliff would drop this subject, or None when it would parse it.

    A trailing newline or surrounding whitespace is not the author's mistake —
    `git log --format=%s` never emits one, but a caller reading a file might — so
    it is stripped before judging rather than reported as a defect.
    """
    text = subject.strip()
    if not text:
        return "the subject is empty"
    if CONVENTIONAL.match(text):
        return None
    for pattern, reason in NEAR_MISSES:
        if pattern.match(text):
            return reason
    return "no `type: description` prefix at all, so cliff reads it as free text"


def review(commits: Sequence[Commit]) -> List[Problem]:
    """Every commit whose subject cliff would silently drop, in input order."""
    problems = []
    for commit in commits:
        reason = subject_problem(commit.subject)
        if reason is not None:
            problems.append(Problem(commit.sha, commit.subject, reason))
    return problems


def render_report(
    commits: Sequence[Commit], problems: Sequence[Problem], scope: str
) -> List[str]:
    """Human-readable result. Always names how many commits were examined.

    A gate reporting "no problems" without saying what it looked at is the shape
    this repository keeps finding behind its false passes, so the count is not
    optional decoration — it is how a reader tells a clean range from an empty one.
    """
    lines = ["commit subjects: examined {} commit(s) in {}".format(len(commits), scope)]
    if not problems:
        lines.append("OK: every subject parses as a conventional commit")
        return lines

    lines.append("")
    for problem in problems:
        lines.append("  {}  {}".format(problem.sha[:8], problem.subject))
        lines.append("      ^ {}".format(problem.reason))
    lines.append("")
    lines.append(
        "{} of {} commit(s) would be dropped by git-cliff, so they would release "
        "nothing and appear in no changelog — and CD would report success.".format(
            len(problems), len(commits)
        )
    )
    lines.append("")
    lines.append(REMEDY)
    return lines
