# Prove the bump matches the history it ships

## What happened

`v1.14.2` and `v1.14.3` were both cut as patch releases. Both ranges contained a
`feat:` commit. Nothing was red at any point: CI passed on every commit, both
release pull requests merged green, both tags exist and are well formed, and the
release notes attached to each are complete — they list the feature.

The two features are behind their tags permanently. git-cliff had already assigned
each of them to a release that shipped, so no later `--bumped-version` can ever
account for them.

| CD ran at | base | `--bumped-version` | `+ --unreleased` | correct |
|---|---|---|---|---|
| tagged v1.14.2 | v1.14.1 | **v1.14.2** ✗ | v1.15.0 | minor |
| tagged v1.14.3 | v1.14.2 | **v1.14.3** ✗ | v1.15.0 | minor |
| a later commit (no feat in range) | v1.14.2 | v1.14.3 | v1.14.3 | patch |

Measured with git-cliff 2.13.1 — the version
`.github/actions/install-git-cliff` pins — at the commits CD actually checked out,
with the later tags deleted to recreate the conditions of each run. The third row
is the negative control: a range whose highest commit really is a patch produces
the same answer either way, so the flag does not simply raise every bump.

## Why

**git-cliff answers "what is the next version" and "what is unreleased" over two
different partitions of history.**

`--unreleased` partitions by *reachability*: the commits after the newest tag that
`HEAD` can reach. The bare bump computation partitions by *commit date*: cliff
walks history chronologically and cuts at tag boundaries. A commit authored on a
branch that stayed open across a release therefore lands inside a release that has
already shipped, because its commit date precedes that release's tag commit — even
though no tag reaches it.

`git cliff --context` at the v1.14.3 commit shows exactly that: `feat(quality): witness
every language with test legs` is filed under release **v1.14.1**, next to the
other feature that v1.14.2 had already mis-tagged. The unreleased bucket held a
fix and a docs commit, so the bump was a patch.

`cd.yml` asked both questions and used both answers — the bump for the tag, and
`--unreleased` for the notes it published beside it. That is why the notes were
right while the version was wrong.

`topo_order = true` does not fix this, and is **not** the remedy: measured, it
leaves the bump unchanged, and combined with `--unreleased` it reintroduces the
misattribution.

## What changed

**The flag, at both call sites.** `.github/workflows/cd.yml` and
`scripts/release_drift.py` now pass `--unreleased` to `--bumped-version`. The
drift script already measured `commits_ahead` over the reachability range
`{latest_tag}..HEAD`, so without the flag it was comparing a version computed from
one partition against a count taken from another.

The empty case was checked before relying on it: at a commit with nothing
unreleased, `git cliff --unreleased --bumped-version` prints the current version
and exits 0. So `NEXT = CURRENT → skip` still works, and `release_drift.py`'s
refusal to read an empty print as "nothing to release" is still reachable only
when cliff genuinely prints nothing.

**And the question the flag leaves unasked.** `scripts/check-release-bump.py`
(logic in `scripts/release_bump.py`, tests in
`scripts/tests/test_release_bump.py`) derives the bump the range *requires* from
`git log` and refuses the release when cliff's answer differs.

This is the repository's founding doctrine applied to a version instead of a
scanner. **A feature released as a patch is indistinguishable from a release that
shipped no features.** The tag is well formed, the notes are complete, CI is
green, and the one watchdog aimed at releases cannot see it:
`release-drift.yml` compares the newest tag against `git cliff
--bumped-version`, which is the same binary that already mis-filed the commit, so
both sides of its comparison agree. Only the ordering of a tag against its own
history separates the two states, and nothing was asking.

The comparison is independent on exactly the axis that broke. The range comes from
`git describe --tags --abbrev=0`, which is reachability-based, and each commit's
required bump is derived from its own subject and body. Two computations that
disagree about what is in the release cannot both be right, so the release stops
rather than tagging.

## What it is not

**Not a re-implementation of cliff.** It answers one question — which of
major/minor/patch/nothing does this range require — and compares it to the version
cliff produced. It renders no changelog and picks no groups.

**Not a subject gate.** An unparseable subject contributes nothing here, exactly
as cliff treats it. Refusing such a subject is
`scripts/check-commit-subjects.py`'s job, on the pull request, where an `--amend`
is still cheap. Duplicating that verdict here would fail every release over the
merge commits every range in this history carries.

**Not wired into `release.yml`.** That workflow releases a version a human typed,
which is a deliberate override; asking whether the history agrees with it would
refuse the override for doing its job. `cd.yml` is where a version is computed,
and computed is where it can be wrong without anyone deciding it.

### Rejected: read the rendered notes for a `### Features` heading

`cliff.toml` sets `header = ""` and the body template emits no version heading, so
the notes carry group names only. A group name is a label `commit_parsers` derived
from the same commit cliff had already mis-filed — asking about the label is
asking cliff twice, over the partition that produced the wrong answer.

## Measured classification

Base `v1.0.0`, one commit, this repository's `cliff.toml`, git-cliff 2.13.1:

| commit | cliff bumps to | required |
|---|---|---|
| `feat: x` | v1.1.0 | minor |
| `fix:` / `docs:` / `refactor:` / `perf:` / `revert:` / `build:` | v1.0.1 | patch |
| `wip: x` | v1.0.1 | patch |
| `chore:` / `ci:` / `test:` / `style:` | v1.0.0 | nothing |
| `fix!: x` / `feat!: x` | v2.0.0 | major |
| `chore!: x` / `ci!: x` | v2.0.0 | major (`!` beats `skip`) |
| `fix: x` + `BREAKING CHANGE:` footer | v2.0.0 | major |
| `chore: x` + `BREAKING CHANGE:` footer | v1.0.0 | **nothing at all** |
| `FEAT: x` / `Feat(s): x` | v1.1.0 | minor |
| `Chore: x` / `CHORE: x` | v1.0.1 | patch |

Three rows carry traps worth naming.

`!` beats `skip = true` because `cliff.toml` lists the breaking-subject parser
first. `chore: x` with a `BREAKING CHANGE` footer releases **nothing** — the skip
parser removes the commit before the footer is read, so a breaking change
disappears entirely. That is this document's own subject one commit type further
along, and it is always a defect, so `classify_commit` reports it as one and the
check refuses the release even when the bump kind is otherwise correct. The remedy
is to put the `!` in the subject, where the first parser sees it.

And the case rows are an asymmetry, not a typo: cliff recognises the conventional
*type* case-insensitively, but `commit_parsers` entries are ordinary
case-sensitive regexes, so `^chore` does not match `Chore:` and a capitalised
chore releases a patch. The classifier therefore lowercases the type for the
`feat` test and matches the skip patterns against the subject verbatim.

The skip patterns are read out of `cliff.toml` rather than hard-coded as a list of
type names, and matched as regexes the way cliff matches them — so `^ci` matches
`citizen:` in both. A malformed or skip-less `commit_parsers` array is exit 2, not
an empty skip list: an empty list would reclassify every `chore:` commit as a
patch and refuse every release.

## Merge commits are in range

Deliberately. cliff processes them and drops them as unparseable, so they
contribute nothing to the required bump either. But excluding them would hide a
`--no-ff` merge whose subject *does* parse — measured: a merge with the subject
`feat: bring in the side branch` makes cliff bump a minor, and the check agrees.
Dropping merges would have created a false-failure class instead of removing
noise. They are collapsed into a count in the report rather than listed, because
twenty merge lines push the deciding commit off the screen and none of them can
change the verdict.

## Exit codes

`0` the bump agrees with the history. `1` it does not — nothing is tagged. `2` the
question could not be asked: a shallow clone (the base tag may be missing, so the
deciding commit can sit outside the truncated range), an unreadable or malformed
`cliff.toml`, a failing `git`, or a `--current` that disagrees with the newest
reachable tag, which means the release and the check are looking at two different
ranges and neither answer can be trusted.

There is no override flag. A check that examined nothing must never read as clean.
