# Intent: refuse a commit subject git-cliff cannot release

## Why

On 2026-08-04 a `fix(quality):` commit landed on `main` with its subject mangled
into free text — `Second-pass review follow-up on the gate. One real gap, two wording
corrections, one decline.` CD ran, decided there was nothing to
bump, and reported success. No tag, no error, no red check, no issue. The fix
shipped to nobody and the pipeline said everything was fine.

That is not a git-cliff bug. `cliff.toml` here sets `conventional_commits = true`
and `filter_unconventional = true`, so a subject that does not parse is *supposed*
to be dropped. The problem is what dropping looks like from outside. Measured with
the exact binary `.github/actions/install-git-cliff` pins (git-cliff 2.13.1, this
repository's `cliff.toml`, one commit after tag `v1.0.0`):

| subject | `git cliff --bumped-version` | stderr |
|---|---|---|
| `fix(quality): a real fix` | `v1.0.1` | — |
| `feat: a feature` | `v1.1.0` | — |
| `fix!: breaking fix` | `v2.0.0` | — |
| `wip: unknown type` | `v1.0.1` | — |
| `chore: housekeeping` | `v1.0.0` | `There is nothing to bump` |
| `Second-pass review follow-up on the gate.` | `v1.0.0` | `WARN … 1 commit(s) were skipped due to parse error(s)` |

Look at the last two rows. **An unparseable commit and a deliberate `chore:` sweep
are indistinguishable from the outside**: both exit 0, both print the version that
is already tagged, and the only difference is a WARN line in a log nobody opens.
This repository already has doctrine for exactly this shape — a tool that could not
run must never read as clean — and here it is the *release decision* that could not
be taken, reporting itself as a release that was correctly declined.

`release-drift.yml` cannot cover it, and that is structural rather than an
oversight. It defines drift as newest-tag vs `git cliff --bumped-version`: the same
question, put to the same binary, which has already dropped the commit. Both sides
of its comparison agree, so it sees a released repository. Any check that reads the
*resulting version* inherits the same blindness, because the version is precisely
where the information was lost.

So the question has to be asked about the subject line, while the commit is still
cheap to fix.

## What changed

- **`scripts/commit_subjects.py`** — new, pure logic: no git, no subprocess, no
  clock. `subject_problem()` returns why cliff would drop a subject or `None`;
  `review()` maps it over a list; `render_report()` renders the verdict.
- **`scripts/check-commit-subjects.py`** — new, the thin dashed CLI over it (the
  same split `check-repo-surface.py` has over `repo_surface.py`). Three modes:
  `--base <sha>` for a pull request range, `--since-tag` for newest-tag..HEAD,
  `--subject "…"` to judge one string touching no repository.
- **`scripts/tests/test_commit_subjects.py`** — new, 12 cases built from the
  measured table above plus the real incident subject.
- **`.github/workflows/ci.yml`** — new `commit-subjects` job, and it is added to
  the `ci` aggregate's `needs:` so the one required check context covers it.

### Parseability only, no type allowlist

The gate enforces that cliff can *parse* the subject. It does not police which
types are allowed, and the measured table is why: `wip:` — a type this repository
has no convention for — bumps a patch and renders under an auto-titled `### Wip`
changelog heading. It releases. A gate rejecting unknown types would be enforcing
taste, and taste belongs in review, not in a check whose job is to stop a silent
non-release. `chore:`/`ci:`/`test:`/`style:` skip by design and pass here.

### Deliberately stricter than cliff in one place

cliff accepts `fix:no space` and bumps it; this rejects it and asks for
`fix: no space`. The asymmetry is the point: being stricter can only produce a
false *failure* the author fixes with `--amend`, never a false pass that loses a
release. Every rejection names the specific mistake — `no space after the colon`,
`an unclosed scope parenthesis`, `a git-generated revert subject`, and eight more
— because "not a conventional commit" is useless advice to someone one character
away.

### Its own job, with full history

`fetch-depth: 0` is load-bearing rather than cautious. At the default depth of 1
the base commit is absent, so `base..HEAD` either truncates or fails — and a
truncated range is exactly the shape that hides a bad subject while reporting
success. The script therefore refuses a shallow clone outright (exit 2) instead of
examining a slice and calling it the whole. Exit codes: 0 clean, 1 a subject would
be dropped, **2 the range could not be established** — a check that examined
nothing must never read as clean, so that is a third answer, not a pass.

It is a separate job rather than a step in `lint-repo` because it is the only check
here that needs history, and several `lint-repo` steps are documented as depending
on its clean shallow checkout. Merge commits are excluded: cliff cannot parse
`Merge pull request #1 from …` either, so every release in this repository's
history carries some, and demanding otherwise would fail every run while saying
nothing.

## Proof

The gate catches the real incident, against real history, in this repository:

```
$ python3 scripts/check-commit-subjects.py --base <sha>^
commit subjects: examined 3 commit(s) in <sha>..HEAD

  <sha>     Second-pass review follow-up on the gate. One real gap, two wording corrections, one decline.
      ^ no `type: description` prefix at all, so cliff reads it as free text

1 of 3 commit(s) would be dropped by git-cliff, so they would release nothing and
appear in no changelog — and CD would report success.
$ echo $?
1
```

And its negative control — current `main`, which is `v1.12.2`:

```
$ python3 scripts/check-commit-subjects.py --since-tag
commit subjects: examined 0 commit(s) in v1.12.2..HEAD
OK: every subject parses as a conventional commit
$ echo $?
0
```

And the third answer, driven against a real `--depth 1` clone of this repository
rather than a simulated flag:

```
$ git clone --depth 1 file:///…/cicd shallowprobe && cd shallowprobe
$ python3 scripts/check-commit-subjects.py --since-tag
commit subject check FAILED: shallow clone: the commit range is truncated, so a bad
subject could sit outside it. Check out with fetch-depth: 0.
This is not a verdict of 'every subject is fine'. A check that could not look must
never read as clean.
$ echo $?
2
```

That matters because the shallow case is not exotic — it is the *default*
`actions/checkout` behaviour, so the wrong workflow configuration is the likely
one, and it truncates the range in exactly the direction that hides a problem.

Note that the report always states how many commits it examined. A gate saying "no
problems" without saying what it looked at is the shape behind every false pass in
this repository's history, so the count is not decoration — it is how a reader
tells a clean range from an empty one. An empty range is legitimate for
`--since-tag` (immediately after a release, the tag *is* HEAD) and an error for
`--base`, where a pull request always carries at least one commit.

The cliff behaviours in the table were measured, not assumed: each subject was
committed into a scratch repository carrying this repository's `cliff.toml`, with
the pinned 2.13.1 asset downloaded and verified against the SHA512 in
`.github/actions/install-git-cliff/action.yml`.

## What this does not cover

- **A wrong-but-parseable type.** `chore:` on a change that should have been
  `fix:` releases nothing, correctly parses, and passes this gate. It is a review
  question; no subject-level check can read intent.
- **A commit that never reaches a pull request.** The push-event mode narrows that
  to newest-tag..HEAD, so a direct push is caught on the next CI run rather than
  before it lands — but direct pushes to `main` are structurally impossible here
  anyway (see `specs/deliver-release-pins-by-pull-request.md`).
- **CD failing for any other reason.** That stays `release-drift.yml`'s job. The
  two are complementary: this one closes the case where CD ran and was *right* to
  do nothing, given the history it was handed.
