# Scan the working tree, not only the commit log

## Why

`ScanSource` ran gitleaks in git-log mode alone (`detect --source .`). That mode
reads commit diffs, so it cannot see a credential that sits on disk without being
committed, and it cannot see anything at all when the uploaded directory carries
no `.git`. Both cases happen constantly, and the second one is the worse of the
two: gitleaks shells out to git, git fails, and gitleaks then reports
`0 commits scanned`, prints `no leaks found` and **exits 0**. Measured on
v8.30.1 against a directory with no `.git`:

```
ERR [git] fatal: not a git repository (or any parent up to mount point /)
ERR error="stderr is not empty"
INF 0 commits scanned.
INF no leaks found
exit 0
```

gitleaks knows it failed and still exits clean, which means the exit status can
never discriminate. Every `testdata` fixture is a plain directory with no `.git`,
so every `module-test` and `composite-smoke` cell that claimed to prove this
module works was in fact proving nothing: the secrets leg searched zero bytes and
reported a clean bill of health. Nothing in the repository detected that, because
no assertion anywhere required the secrets leg to actually find a secret.

The two modes are complementary rather than ranked. Measured on v8.30.1:

| fixture | `dir .` | `detect --source .` |
|---|---|---|
| secret only in history, deleted from the tree | 0 | 1 |
| secret uncommitted in the working tree | 1 | 0 |
| no `.git` at all | 1 | 0 |

## What changed

`src/security/secrets_source.go` now always scans the working tree, and adds a
history leg when the directory carries a `.git/` directory. `runGitleaksLeg`
captures the exit status, stderr and report to files and exits 0, so
`gitleaksRunError` in the new `src/security/gitleaksreport.go` decides what
happened instead of Dagger's exec status. A history leg that reports no commit
count, or a count of zero, is an error.

Findings are now derived from the same SARIF document the envelope carries. There
used to be a second gitleaks invocation with `--report-format json` whose only job
was counting, and its error was discarded, so a failed counting run produced zero
findings beside a SARIF that listed them — and the gate trusted the count.

`.github/workflows/ci.yml` gained the assertion that was missing: a source scan of
`testdata/node-app` must report a gitleaks finding in `leaked.env.fixture`, which
is the one fixture in the repository deliberately left detectable.

## Decisions

**Every run passes `--redact`.** gitleaks writes the credential it found into
`region.snippet.text`, and that document is passed into the evidence envelope
verbatim, which is then published as a CI artifact and handed out by
`cross-cutting/report`. A secrets scanner that republishes the secret into a file
with weaker and longer-lived access control than the source is amplifying the
leak it was hired to find. Redaction keeps ruleId, file, line and columns, so
triage loses nothing — the literal value is in the developer's own file at that
line.

**Deduplicate on rule, file and line.** A credential that is both committed and
still on disk is reported by both legs, and it is one leak needing one
remediation. Keying on gitleaks' own fingerprint would count it twice, since the
fingerprints differ only by a commit prefix (`cfg.py:github-pat:1` against
`<sha>:cfg.py:github-pat:1`).

**Keep the tree leg's document as the base.** Both legs emit the full 222-rule
gitleaks catalogue, about 49 KB, so merging two whole documents would put a second
copy of it into every envelope and tell the reader nothing new.

**A missing `.git` is not a failure; an unreadable one is.** `historyAvailable`
requires a `.git/` directory rather than any entry named `.git`, because in a git
worktree or submodule `.git` is a file holding an absolute
`gitdir: /path/to/main/.git/worktrees/x` pointer that does not exist inside the
container. Demanding history there would fail the gate on a valid checkout, and
this repository itself uses worktrees.

**A history failure does not discard the tree leg's findings.** `runGitleaks`
returns a report together with an error in that case, unlike `runSemgrep` and
`runTrivyFS`, which return nil. Nulling the result would trade a located,
actionable secret for a message about a different leg.

## Known residue

- A repository with a readable `.git/` and no commits yet fails the history leg,
  because `0 commits scanned` is textually identical to the broken-object-store
  case. The error names both causes. A checkout in CI always has at least one
  commit, so this is reachable mainly in local runs, and a loud failure that
  explains itself was chosen over a silent clean verdict.
- Two *different* credentials caught by the same rule at the same file and line in
  different commits collapse into one finding, since `--redact` removes the value
  that would tell them apart. The reported location and the remediation are
  identical in that case.
- The history leg adds a second container execution to every `ScanSource` run on a
  real checkout. The tree leg alone runs where there is no `.git/`.
- `testdata/go-app`'s secret carries `gitleaks:allow`, and the root
  `.gitleaks.toml` allowlists all of `testdata/`, so neither can ever demonstrate
  detection. `leaked.env.fixture` carries that proof alone.
- The envelope's `"tool":{"name":"security-source","version":""}` is still blank,
  so evidence cannot attribute a secrets finding to the scanner build that found
  it. That is a separate gap from this change.
