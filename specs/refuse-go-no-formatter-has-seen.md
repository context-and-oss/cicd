# Refuse Go source no formatter has ever looked at

## What was measured

`gofmt -l` over the tracked Go files of this repository, before this change:

```
$ git ls-files -z '*.go' | xargs -0 gofmt -l
src/internal/evidence/schema_test.go
src/risk/scanner.go
```

Two of 152 tracked Go files. Both diffs are whitespace only — a struct literal
whose fields were never re-aligned after a longer field name joined them, and an
inline `struct{ … }` gofmt would break across lines:

```
-		TimestampUTC:  time.Now().UTC().Truncate(time.Second),
-		DurationMS:    4200,
+		TimestampUTC:   time.Now().UTC().Truncate(time.Second),
+		DurationMS:     4200,
 		FailOnSeverity: evidence.SeverityHigh,

-			Message struct{ Content string `json:"content"` } `json:"message"`
+			Message struct {
+				Content string `json:"content"`
+			} `json:"message"`
```

The lines arrived in two commits (2026-04-23 and 2026-05-19). Both are
contained in **all 40 tags this repository has ever cut**. Nothing reported them,
because nothing asked:

```
$ grep -rn 'gofmt\|gofumpt' .github/workflows/ Makefile scripts/*.py
(no match)
```

No Makefile target, no workflow step and no script ran a formatter. The only
formatting signal available was a human reading a diff, and across 40 releases it
did not fire.

## Why this belongs with the false-pass doctrine

An unformatted file fails no gate and ships no wrong verdict, so the honest first
question is whether this is a real instance of the family or a tidiness complaint
borrowing its language. It is a real instance, on one specific axis: `make lint`
printed nothing about formatting on a tree with two unformatted files, exactly as
it would have printed nothing on a clean one. **The absence of a formatter was
indistinguishable from a formatted tree.** That is the same shape as a scanner
that could not run reporting zero findings — the reader cannot tell "asked and
clean" from "never asked" — and the remedy is the same: ask the question, and make
a formatter that could not run say so rather than say nothing.

What this is *not* is a claim that formatting matters much. It is cheap to ask, so
the argument for asking does not need the answer to be important.

## The adjacent hole this deliberately does not close

`.github/workflows/ci.yml` runs golangci-lint with `working-directory:
src/internal`, and `src/internal/.golangci.yml` is the repository's only config:

```yaml
version: "2"
linters:
  enable: [errcheck, govet, staticcheck, ineffassign]
```

Two facts follow, and the second is larger than this spec's subject:

1. There is no `formatters:` key. golangci-lint v2 moved gofmt/gofumpt/goimports
   under that top-level key, so formatting was unchecked even inside the one
   directory that is linted at all.
2. The 15 Dagger modules under `src/` receive **no golangci-lint whatsoever** —
   not errcheck, not govet, not staticcheck. `src/risk/scanner.go` was not merely
   unformatted; it has never been statically analysed.

Extending golangci-lint to reach the modules was considered and rejected *for this
change*, on a structural ground rather than an effort one. A Dagger module compiles
only once its generated SDK exists — `dagger.gen.go` plus `internal/dagger/`, both
gitignored, both produced by `dagger develop` — and golangci-lint needs a
compilable package because staticcheck and errcheck are type-aware. Linting the
modules therefore means running Dagger inside `lint-repo`, the one CI job that
deliberately requires no Dagger session, and that trade (job runtime, a Dagger
dependency in a job that has never needed one, and a first-run finding count
nobody has seen) deserves
its own argument and its own decision.

`gofmt` requires none of it: it parses one file at a time, resolves no imports and
type-checks nothing. So the cheap half closes here and the expensive half is
written down — in `scripts/go_format.py`'s module docstring and in the CI step's
comment — rather than left for rediscovery. **Closing the cheap hole must not read
as a claim that the expensive one is closed**, which is the failure mode this
repository is about, applied to its own remedy.

## Decisions

**gofmt, not gofumpt.** gofmt is the language's own floor: its output is not a
matter of taste, so a check that lands across 15 modules at once produces no
findings anyone can reasonably argue with. gofumpt adds a style opinion, and a
gate whose findings are debatable is a gate people learn to route around. Nothing
prevents a later, separately-argued move to gofumpt.

**Tracked files only, from `git ls-files`.** The generated SDKs are gitignored, and
grading them would report a code generator's output as this repository's debt — a
codegen emitting unformatted Go is an upstream bug, not a diff to commit here. It
also means the check carries no exclusion list of its own to drift out of step with
`.gitignore`. Measured: an unformatted `dagger.gen.go` in the working tree is not
flagged (`CLITests.test_an_untracked_file_is_not_graded`).

**Three answers, not two.** Exit 0 clean, exit 1 unformatted, exit 2 the question
could not be put to gofmt — the same shape as `scripts/check-release-bump.py` and
`scripts/check-release-gate.py`. Exit 2 covers four states, each measured:

| state | exit | measured by |
|---|---|---|
| no gofmt on PATH and no `go` to locate one | 2 | `test_no_gofmt_on_path_is_exit_2` |
| gofmt found but the run fails (e.g. a file it cannot parse) | 2 | `test_a_gofmt_that_fails_is_exit_2_and_never_a_clean_report` |
| `git ls-files` fails or the root is not a repository | 2 | `test_a_directory_that_is_not_a_git_repository_is_exit_2` |
| gofmt works but the file list is empty | 2 | `test_a_repository_with_no_go_files_is_exit_2_not_a_pass` |

The last one is the subtle one, and it is the reason the check does not simply
trust a clean `gofmt -l`. "0 of 0 files are unformatted" is **vacuously** true, in
precisely the way `allRan` stayed vacuously true over an empty language set in
[refuse-a-language-set-that-scans-nothing.md](refuse-a-language-set-that-scans-nothing.md):
a broken glob, a moved script, or a run outside the checkout all produce a green
tick over nothing examined. A repository of Dagger modules written in Go has Go
files; zero of them is a broken file list, not a result.

Likewise a non-zero exit from gofmt discards its stdout rather than reading it as
a partial answer — an incomplete listing is not a shorter listing.

**No override flag.** There is nothing to override: the fix is `make fmt`, which
rewrites the files and needs no judgement. A gate that can be waived on a change
of this cost would only ever be waived by accident.

## What exists

| path | what it is |
|---|---|
| `scripts/go_format.py` | pure classifier — no subprocess, no file reads |
| `scripts/check-go-format.py` | CLI: locates gofmt, lists tracked files, runs it; `--write`, `--root` |
| `scripts/tests/test_go_format.py` | 17 tests, including every exit-2 state above |
| `make check-go-format` / `make fmt` | audit / fix |
| `.github/workflows/ci.yml` → `lint-repo` | "Check Go formatting", after the capsule check |

`--write` exists so the remedy is one command, and it reports what it rewrote
rather than exiting 1 about files it has just fixed.
