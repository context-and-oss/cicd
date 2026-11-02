"""Refuse Go source no formatter in this repository has ever looked at.

Two files had been unformatted since the commits that introduced them —
`src/internal/evidence/schema_test.go` and `src/risk/scanner.go` —
and nothing in the repository could have said so. `gofmt -l` was run by no
Makefile target, no workflow step and no script; the only formatting signal
available was a human reading a diff.

That is not one of the silent-false-pass shapes this repository already defends
against, and it is worth being precise about why it still belongs here. An
unformatted file breaks no gate and ships no wrong verdict. What it does is make
the *absence* of a formatter indistinguishable from a formatted tree: `make lint`
printed nothing about formatting on a tree with two unformatted files, exactly as
it would on a clean one. The remedy is the same as everywhere else here — ask the
question, and let a tool that could not run say so instead of reporting nothing.

The scope is deliberately narrow. `gofmt` parses one file at a time, resolves no
imports and type-checks nothing, so it covers every module from the Dagger-free
`lint-repo` job. golangci-lint cannot: a module only compiles once its generated
SDK exists (`dagger.gen.go` plus `internal/dagger/`, both gitignored, both produced
by `dagger develop`), so for as long as `lint-repo` was the only lint job the 15
Dagger modules under `src/` got no errcheck, no govet and no staticcheck at all.
That hole is closed by `scripts/ci/lint-modules.sh` and ci.yml's `lint-modules`
job, which run Dagger and lint each module in both build-tag sets. This check
stays separate because it needs none of that and so still runs on a tree whose
SDKs cannot be generated.

`gofmt`, not `gofumpt`. gofmt is the language's own floor and cannot be argued
with, which is the property wanted from a check that lands across 15 modules at
once; gofumpt adds a style opinion, and a check whose findings are debatable is a
check people learn to override.

Tracked files only, from `git ls-files`. The generated SDKs are gitignored, and
they are not ours to grade — a codegen that emitted unformatted Go would be a bug
to report upstream, not a diff to commit here. It also means the check needs no
exclusion list of its own to drift out of step with `.gitignore`.

Pure logic only: no subprocess, no file reads. `scripts/check-go-format.py`
locates gofmt, lists the files and runs it; every branch below is driven directly
by `scripts/tests/test_go_format.py`.
"""

from __future__ import annotations

from typing import List, NamedTuple, Optional, Sequence

# Exit codes. 2 is not a softer 1: it means the question could not be put to
# gofmt at all, which is the state a formatting check must never report as a
# clean tree. Same three-answer shape as scripts/check-release-bump.py and
# scripts/check-release-gate.py.
EXIT_OK = 0
EXIT_UNFORMATTED = 1
EXIT_CANNOT_ASK = 2


class Verdict(NamedTuple):
    exit_code: int
    lines: List[str]


def parse_gofmt_list(stdout: str) -> List[str]:
    """Return the paths `gofmt -l` named, sorted and de-duplicated.

    gofmt prints one path per line and prints nothing at all for a clean tree,
    so an empty string is a legitimate clean answer — it is the caller's job to
    have established that gofmt actually ran.
    """
    seen = {line.strip() for line in stdout.splitlines() if line.strip()}
    return sorted(seen)


def verdict(
    gofmt: Optional[str],
    files_checked: Sequence[str],
    listing: Optional[str],
    probe_error: Optional[str] = None,
) -> Verdict:
    """Classify a gofmt run.

    `gofmt` is the resolved binary path, or None if it could not be found.
    `listing` is gofmt's stdout, or None if the run itself failed; `probe_error`
    carries whatever stderr or exception text explains a None.
    """
    if gofmt is None:
        return Verdict(
            EXIT_CANNOT_ASK,
            [
                "gofmt could not be found, so no Go file was checked for formatting.",
                _because(probe_error),
                "A formatter that never ran reports no unformatted files exactly "
                "like a formatted tree, so this is a failure and not a skip. "
                "Install the Go toolchain, or put gofmt on PATH.",
            ],
        )

    if listing is None:
        return Verdict(
            EXIT_CANNOT_ASK,
            [
                f"{gofmt} was found but the run failed, so no verdict is available.",
                _because(probe_error),
                "This is exit 2 rather than a pass: nothing was learned about the "
                "tree's formatting.",
            ],
        )

    # Zero files with a working gofmt is not a pass either. It means the file
    # list came back empty — a broken glob, a `git ls-files` run outside the
    # repository — and "0 of 0 files are unformatted" is vacuously true in
    # exactly the way `allRan` was vacuously true over an empty language set.
    if not files_checked:
        return Verdict(
            EXIT_CANNOT_ASK,
            [
                "no Go files were found to check.",
                "A repository of Dagger modules written in Go has some, so this is "
                "a broken file list rather than a clean result, and a clean result "
                "over nothing is what this check exists to refuse.",
            ],
        )

    unformatted = parse_gofmt_list(listing)
    if unformatted:
        lines = [
            f"{len(unformatted)} of {len(files_checked)} tracked Go file(s) are not "
            f"gofmt-clean:",
            "",
        ]
        lines += [f"  {path}" for path in unformatted]
        lines += [
            "",
            "Run `make fmt` (or `gofmt -w` on the paths above) and commit the result.",
        ]
        return Verdict(EXIT_UNFORMATTED, lines)

    return Verdict(
        EXIT_OK,
        [f"go format check: OK ({len(files_checked)} tracked Go file(s) are gofmt-clean)"],
    )


def _because(detail: Optional[str]) -> str:
    detail = (detail or "").strip()
    return f"  {detail}" if detail else "  (no further detail was reported)"
