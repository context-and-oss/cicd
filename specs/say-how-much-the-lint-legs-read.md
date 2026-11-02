# Say how much the lint legs read

## Why

`pylint: FINDINGS, 1 HIGH` on `testdata/python-app` was a measurement of
nothing. The leg ran `pylint .`, and pylint reads a directory argument as one
package: on a flat tree with no `__init__.py` at its root it printed a single
`F0010 parse-error` and linted no file (measured, pylint 3.1.0 in the pinned
`python:3.12-slim` image). The parser counted that fatal message as a HIGH
finding, so the leg failed at the default threshold as if it had found a bug,
and passed at `--fail-on NONE` as if it had run. On a tree that *is* a package
it skipped every directory below it that is not one. Neither leg said how much
it read, so neither case was visible from the evidence.

ESLint had the count in hand — its JSON report is one entry per linted file —
and dropped it.

## What changed

**pylint (`pylinttargets.go`, `pylintreport.go`, `lint.go`).** cicd lists the
files and hands pylint exactly that list, through a NUL-separated file read by
pylint's own entry point (argv cannot overflow, and every path is `./`-prefixed
so none reads as an option). Pruned before pylint sees them, counted and named
in a warning: any path under a hidden directory, `node_modules`, `__pycache__`,
`site-packages`, or a directory holding a `pyvenv.cfg` (a virtualenv is found by
what it is, not by its name).

- The report is `--output-format=json2`. Its root must be an object carrying
  `messages`; a json1 array, `null` or a truncated document is "not pylint
  JSON", a non-run.
- A `fatal` message means pylint could not read that file. It is never a
  finding. The leg is a non-run naming the unread paths ("could not read N of
  M file(s) it was given"), and reports no `Examined`: the files it did read do
  not stand for the tree. The findings it did produce stay in the SARIF.
- On success `Examined{Unit: "files", Count: len(targets)}`.
- No target left (Python detected from `pyproject.toml` or
  `requirements.txt` alone) runs no container, and the leg reads `SKIPPED` with
  `Examined` 0 and a warning saying why.
- The SARIF location is the file path. It was pylint's dotted module name,
  which is not a location, so the same finding moves identity (a finding's
  location is part of its identity).

**ESLint (`eslintreport.go`, `lint.go`).** `eslintFilesLinted` reads the
report's array length per project; `eslintExamined` sums them, and says nothing
(`nil`) when the leg did not run cleanly or any project's count is unknown — a
sum over some projects would read as the whole leg's scope.

**`lintOutcome`.** A clean lint over zero files is `SKIPPED`, not `CLEAN`.
Only `CLEAN` is downgraded; it still passes.

## Why cicd counts pylint's files and not semgrep's

`say-what-semgrep-examined.md` rejects a count taken beside the tool: semgrep's
target set applies its own filters, so a directory walk would disagree with the
scan. Here the count holds because the list *is* the input: pylint is handed exactly these files and
nothing else, and the one way it can fail to read one of them — a fatal
message — turns the count off. pylint's own `statistics.modulesLinted` is not a
file count (measured: 10 for 8 files under `--recursive=y`, 2 for an empty
directory), so it is not used.

## Not changed, by design

golangci-lint and `dotnet format` report no count cheaply, so their rows keep a
nil `Examined` ("examined not stated"), which is honest. The lint rollup shows
no total across mixed units (`src/cross-cutting/evidence/concerns.go`).

## Blast radius

- Flat-layout Python consumers used to get one bogus HIGH finding. Now their
  files are linted, so real findings appear, including real HIGH ones (pylint
  `error` messages, such as a syntax error).
- pylint SARIF URIs change from module names to paths, which shifts any
  baseline keyed on them.
- A lint leg that read zero files reads `SKIPPED` where it read `CLEAN`.

## Measured end to end (`quality check --fail-on NONE`)

| Fixture | Before | After |
|---|---|---|
| `testdata/python-app` (flat) | 1 HIGH: `parse-error __init__.py`, 0 files linted | FINDINGS, 4 conventions, examined 3 files |
| scratch tree: 5 project files, a syntax error in `sub/broken.py`, plus `.venv/`, `node_modules/`, `.hidden/` | — | FINDINGS, 1 HIGH (`E0001 sub/broken.py`) + 6 LOW, examined 5 files, warning "skipped 3 .py file(s)" |
| `testdata/node-app` (ESLint) | examined not stated | FINDINGS 3, examined 4 files |

## Tests

`pylinttargets_test.go` (pruning, warnings, the script, fatal → non-run and the
path URI, `lintOutcome`, the ESLint count), and the pylint rows of
`nonrun_matrix_test.go`, now on json2 fixtures including the fatal case.
