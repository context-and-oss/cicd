# A runner that never started is not a failing suite

## Intent

`gatedPassed` lets `--fail-on NONE` pass a suite that ran and failed, and fails
a leg that never ran. The rule is only as good as the leg's `ran` flag, and the
auto-detected test legs set it from one fact: the runner exited with a number.
Any number. So every exit a runner uses for "I produced no result" read as a
failing suite, and NONE passed it.

Measured by running the commit composite on three public repositories:

- **python-poetry/cleo.** Its `conftest.py` imports `cleo`. The auto Python leg
  installs pytest and pytest-cov, never the project, so pytest exited 4 having
  run nothing. The quality envelope read `passed: true` beside
  `pytest failed (exit 4)`.
- **changesets/changesets.** A pnpm workspace. The leg's `npm install` failed
  and was swallowed by `|| true`; `npx` then fetched a vitest nobody pinned,
  which could not load `vitest.config.ts` and printed a *Startup Error*. Vitest
  exits 1 for that and for failing tests alike, so it read as
  `vitest failed (exit 1)`.
- And, found while fixing the first: the Python leg chained
  `pip install pytest && …; echo $? > /tmp/pytest.exit`, so a pip that could
  not install pytest wrote pip's exit into pytest's sentinel.

## Chosen approach

The decision stays in `foldTestLeg`'s callers, per runner, because only the
runner's own contract says which statuses carry a result
(`src/quality/testlegrun.go`):

- `pytestNonRun`: pytest's documented exits 2, 3, 4 and 5 become non-runs that
  name the status. Only exit 1, `TESTS_FAILED`, is a suite that ran and failed.
  Exit 2 covers an interrupt as well as a collection error; a suite stopped
  part way is a run on part of its input and must not read as all of it.
- `vitestNonRun`: a non-zero exit with no `Tests` summary line is a non-run. A
  vitest that executed tests prints the summary, failing or not.
- `pytestScript` and `vitestScript` record what the install exited with
  (`/tmp/pip-install.exit`, `/tmp/node-install.exit`). pytest runs only after a
  successful install, and a failed npm install is named as the likely cause of
  a vitest that never started.

A non-run carries no exit code. That is how every reader tells it apart from a
failing suite, so the reclassified leg drops the code with the result.

Both messages name the witnessed test leg (`--test-cmd`) as the remedy: the auto
Python leg installs with pip only, and a repository whose suite needs its own
install (Poetry, PDM, Hatch) needs to say how. The Node legs have since learned
pnpm and yarn; see below.

## Rejected

- **Install the project in the auto Python leg** (`pip install -e .`). It would
  have made cleo pass, and it guesses: Poetry, PDM, Hatch and plain
  requirements files install differently, and a guess that half-works produces
  a suite that ran on part of its imports. The witnessed leg already runs the
  consumer's own command.

  Re-examined after the open-source runs (cleo, changesets, MediatR) and kept
  rejected, now for three reasons rather than one:
  1. *No single installer.* Poetry, PDM, Hatch, uv and requirements files
     resolve differently, and cleo needs Poetry to install itself. Picking one
     is a guess, and a wrong guess is a suite that ran on part of its imports,
     the exact non-run this spec exists to name.
  2. *Arbitrary build code.* Installing a Python project runs its build
     backend (`setup.py`, a PEP 517 hook), which is the consumer's code running
     inside a leg cicd attests as its own. The Node legs turn lifecycle scripts
     off (`--ignore-scripts`); pip has no equivalent for building a project
     from source.
  3. *No feed credential.* A private index needs a credential cicd has no
     input for on this leg, so a private dependency would fail the install and
     read as the project's fault.

  The witnessed leg (`--test-cmd`) answers all three: the consumer's command,
  in the consumer's toolchain, attested as theirs.
- **Detect pnpm and yarn in the auto Node legs.** A larger feature with its own
  pinning questions (corepack, the package manager's version). Recorded, not
  done here; done since in
  [install-with-the-projects-package-manager.md](install-with-the-projects-package-manager.md).
- **Treat any non-zero vitest exit as a non-run.** Then a failing suite would
  fail at NONE, which is the opposite error.

## Expected result

Run on the same three inputs at `--fail-on NONE` after the change: cleo and the
`go-app` fixture under `--include python` report `passed: false`, outcome
`ERROR`, naming pytest's exit 4 and exit 5; changesets reports
`vitest: did not run (exit 1 with no test summary)` and `npm install exited 1`.
The positive controls `testdata/python-app` and `testdata/node-app` still pass,
each with one test counted.

`src/quality/nonrun_matrix_test.go` holds each status at every threshold, with
controls proving exit 1 with a result is still a failing suite NONE may pass.
`scripts/smoke/non-run-matrix.sh` asserts the new pytest wording end to end.

## Closed since

- **The ESLint leg records its install and gives the advice that fits.**
  `eslintScript(install bool)` writes the install's exit to
  `/tmp/node-install.exit` instead of `|| true`, and the prepared path, which
  runs no install, is a builder argument rather than a `strings.TrimPrefix` of
  the install line that silently re-installed if the literal drifted. On exit
  127 `eslintRemedy` branches on that exit: failed → "npm install exited N …
  fix the install"; clean → add eslint to `devDependencies`; absent (prepared)
  → it says it cannot see the install and names both. Any other non-run after a
  failed install names the install as the likely cause. ESLint now resolves as
  `npx --no -- eslint`: measured in the pinned node:20-alpine, an npm workspace
  member declaring eslint 9.39.1 had it hoisted to the root, and
  `./node_modules/.bin/eslint` in the member exited 127, which the old remedy
  answered with "add eslint to devDependencies". Not reachable through today's
  detection, which lints only the topmost `package.json`; it is once a leg runs
  in a member, and it is the resolver vitest uses. With no eslint anywhere,
  `npx --no` exits 1 — ESLint's own "found problems" — so the script checks the
  version first and writes 127 itself.

- **vitest is never fetched.** `vitestScript` runs `npx --no -- vitest`, which
  resolves the project's vitest the way node does (up through a workspace
  root) and refuses the registry. The version is read into
  `/tmp/vitest.version` before anything else installs a package; empty means
  no vitest, the script runs nothing, and `vitestNonRun` reports "vitest is not
  installed in this Node project, and cicd does not fetch one", with the
  install's exit and remedy when the install failed. The coverage provider is
  installed as `@vitest/coverage-v8@<that version>`, never unversioned.
  Measured in the pinned node:20-alpine: an npm workspace member whose vitest
  is declared at the root installs none from the member, and the old script
  then fetched vitest 4.1.12 and tested the tree with it.

- **A vitest file that could not load is not a failing test.** vitest lists a
  file it could not import, or whose `beforeAll` threw, under `Failed Suites`,
  exits 1, and counts only the tests of the files that loaded. Measured on
  changesets after the pnpm install landed (node:24-alpine, pnpm 11): 21 of 39
  files failed to resolve a workspace package that builds itself in
  `postinstall`, which `--ignore-scripts` skips, and the summary read
  `Tests 129 passed (129)`. The leg said `vitest failed (exit 1)` and the
  coverage warning blamed the report. `vitestSuiteNonRun` (`testlegrun.go`)
  makes any `Failed Suites` block a non-run that ran on part of the suite: it
  names the files (sorted, deduped, first 10 by name), quotes vitest's own
  count against the `Test Files` total, quotes the counts of the files that
  ran as a partial result and withholds them from `tests`, and quotes none of
  the files' errors, because one line of a long log is a claim. Beside a real
  failing test it is still a non-run, the rule `goTestNonRun` applies to a Go
  package that did not build: NONE may suppress a failing test, never a
  suite that did not all run. The native leg adds that cicd installs with
  lifecycle scripts off and names `--test-cmd` as the leg that can build; a
  BYO node leg gets the same classification without that sentence, since its
  install is the consumer's. With the provider in place, the coverage warning
  now says the suite did not pass and that vitest writes no report for such a
  run (`coverage.reportOnFailure`, off by default); cicd does not turn it on,
  since coverage of a failed run is not a measurement of the suite.
  Residue: vitest exit 1 with every test passed and only an unhandled error
  still reads `vitest failed (exit 1)`; its outcome is ERROR and it fails at
  NONE, so only the wording is generic.

## Still open

- **pytest itself is unpinned.** `pytestScript` (`src/quality/testlegrun.go`)
  runs `pip install pytest` and `pip install pytest-cov` with no version, and
  the envelope records `Tool.Version: "latest"`, which names no version a
  reader can reproduce. The install's exit is recorded, so a failed install
  is a named non-run; what is not recorded is which pytest ran. Closing it
  means pinning both where Renovate can move them and reporting the version
  pip installed, the way the golangci-lint leg reports the version that ran.
  Not done here: it changes no verdict, only the reproducibility of one.
