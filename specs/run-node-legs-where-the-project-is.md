# Intent: the Node legs run in the project directory, not at the mount root

## Why

`autoDetectLanguages` in `src/quality/lint.go` searched for marker files to depth 4
and returned a list of *languages*. The location it found each marker at was thrown
away. Both Node legs then mounted the tree at `/src` and ran there unconditionally,
so on a monorepo whose `package.json` lives in a nested directory the detector said "this is a
Node repo" and the runners went looking for the project in a directory that does not
contain one.

Measured with the source-owned `testdata/node-app` fixture copied into a nested
directory, with no project at the root:

```
lint node: eslint: did not run (exit 127): sh: ./node_modules/.bin/eslint: not found
test node: vitest failed (exit 1)
```

Zero findings, no coverage figure, and a red gate. The lint leg at least says what
happened, because `eslintRunError` classifies the exit status. The test leg in
`src/quality/test.go` was worse than useless: `npx vitest run` at a root with no
`node_modules` makes `npx` fetch an unpinned vitest off the network, run it against a
tree containing no tests, and report `vitest failed (exit 1)`. The message names
neither the real problem nor its fix, and the version that produced the verdict was
chosen by the registry rather than by the team's lockfile.

A solution with a front end beside it can have this layout. The gate could
not lint or test such a nested Node project at all.

## What changed

`resolveNodeProjects` feeds both legs from one marker search, so detection and
execution can no longer disagree about where the project is. `nodeProjectDirs` in the
new `src/quality/nodeproject.go` turns the search output into directories, and both
`runEslint` and `runVitest` pass each one to `WithWorkdir`.

The rule is shallowest `package.json` wins, with ties kept.

A root `package.json` therefore beats everything below it. That is what npm, pnpm and
yarn workspaces require: the root config governs the whole tree and the hoisted ESLint
lives in the root `node_modules`, so descending into each package would install
several times over and lint under configs the root overrides. Only when the root has
no `package.json` do the shallowest siblings become the projects, and equal depth then
means genuinely separate projects (illustratively, `ui/` beside `worker/`), so each is linted and
tested and the results are merged.

`node_modules`, `bower_components` and `.yarn` are excluded from the candidates. A
`package.json` inside one of those describes a dependency, and without the filter a
repository whose only `package.json` is vendored would have cicd linting the source of
its own linter. Build output is deliberately not excluded, because skipping a
directory means reporting less than the tree holds, and a repository that generates
`dist/` has a root `package.json` that wins anyway.

The directory each leg ran in is recorded in `warnings[]`, so the evidence states
where the verdict came from rather than leaving a reader to assume the root.

`src/quality/nodeproject_test.go` pins the selection, the limit, the version summary
and the coverage merge. `.github/workflows/ci.yml` builds the nested layout from the
existing fixture and asserts against real evidence.

## Decisions

**More than four projects at the shallowest depth is an error, not a truncated run.**
Each project costs its own `npm install`. Linting four of thirty and reporting no
findings from the other twenty-six is the false pass this module exists to prevent,
therefore the limit fails the gate and the message names the projects that went
unlinted along with the three ways out: point `--src` at one project, add a workspace
root `package.json`, or drop `node` from `--include`. Four covers the layouts that
legitimately have no root manifest; beyond that the repository is a workspace, which
has a root manifest and resolves to a single directory however many packages it holds.

**Coverage across projects is weighted by coverable lines.** A plain mean of 100% over
five lines and 40% over five thousand reports 70%, which clears a 60% ratchet that the
five-thousand-line project fails outright, so the mean is a false pass wearing a
percentage. Projects reporting no coverable lines carry no weight, since their
percentage is arbitrary. When every project reports zero lines there is nothing to
weight, so the plain mean stands and `coverageLines` is omitted rather than sent to
the ratchet's minimum-lines guard as a fabricated zero.

**The directory reaches the container through `WithWorkdir`, not through the shell
script.** Directory names come from a consumer's tree, and both legs build their
command as a single `sh -c` string. Splicing a path into that string is the same
defect `scripts/check-ado-templates.py` exists to catch one level up, so the path is
passed as an argument instead and never parsed by a shell.

**`tool.version` lists every distinct ESLint that ran.** Sibling projects can pin
different versions and the envelope carries one field, so naming whichever project
finished first would misattribute the other's findings. Per-project versions stay
exact on each SARIF run's driver.

## Proof

The nested fixture, before and after, with everything else held constant:

| | before | after |
|---|---|---|
| `errors[]` | eslint exit 127, vitest exit 1 | empty |
| `findingsCount` | 0 | 3 HIGH |
| ESLint reported | none | 8.57.1 |
| `coverageByLanguage.node` | absent | 75 |

The flat layout, `testdata/node-app` with its `package.json` at the root, is
byte-identical before and after: three HIGH findings, 75% coverage, no warnings. The
CI assertions were run against both recorded envelopes and against the pre-fix
envelope; the nested assertion fails on the pre-fix evidence, which is what gives it
teeth.

## Known residue

The `find` search is still capped at depth 4, so a project nested deeper than that is
invisible to detection and therefore to this resolution as well. The cap predates this
change and moving it would alter which languages get detected in every consumer
repository, so it stays as it is.

SARIF `artifactLocation.uri` values remain the absolute container paths ESLint emits,
now including the nested project directory beneath `/src/`. They were already absolute before this change, so
nothing regressed, but a dashboard rendering them shows a mount path rather than a
repository-relative one.

Sibling projects are linted one after another rather than concurrently. Each carries
its own `npm install`, so a repository with four projects pays four installs in
sequence.
