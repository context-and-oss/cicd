# Intent: the Node lint leg runs the consumer's ESLint, not cicd's opinion of one

## Why

`src/quality/lint.go` ran this:

```
npx eslint --format json --no-eslintrc --env browser,node,es2021 --rule '{"no-undef":"error"}' .
```

Two defects in one line.

**It ignored the repository being linted.** `--no-eslintrc` discards the consumer's
config: their plugins, their rule set, their severities, their per-directory
overrides. What ran instead was a single rule cicd picked. A team could have a
carefully maintained ESLint setup and a green cicd gate that had never consulted it,
and the evidence envelope named the tool `eslint` without saying that almost none of
their configuration participated.

**On ESLint 9 it could not run at all.** `--no-eslintrc` and `--env` were removed in
the flat-config release. Measured against 9.39.5, that command exits 2 with an empty
report; against 8.57.1 it works. Any consumer on a current ESLint therefore had a
Node lint leg that produced nothing. `eslintRunError` (added earlier) does now catch
the exit-2 case, so this is no longer a silent pass — but "reliably fails" is not the
goal either.

## What changed

The command is now `./node_modules/.bin/eslint --format json .` — no config flags, so
ESLint resolves configuration the way the repository intends, on either config era.

`npx` is gone on purpose. When a repo has no ESLint dependency, `npx` fetches one from
the network, so the gate's verdict would come from a version nobody chose and could
change between runs with no change in the repository. `node_modules/.bin/eslint` is
the version the team's lockfile pins. When it is not there the shell exits 127 and
`eslintRunError` reports it, with the fix in the message rather than in a container
log that is gone by the time anyone reads the evidence: add ESLint to
`devDependencies`, point `--src` at the directory holding `package.json`, or drop
`node` from `--include`.

Since then the binary is resolved as `npx --no -- eslint`, which never fetches but
does find an npm workspace member's ESLint hoisted to the root, and the 127 remedy
follows the install's recorded exit; see
[a-runner-that-never-started-is-not-a-failing-suite.md](a-runner-that-never-started-is-not-a-failing-suite.md).

The version in the envelope and in the SARIF driver is now whatever
`eslint --version` reported (`eslintVersionLabel`), or the literal `unknown`. The
constant `eslintVersion = "8.57.0"` is deleted from `src/quality/images.go`: it
attributed every finding to a build that never executed, and an unknown version is a
fact worth recording rather than a blank to fill with something plausible.

`eslintStderrMessage` replaces `lastNonEmptyLine` for crash output, because ESLint
prints its banner first and a documentation URL *last* — taking the final line gave
"https://eslint.org/chat/help to chat with the team." while the diagnostic sat in the
middle. The four layouts it handles (missing flat config, missing legacy config,
unresolvable rule, missing binary) are measured, and each appears verbatim in
`src/quality/eslintreport_test.go`.

## Decisions

**A JS repo with no ESLint now fails instead of passing.** This is a behaviour change
for consumers and the sharp edge of the change, so it is stated rather than buried.
Before, such a repo got cicd's one-rule lint and a green leg; now it gets an error
with a remedy. The alternative — treat "no ESLint here" as not-applicable and skip
the leg — needs a *skipped* concept the evidence schema does not have, and until it
exists the only way to express a skip is `passed=true` with zero findings, which is
the exact shape this repo forbids: a leg that did not run must not read as clean.
Whether to add that concept to the schema is a larger call than this change.

**Findings will change, sometimes a lot.** Running a real config on a repo that has
only ever seen `no-undef` can surface plenty. `--fail-on NONE` collects without
failing, which is the migration path for a consumer who wants to see the volume
before gating on it.

**Rule severities stay ESLint's.** Severity 2 maps to HIGH and severity 1 to MEDIUM,
unchanged. cicd does not reinterpret how a team graded its own rules.

## Known residue

**Yarn PnP gets the wrong advice.** A repository using Plug'n'Play has no
`node_modules`, so the shell exits 127 and the remedy tells them to add ESLint to
`devDependencies` — which they already did. They would need `yarn eslint` or a
`--toolchain-image` that shims it. The failure is loud and the message is wrong,
which is the acceptable half of the trade; detecting PnP is not attempted here.

**`testdata/node-app` reports three HIGH findings, before and after this change.**
Measured with its own ESLint 8.57.1: `test` and `expect` are undefined in
`index.test.js` because the fixture never tells ESLint about Vitest globals, and
`vitest.config.js` is a parse error because `.eslintrc.json` sets no
`sourceType: module`. Both commands produce exactly the same three, so this change
moves nothing in CI — but the fixture is the Node example consumers copy, and its
config does not lint its own files. Repairing it is a separate change with its own
blast radius, since finding counts there are what other assertions would be written
against.

**Nothing in CI checks the quality gate's verdict.** `Check` returns an envelope with
`passed:false` and no Go error, so `dagger call check` exits 0 either way, and the
`module-test` cell for `src/quality` makes no assertion about it. That is why the
three findings above have never turned anything red. Out of scope here, but it means
the Node leg's gating is currently unproven by the pipeline.

The `quality` module still installs golangci-lint 1.57.2 while `src/internal/.golangci.yml`
is v2 schema, and `lint.go` passes the v1 `--out-format sarif` flag. That is the Go
leg, a separate inconsistency, and not touched here. *(Closed by
[prove-the-go-lint-leg-ran.md](prove-the-go-lint-leg-ran.md): that combination meant the
Go leg had never run on any repository, and the `|| echo` fallback made it read as
clean.)* `pylintVersion` remains a
hand-pinned constant with no Renovate coverage, because `make check-image-pins` only
walks `From(...)` references and a pip package inside an image is not one.
