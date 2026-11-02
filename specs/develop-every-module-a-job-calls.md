# Develop every module a job calls, not just the one it was named for

`scripts/ci/dagger-develop.sh` exists so that a `dagger develop` which could not
*fetch* stops wearing a compile error's face. It is applied to the module each
job was named for. A `dagger call` against any *other* module generates that
module's SDK implicitly, inside the call — outside the wrapper, with no
classification and no retry — so the door the wrapper closed is still open one
module over.

## Why

`v3.8.1` took three attempts to cut. Attempt 1 (a CI run on `main`)
went red in `Test src/security`:

```
Error: load package ".": package name is empty
failed to get type defs json during module sdk codegen: exit code: 1
```

The commit under test touched **zero Go files**, and CI on its
parent had passed the identical step half an hour earlier. The same
class appears in another run with different wording:

```
Error: generate type defs: cannot find default codegen GraphQLMarshaller interface in:
```

Two occurrences in twelve runs. Each read as "your module does not compile".
Neither was retried. The aggregate `ci` job is the one context the `main`
ruleset requires, so one of them stopped a release.

The step that failed is `ci.yml`'s `module-test` cell for `src/security`, which
makes a cross-module call:

```
dagger -m ./src/build call build-archive --src ./testdata/node-app … \
  && dagger -m ./src/security call scan-archive …
```

The job's wrapper ran against `"$MODULE"` — `src/security`. `./src/build` had
no develop run against it, so the CLI generated its SDK inside the `dagger
call`, where [specs/stop-losing-the-port-race.md](stop-losing-the-port-race.md)
cannot reach it.

## What the issue named, and what was actually there

The original report named one site. Enumerating every `dagger -m` against a `src/`
module in every declared workflow, and every module's dependency closure from
its `dagger.json`, found **seven**:

| Site | Call | Covered by |
|---|---|---|
| `ci.yml:601` | `src/security` cell → `./src/build` | nothing |
| `ci.yml:730` | `src/stage-2\|src/stage-4` cell → `stage-orchestrators.sh`, which calls both | one of the two, never both |
| `ci.yml:815` | `src/cross-cutting/report` cell → `./src/security` | nothing |
| `dogfood-precommit.yml:156` | → `./src/composites/precommit` | nothing — the job has no develop step at all |
| `cd.yml:210` | `dagger functions -m "./$MODULE"` over every module | nothing |
| `release.yml:152` | the same loop | nothing |

The last two are the sharpest. `dagger functions` generates a module's SDK
exactly as `dagger call` does, and that loop is the release gate: one
`sum.golang.org` stream reset there prints `FAIL: $MODULE did not load` and
aborts a release that had nothing wrong with it. That is the failure this whole
line of work started from, sitting unwrapped in the release path itself.

`scripts/smoke/commit-apps.sh:40`'s `dagger -m ./src/security` is **not** a gap:
the job develops `src/composites/commit`, and `security` is inside its
dependency closure.

## What coverage means

A module is covered when the wrapper ran against it **or** against something
that depends on it, *earlier in the same job*. Three parts, each load-bearing:

**The dependency closure counts.** `dagger develop` cannot generate a module's
bindings without loading every module it depends on, so a dependency's codegen
runs inside the wrapper and its flakes are retried. Demanding a second explicit
develop for a dependency would be noise, and noise is what the next author
deletes. A `dependencies[].source` that is not a local path is a git address —
nothing in this repository develops it — so it widens nothing.

**Order counts.** A develop below the call protects nothing: the call that runs
first is the one that pays for the codegen. A check that only asked "does this
job mention the wrapper?" would call the broken ordering clean.

**The job boundary counts.** An engine, and therefore a generated SDK, is never
shared between two jobs.

## What changed

**Seven explicit wrapper calls.** `ci.yml` develops `src/build` in the security
arm, `src/stage-2` and `src/stage-4` in the stage arm (developing the one
already developed is a no-op), and `src/security` in the report arm.
`dogfood-precommit.yml` gets a develop step it never had. `cd.yml` and
`release.yml` develop each module through the wrapper inside their validation
loop, and a develop that fails sets `FAILED=1` for that module — so a genuinely
broken module still fails the loop, and a fetch fault is retried first.

**`check_cross_module_develop`** (`scripts/repo_surface.py`, check 17) refuses
the next one. It walks each job's lines in order, tracks which modules the
wrapper has developed expanded to their closures, and names every `dagger -m
./src/X` nothing earlier covers. `$MODULE` is resolved from the `case "$MODULE"
in` arm the call sits under. A step invoking `scripts/smoke/<name>.sh` is
followed into that script, because a `dagger -m` line running there is exactly
as unwrapped as one written inline — that is how `commit-apps.sh` was
classified at all.

## Traps

**A multi-label case arm is covered by the intersection of its labels'
closures, not the union.** `src/stage-2|src/stage-4)` runs for whichever cell
matched, and `"$MODULE"` developed exactly that one. Unioning lets each label
vouch for the other's calls — which would have hidden `ci.yml:730`, the gap the
issue did not know about.

**Prose is stripped before matching.** The first version of this check read
`dagger functions -m ./src/stage-N` out of `stage-orchestrators.sh`'s header
comment and reported a module that does not exist. `#` inside quotes is left
alone, which is approximate and safe in the approximate direction: at worst a
genuine call stays visible.

**A pinned consumer reference is left alone.** `dagger -m
github.com/context-and-oss/cicd/src/quality@vX` names a module the CLI fetches from
git; no develop here could cover it, and flagging it would make the check
unusable in the one file consumers copy.

**The check cannot produce a green.** Like the classifier it defends, it only
chooses whether a failure is named. Nothing it does turns a red run green.

## Proof

`scripts/tests/test_repo_surface.py::CrossModuleDevelopTests` — thirteen cases
over a throwaway fixture repository: no develop at all, develop before, develop
after, develop in another job, a dependency of the developed module, a git
dependency, `$MODULE` with and without its wrapper, a single-label arm, a
multi-label arm, a call inside a smoke script, a comment, and a pinned consumer
reference.

Each of the three mechanisms above was mutated and the suite re-run: removing
the comment strip fails only `test_a_comment_naming_a_module_is_not_a_call`,
removing the closure walk fails only
`test_a_dependency_of_the_developed_module_is_covered`, and turning the arm
intersection into a union fails only
`test_a_multi_label_case_arm_is_covered_only_by_the_intersection`. A check whose
tests all still pass when its logic is removed defends nothing.

## Known residue

**`make develop-all` still calls `dagger develop` directly**, on purpose — a
local convenience target where the failure is visible to the person who ran it.
Unchanged from the previous spec.

**The check reads declared workflows only.** A `dagger -m` in a document, a
template, or an ADO pipeline is not covered. Templates run in a consumer's
repository against pinned module references, which no develop here could
generate; ADO templates are checked behaviourally by
`scripts/check-ado-templates.py` and use the same pinned references.

**A develop inside a composite action would not be seen.** The check does not
follow `uses: ./.github/actions/...` into the action's own steps. Nothing
currently develops from one; if something does, this check will call it a gap,
which is the safe direction.
