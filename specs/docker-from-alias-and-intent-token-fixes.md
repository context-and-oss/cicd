# Intent: stop DOCKER-002 firing on multi-stage FROM aliases, and lock in the intent tokenizer fix

## Why

Two gate bugs were producing findings that describe nothing real, and a green
gate that lies is worse than no gate.

The risk gate: `src/risk/policy/infra/docker.rego` iterated every argument token of
a `FROM` instruction. The conftest dockerfile parser hands the whole argument
list to `instr.Value`, so a multi-stage `FROM golang:1.26-alpine AS builder`
arrives as three tokens and the rule judged `AS` and `builder` as untagged base
images. A full-repository `risk.Validate` therefore reported two MEDIUM
DOCKER-002 findings against a Dockerfile that is correctly pinned. Those two
phantom findings are also the reason the repo's own precommit gate could not be
tightened past HIGH.

The intent gate: its `pathToken` regex used an ordered extension
alternation with no terminal boundary. Because Go's RE2 engine matches
alternatives leftmost-first rather than leftmost-longest, `js` matched before
`json` and truncated a bare `package.json` mention to `package.js`, which then
failed to couple to the changed `package.json` and raised a false
refs-infer-coupling error on honest artifacts. The one-character fix landed
separately; what was missing was a test that fails if anyone reorders that
alternation again.

## What changed

`src/risk/policy/infra/docker.rego` now binds `image := instr.Value[0]` — the
only token in a `FROM` argument list that names an image — instead of iterating
the list. The `count(instr.Value) > 0` guard keeps the rule silent on a `FROM`
carrying no arguments rather than referencing an absent index. Every existing
DOCKER-002 behaviour is unchanged: untagged images, `:latest`, registries with a
port in the host, `scratch`, and digest-pinned references all still resolve the
same way, since the pin decision was always made about a single image string.

`src/risk/policy/infra/docker_test.rego` gains seven cases covering the parser
token shape the bug came from: a pinned image with an `AS` alias in upper and
lower case, an unpinned image with an alias firing exactly once with the alias
excluded from the reported resource, `scratch` and a digest-pinned image with
aliases, a later unpinned stage caught behind a pinned first stage, and a `FROM`
with an empty argument list. These assertions fail against the iterating
implementation, so the suite is a regression gate rather than documentation.

`src/cross-cutting/intent/rules_test.go` adds behaviour-level coverage for the
tokenizer: complete tokens for `.json`, `.jsx` and `.tsx`, unchanged `.js`/`.ts`
handling, a `.css` mention that is not clipped to `.cs`, and a
`checkRefsCoupling` table proving a bare `package.json` mention couples to a
changed `package.json` — with unrelated-diff cases as the positive control, so a
rule that never reports anything cannot pass.

`Makefile` gains a `policy-test` target and `.github/workflows/ci.yml` calls it
from `lint-repo`, blocking, because Rego assertions that nothing executes are
not a gate. The target pins the same conftest image `src/risk/opa.go` uses at
runtime, so a pass there reflects what the real gate will do. `make
policy-test` shells out to the local `docker` CLI, which this sandbox does not
have, but the identical `conftest:v0.58.0 verify` invocation was run for real
through the sandbox's Dagger engine (`dagger core container ... with-exec
conftest,verify,--policy,/policy`) against both policy directories: 9/9 pass
in `policy/findings`, 81/81 pass in `policy/infra`. Reverting only the
`docker.rego` fix and re-running the same suite against `policy/infra`
reproduces 6 failures — all six of the new multi-stage `FROM ... AS` cases —
confirming the regression suite actually depends on the fix rather than
passing vacuously. `ubuntu-latest` runners carry Docker, so `make
policy-test` itself also runs for real in CI. The same workflow now runs the
intent module's tagged unit tests in its module matrix.

`.github/workflows/dogfood-precommit.yml` raises `--fail-on` from `HIGH` to
`MEDIUM`, now that the DOCKER-002 parser fix clears the
stated blocker. See Decisions below for what is and is not measured for that
change.

## Decisions

We fixed the parser handling rather than adding a policy exception for the
Dockerfile under `testdata/go-app`, since an exception would have left the same
phantom findings waiting for every consumer with a multi-stage build.

We raised `.github/workflows/dogfood-precommit.yml` from `--fail-on HIGH` to
`--fail-on MEDIUM`, as the risk-gate report asked, once the risk-side proof
existed. That flag is a single value threaded into `quality.Check`,
`security.ScanSource`, `risk.Validate` and `intent.Check`
(`src/composites/precommit/main.go`), so raising it tightens four gates at
once.

This was measured directly rather than inferred. A real `dagger -m ./src/risk
call validate --source . --fail-on NONE` run against the repository's own
current source (real `conftest:v0.58.0` engine, not a mock) reports
`findingsCount: 0`, `infraFilesScanned: 54`, `passed: true` — the repository
carries no findings.json/decisions.json, so pass 1 is skipped with a warning
and pass 2 (the infra scan this fix touches) is the whole result. Reverting
just the docker.rego fix and re-running the same infra policy suite
reproduces exactly the two MEDIUM DOCKER-002 findings the risk-gate report describes,
which is what makes the zero believable rather than vacuous. A real `dagger
-m ./src/security call scan-source --src . --fail-on NONE` run (Semgrep +
Trivy + Gitleaks against the whole repo, including the deliberate secret and
vulnerable-dependency fixtures under `testdata`, which are `gitleaks:allow`ed
and CI-fixture-flagged respectively) also reports `findingsCount: 0`. The
`quality.Check` side was not independently re-measured full-repo — the module
auto-detects a single language from marker files in the directory it's given,
and the repo root has no single go.mod/package.json to detect against, so a
full-repo call isn't a like-for-like check the way `risk.Validate` and
`security.ScanSource` are; `src/internal`'s own `go.mod` also requires `go >=
1.26.2`, which this sandbox's toolchain (`go1.24.13`) cannot satisfy without
network access to `storage.googleapis.com` for a toolchain download, which
this sandbox does not have. If the real `--fail-on MEDIUM` dogfood run trips
on a genuine `quality.Check` finding, that finding must be fixed or explicitly
risk-accepted through the risk module's own decision mechanism, not treated as
a reason to quietly revert this threshold.
