# Reach a database from a test leg

> A consumer's integration suite failed at fixture initialisation on every
> commit run because a BYO test leg had no database to talk to. The integration
> tests stayed on the consumer's own CI while the unit tests ran under cicd;
> evidence for the unit tests alone did not attest the integration suite.

Capsule CAPS-063.

## What was missing

`quality.Test` runs a consumer's own command in a container built from the
resolved toolchain image and nothing else. A suite that opens a PostgreSQL
connection gets `Connection refused` in its fixture, the suite reports the
failures, and the leg reports a failing test run — which at `--fail-on NONE`,
the setting a team onboards on, is suppressed.

There was no shape in the leg document for "this command needs something
running beside it", and the obvious workaround — mounting the runner's Docker
socket — was rejected by the consumer before it was rejected here. It hands a
consumer-authored command string root on the runner, it makes the result depend
on ambient daemon state nothing in the evidence describes, and a container
started that way is invisible to the envelope. cicd would be attesting a test
run whose dependencies it cannot name.

## The shape

`services` is a key **inside** the existing `--test-legs` JSON document:

```json
[{"label":"api","language":"dotnet","cmd":"dotnet test",
  "services":[{"alias":"db","image":"postgres:16-alpine","port":5432,
               "env":{"POSTGRES_PASSWORD":"test"},
               "readyCmd":"pg_isready -h db -U postgres","readyTimeout":60}]}]
```

That placement is most of the change's cost, and it was chosen for what it does
*not* touch. `src/quality/contract.json` declares `testLegs` as a bare
`"type": "String"`, so a new key inside the document changes no contract, adds
no Dagger parameter, needs no `check_composite_params_reachable` (check 19)
wiring, and touches neither starter surface nor either ADO template. A
`--services` flag would have needed all of them, and would have had to say which
leg it belonged to.

| key | required | rule |
|---|---|---|
| `alias` | yes | unique in the leg; lowercase `[a-z0-9-]`, letter-initial, alphanumeric-final, ≤63 |
| `image` | yes | verbatim, the consumer's own (ADR-004 level 3) |
| `port` | yes | 1–65535. **No default** |
| `env` | no | `map[string]string`; key names reach the evidence, values never |
| `readyCmd` | no | run in the **service's own image** until exit 0 |
| `readyTimeout` | no | seconds, default 60, max 300; an error without `readyCmd` |

At most `serviceLimit` (4) per leg. `testLegLimit` is 8, so the product is
bounded at 32 containers — over the limit is an error, never a truncated run,
the rule `testLegLimit` already sets.

**`port` has no default and that is the point.** Guessing 5432 from
`postgres:16` is a binding that looks configured and reaches nothing when the
image is `postgres:16` on a non-standard port, or `mcr.microsoft.com/mssql`. A
declaration cicd invented cannot be attested.

## The probe is attribution, not detection

`WithServiceBinding` is lazy at bind time, but the engine gates the **dependent
exec** on the service's exposed ports becoming reachable. Measured on Dagger
v0.20.8, a service exposing 5432 and never listening failed the dependent exec
after **2m6s**:

```
invalid nil ref / start lcb7r1364736o (aliased as db):
service exited before healthcheck
```

So the gate already existed, and so did the mechanism that turns it into a
verdict: `ran := execErr == nil` → `allRan` → `gatedPassed`. What was missing was
a way to *declare* a service, and **attribution**.

Bound straight to the leg, that engine failure lands on the leg's own test exec.
`invalid nil ref` there is indistinguishable from a suite that segfaulted, and
the `errors[]` entry would name the leg's command rather than the alias that
failed. So each service is first bound to a throwaway `alpineImage` container
running `echo`, and that exec is forced. It is gated by the **same** healthcheck
— this detects nothing the leg's own exec would not have detected — and it is
the difference between "the api leg did not run" and "service `db`
(`postgres:16-alpine`, port 5432) never became reachable".

The probe container is the pinned `alpineImage` precisely so the **bind** verdict
never depends on a consumer image having a shell.

The order is the mechanism, not a detail: every service is probed before the
leg's base container is built, and a failure returns `legOutcome{Ran: false}`
without the leg's command ever running.

## Why the failure is `errors[]` and not a warning

`gatedPassed(ran, severityOK, threshold)` returns false for `!ran` before it
looks at the threshold, so a non-run fails at `NONE`. That is the entire reason
the issue insists on it: the consumer runs `--fail-on NONE`, where a failing
test is collected and forgiven and a non-run is not. A suite that could not
reach its database did not report "no failures". It reported nothing.

A warning here would be the founding doctrine given away on the one setting
where it matters most — the same shape as `--fail-on NONE` once suppressing
`errors[]`, which this repository has already fixed once.

## `readyCmd` runs in the service's image

The approved plan said pinned alpine, on the `security/web.go` `probeReadiness`
precedent. The plan was wrong, and the worked example in the plan is what
disproved it: `pg_isready -h db -p 5432` does not exist in alpine. Neither does
`redis-cli`, nor `mysqladmin`. A readiness check confined to alpine could
express `nc -z` and essentially nothing else — the engine's port gate spelled by
hand, which is exactly the claim `readyCmd` exists to improve on.

The readiness container is a **client** reaching the service across a binding,
so the service still does not vouch for itself; what its own image supplies is
the client binary. The attribution probe stays in pinned alpine, so the split is
deliberate: the bind verdict is cicd's and runs in cicd's image, the readiness
verdict is the consumer's and runs in theirs.

`serviceReadyScript` loops until exit 0 or the timeout, writes status, attempts
and elapsed seconds to `/tmp`, and ends `exit 0` — the `probeReadiness` shape,
so the *container* succeeding is never the claim, the file it wrote is.

**There is no fallback to the engine gate.** A `readyCmd` that was asked for and
never passed is an `errors[]` entry. Downgrading it to `readyVia:
engine-healthcheck` is the `|| true` this repository refuses, one field over.

## `ready: true` means two different things, and the evidence says which

`readyVia: engine-healthcheck` means a port accepted a connection. That is a
**floor, not a verdict** — PostgreSQL's port answers before it finishes
recovery, and the suite that connects then gets `the database system is starting
up`. `readyVia: ready-cmd` means the consumer's own check passed, and it is the
only claim about readiness cicd did not invent.

`servicesSummary` states the floor in `warnings[]` — the channel
`cross-cutting/evidence` propagates into the PR comment, since it drops
`genericReport` entirely — and it fires **only** when at least one service in
the leg rested on that floor. A leg whose services all passed a declared
`readyCmd` has nothing to disclose, and a line on every run is the
`build.NoArtifact` noise rule.

## Two parsers read this document

App mode marshals `[]appLeg` straight into `quality.Test`'s `TestLegs`
(`src/composites/commit/app.go:81-86`). A key `appLeg` does not model is dropped
silently in transit, so the leg would run against nothing while the consumer's
configuration says it has a database. `appLeg` therefore models `services` field
for field, and `parseAppLegs` validates it.

The modules are isolated Go modules and cannot share a type, so the agreement is
**asserted against one corpus from both ends** rather than assumed:
`src/quality/testdata/leg-service-documents.json` holds 14 leg documents with an
expected verdict each, read by `TestLegServiceDocumentsParseAsDeclared` in
quality and `TestAppLegsAndTestLegsShareOneKeySet` in the commit composite. Two
fixtures would drift, which is the defect rather than a risk of it.

It earned its keep on the first run. `json.Decoder.DisallowUnknownFields`
refuses a key that matches **no** field, and Go matches field names
**case-insensitively** — so `readycmd` bound to `ReadyCmd` and was accepted by
quality, while `parseAppLegs`'s case-exact key map refused it. One configuration,
two verdicts, decided by which composite read it. `checkServiceKeyCase` closes
it for service keys. The leg's own keys are left alone: they have been
case-tolerant since `--test-legs` shipped, and tightening them is a breaking
change that belongs to its own decision.

`parseAppLegs` also refuses services on a **lint** leg. A lint command reads the
source and reaches nothing, so a database beside it is a container pull and a
healthcheck wait bought with nothing, and accepting the key there would make it
look supported everywhere.

## Where the code lives

`src/quality/services.go` is **untagged**: the schema, validation, the
alias→env mapping, the readiness script, the probe fold and every sentence a
service failure produces. `byotest.go` is `//go:build !unit_test` and keeps only
the container wiring. This is the split every rule in this module has had to
make — the rules that were wrong for as long as they existed were the ones
sitting in a tagged file, unreachable from `make test-module-units`.

Both mechanisms were mutated and the suite re-run: removing `services` from
`parseAppLegs`'s key map fails `TestAppLegsAndTestLegsShareOneKeySet` on three
documents, and removing `checkServiceKeyCase` fails
`TestLegServiceDocumentsParseAsDeclared` on exactly the case-variant document.

## The alias charset is stricter than a leg label

`validLegLabel` accepts `.`, `-`, `_` and uppercase. An alias cannot: it is bound
as a DNS label, where `.` and `_` are illegal, and it is upper-cased into
`CICD_SERVICE_<ALIAS>_HOST`, where `db-1`, `db.1` and `db_1` all collapse to
`CICD_SERVICE_DB_1_HOST` and would overwrite one another with no error anywhere.
`validServiceAlias` is lowercase `[a-z0-9-]`, letter-initial, alphanumeric-final.

The explicit env-prefix collision check is kept even though the charset makes it
unreachable today. It is the guard that survives someone widening the charset.

## The one thing a unit test cannot prove

Every rule above is asserted in `src/quality/services_test.go` against a
hand-built `serviceProbe`. None of that binds a container, so a binding attached
to the wrong container, an env var injected after the exec, or a probe whose
result is never read passes the entire unit suite.

`scripts/smoke/test-leg-services.sh` runs the engine, in the `module-test`
quality cell and in `make smoke`. Two cases, and what makes each one a
measurement rather than a rendering check:

The reachable case asserts through the **consumer's own command**, not through
evidence. The leg reads `CICD_SERVICE_CACHE_HOST` and `CICD_SERVICE_CACHE_PORT`
under `set -eu` and speaks Redis to them. An absent binding does not resolve, a
missing variable fails the line before `redis-cli` is called, and a wrong value
never answers `PONG`. `ready: true` distinguishes none of those from a working
bind, because cicd writes that field itself. The leg runs in `redis:7-alpine`
(its own `toolchainImage`, ADR-004 level 1) so the client is present without an
install step, and the assertions pin `readyVia: "ready-cmd"` plus the **absence**
of the engine-port floor disclosure — a line that appears on a run which made the
stronger claim is the noise that gets it ignored on the run that mattered.

The dead case is the load-bearing one, and it asserts what the leg did **not**
do: `passed: false`, an `errors[]` entry naming the alias, and
`THE-DEAD-LEG-COMMAND-RAN` absent from the envelope. Both cases also grep the
serialised document for the service's env **value** — the field that leaks is the
one nobody thought to parse, the `dotnetKeepOutput` rule.

Measured, `alpine:3.20` exposing 5432:

```
byo-test: service db (alpine:3.20) never became usable on port 5432: invalid nil
ref start jt8781dmim0ci (aliased as db): service exited before healthcheck …
The leg's command did not run, so this is a non-run rather than a failing test —
at every threshold, NONE included.
```

The JSON is built with `jq -n`, not string concatenation. The first version of
the script spliced the quoted shell command by hand, its inner double quotes
closed the JSON string, and the module refused the document before a single
container started.

## Cost

A service that stays up and never listens costs about **two minutes** before the
run reddens, and that budget belongs to the **engine's** healthcheck. cicd did
not choose it and exposes no knob for it — stated here rather than implied, the
discipline `tell-a-dead-zap-from-a-clean-one` applies to `-T`.

A service whose container *exits* is cheap: the smoke's `alpine:3.20` case
reddens in under two seconds, because the engine reports a dead container rather
than waiting out a silent one. The expensive shape is the image that starts,
stays running and never binds the declared port — a wrong `port`, or a database
that dies during initialisation while its supervisor lives.

## Residue

- **The engine's healthcheck timeout is neither configurable nor recorded.**
  `waitedSeconds` is measured for `readyCmd` only; the ~2m the engine spends
  before failing a bind is not in the envelope. A consumer reading a red run sees
  the alias and the message, not how long it cost.
- **`legReport.services[]` does not reach `combined-evidence.json`.**
  `cross-cutting/evidence` drops `genericReport`, so the per-service structure is
  audit-bundle-only and the PR comment gets the `errors[]`/`warnings[]` sentences
  alone. Same constraint every producer in this repository works under; not
  changed here.
- **A service is bound for the whole leg, not for part of it.** A suite needing
  a database for 3 of 200 tests pays the pull and the wait for all 200. Splitting
  a leg is the consumer's lever.
- **`build.BuildArchive` still cannot declare a service.** An archive build that
  needs a database to generate something is out of scope, and that function
  returns a `*dagger.Directory` with no `warnings[]` to say so — the same residue
  `name-the-version-file-cicd-could-not-use` recorded.
