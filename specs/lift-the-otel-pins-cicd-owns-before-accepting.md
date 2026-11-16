# Lift the otel pins cicd owns before accepting what it cannot

An acceptance is for a fix cicd cannot pin. When an advisory names three
packages and cicd can pin two of them, accepting all three is a suppression
wearing an acceptance's clothes.

## Why

GHSA-q7gw-24fr-5p69 (CVE-2026-128085, MEDIUM) was published on 2026-11-13. It
names `go.opentelemetry.io/otel/sdk`, `go.opentelemetry.io/otel/trace` and
`go.opentelemetry.io/otel/sdk/log`, all fixed at v1.47.0, and this repository
builds every one of its fifteen modules against v1.46.0, v1.46.0 and v0.16.0.
The last green "Precommit on self" run was on 2026-11-11; from 2026-11-16 every
run on `main` and on every open pull request reported the advisory three times
per `go.mod`, 45 MEDIUM rows at `--fail-on MEDIUM`, and nothing in the tree had
changed.

The three packages are held by three different hands, which is the whole
reason this is not one more line in `--vuln-accept`:

| package | held at | held by |
|---|---|---|
| `otel/sdk/log` v0.16.0 | a `replace` line `dagger develop` copies from `dagger.io/dagger`'s own go.mod on every run | Dagger's codegen (CAPS-058 d02) |
| `otel` core v1.46.0 | a `replace` line this repository wrote, because core v1.47.0 and log v0.16.0 form an import cycle | cicd, forced by the line above (CAPS-064) |
| `otel/trace` v1.46.0 | the same module-owned `replace` block, pinned beside core | cicd, by choice |
| `otel/sdk` v1.46.0 | the `require` block | cicd (CAPS-070) |

The first question was whether a `DAGGER_VERSION` bump removes the codegen pin,
since that is the removal condition every existing otel acceptance is keyed to.
It does not. The Go SDK's go.mod at v0.21.9, v0.21.10, v0.21.11 (the current
release) and on `main` all carry the same four `replace … v0.16.0` lines for
`otel/log`, `otel/sdk/log`, `otlploggrpc` and `otlploghttp`; that block is what
codegen writes into every module. A Dagger bump today changes the engine and
leaves every one of these rows where it is.

The second question was what cicd can move on its own, measured on
`src/quality/go.mod` with the generated client present:

- `go get go.opentelemetry.io/otel/sdk@v1.47.0` moves `otel/sdk` and, with it,
  `otel/sdk/metric` to v1.47.0. The module builds and vets against core held at
  v1.46.0, and a `dagger develop` afterwards leaves go.mod byte-identical,
  because the require block is not codegen's to rewrite.
- Moving the module-owned `replace` for `otel/trace` to v1.47.0 builds and vets
  the same way, because the cycle CAPS-064 records runs between core's
  `internal/global` and `otel/log`, and trace is on neither side of it. Develop
  leaves module-owned replaces alone (CAPS-064 d01), and a second develop left
  go.mod and go.sum byte-identical.
- `otel/sdk/log` cannot move. The replace line is rewritten on every develop,
  and CAPS-058 d02 measured what committing a higher version anyway produces: a
  go.mod that advertises a version the build does not use.

So 30 of the 45 rows have a pin that holds, and 15 do not.

## The mechanism

Every module's go.mod moves `otel/sdk` to v1.47.0 in the require block and
`otel/trace` to v1.47.0 in the module-owned replace block, with a comment above
the trace line saying why it differs from the core and metric lines beside it.
The same script applied the change to all fifteen modules, then ran
`dagger develop`, `go build ./...`, `go vet .` and a second `dagger develop`
in each, refusing any module where the build failed or the second develop
changed a byte.

`.github/workflows/dogfood-precommit.yml` gains a fourth `--vuln-accept` line,
for CVE-2026-128085, in the same shape as the three above it: the package and
version it covers, the codegen replace line that holds it there, the exposure
argument, and the removal condition. The reason states that `otel/sdk` and
`otel/trace` are at v1.47.0 in every go.mod and must not appear among the rows
the acceptance covers, so the `VULN ACCEPTED — … covered N finding(s)` warning
line is readable as a count: fifteen rows, one per module, all naming
`otel/sdk/log`. A sixteenth row, or a row naming another package, is a
regression the warning line shows rather than one the acceptance hides.

The removal condition is a `DAGGER_VERSION` bump whose codegen emits
`sdk/log >= 1.47.0`. The log modules skipped from the v0.x line to v1.47.0 in
this release, so the condition is written against the version the advisory
names as fixed, not against the v0.17.0 that follows v0.16.0 numerically and is
still inside the vulnerable range.

The exposure argument, for the record: the bypass lets an attribute value made
of U+FFFD runes exceed the configured length limit on a span or log record. The
only records these modules emit are the Dagger engine's own telemetry about the
module's execution, delivered to the engine on the runner, so the worst case is
an oversized attribute inside one CI run's trace, with no data leaving the run.

## Rejected

**Bump `DAGGER_VERSION` to 0.21.11.** Measured against the SDK's go.mod at that
tag: the four log replace lines are unchanged, so the bump would move every
workflow's engine for no change in any of the 45 rows or the three existing
acceptances. It stays the right removal condition and the wrong fix today.

**Accept all three packages under one line and move nothing.** Cheapest diff:
one workflow file. Rejected because the acceptance would then cover thirty rows
cicd can clear, and the warning line that is supposed to make a regression
visible would read "covered 45 finding(s)" on the day the fix landed and on the
day it quietly came undone, with no way to tell the two apart.

**Move `otel/sdk/log` by committing a v1.47.0 replace line anyway.** CAPS-058
d02 already measured this: codegen rewrites the line per module on every
develop, so the repository ends up reporting one package at two versions
depending on which job developed which module.

**Lift core to v1.47.0 as well.** It does not compile; the import cycle with
`otel/log` v0.16.0 is the reason the CAPS-064 pin exists, and the log pin is
codegen's.

## Traps

**Pinning trace beside core again for uniformity.** The core and metric lines
say v1.46.0 and the trace line says v1.47.0, and a reader tidying the block
would make them agree. The comment above the trace line is there to stop that;
if it goes, the fifteen trace rows come back under an acceptance whose reason
says they must not, and only the covered-rows count in the warning would show
it.

**Reading the acceptance's row count as noise.** The reason names the expected
shape: fifteen rows, `otel/sdk/log` only. The warning line is the one place a
regression in the other two packages surfaces while the acceptance stands, and
it surfaces as a number. The number is the signal.

**Renewing the acceptance when the removal condition lands.** A Dagger release
whose SDK moves its log replace to v1.47.0 or later makes this line go UNUSED
on the next dogfood run, together with the three above it, because all four
sit on the same codegen-owned block. Delete all four then; a renewed acceptance
for a fixed finding is a standing permission for the identifier to return.
