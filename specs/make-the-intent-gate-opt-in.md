# Intent: the change-intent gate is opt-in, and says so when it was not asked

## Why

The change-intent gate ran in both stage-2 orchestrators, unconditionally. It is
the only check in that gate that does not read the code: it asks whether the
author wrote down *why* the change exists — a spec, a capsule, a `*.intent.md`, a
`.changes/` entry — and whether that artifact is coupled to the files touched.
That question gates a team practice, not a property of the artifact being
shipped, and two consequences of shipping it as a mandatory check are wrong in
different ways.

At the commit stage it is wrong structurally. Commit runs on the push that
already merged. A failure there blocks nothing the author can still amend: it
turns `main` red over a document, and because the source gate precedes the
artifact tail, the artifact that stage exists to build and scan never gets
built. Quality, SAST, secrets, dependency-vuln and risk earn their place there
because each can find a defect in the code being shipped. Intent cannot, and its
only available remedy — write the artifact in a follow-up commit — is not
available to the run that failed.

At the pre-commit stage it is wrong as a default rather than as a gate. A team
that records change rationale in the pull request body, in a tracker, or in a
commit trailer has nothing to gain from a pipeline failing over a missing file
whose format cicd chose. The teams that write these artifacts want them enforced,
which is a switch, not a policy for every consumer.

Removing it, though, walks straight into this repository's founding failure mode
from a new direction. "A tool that could not run must never read as clean"
(root `CLAUDE.md`) was written about scanners that crash and report zero
findings. An opt-in gate that is switched off produces exactly the same artefact:
an envelope with no findings, a green run, nothing in `errors[]`. Nobody deleted
a scanner and nobody wrote `|| true` — the false pass arrives through a
configuration flag instead. And it arrives retroactively for every consumer who
had the gate: the release that makes a mandatory check optional silently turns it
off for them.

## What changed

**`intent.Check` gained a `notRequired` parameter and an early return**
(`src/cross-cutting/intent/check.go`). When it is set the gate discovers nothing,
reads no diff, applies no rule, and returns an envelope built by
`buildNotRequiredEnvelope` (`src/cross-cutting/intent/main.go`) that states its
own inaction on both channels a reader has:

- machine: `genericReport.required: false`, alongside the existing `tool`,
  `version` and an empty `findings` array. The field is written on the required
  path too (`required: true`), because a field that exists only in one state is
  read as absent rather than as false by anything that predates it.
- human: the warning `intent-gate: NOT REQUIRED — change intent was not checked
  for this change (opt in with --require-intent)`. `notify` renders warnings
  verbatim into the pull request comment and there is no per-module status row it
  could contradict, so this line is what a reviewer actually sees. It is also how
  a consumer upgrading past this change discovers that a gate they had is now
  off.

A direct call still gates: `notRequired` defaults off, because a gate you invoke
by name must never be the one that quietly does nothing.

**The parameter is negative, and inverting it would break the gate.** Dagger's
generated Go client omits any optional argument holding its zero value — the
emitted guard is `if !querybuilder.IsZeroValue(opts[i].NotRequired)` — so an
optional bool can only ever be transmitted as `true`. A positively-named
`required` parameter defaulting to on could therefore never be switched off by a
caller: the orchestrator would pass `false`, the client would drop the argument,
and the gate would run anyway. The state that must survive the wire is "do not
check", so that is the one held as non-zero.

**`stage-2.Run` gained `requireIntent`** and inverts it at the call site
(`NotRequired: !requireIntent`, `src/stage-2/main.go`). Intent stays in the
returned slice either way, so the evidence count does not depend on the flag and
downstream aggregation is unchanged. `requireIntent` is also declared in
`src/stage-2/contract.json`, so removing the flag fails contract verification
rather than silently reverting the behaviour.

**`precommit.Run` forwards it; `commit.Run` does not pass it and exposes no flag
of its own.** `commit.Run` also loses its `--intent-globs` passthrough:
configuration for a gate that cannot run is a promise the composite does not
keep. The removal is documented as an amendment to
[ADR-005](../docs/decisions/ADR-005-commit-stage-code-and-artifact.md), whose
"all six checks run at every stage" symmetry this contradicts.

**Consumer surfaces expose one switch each**, off by default: the
`require-intent` input on the reusable `precommit.yml`, a commented block in
`templates/github-actions/precommit.yml`, the `REQUIRE_INTENT` pipeline variable
in both Azure DevOps pre-commit templates (passed through the step's `env:`
mapping and compared as `"$REQUIRE_INTENT"` — an ADO macro spliced into a bash
body is not contained by the quotes around it), and `CICD_REQUIRE_INTENT=1` in
both `cicd-prepush` copies. The pre-push runner prints which state it is in on
every run. Its published-module fallback pin predates the flag and will reject it
loudly, which is the correct failure: a local run that silently dropped the flag
would report a gate it never ran.

**cicd requires intent of itself.** `dogfood-precommit.yml` passes
`--require-intent`. This repository's `specs/` artifacts are how its behaviour is
argued for, and the release path generates a real intent artifact
(`scripts/ci/write-release-intent.py`) rather than being exempted from the gate —
this file exists because that gate is on.

## Also in this change

`scripts/cicd-prepush` and `templates/local/scripts/cicd-prepush` renamed their
internal `intent_diff` to `change_diff` and their log line from `Intent scope:`
to `Change scope:`. The diff they compute has scoped the risk infra scan as well
as intent since the risk gate learned to read one; naming it after a single
consumer described less than it does. `docs/how-to-guides/run-pipeline-locally.md`
follows, and its `#intent-gate-scoping` anchor becomes `#change-scoping`.

`src/composites/precommit/CLAUDE.md` dropped the parameter count from its
abridged signature, because that count had drifted from the real signature twice
(it claimed 22 against 28) and an abridged listing does not need a number to be
useful.

## Proof

- `src/cross-cutting/intent/not_required_test.go`
  (`TestNotRequiredEnvelopeIsDistinguishable`) asserts what the two envelopes
  share and what separates them: both pass with zero findings and both stay in
  the audit; only the checked run carries `required: true`, only the opted-out
  run carries a warning containing `NOT REQUIRED` and `--require-intent`, and
  `required` is read as a `*bool` so an absent field fails rather than
  defaulting. Measured green in a clean-checkout copy of the module
  (`go test -tags unit_test ./...` → `ok dagger/intent 0.221s`, 8 suites).

- Measured end-to-end against `testdata/go-app` (2026-08-12), the same pair of
  `dagger -m ./src/cross-cutting/intent call check` invocations that `ci.yml`'s
  `module-test` cell now runs:

  | | `passed` | `findingsCount` | `genericReport.required` | warning |
  |---|---|---|---|---|
  | default (gates) | `true` | 0 | `true` | `intent-gate: 1 artifact(s) checked, no violations` |
  | `--not-required` | `true` | 0 | `false` | `intent-gate: NOT REQUIRED — change intent was not checked …` |

  The first two columns are identical, which is the whole point: the verdict
  cannot distinguish these runs and the two added fields are the only thing that
  can.

- `scripts/smoke/stage-orchestrators.sh` runs `stage-2.Run` twice against a
  fixture. The default call asserts `genericReport.required is False` and a
  `NOT REQUIRED` warning; section 2b repeats the call with `--require-intent` and
  asserts `required is True` and an `artifact(s) checked` warning. A flag wired
  to nothing passes the first assertion and fails the second. Its existing
  static equivalence guard already fails if a `stage-2.Run` parameter is not both
  a `precommit.Run` parameter and forwarded in the `Stage2RunOpts{}` literal, so
  `requireIntent` cannot be exposed without being wired.

- `scripts/smoke/commit-shapes.sh` asserts, for every shape, that the audit
  carries the `NOT REQUIRED` record and that no finding has `tool == intent-gate`.
  Asserting the record rather than asserting nothing is what keeps the removal
  honest: re-enabling the gate at commit fails, and dropping intent from the
  audit entirely fails too.

- `scripts/check-ado-templates.py` caught the first draft of this change: the
  explanatory comment above the ADO opt-in quoted `REQUIRE_INTENT` in macro form
  inside a bash body, and the interpolation check refused it. The comment was
  reworded; no check was relaxed.

## The bug this change wrote and then removed

The first version of the `notRequired` doc comment explained the inversion by
quoting a default pragma as prose. Dagger's parser reads pragmas anywhere in a
parameter's doc block, so the quotation became the parameter's real default:
`// Default: true` appeared in the generated `intent.gen.go`, which switched the
gate off for every direct caller — including `ci.yml`'s own fixture cell, whose
assertion that a direct call gates would have been the only thing standing
between that and a merge. It is the same class as the change itself, one layer
down: an explanation of a switch that silently flipped the switch. The comment
now carries no literal pragma and says why it must not.
