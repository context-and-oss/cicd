# Glossary

The words this repository uses with a fixed meaning. Most of them come from the
[engineering doctrine](./doctrine.md), where a rule is only as precise as the
vocabulary it is written in.

**Band.** The major version line of a language toolchain cicd pins an image for
— `.NET 8`, `.NET 10`, `Node 20`. A module reads the band the repository
declares (`global.json`, `.nvmrc`, a `<TargetFramework>`) and selects the
digest-pinned image for it; a band cicd does not pin is an error, never a
silent fallback to the nearest one.

**Capsule.** A short, structured record under `.capsules/` of one decision or
measurement: the question, what was measured, what was rejected and why. A
capsule is the evidence behind a sentence in a spec or a CLAUDE.md; it is
historical, never edited after the fact.

**Composite.** A Dagger module under `src/composites/` that wires stage
orchestrators and cross-cutting modules into one pre-wired pipeline with a
single `Run` entry point — `precommit`, `commit`, `dast`. Consumers call a
composite from the workflow starters under `templates/`.

**Dogfood.** Running cicd's own pipelines against this repository, so the gate
that grades consumers grades the code that implements it. The `dogfood-*`
workflows and the `composite-smoke-*` jobs are the dogfood runs.

**Envelope.** The JSON evidence document every entry function returns: who ran
(`tool`), on what (`repository`, `commitSha`, `examined`), what it found
(`findings`, `findingsBySeverity`), what it could not do (`errors[]`,
`warnings[]`), and the verdict (`passed`). The schema is
`src/internal/evidence/schema.go`; the native tool report rides inside it, never
beside it.

**Gate.** A verdict a pipeline stops on. A gate reads `passed` from an envelope
and the severity threshold from `--fail-on`; `--fail-on NONE` disables the
threshold and never the non-run check. A gate that is switched off says so in
its own envelope (`intent-gate: NOT REQUIRED …`).

**Leg.** One tool run inside an entry function, scoped to one language or one
concern — the Node lint leg, the .NET test leg, the history leg of the secrets
scan. Each leg records whether it ran; the entry function folds the legs into
one envelope, and a leg that could not run is an `errors[]` entry, not a
missing row.

**Non-run.** A tool that did not execute, or executed and produced no
readable report. It reports zero findings exactly like a clean tree does, which
is why every rule in the doctrine exists: a non-run is classified from exit
status and stderr and lands in `errors[]` with `passed=false`, whatever
`--fail-on` says.

**Shape.** What the commit pipeline builds and attests: `container` (an OCI
image from a Dockerfile), `archive` (a zip or folder from a build command), or
`none` (a library with nothing deployable). The shape is a parameter of
`commit.Run`, never auto-detected, and `none` says in its envelope which
attestations it skipped.

**Spec.** A document under `specs/` written before or alongside a fix: the
defect as measured, the mechanism that closes it, the alternatives rejected and
the traps that would reopen it. A doctrine rule links the spec that holds its
measurements; the rule is the summary, the spec is the argument.

**Stage.** One of the twelve stages of the CD model in
[the CD model](./continuous-delivery/cd-model/index.md). A stage orchestrator
(`src/stage-2`, `src/stage-4`) runs the domain modules that stage requires and
returns their envelopes; the other ten stages are on the
[roadmap](../../ROADMAP.md).

**Witnessed.** A test run cicd observed rather than trusted: `quality.Test`
runs the consumer's own command, reads the runner's output and the coverage
document it wrote, and attests per language what ran and what it covered. A
command cicd did not see the output of is not witnessed, and the envelope says
which language it witnessed, never the whole repository.
