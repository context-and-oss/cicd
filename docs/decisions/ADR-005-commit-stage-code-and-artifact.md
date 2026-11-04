# ADR-005: Commit stage scans code and artifact, any repo shape

## Status
Accepted

## Context
The commit stage scanned only the built artifact — it built an OCI image, SBOMed
it, and scanned the image. It ran no checks against source code: no lint/test,
no SAST, no source-secrets, no dependency-vuln, no risk, no intent gate. Code
defects reached `main` ungated at the authoritative stage, inverting the tier
model documented in the shift-left explanation (pre-commit is the fast PR loop,
commit the heavy authoritative gate). The stage was also container-only via
`Run`, with a bolted-on `RunArchive`; repos that build no deployable artifact
(libraries, infra/config repos) had no commit path at all.

ADR-001 committed to one composite entry point per shape (`Run` / `RunArchive`).
That clause is superseded here: shape is a runtime concern of a single stage, and
maintaining a second entry point plus its four workflow templates cost more than
one selector param. ADR-001's ownership split and its no-auto-detect rule stand.

## Decision
The commit stage scans code *and* artifact for any repo shape through one
`commit.Run` with an explicit `--artifact container|archive|none` selector.

- **Source gate** — six artifact-agnostic checks (quality, SAST, secrets,
  dependency-vuln, risk, intent) run on `src` for *every* shape via a single
  `dag.Stage2().Run()` call. This is the code coverage the stage previously
  lacked. (The intent gate was later removed from commit — see the amendment
  below; the other five are unchanged.)
- **Artifact tail** — a shape-specific scan appended after the source gate:
  - `container` — build the image (`Dockerfile`), SBOM it, scan it.
  - `archive` — run the consumer build command in a toolchain container
    (ADR-004), SBOM from source lockfiles, secrets-scan the built output.
  - `none` — no build; the SBOM comes from the source-lockfile Trivy-FS
    CycloneDX the source gate already produced.
- **Heavy tier** — commit's configs are cranked up relative to pre-commit (full
  Semgrep rulesets, opt-in TruffleHog verification, lower `--fail-on`) plus the
  artifact scan. "Heavier" is config on the same tools, not new tooling.
- **Incremental diff (amended)** — the diff is still forwarded to stage-2 for
  change-intent reporting, without making intent a commit gate. Commit explicitly
  selects `InfraScope: "tree"`: infrastructure policy scanning ignores the diff
  and evaluates the whole supported tree, not just this push's changes.

Pre-commit is **not** thinned by this change. It stays the full fast suite with
light configs for fast PR feedback; commit is the heavy tier layered on top,
running the same checks against fuller configs plus the artifact scan. The two
stages differ by configuration weight and the artifact tail, not by which checks
run. (The amendment below is the one exception to that last sentence: intent is
a pre-commit-only gate.)

The explicit selector is deliberate: cicd never auto-detects the artifact shape
or the build command (ADR-001). The consumer declares the shape.

## Consequences
Easier: code defects are gated at the authoritative stage; every repo shape —
container, archive, or none — has one commit path; `combined-evidence.json`
carries source-gate findings plus the correct artifact evidence for the shape.

Harder: hard cutover with no back-compat — `RunArchive`, the four
`commit-archive` templates, and the `commit.Run` signature change together. Safe
because this repo is the sole consumer and re-points its own pins; the version-pin
coherence gate keeps the tree consistent.

The commit composite has no step contract, so there is no contract to rework:
`commit.Run`'s signature is verified by its callers (workflows/templates) via the
workflow-pin coherence lint, not by a `contract.json`.

## Amendment: commit supports witnessed coverage and the ratchet

The original precommit-only placement in ADR-002 is superseded. In repository
mode, `commit.Run` forwards `testCmd`, `testLegs`, `coveragePath`, `baseline`,
`tolerance` and `coverageGate` to stage-2, so commit evidence can include witnessed
coverage and a ratchet verdict. Fetching a prior baseline automatically remains
caller/workflow policy, not a guarantee of this API. Missing-baseline warnings
must remain visible, and the ratchet does not replace an absolute coverage floor.

## Amendment: the intent gate is pre-commit-only, and opt-in there

The "same checks at both stages" symmetry above holds for the five checks that
examine code. It does not hold for the sixth, and shipping it at commit was a
mistake this ADR made by counting checks rather than asking what each one gates.

Intent does not read the code. It asks whether the author wrote down *why* the
change exists — a spec, a capsule, a `*.intent.md`, a `.changes/` entry — and
whether that artifact is coupled to the files touched. That question is only
actionable while the change is still under review. Commit runs on the push that
already merged: a failure there blocks nothing an author can still amend, turns
`main` red over a document, and — because the source gate precedes the artifact
tail — costs the build and scan of the artifact this stage exists to produce. A
gate whose only available remedy is a follow-up commit is not gating the change
it fired on.

So:

- `commit.Run` no longer runs intent and exposes no flag to turn it on. Its
  `--intent-globs` passthrough is gone with it: configuration for a gate that
  cannot run is a promise the composite does not keep.
- `stage-2.Run` still composes `intent.Check` — it is where the six checks live —
  but behind `--require-intent`, which `precommit.Run` forwards and `commit.Run`
  does not pass.
- In pre-commit the gate is **opt-in, off by default**. It enforces a team
  practice rather than a property of the code, and a team that records change
  rationale in the PR body or a tracker should not have its pipeline fail over a
  missing file. Teams that do write these artifacts turn it on and get the gate
  they had.

Off is stated, never inferred. An opt-in gate that is switched off produces
exactly what a gate that passed produces — an envelope with no findings — which
is this repository's founding failure mode ("a tool that could not run must never
read as clean") arriving through a config flag instead of a crashed scanner. So
`intent.Check` still runs when it is not required, and returns an envelope
carrying `genericReport.required: false` plus the warning `intent-gate: NOT
REQUIRED — change intent was not checked for this change (opt in with
--require-intent)`. Notify renders warnings verbatim, so the PR comment says it
out loud. That warning is also how a consumer upgrading past this change
discovers that a gate they had is now off.

cicd itself passes `--require-intent` in `dogfood-precommit.yml`: its `specs/`
artifacts are how its behaviour is argued for, and the release path generates a
real intent artifact (`scripts/ci/write-release-intent.py`) rather than being
exempted from the gate.

Proof and the measured Dagger constraint that forced the flag to be negative in
the module (`notRequired`) live in
[specs/make-the-intent-gate-opt-in.md](../../specs/make-the-intent-gate-opt-in.md).

## Amendment: `none` states what it left unattested

The decision above listed `none` as "no build; the SBOM comes from the
source-lockfile Trivy-FS CycloneDX the source gate already produced" and stopped
there, and the implementation matched: the `none` arm of the selector switch was
a comment and nothing else. So the shape recorded its own choice nowhere. A
commit-stage audit of a repository that ships several deployables and an audit of
a repository that ships none were byte-identical — same `passed: true`, same
`sbom.cdx.json`, same finding counts, and no statement anywhere that no artifact
had been built, SBOM'd or scanned.

That is the amendment above one paragraph over. The reasoning that made an
opt-in gate declare itself off applies unchanged to an artifact tail that did not
run: it produces exactly what an artifact tail that ran and found nothing
produces. The only difference is that the selector value is more inviting than a
flag, because `none` is also the shape a consumer reaches for when the other two
do not fit their repository. A multi-artifact repository using builders that
need no Dockerfile can have no applicable container or archive tail;
`none` then runs without attesting those deployables.

So the `none` tail is `build.NoArtifact`, an evidence function that runs no tool
and returns a **warned pass**: `genericReport.artifactAttested: false` for
machines, and for humans one warning notify renders verbatim into the PR comment
and the Teams card — `artifact: NOT ATTESTED — --artifact none was selected …`,
naming the five build/scan steps that were skipped and stating that the
`sbom.cdx.json` in the same audit directory describes source lockfiles rather
than a deployable.

Warned, not failed, for the reason `quality: NO LANGUAGE DETECTED` is a warning:
a library or an infra/config repository genuinely has nothing deployable — that
is the case `none` was added for — and `--fail-on NONE` deliberately does not
suppress a non-run, so a failure here would be a permanent red with no remedy
available to the consumer. This is disclosure, not gating.

What this amendment does **not** do: it does not give a multi-artifact repository
a shape that fits. `--artifact` still describes at most one artifact, and a
repository shipping several still has to pick one or pick `none`. The disclosure
makes that choice legible in the evidence instead of invisible; it does not make
it correct. Multiplicity is a separate decision.

Reasoning, the measured indistinguishability and the rejected alternatives are in
[specs/say-what-no-artifact-left-unattested.md](../../specs/say-what-no-artifact-left-unattested.md).

## Alternatives rejected
- Keeping the artifact-only commit stage and adding a separate source-scan stage:
  two authoritative gates to keep coherent, and the artifact/source evidence
  never merges into one envelope.
- Auto-detecting the shape from repo markers: violates ADR-001 (cicd never
  auto-detects build inputs) and makes attestation depend on heuristics.
- Per-shape entry points (`Run` / `RunArchive` / a third for `none`): the entry
  count grows with every shape, each dragging its own workflow templates — the
  cost that motivated collapsing to one selector.
