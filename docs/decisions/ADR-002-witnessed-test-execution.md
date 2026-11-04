# ADR-002: Witnessed BYO test execution, precommit-only

## Status
Accepted; the precommit-only placement below is superseded by the current-support amendment.

## Amendment: witnessed tests also run at commit

In repository mode, `commit.Run` now forwards `testCmd`, `testLegs`,
`coveragePath`, `baseline`, `tolerance` and `coverageGate` to `stage-2.Run`.
Both precommit and commit can therefore produce witnessed coverage and run the
ratchet. The original placement and no-commit-coverage consequences below record
the earlier rationale, not a current API restriction. Automatic baseline retrieval
is a separate workflow policy; API support does not establish that a caller fetches
or supplies a baseline. A ratchet is not an absolute minimum-coverage gate.

## Context
Compliance requires demonstrating test results and coverage trend as evidence.
Lint and build success were judged evidence-irrelevant; test pass + coverage are
not. Self-reported numbers (consumer hands cicd a report file) are weak
attestation: "a JSON file said 87%". The existing `quality.Check` runs vanilla
test commands (`npx vitest run` with no repo orchestration, deps installed with
`--ignore-scripts`), so its coverage number is not the number a sophisticated
repo recognizes as its coverage — evidence of the wrong number is worse than no
evidence.

## Decision
cicd executes the **consumer's own test command** (`Quality.Test(testCmd, ...)`)
in a cicd-controlled toolchain container and harvests normalized coverage
(v8 json-summary, go coverprofile, pytest-cov JSON, cobertura XML) into the
evidence envelope. The consumer owns the test *definition*; cicd owns the
*execution and attestation* — the same split the Dockerfile already proved.

Placement: **precommit (stage-2) only.** The ratchet gates PRs where developers
can react; the per-PR evidence chain is the coverage trend record. The commit
stage stays artifact-focused (build/SBOM/scan/DT) and `stage-4` is untouched.

`Check` survives unchanged as the auto-detect baseline for config-less repos,
gaining only an optional `lintOnly` flag so a repo supplying `testCmd` keeps the
baseline lint without a redundant vanilla test run.

## Consequences
Easier: compliance-grade witnessed attestation; consumer keeps config truth and
local/CI parity; single test execution per PR; additive v1.x release.
Harder: cicd owns toolchain runtime concerns (version resolution — ADR-004);
the commit-stage bundle carries no coverage (the trail lives in PR runs that
admitted each merge).
Committed to: report ingestion stays out unless an auditor demands envelope-level
results for merge commits; if that day comes, ingestion is additive (a new
envelope source), not a rework.

## Alternatives rejected
- Report ingestion (consumer runs tests, cicd wraps the report): self-reported
  evidence, JUnit-dialect swamp, per-format integration surface.
- Both-stages execution: every merge pays the full suite twice for marginal
  audit gain.
- Commit-only: ratchet failures discovered after merge — broken main on
  coverage dips.

## Amendment (2026-08-17) — one leg per language

The original decision said "the consumer's own test command", singular, and the
implementation took it literally: one `--test-cmd`, one container, one
`--coverage-path`. The container came from `langs[0]`, the first entry of the
fixed order `go, node, python, dotnet` in `autoDetectLanguages`. On a polyglot
repository — a `package.json` and a `.csproj` side by side — that made an enum's
ordering decide which stack got tested, and the other stack was simply not
tested.

The defect worth an amendment is not the missing capability. It is that the
resulting envelope listed **every detected** language under `languages` and
reported `passed=true`, so a run that witnessed half the repository was
byte-indistinguishable from one that witnessed all of it. That is the
"a tool that could not run must never read as clean" doctrine arriving through a
surface limitation instead of a crashed scanner.

Amended decision: `Quality.Test` accepts **either** `--test-cmd` (one command,
unchanged) **or** `--test-legs`, a JSON array of legs, each carrying its own
label, language, command, and optional coverage report and toolchain image. The
two are mutually exclusive and setting both fails the run. The polyglot form is
threaded through `stage-2` and both composites, and exposed as the `test-legs`
input on both reusable workflows.

The reporting half is the part that must not be traded away later:

- `languages` in the Test envelope lists what was **witnessed**, not what was
  detected.
- A `genericReport` (`genericFormat: byo-test-legs`) carries the
  detected / witnessed / unwitnessed language triple plus a per-leg record
  (label, language, image, ran, exit code, coverage) — structure a machine can
  read without matching prose. The leg's *command* is deliberately absent: it is
  consumer-authored text that can carry an inline credential.
- An unwitnessed detected language always emits a `byo-test: NOT WITNESSED …`
  warning, which notify renders verbatim into the PR comment.

That last one is a **warning, not `passed=false`**, and the justification is the
`gatedPassed(ran, severityOK, threshold)` contract: `ran` means the work cicd was
asked to do could not be done, and it fails at every threshold including
`--fail-on NONE`. A language nobody asked to be tested is not that case — it is
`lintLanguage`'s existing "nothing was asked of a tool, so nothing failed to run"
(`ran=true`), and it is how the intent gate reports being switched off. Failing
instead would turn a version bump red for every repository with an incidental
marker file, which trades one silent wrong answer for a loud one.

Also decided, and cheaper to keep than to relitigate:

- Coverage is keyed on the **language**, never the leg label. `coverageByLanguage`
  is the only shape `parseBaselineCoverage` accepts and the baseline is a previous
  run's `combined-evidence.json`, so label keys would compare this run against a
  document that has none — a ratchet silently comparing nothing (ADR-003).
  Legs sharing a language are combined by coverable-line weighting, the same rule
  the multi-project Node lint leg already uses; per-leg figures survive in the
  `genericReport`.
- A leg's `language` accepts only the four canonical values, not the `--include`
  aliases, because the value is also that coverage key.
- Legs are capped at 8; a ninth is an error, never a truncated run. They run
  sequentially by default; `parallelism` (1–4) bounds the legs in flight, and
  the evidence is folded in declaration order either way.

Alternatives rejected are recorded in
[.capsules/CAPS-008-witness-every-language.capsule.yaml](../../.capsules/CAPS-008-witness-every-language.capsule.yaml).
