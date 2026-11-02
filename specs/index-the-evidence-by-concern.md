# Index the evidence by concern

## Why

The bundle is organised by producing module. `parts/03-security.json`,
`parts/05-quality.json`, and an index saying what each part contained. That is
how the pipeline is built, and it is the wrong axis for every question anybody
actually asks it.

"What about SAST?" is answered by one row inside `parts/03-security.json`, next
to two rows that answer entirely different questions. To find it a reader has to
already know that Semgrep runs in the same envelope as Trivy and Gitleaks. That
is pipeline trivia, and it is the last thing between this bundle and a report
somebody can send to a customer.

The two axes are not the same and neither is derivable from the other. `security`
alone answers four concerns; "tests" arrives from five runners across two
modules. The comment above `SourceStatus` has named this gap since the per-tool
split landed — *"a consumer cannot express 'SAST clean, SCA failed'"* — and
`quality/sources.go` called its own row shape *"the shape a per-concern report
needs"*. This is that report's index.

## The decision that shaped everything else

Something has to say which concern a row belongs to. The cheap way is a lookup
table in the aggregator keyed on `(module, scope, tool)`. It was rejected, and
the argument is already written in the file where that table would have lived:

> Propagated, never derived. […] anything computed here would be a guess wearing
> a verdict's clothes.
> — `src/cross-cutting/evidence/main.go`

A concern table's failure mode is silent. Add a scanner to `security` next year
and it is filed under whatever a fuzzy match returns, while the report still
reads as complete with a whole section in the wrong place. And the table cannot
even be written correctly today: `trivy` appears twice in this pipeline — `build`
runs it to GENERATE the SBOM, `security` runs it to SCAN one — and the tool name
cannot tell those apart.

So the producer declares it. That is five `SourceStatus` construction sites and
four envelope-level ones, and an untagged row is collected under
`concerns/unclassified.json` rather than dropped or guessed at.

## What changed

**`src/internal/evidence/schema.go`** — a `Concern` type, ten constants, and the
field on both `SourceStatus` and `Envelope`. Envelope-level is for a module whose
work falls under exactly one concern; a module fusing several states it per tool,
because an envelope-wide concern over a mixed set files Semgrep's verdict under
whichever concern was written first.

`SchemaVersion` moves to **1.3.0**, `schema.json` gains the `$defs/concern`
enum, and `shapeHistory` gains its row. That is not bookkeeping: this constant
sat at 1.0.0 through the addition of `Sources`, `Tests` and `Scope`, and a
consumer that believed it rendered a clean report out of absent data.
`make sync-schema` propagates the copies; `src/risk` is outside the generator and
was updated by hand, which `check-repo-surface` caught rather than trusted.

**Producers** — `security` declares SAST / secrets / SCA / licences across its
six `toolResult` sites, DAST on the ZAP envelope, SCA on the frozen-SBOM rescan.
`quality` takes the concern as a parameter to `legSource` and `brokenLegSource`
rather than reading it off `Tool.Name`; the caller is already inside the lint
branch or the test branch and knows. `risk` declares IaC, `build` declares SBOM.

**`src/cross-cutting/evidence/main.go`** — the "rows replace the envelope" rule
becomes `envelopeRows`, because the concern index needs the same answer over the
same envelopes. Two copies of that rule would eventually disagree, and the
disagreement would be invisible: a bundle whose `concerns/` counts a fused module
once and whose `combined-evidence.json` counts it three times is internally
inconsistent with nothing anywhere failing.

**`src/cross-cutting/evidence/concerns.go`** (new) — `concerns/<concern>.json`
and `concerns/index.json`.

Rows are **pointers**. Each names the part file its evidence lives in and
restates only the counts a reader scans; the findings stay in `findings.sarif`
and in the verbatim envelope. Copying them would double the bundle's largest
documents to say nothing new, and would create a second copy that can disagree
with the first.

`Passed` is the AND and `Outcome` is `worstOutcome`, the same two folds the
combined envelope uses — a concern is a subset of the same rows, so any other
fold would let the two documents disagree about one run.

`foldExamined` sums denominators only when the sum means something. Every row
must count in the same unit, because "coverable lines" plus "resolved packages"
is a number about nothing printed under a heading that implies a real total. And
every row must state one, because a sum over the three scanners that answered,
presented as the concern's denominator, understates it by whatever the silent
fourth looked at — and an understated denominator flatters the findings. `Total`
is never folded: two tools' scopes overlap in ways this layer cannot see.

Order is fixed by `concernOrder`, not alphabetical and not by findings count, so
two runs of the same pipeline produce byte-identical indexes and a week-to-week
diff means something.

**`notAnswered`** is the field that stops this directory from becoming the
failure class it was built to fix. A reader handed seven concern files can see
which seven are there; they cannot see that ten exist, so "no SAST file" reads
identically to "no SAST problem". An empty `concerns/sast.json` was the other
option and is worse — it is a document asserting SAST ran and reported nothing.

`notAnswered` is deliberately not a verdict, and the name says so. This module
cannot know which concerns a pipeline OUGHT to answer: a repository with no
infrastructure has no IaC leg and is not missing one. Calling those absences
defects would be inventing a denominator, which is the same sin one level up. The
document states the two things it knows — these questions exist, this run
answered these — and leaves the judgement to the reader who knows the project.

**`src/quality/module.go`** and the const block moved into
`src/cross-cutting/evidence/bundle.go` — both are declarations that untagged code
needs and a tagged or generated file used to own. `moduleName` lived in
`quality/schema.go`, which `make sync-schema` regenerates wholesale, and a
routine sync deleted it; only the compiler caught that. A declaration that must
survive the generator belongs outside its output, and one a test must reach
belongs outside the Dagger build tag.

## What this does not do

It does not change any verdict, any gate, or any existing file in the bundle.
`concerns/` is additive; `combined-evidence.json` and `parts/` are byte-identical
to before for a run whose producers declare nothing.

It does not group the PR comment by concern. `notify` now receives `concern` on
every `sources[]` row and can render that way, but the rendering is a separate
change with its own failure modes.
