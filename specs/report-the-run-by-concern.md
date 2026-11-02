# Report the run by concern

## Why

The evidence bundle now indexes itself by concern. The report a human reads
still does not.

`comment.md` is not a side channel — `commit.yml` appends it to
`GITHUB_STEP_SUMMARY` and `notify` posts the same bytes as the pull request
comment — so it is the document. And it reports the run by the tool that ran:
eleven rows in input order, `security / semgrep`, `security / trivy
(security-source)`, `quality / golangci-lint`. Every row is accurate and the
table as a whole answers a question nobody asked.

"Is our SAST clean?" is the question. Answering it from that table requires
knowing that Semgrep is the SAST leg, that `trivy` appears twice under two
different concerns, and that `quality` owns three of the rows. That is pipeline
trivia. A customer reading the report does not have it, and the report is
supposed to be for them.

## Where the fold lives, and why not here

`notify` could group `sources[]` by `concern` itself. It has the rows and the
field.

It does not, because the bundle's `concerns/index.json` and this comment come
out of the same run and get read side by side by the same person. Two
independent folds of one set of rows drift apart the first time somebody
changes one of them, and the drift is invisible: two documents, each internally
consistent, disagreeing about SCA with nothing anywhere failing. That is the
same argument that pulled `envelopeRows` out of `main.go` one change ago, and
it applies harder here because these two documents are the ones a customer
actually sees.

So the aggregator folds once and ships the answer. `Envelope.Concerns` carries
it, `concerns/index.json` and the comment both render it, and
`TestTheEnvelopeAndTheBundleAgreeAboutEveryConcern` compares them as wire bytes
rather than trusting that they still match.

## What changed

**`src/internal/evidence/schema.go`** — `ConcernRollup` and `ConcernReport`,
and `Envelope.Concerns *ConcernReport`. `SchemaVersion` moves to **1.4.0** with
its `shapeHistory` row and its `schema.json` `$defs`.

A rollup carries counts and a verdict, never rows. The rows are already in
`sources[]` and the findings are already in `findings[]`; a second copy would
grow the largest document in the bundle to say nothing new, and it would be a
copy that can disagree with the original. `Tools` is a count for exactly that
reason — it says how many rows stand behind the verdict without restating them.

`Concerns` is nil on a module envelope and non-nil on anything the aggregator
touched, including a run whose producers declared nothing at all. That case is
an empty `answered` beside a `notAnswered` naming all ten, which is the honest
report of an unconverted pipeline. Returning nil there would say "nobody folded
this", which is a different and untrue claim.

**`src/cross-cutting/evidence/concerns.go`** — `concernRows` splits the row
gathering out of `buildConcerns`, and `concernReport` folds for the envelope
using the same gathering and the same `summariseConcern`. `names` is nil for
the envelope fold, because a consumer holding only `combined-evidence.json` has
no `parts/` directory to point into and a path to a file it cannot open is
worse than no path.

`concernEntry` now embeds `ConcernRollup` instead of restating its fields, so
the index and the envelope cannot describe the same concern differently. It
gains `examined` as a side effect, which the index should have carried anyway.

**`src/notify/concernreport.go`** (new) — the **By concern** table, above the
per-tool table rather than replacing it. The per-tool table is the detail and
stays the detail; what changes is that a reader who never scrolls past the
first table now has the summary.

Labels are presentation and nothing else: `sast` is the right thing for a
filename and a JSON enum, and neither the acronym nor a word in a table a
customer reads. A concern this version has never heard of prints verbatim,
because flattening a forward-compatible addition into silence is the same bug
as an absent row reading clean.

**`notAnswered`** renders as *"No tool in this run reported on: IaC, DAST."* —
prose, no emoji, no severity. A reader shown eight concerns cannot see that ten
exist, so an absent SAST row would read exactly like a clean one, and this
supplies the denominator the table cannot. It is not a defect list: nothing
here knows which concerns a repository OUGHT to answer, and one with no
infrastructure has no IaC leg and is not missing one. A test asserts the
wording carries no failure marker, since the temptation to promote it to a
warning is obvious and wrong.

## Two things found while looking at the rendered output

**An empty severity table.** `buildMarkdown` wrote the *Findings by severity*
heading and its column rule whenever `findingsCount > 0`, then filled it from
`findingsBySeverity`, which producers can leave empty. A run reporting twelve
findings with no breakdown published a heading, a rule, and nothing underneath.
Beside `Findings: 12` an empty severity table reads as twelve findings that are
severe in no way — the reassuring answer, and not one any tool gave. It now
says `not stated`, the same word `examinedCell` uses for an absent denominator
and for the same reason.

**`card.go` printed `Findings:` and an ungrouped six-digit count.** The markdown report has grouped
thousands since the per-tool table landed, on the grounds that `345678` and
`34567` are the same shape to a scanning eye. The Teams card was left behind,
and it is the surface most likely to be read at a glance on a phone.

## What this does not do

It does not change any verdict or any gate. It does not reorder or remove the
per-tool table. It does not touch the ADO or Teams delivery paths beyond that
one count, and no test in this repository posts to either — the outbound
protocol rule in `CLAUDE.md` stands.
