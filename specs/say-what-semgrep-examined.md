# Say what semgrep examined

## Why

`semgrep: ✅ clean, 0 findings, examined not stated`.

Every scanner in this pipeline now reports a denominator except the one that
answers the SAST question. Trivy says how many packages it resolved, the
licence scan says how many declarations it read against how many components
exist, coverage says how many lines were coverable. Semgrep says nothing, and
"0 findings" over an unknown scope is the exact conflation `Examined` was added
to end.

The two readings it collapses are not close. "Semgrep read 1,204 files and
there is nothing" is the report. "Semgrep matched no targets and therefore
found nothing" is an outage in the SAST leg, and this repository has already
shipped that once: the module's own default ruleset was `auto`, semgrep refuses
`--config auto` while `--metrics=off` is set, and the old command turned that
exit-2 failure into an empty SARIF that read as zero findings on every
default-configured consumer. `semgrepConfigFlags` guards the cause. Nothing
guarded the symptom.

## Why not derive it

Counting the files ourselves is available and wrong. Semgrep's target set is
not a directory walk: it applies `.semgrepignore`, language detection, and the
rule set's own file filters, and a count taken beside it would disagree with
the scan by an amount that varies per repository. A denominator that does not
match the numerator is worse than none — it is a confident number that
scales the findings up or down against a scope no tool measured, with nothing
saying by how much.

So the number comes from semgrep. Its SARIF has no field for it, but its JSON
output does, under `paths.scanned`, and `--sarif-output` and `--json-output`
together emit both formats from ONE scan. The cost is a second output file, not
a second pass over the source.

## What changed

**`src/security/semgreprun.go`** — the script moved here from `sast.go`, and
`semgrepExamined` parses the count.

The script is invocation policy, which is this file's stated subject, and
`sast.go` carries `//go:build !unit_test`, so a script declared there is
invisible to the tests that pin its flags. Those tests are the point:
`--json-output` is the entire mechanism, and dropping it in a later edit would
return the module to an unstated denominator with every other test still green.
That failure has a name in this repository, and it is the reason `moduleName`
moved out of a generated file two changes ago.

The count is taken **in the container**. `paths.scanned` names every file
semgrep read, which on a large repository is the biggest document this
container produces, and nothing here wants the list — only its length. Reading
it across the Dagger boundary to call `len` on it would move megabytes for a
number that fits in five bytes.

`/tmp/semgrep.scanned` is truncated before the scan, so a semgrep that dies
leaves an empty file rather than a stale count from an earlier layer. Every
failure in the counting step lands in that same empty file: no `report.json`, a
JSON shape semgrep changed, a python that is not there. None of them fail the
scan. A run whose SARIF is good and whose accounting could not be read is still
a run, and failing the gate over a reporting gap would turn a missing sentence
into an outage.

**`semgrepExamined` returns a pointer, and that is the whole design.** An empty
or unparseable value is nil — "did not state". A count of zero is NOT nil.
"Semgrep examined 0 files" is the alarm this change exists to make visible, and
it is precisely what an `int` defaulting to zero on a failed read would be
mistaken for. The test table covers the empty file, whitespace, a python
`None`, a traceback, a negative, and a float, and each one is nil rather than
zero.

**Unit is files and there is no total.** `paths.skipped` appears only under
`--verbose`, so the run has no basis for a claim about what existed in scope,
and inventing one from a directory walk is the derivation rejected above.

**`src/security/sast.go` and `main.go`** — `runSemgrep` returns the `Examined`,
and the semgrep `toolResult` carries it.

## What this does not do

It does not change what semgrep scans, which rules it runs, or how its exit
status is classified. It does not change the SARIF. `--sarif --output FILE`
becomes `--sarif-output=FILE`, which is the same file with the same content;
what moves is stdout, which now carries semgrep's text summary rather than the
SARIF, and which nothing reads.

Verified against the pinned image — `semgrep/semgrep:1.161.0` — rather than
assumed: both flags exist, one scan writes both files, and `paths.scanned`
lists exactly the files semgrep chose, excluding the ones its own target
selection dropped.
