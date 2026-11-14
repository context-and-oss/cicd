# Mark a partly read scan

## Goal

A SAST row whose parser rejected part of the tree must not render as
`✅ clean` or a plain `🔎 findings`. A consumer's scheduled run on a C#
repository showed exactly that: the parser had rejected a large share of the
files, the disclosure was one `warnings[]` line, and the row the reader scanned
said clean. The partial scan stays a **warning**, not an error or a new
Outcome. A permanent red over a parser the consumer does not control gets SAST
switched off along with its findings
([doctrine](../docs/explanation/doctrine.md#a-tool-that-ran-on-part-of-the-input-must-not-read-as-having-run-on-all-of-it)).

The same change removes a remedy the warning promised without measurement.
"a newer semgrep or the Pro engine may accept the construct" was false for the
newer OSS release cicd measured: it rejected the same files.

## Change locations and reason

- `src/internal/evidence/schema.go` (and every synced copy) — `Examined.Partial`,
  the count of examined units the tool itself named as read only in part.
  Schema 1.8.0, a minor bump: one optional property.
- `src/internal/evidence/schema.json`, `schema_version_test.go` — the property
  and the 1.8.0 shape row.
- `src/security/semgrepnotifications.go` — `partialFiles()` counts distinct
  files across parse failures and rule timeouts. The parse-failure clause no
  longer promises a remedy. Semgrep OSS's measured C# gaps — primary
  constructors and null-conditional assignment rejected, record declarations
  skipped with **no notification** — are why the engine is now Opengrep
  ([swap-semgrep-for-opengrep](swap-semgrep-for-opengrep.md)), so the clause
  names the pinned engine's own behaviour instead: one statement or member is
  skipped, or after an unbalanced brace the whole file.
- `src/security/main.go` — sets `Examined.Partial` on the semgrep row, only
  when semgrep stated its `Examined`.
- `src/cross-cutting/evidence/concerns.go` — `foldExamined` sums `Partial`. It
  is a subset of each row's `Count`, so unlike `Total` the sum claims nothing
  no tool reported.
- `src/notify/outcomereport.go`, `concernreport.go` — the Outcome cell appends
  `· ⚠️ partial scan` and the Examined cell appends `(N partly read)`.

## Bounded change

- No Outcome value, verdict, `passed` or `errors[]` entry changes.
- `Partial` counts only files a notification named. An unattributed
  notification stays in the warning and adds nothing here.
- `Partial` counts files, not lines. A file whose rejected span is one member
  and a file whose span is all of it count the same; the warning's last
  sentence says the span can be the whole file.

## Invariants

- `Partial` is omitted when zero, so producers that never set it are unchanged
  on the wire.
- The notify marker appends to the producer's outcome and never replaces it.
- The warning stays one line, and never quotes the rejected source.

## Evidence and checks

- `src/security`: `TestSemgrepNoticesPartialFiles`,
  `TestTheParseWarningDoesNotDescribeSemgrepsGaps`, and the updated
  `TestSemgrepNotificationsLanguageSplit`, which refuses the old remedy text
  and requires the whole-file case.
- `src/notify`: `TestAPartlyReadScanSaysSoInBothColumns`.
- `src/cross-cutting/evidence`: the fold case in
  `TestADenominatorIsOnlySummedWhenTheSumMeansSomething`.
- `src/internal/evidence`: the schema version gate and schema JSON tests.
