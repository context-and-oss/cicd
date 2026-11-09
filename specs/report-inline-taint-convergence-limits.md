# Report inline taint analyses that stopped before convergence

## Why

The pinned engine can exit zero, list every selected input and rule, and emit no
SARIF notification while its JSON timing payload reports `fixpoint_timeouts`.
These taint analyses stopped before convergence. Zero results in that situation
must not appear without a partial-coverage disclosure merely because the CLI and
catalogue look healthy.

A concurrency experiment on an independently authored smaller fixture did not
establish full-workload completion within the former adapter deadline.
That scheduling change is not included here. This is a diagnostic correction,
**not** a timeout fix or a completed consumer qualification.

## Mechanism

`src/security/semgrep_inline.py` requests documented `--time` output for the inline
invocation. It validates the specific diagnostic fields it needs and reconstructs
warning-only SARIF notices using authored text and typed locations. It never
copies an upstream diagnostic message or guesses a rule identity from that
message. The existing source maps restore original HTML paths and UTF-16 columns.

An unattributed warning is counted without a guessed location. An unknown path,
malformed diagnostic or ambiguous run is a non-run before publication. The
ordinary source scan still consumes its existing SARIF notices; this change does
not claim timing-only fixpoint visibility for that pass.

`semgrepnotifications.go` classifies the projected `Fixpoint timeout` descriptor,
counts taint scopes and distinct original files, and states that their findings
are a floor, not a complete verdict. Error-level diagnostics are not demoted.
This preserves the existing partial-parser and rule-timeout **warning** policy.
Disclosure is neither human acceptance of partial analysis nor a new severity
gate. An execution timeout remains a non-run, including at `NONE`.

Selection, full classic-script groups, independent module/template scopes,
applicable pinned rule membership, original-file counts, per-run catalogues,
source redaction and the existing publication boundary remain load-bearing.
This diagnostic projection does not itself alter scheduling or execution limits.
The current execution-lifetime policy is described in
[finish-inline-analysis-with-the-caller](finish-inline-analysis-with-the-caller.md).
No batching, retry, rule/input omission, image/rule-pin update, registry fallback,
new dependency or consumer flag is introduced.

## Validation and limits

- Python controls cover authored messages, withheld diagnostic text, Unicode and
  encoded original paths, unattributed warnings, unsupported shapes and late
  failures retaining the original SARIF.
- Go controls require the consumer-facing partial warning to name convergence
  limits and affected files without copying diagnostic prose or demoting errors.
- Real pinned-engine source/composite controls retain unsafe cross-classic-block
  flows, safe text/numeric sinks, original locations, HIGH/NONE behaviour, explicit
  custom selection and parser-source redaction.
- Diagnostic-shape regressions use independently authored synthetic metadata;
  replay of an actual engine diagnostic payload is separate private validation,
  not a public consumer fixture or a new successful scan.

Loaded-rule membership, scanned-input equality and CLI success alone do not prove
convergence. No capacity or native-qualification claim follows from these tests.
