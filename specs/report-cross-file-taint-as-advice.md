# Report cross-file taint as advice

## Why

`ScanSource`'s Opengrep pass follows taint inside one function. A request
parameter handed to a helper, in the same file or another, and concatenated
into SQL there is not found. Hosted code-scanning products that follow data
across the whole program find it, so a consumer replacing one with cicd loses
that finding class unless cicd follows it too.

Opengrep 2.0.0 has an interfile mode (`--enable-interfile`) that does. In the
pinned semgrep-rules commit, 27 of the audit and OWASP rules carry
`options.interfile: true`: 6 Go, 7 Java, 14 JavaScript/TypeScript, and none for
C#. Only those rules change behaviour under the mode.

## Measured

Pinned Opengrep 2.0.0 and pinned rules, on the fixture below:

| Flow | Single-function | Interfile |
|---|---|---|
| source and sink in one function | found | found |
| sink in a helper in the same file | not found | found |
| sink in a helper in another file | not found | found |
| a chain five calls deep, default depth 3 | not found | not found, `SemgrepWarning` names the rule and depth |
| the same chain, `--interfile-depth=-1` | not found | found |

The same for Go (`tainted-sql-string`), Java (Spring `tainted-sql-string`) and
JavaScript (`express-sequelize-injection`). For C# the mode changes nothing:
no C# rule opts in.

The cost, on public trees with the full pinned packs:

- **A mid-sized Go repository** (~400 Go files): 6 s and ~1 GB peak became
  83 s and ~3 GB, with no finding added or lost.
- **Smaller Go and JavaScript repositories**: under twice the time, no finding
  added or lost, a depth-cap warning on each.
- **A tree of ~30,000 files**: the interfile run was killed for memory (exit
  137) inside a 12.5 GB engine, where the single-function scan finished in
  about two minutes.

Library code has few request-to-sink flows, so no public tree added a finding;
the fixture proves the capability, not a yield.

## What changed

- **A `ScanTaint` entry** in the security module, not a `ScanSource` flag:
  the cost is the analysis's, not the rule count's, and a merge gate should
  not pay it by default. It is wired into no composite.
- **The rule set is a manifest**, `src/security/rules/opengrep-interfile.txt`:
  the 27 interfile rules, each a row the audit or OWASP manifest already pins
  at the same path. Staged from the same pinned commit; co-located rules a
  staged file brings are excluded, and the 27 are the floor.
- **Two runs, one row.** The manifest runs without and with
  `--enable-interfile`. Only what the interfile run adds is reported, by a
  multiset on (rule, file, line, column): `ScanSource` reports the rest, and
  the aggregate sums findings across envelopes. A single-function finding the
  interfile run did not return is named in a warning; `ScanSource` still gates
  on it.
- **Advisory by default.** `--taint-gate warn` (default) lowers the threshold
  to `NONE`, as `ScanLicenses` does: findings pass with a warning that says
  they are not enforced; a run that did not complete fails at every setting.
  `--taint-gate gate` enforces `--fail-on`. There is no `off`.
- **The depth is named.** `--interfile-depth` (default 3, Opengrep's own; `-1`
  for none, `0` refused as the single-function scan again). It is passed as
  `--interfile-depth=N`: Opengrep exits 2 on a separate `-1`.
- **What the engine did not follow is named.** A depth-cap notification
  becomes a `DEPTH CAPPED` warning listing each rule. A rule whose interfile
  budget ran out names no file; it is a `PARTIAL SCAN` "in interfile
  analysis, which spans every file", not a file read in part.
- **Non-runs are errors.** Either run failing; an engine kill, named as the
  likely out-of-memory kill it is; the rule floor not met on either run; a
  SARIF the delta cannot read. A failed baseline keeps the unfiltered
  interfile findings beside its error.
- **The SARIF run carries `automationDetails.id: opengrep-interfile`**, so an
  aggregate or an upload keys it apart from `ScanSource`'s Opengrep run.
  Redaction is the same as `ScanSource`'s: matched source, code flows and
  related locations never leave the container.

## What gets worse

- **Every call costs two engine runs**, and the interfile one costs a multiple
  of the single-function scan's time and memory. On a large tree it may not
  finish at all; that is an error, not a pass. `--path` and a lower depth
  reduce it.
- **Depth 3 misses longer chains.** Raising it costs more; the warning says
  which rules stopped.
- **No C#.** Cross-method flow in .NET is the Roslyn leg's
  ([analyse-dotnet-with-roslyn](analyse-dotnet-with-roslyn.md)).

## Checks

- `src/security/taint_test.go`: the manifest a subset of the pinned packs at
  the same paths, 27 rules, no C#; the plan pinned, not inline, every staged
  rule required or excluded; gate and depth refusals; the depth as one
  argument; the multiset delta with a duplicate and a lost finding;
  unreadable SARIF shapes refused; a failed baseline and a killed interfile
  run; the floor; the advisory and suppression warnings; and the measured
  depth-cap and rule-only timeout notifications, verbatim.
- `scripts/smoke/interfile-taint.sh`, run by the `module-test` security cell
  and `make smoke`: the real engine over `testdata/interfile-taint`, in warn
  mode at depth 3 (exactly the six cross-function findings, none of the
  three single-function ones, `DEPTH CAPPED`, a pass) and in gate mode with no
  limit (the deep chain found, no depth warning, a fail).

## Residue

- Only the arm64 engine was exercised locally; amd64 is exercised by CI.
- The cost figures are from library code; an application tree with more
  request handlers may cost more. A consumer measurement before making it a
  merge gate is the next step.
