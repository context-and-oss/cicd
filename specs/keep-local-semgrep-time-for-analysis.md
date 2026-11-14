# Keep local Semgrep time for analysis

## Why

An inline SAST process exhausted its execution window in a consumer monorepo.
The initial explanation was aggregate rule-analysis cost, but that alone was
not established by the failure. An independently authored generated-HTML
workload distinguished analysis from optional scanner startup work.

With the same digest-pinned Semgrep engine, pinned rule membership, selected
inputs and two expected findings, a network-isolated adapter control took about
127 seconds. Turning off only the optional version check took about 9 seconds.
The production adapter with the explicit command-line switch also took about
9 seconds, retaining both findings at their original HTML paths and reporting
no parser notifications. These are synthetic local measurements, not a native
consumer pass or a promise of the same timing on another runner.

A batching experiment made the same workload take about 245 seconds because
it repeated startup. That experiment was rejected. Smaller batches were not
evidence of greater capacity, and increasing time limits would have hidden the
avoidable wait rather than removed it.

## Mechanism

`src/security/semgreprun.go` and `src/security/semgrep_inline.py` pass
`--disable-version-check` to their Semgrep scan commands. The engine is already
digest-pinned, so a best-effort update/banner service must not consume the time
reserved for analysing source. The switch does not disable rule evaluation,
rule-source fetching, metrics safeguards, parser diagnostics, dependency or
vulnerability database refreshes. Explicit live rulesets still need the registry;
this is not a claim that every SAST plan works offline.

The inline pass keeps its original selected-file inventory, single invocation,
shared classic-script scopes, rule floor, source maps, redaction and 300-second
process limit. There is no batching, retry, new scope limit, consumer flag,
image change, suppression, schema change or severity relaxation. Internal
failures remain non-runs even at NONE; parser limitations retain their existing
partial-scan disclosures. Original findings survive an inline failure.

## Validation and traps

`src/security/semgreprun_test.go` checks the executable ordinary scan command,
not merely a comment mentioning the switch. `src/security/semgrep_inline_test.py`
drives production `analyse` and requires the option, existing metrics and rule-id
flags, unchanged combined classic scope, original deadline and exactly one call.
The existing missing-input, missing-rule, failed-process, source-map and
publication controls remain active.

A pinned-engine loopback control uses a fresh version cache for every case:
the unchanged CLI/adapter contacts the owned update endpoint, while the fixed
commands do not and retain their findings. A contradictory explicit enable
via the upstream environment is an unsupported CLI combination, not a success
or a reason to fall back. The production image supplies no such override.
The production source/composite smoke remains the end-to-end detection and
verdict check; a local timing improvement does not replace it or downstream
exact-version qualification.

## Rejected and limits

- Extending the deadline or introducing per-consumer skips changes the gate
  instead of removing this optional network dependency.
- Batching without a completed-scan performance comparison repeats initialization
  and can make capacity worse. No batching implementation is shipped here.
- Disabling every network access would break explicit live packs and pinned
  rule-source retrieval. Only the engine's optional update probe is disabled.
- This repairs one measured startup failure mode, not every possible scanner
  timeout. Expensive analysis can still exceed the unchanged deadline and fail.
- A runtime correction requires a new release and fresh affected-consumer
  evidence. Published tags and previously qualified consumer/provider pins must
  not be moved or silently upgraded as a side effect.

## Amendment — the switch is gone with the probe

The engine is now Opengrep 2.0.0 ([swap-semgrep-for-opengrep](swap-semgrep-for-opengrep.md)).
It has no version check and no telemetry, and it refuses
`--disable-version-check` and `--metrics` as unknown options, writing an empty
report, rather than ignoring them. Both scan commands drop both flags. The
optional startup request this spec removed does not exist in the new engine, so
the measured analysis-time saving holds without a switch.
`TestTheScanRunsOpengrepWithoutSemgrepOnlyFlags` and the inline adapter test
now require the flags' absence. The rest — single inline invocation, original
inventory, process limit, no batching — is unchanged.
