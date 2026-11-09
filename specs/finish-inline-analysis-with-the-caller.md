# Let inline analysis finish under the caller's lifetime

## Why

The inline adapter imposed its own five-minute subprocess timeout, independently
of the ordinary source scan and the caller's execution lifetime. A large selected
HTML workload can require more analysis time even though the supported engine is
running and has not exhausted memory. Small functional smoke tests do not prove
that every selected workload fits this arbitrary cutoff.

## Mechanism

`src/security/semgrep_inline.py` waits for the supported, digest-pinned Semgrep
invocation without adding an adapter-specific elapsed-time timeout. There is no
engine fork, alternate scanner, shard scheduler, automatic retry or hidden rule
or input reduction. The caller's cancellation and execution ceilings still
apply; this does not promise an infinite hosted job or change a workflow limit.

All ordinary selected inputs, complete shared-classic groups, independent
module/template scopes and applicable pinned rules remain required. Input and
loaded-rule membership are checked after the engine finishes; maps restore
original paths and UTF-16 locations before the existing source-redaction
boundary. Results are published only after the complete invocation and mapping
validation. Failure or cancellation cannot publish partial inline results as a
successful combined report. Existing ordinary findings remain available on an
inline failure, including at `NONE`.

The engine's own rule and convergence limits retain their existing warning
policy. Waiting longer is not a reason to hide those warnings or claim complete
analysis: findings beside a partial-analysis warning remain a floor. Neither
process exit zero nor a loaded-rule catalogue proves convergence.

## Validation and limits

- A regression asserts that the invocation adds no subprocess timeout, still
  runs exactly once and keeps its selected inputs, rules and startup flags.
- Cancellation and execution/mapping failure controls preserve the ordinary
  report and do not publish an inline-success disclosure.
- Source and composite smokes retain unsafe/safe, shared-classic, independent
  scope, Unicode/mapping, partial-parser/redaction and severity-gate controls.
- Representative full-selected-workload execution is a separate compatibility
  check. Functional test totals and small fixtures are not a capacity receipt.

This change does not raise a caller's platform ceiling, grant credentials, alter
secret policy or qualify a consumer merely because the source checks pass.
