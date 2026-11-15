# Plan the feedback loops before the stages they read from

## Why

The roadmap described each remaining stage as a forward step and had no home
for work that reads a late stage and writes into an early one. Two such loops
were requested: turning production errors from Sentry and Azure into proposed
fixes, and turning a merged fix into the prevention that would have caught it.
Neither fits a single stage. Filed under Stage 11 or Stage 4, either would read
as a gate, and a gate that opens pull requests or calls a model on every run is
the wrong contract for both.

## The mechanism

`ROADMAP.md` gains a "Feedback loops" section. It places both loops outside the
stage sequence and runs each on its own cadence, the shape the shipped DAST
composite already has. Both end in a proposal that re-enters at Stage 1 rather
than in a write to trunk or to a telemetry source.

Four decisions are recorded there because each one closes a door the loops
would otherwise open:

- A deterministic sanitiser screens every prompt before any model sees it,
  because consumer logs that should carry no personal data have not been
  measured to carry none. A hit parks the record instead of redacting it.
- Logs-to-fixes uses the Stage 11 source adapters and read-only identity
  instead of its own clients, since two resolvers for one question means one of
  them is wrong.
- Learn-from-bugs reruns the proposed regression test through the witnessed BYO
  test, red on the parent and green on the fix, because validation that an
  agent reports about its own change is a claim, not evidence.
- The investigator tool must be publicly installable and pinned, so that cicd
  does not depend on something a consumer cannot fetch.

## Rejected

- Filing logs-to-fixes under Stage 11 `Observe`. That function returns a
  release health verdict; triage of an open-ended error stream is a different
  question and must not block a release.
- Running learn-from-bugs as a merge gate. "No change" is a valid outcome, and a
  gate whose pass state includes "the model decided nothing was needed" grades
  its own blind spot.

## Traps

- Shipping logs-to-fixes ahead of the Stage 11 source contract creates the
  duplicate Sentry and Log Analytics clients the section rules out.
- Reporting an agent timeout or an invalid report as `no_change`.
- Recording a parked record's matched value in the evidence.
