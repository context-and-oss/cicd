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

## False positives and the proposal shape

A loop that triages a live error stream on a schedule sees the same noise
every run. Without memory it re-proposes every dismissed group, pays a model
call for it, and teaches its readers to ignore it. The roadmap therefore keeps
one record of decisions, the issue tracker, keyed by a fingerprint marker on
each issue. A dismissal there holds until the group regrows in a newer release
or regresses after a fix. Repeated dismissals of one pattern turn into a rule
proposal instead of being re-decided case by case. Precision per class is
measured from proposal outcomes, and a class below the consumer's floor drops
to a lower output level on its own.

Walking one recurring, harmless exception through that design exposed three
gaps, and the roadmap now closes each:

- A `noise` verdict never reaches the tracker, and cicd keeps no state, so
  the cache of triage results had nowhere to live. Every run would have sent
  the same noise to the model again. The previous run's evidence is now an
  optional input. When it is missing, the run re-triages and says so instead
  of failing, because a missing memory costs money and does not make the
  result wrong.
- Regrowth is measured as a rate per user or request rather than as a count,
  since a count rises with traffic and would reopen harmless noise.
- Recurring noise in the consumer's own code becomes a `reporting-noise`
  proposal that stops the code reporting an expected condition, instead of a
  rule that hides it. The loop never mutes anything at the source, so the
  lasting fix has to be in the code. Rules remain for code the consumer does
  not own.

The issue is always the unit of record and a draft PR only attaches to one,
since dedupe, dismissal and the learn-from-bugs hand-off all need an issue. The
choice between issue and PR uses confidence and blast radius. A PR also needs a
reproducing test that cicd witnesses red then green, because a model's
confidence in its own triage is a claim. High blast radius never produces an
automatic PR.

## Where the investigator runs

A spike ran an issue-plus-fix investigator, driving an agent CLI against an
Azure AI Foundry deployment, in GitHub Actions. The agent CLI sandboxes every
command it runs with Linux namespaces.

- On the runner, a VM, the sandbox started. It denied network access, hid other
  processes' environments, and limited writes to the workspace. Each property
  was checked against an unsandboxed positive control.
- Inside a container the sandbox did not start, either under the default
  profiles or with seccomp and AppArmor unconfined.

The roadmap therefore runs the investigation on the runner instead of in a
Dagger module. That is the first such exception, and `ROADMAP.md` states it
with its reason. Only the witness and the evidence stay in Dagger.

The sandbox does not restrict reads, so the job design carries the rest of the
protection. The investigating job holds only a short-lived model token, and the
token that opens a pull request lives in a later job that never runs alongside
the agent.

## Rejected

- Filing logs-to-fixes under Stage 11 `Observe`. That function returns a
  release health verdict; triage of an open-ended error stream is a different
  question and must not block a release.
- A state file owned by cicd for dismissals. It would be a second record next
  to the tracker where people actually close issues, and the two would drift.
- Opening a PR on model confidence alone, or a PR without an issue.
- Opening an issue for every `noise` verdict so the tracker would remember it.
  That floods the tracker with exactly what the loop exists to filter out.
- Muting recurring noise in Sentry or Azure. That hides the event without
  fixing the code that reports it, and needs a write identity on the telemetry
  source.
- Running the investigator in a Dagger container without the agent's sandbox.
  Model-chosen commands would get network access and the credential, and cicd
  cannot restrict a container's egress.
- A privileged container to let the sandbox start. It hands the most privilege
  to the process running model-chosen commands, and it was not shown to work.
- Running learn-from-bugs as a merge gate. "No change" is a valid outcome, and a
  gate whose pass state includes "the model decided nothing was needed" grades
  its own blind spot.

## Traps

- Shipping logs-to-fixes ahead of the Stage 11 source contract creates the
  duplicate Sentry and Log Analytics clients the section rules out.
- Reporting an agent timeout or an invalid report as `no_change`.
- Recording a parked record's matched value in the evidence.
- Treating an unreadable tracker as "no prior decisions". That re-proposes
  every dismissed group in one run.
- Reopening a dismissed group just because it fired again, with no newer
  release and no regrowth.
- Giving the investigating job a write token, or any secret besides the model
  credential, because the agent's sandbox lets it read them.
- Failing the run when the previous evidence is missing. That would turn a
  cache miss into an outage of the whole loop.
