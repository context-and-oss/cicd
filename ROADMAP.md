# Roadmap

**Nothing on this page is implemented.** This is a design record for the *remaining* stages of the
[CD Model](docs/explanation/continuous-delivery/cd-model/stages.md), and for the feedback loops
that run between stages: every module, composite,
function signature and evidence field below is a decision captured ahead of implementation so the
work can proceed without re-interviewing. Names and signatures here are proposals and will change
when the code is written. TBD items are explicitly marked, and no phase has a delivery date.

For what is **implemented today** — the Stage 2 source gate, the commit
composite's `container|archive|none` artifact tail, and independent running-app
DAST — see the [module map](README.md#module-reference) and
[implementation reference](docs/reference/index.md). The [changelog](CHANGELOG.md)
separates the clean bootstrap from still-unverified publication/release behaviour. Do not pin, call, or wire anything named on this page: none of
it exists at any tag.

Phase 1 (Stages 2 and 4) is delivered and is not described here.

---

## Cross-stage design — delivery targets, telemetry sources, and identity

Stages 5, 10, and 11 must support a heterogeneous fleet without pretending that every deployable
is an Azure Web App. Delivery is therefore a **target plan**, not one hard-coded deploy command.
A release may select one target, several targets, or different targets at different stages:

| Target | Typical stage | Behaviour |
|--------|---------------|-----------|
| `cdn` | 5 and/or 10 | Upload a versioned package, verify checksum/origin, and optionally activate or purge |
| `test-environment` | 5 | Deploy to a test environment, resolve its URL, and run health/smoke/DAST verification |
| `production-environment` | 10 | Apply approval policy, deploy or swap, verify health, and return a rollback handle |

Targets are independently selectable: CDN only, test environment only, both, or a later production
target are all valid shapes. Each target returns its own evidence envelope. A plan may declare an
explicit dependency when order matters (for example, publish package before activating a CDN path),
but no implicit global order is inferred from which targets happen to be present.

Stage 11 consumes **multiple telemetry sources** through one normalized SLO/health contract:

- **Log Analytics Workspace** is the primary Azure log plane. Workspace-based Application Insights,
  Azure resource diagnostics (including Web Apps and Cosmos DB), activity logs, and custom tables
  can be queried there.
- **Azure Monitor** supplies metrics, alerts, resource health, and availability signals that are not
  merely log rows.
- **Sentry** remains a native source for release, issue, regression, and error-rate signals. The
  stage queries it through a read-only adapter; copying all Sentry data into Log Analytics is optional,
  not a prerequisite.
- Additional sources (CDN diagnostics, HTTP/SLO probes, OpenTelemetry, or custom Log Ingestion API
  tables) implement the same adapter contract. A stage may require one or several sources.

Authentication is a cross-cutting control plane:

- CI authenticates to Azure with short-lived workload identity federation (Azure DevOps service
  connection or GitHub OIDC) where available, not a shared client secret.
- Test and production use separate identities and resource scopes. A production approval unlocks
  the production identity; it does not promote the test identity's permissions.
- Deployed Azure workloads use managed identity for Cosmos DB, Key Vault, Storage, and other Azure
  resources, with data-plane roles where the service has a distinct data plane.
- CDN, Sentry, and Power Platform use provider federation where supported. Otherwise the adapter
  receives a vault-backed, rotated, narrowly scoped credential reference (for Power Platform,
  typically a dedicated application user), never a raw credential in the deployment plan.
- Deployment/publish identities are separate from Stage 11 read-only telemetry identities.
- Evidence records the auth mode, identity subject/client id, target scope, and preflight result, but
  never a token, secret, connection string, or credential-bearing URL.

The concrete target/source schema and provider-specific role sets remain implementation work. These
rules are the invariant every adapter must preserve.

---

## Phase 2 — Stage 5: Acceptance

**Scope**: Installation Verification (IV), Operational Verification (OV), Performance Verification (PV).  
**Status**: Design decided (PV tooling TBD).

### Modules

#### `src/stage-5/iv` — Installation Verification

Delivers the application according to the Stage 5 subset of the target plan (test environment, CDN,
or both), then probes the resulting endpoint(s) to confirm the delivery succeeded. Azure ARM is one
environment adapter, not the stage contract.

| Decision         | Value                                                                                     |
|------------------|-------------------------------------------------------------------------------------------|
| Deploy mechanism | Target adapter: Azure ARM/Web App, CDN package publish, or another configured test target |
| Verification     | HTTP GET to configurable health endpoint, assert 2xx                                      |
| Primary function | `Verify(ctx, artifact *dagger.File, plan *dagger.File, ...) ([]*dagger.File, error)`        |
| Authentication   | Target-specific identity references; unavoidable secrets arrive only as `*dagger.Secret`  |
| Evidence         | One envelope per selected target; every delivery and target-specific verification must pass |

#### `src/stage-5/ov` — Operational Verification

Consumes the targets resolved by IV and probes their health/smoke contract to confirm the delivered
application behaves correctly. A container target may run locally inside Dagger; a CDN or deployed
environment is verified through its resolved endpoint.

| Decision         | Value                                                                                    |
|------------------|------------------------------------------------------------------------------------------|
| Mechanism        | Resolve endpoints from IV; start a container locally only when that is the selected target |
| Verification     | HTTP health, smoke contract, package-origin check, or target-specific verifier             |
| Primary function | `Verify(ctx, targets *dagger.File, ...) ([]*dagger.File, error)`                            |
| Evidence         | One envelope per target; a target that cannot be reached never reads as clean               |

**Not already shipped by DAST's readiness probe.** `security.scan-web` starts a
container and probes it, but the probe is a *fact recorded in a scan envelope* at
the moment of the scan, not a verdict of its own — and it answers "could the
target be reached" rather than "does the running service behave correctly". OV
owns health attestation as its own verdict, and may share
`src/security/appservice.go` when it lands.

#### `src/stage-5/pv` — Performance Verification

Runs a performance baseline against the acceptance environment.

| Decision         | Value                                                             |
|------------------|-------------------------------------------------------------------|
| Tool             | **TBD** (k6 / Gatling / Locust)                                   |
| Primary function | `Verify(ctx, target string, ...) (*dagger.File, error)`           |
| Threshold        | Configurable via `--fail-on` threshold (latency p99 / error rate) |

### Composite

`src/composites/acceptance` — runs IV → OV → PV in sequence, collects evidence from all three,
calls `src/cross-cutting/evidence` and `src/notify`.

```text
stage-5/iv  ──┐
stage-5/ov  ──┼──► evidence.Wrap ──► notify.Notify
stage-5/pv  ──┘
```

**Environment**: When the plan includes a test environment, IV and OV share it and Stage 7
(Exploration) reuses it — no second deploy. A CDN-only Stage 5 plan verifies the published package
and endpoint but creates no reusable environment; the evidence must say so.

---

## Phase 2 — Stage 6: Extended

**Scope**: Release-cadence DAST, extended performance testing, compliance.  
**Status**: DAST and compliance tooling decided; extended perf tooling TBD.

**Cadence model**: Stage 6 modules fire on a **release cadence** (monthly/quarterly), not on
every commit. Triggered by a separate workflow (manual or scheduled cron), not by the
pre-commit/commit composites. Findings inform the next release, not the current build.

### Modules

#### `src/stage-6/dast` — Dynamic Application Security Testing (release cadence)

External attack simulation against the deployed production-shaped target, **through the WAF**.
Answers "can the deployed system be attacked today?" — distinct from the shipped `security.scan-web`,
which answers "are we shipping vulnerable code?" against a target the consumer points it at.

| Decision         | Value                                                                        |
|------------------|------------------------------------------------------------------------------|
| Tool             | [Heyhack](https://heyhack.com) via REST API                                  |
| Primary function | `Scan(ctx, target string, apiKey *dagger.Secret, ...) (*dagger.File, error)` |
| Cadence          | Monthly or quarterly — fired by `src/composites/extended`, not by commit path    |
| Target           | Public URL of acceptance/production env, **through the WAF**                 |
| `--fail-on`      | CRITICAL / HIGH / MEDIUM / LOW / NONE (same pattern as other scan modules)   |
| Evidence         | SARIF output embedded in envelope                                            |

**Why both `security.scan-web` (ZAP) and `src/stage-6/dast` (Heyhack)?**
Different questions, different cadences, different positions relative to the WAF:

| Module               | Tool    | Cadence            | Position       | Question answered                       |
|----------------------|---------|--------------------|----------------|------------------------------------------|
| `src/composites/dast` (shipped) | ZAP | Baseline on mainline and nightly, full weekly and on demand — its own workflow, wired into no other composite | Behind WAF in CI | "Are we shipping vulnerable code?"     |
| `src/stage-6/dast` (planned) | Heyhack | Monthly/quarterly | Through WAF | "Can the deployed system be attacked?"  |

The intent is that teams pick which they wire in — both, either, or neither. Today only the
ZAP path exists: `src/composites/dast` and the reusable
[`dast.yml`](.github/workflows/dast.yml) workflow, with `--app url|service|container`
selecting who starts the application. Only `container` builds from the commit under test
and can attest what it scanned; the other two say so on every run. Consumers who need the
module alone still call `security.scan-web` directly. See
[docs/reference/dast.md](docs/reference/dast.md). Teams
running on Azure with WAF in front gain little from a CI-time external scan (the WAF
intercepts most generic payloads), but benefit from periodic external attack simulation
plus continuous behind-WAF defect detection.

**Manual pentest** stays a compliance line item outside the pipeline — humans still beat
automated tools for business-logic and access-control flaws.

#### `src/stage-6/perf-test` — Extended Performance Testing

| Decision         | Value                                                 |
|------------------|-------------------------------------------------------|
| Tool             | **TBD**                                               |
| Primary function | `Test(ctx, target string, ...) (*dagger.File, error)` |

#### `src/stage-6/compliance` — Compliance Checks

| Decision         | Value                                                                  |
|------------------|------------------------------------------------------------------------|
| Standard         | OWASP (ASVS / Top 10 checks)                                           |
| Tool             | TBD — likely OWASP ZAP in active scan mode or a dedicated ASVS checker |
| Primary function | `Check(ctx, target string, ...) (*dagger.File, error)`                 |
| `--fail-on`      | CRITICAL / HIGH / MEDIUM / LOW / NONE                                  |

### Composite

`src/composites/extended` — runs dast → perf-test → compliance, aggregates evidence, notifies.

**Trigger model**: invoked by a scheduled workflow (monthly/quarterly cron) or manual
release-prep run — **not** wired into the commit path. Findings are release-blocking only
for the upcoming release, not for individual merges.

```text
stage-6/dast        ──┐
stage-6/perf-test   ──┼──► evidence.Wrap ──► notify.Notify
stage-6/compliance  ──┘
```

---

## Phase 3 — Stages 7–12: Release Pipeline

**Status**: High-level shape decided; several modules TBD.

### Stage 7 — Exploration

Exposes the acceptance target(s) already delivered by Stage 5 IV for UAT and demo. No new delivery:
it reuses the running test environment or published CDN endpoint. A plan with no explorable target
records Stage 7 as not applicable rather than inventing an environment.

| Decision         | Value                                                               |
|------------------|---------------------------------------------------------------------|
| Primary function | `Expose(ctx, environmentUrl string, ...) (*dagger.File, error)`     |
| Behaviour        | Validates environment is still live, returns access URL in evidence |
| Evidence         | Envelope with environment URL and health status                     |

### Stage 8 — Start Release

Creates a release branch from the current commit.

| Decision         | Value                                                                                    |
|------------------|------------------------------------------------------------------------------------------|
| Primary function | `StartRelease(ctx, version string, repoToken *dagger.Secret, ...) (*dagger.File, error)` |
| Behaviour        | Creates `release/<version>` branch via GitHub API                                        |
| Evidence         | Envelope with branch name and commit SHA                                                 |

### Stage 9 — Release Approval

| Decision   | Value                                                                                |
|------------|--------------------------------------------------------------------------------------|
| Mechanism  | **TBD**                                                                              |
| Candidates | External approval API, GitHub environment protection rules, ServiceNow change ticket |

### Stage 10 — Production Deploy

Delivers the approved release to its selected production targets. A release may publish a package
to a CDN, deploy to a production environment, or do both. Target results are independent evidence
entries so a successful CDN upload cannot hide a failed environment deploy (or vice versa).

| Decision         | Value                                                                                                                |
|------------------|----------------------------------------------------------------------------------------------------------------------|
| Primary function | `Deliver(ctx, artifact *dagger.File, plan *dagger.File, ...) ([]*dagger.File, error)`                              |
| Targets          | CDN publish and/or production environment; provider adapters own their target-specific inputs                      |
| Verification     | Package checksum/origin for CDN; health and optional slot verification for an environment                           |
| Evidence         | One envelope per target with deployment/package id, resolved endpoint, verification, and rollback/activation handle |
| Authentication   | Target-specific identity reference; production identity is separate from test and telemetry identities              |

### Stage 11 — Live Monitoring

| Decision       | Value                                                                                                          |
|----------------|----------------------------------------------------------------------------------------------------------------|
| Primary hub    | Log Analytics Workspace for workspace-based Application Insights and Azure resource/custom logs                 |
| Source model   | Multiple adapters: Log Analytics, Azure Monitor metrics/alerts, Sentry, CDN diagnostics, HTTP/SLO, custom sources |
| Primary function | `Observe(ctx, release *dagger.File, sources *dagger.File, ...) (*dagger.File, error)`                         |
| Correlation    | Every query is bounded to the release id/version, target, environment, and observation window                    |
| Authentication | Read-only identity per source; never reuse a deployment or publish identity                                      |
| Open work      | Normalized SLO schema, source quorum policy, observation window, and provider-specific queries remain TBD          |

### Stage 12 — Release Toggling

| Decision   | Value                                                                  |
|------------|------------------------------------------------------------------------|
| Mechanism  | **TBD**                                                                |
| Candidates | Azure App Configuration feature flags, LaunchDarkly, custom toggle API |

### Composites

Two composites are planned for stages 7–12:

**`src/composites/pre-release`** — stages 7 → 8 → 9 (exploration through approval gate)

**`src/composites/release`** — stages 10 → 11 → 12 (production deploy through toggling)

---

## Feedback loops — from late stages back to early ones

**Status**: Shape decided; investigator tool and source adapter fields TBD.

The two loops below are not stages. Each one reads from a late stage and writes to an early one.
Like the shipped `src/composites/dast`, each runs on its own cadence in its own workflow, no other
composite calls it, and it never gates a merge. Each produces a **proposal**: an issue or a draft
pull request. That proposal enters the CD Model at Stage 1 like any other change, so the fix or the
prevention passes Stages 2–4 like any other change. cicd never merges, never pushes to trunk, and
never writes back to a telemetry source. ADR-001 keeps publishing out of cicd for the same reason.

```text
Stage 1 ─► 2 ─► 3 ─► 4 ─► … ─► 10 ─► 11 (Live)
      ▲              │               │
      │              │ fix merged    │ Sentry / Azure logs
      │              ▼               ▼
      ├────── learn-from-bugs  logs-to-fixes
      │       draft PR: test,        │
      │       check or guidance      │
      └─ issue / draft PR (the fix) ─┘
```

The loops chain together. When a fix proposed by logs-to-fixes merges, that merge triggers
learn-from-bugs, using the logs-to-fixes brief as the issue.

### Module: `src/feedback`

There is one domain module with three functions. The two loops share a sanitiser and a model
contract, so they share a module. They do not share a composite.

| Function   | Role                                                                                       |
|------------|--------------------------------------------------------------------------------------------|
| `Sanitize` | Deterministic personal-data and credential screen. It runs before every model call in either loop |
| `Triage`   | Logs-to-fixes: groups and classifies telemetry, then writes one brief per qualifying group |
| `Learn`    | Learn-from-bugs: turns an issue plus its fix into a witnessed prevention proposal          |

Model access inside Dagger (`Triage`) follows the `risk` module's contract: native `dag.LLM()`,
or an OpenAI-compatible `--llm-url` with `--llm-token` as a `*dagger.Secret`. A second model path
is not introduced. The learn-from-bugs investigator runs outside Dagger (see Loop B), but it uses
the same endpoint and the same kind of token.

### Shared: the consumer brings the model, and no model secret is stored

cicd holds no model credential. Each consumer brings three things:

- **Endpoint and deployment.** An OpenAI-compatible Responses endpoint, such as Azure AI Foundry,
  and a deployment name. Both are inputs to the reusable workflows, never constants in them. The
  consumer's code and issue text go to the consumer's own endpoint, under the consumer's tenant,
  region and data terms.
- **Identity.** An Entra app registration (client ID and tenant ID) with a model-calling role on
  that endpoint, and nothing else. The workflow exchanges GitHub's OIDC token for a short-lived
  Entra token and passes it on as a secret. There is no API key to store, leak or rotate.
- **Shared settings as org variables.** The endpoint, deployment, client ID and tenant ID are not
  secret. An organisation sets them once as org-level Actions variables, and its repositories pass
  them in. A new consumer repository in that organisation needs no setup of its own.

**One federated credential per consumer organisation, not per repository.** Entra's
claims-matching federated credential (a preview feature, used anyway because the alternative is
one credential per repository with a low per-identity cap) trusts a pattern of callers instead of
one subject. Its expression must pin all three of these:

- `repository_owner_id`: the organisation's immutable numeric ID. This is the guard. A name pattern
  such as `repo:<org>*` also matches any other organisation whose name starts the same way.
- `sub`: the trunk branch, such as `repo:<org>/*:ref:refs/heads/main`, so a pull request branch
  cannot obtain a token.
- `job_workflow_ref`: cicd's reusable workflow **at a release tag**, such as
  `<cicd-repository>/.github/workflows/learn-from-bugs.yml@refs/tags/v*`. A `@*` ref also
  accepts a branch carrying a modified copy of the workflow.

cicd is public, so `job_workflow_ref` alone would trust every repository on GitHub that calls the
workflow. The owner ID is mandatory, not a refinement.

### Shared: sanitise before any model sees the text

Both loops send untrusted text to a model: log records in one, issue text in the other. Consumer
logs are expected to carry no personal data. `Sanitize` runs anyway, because nothing measures that
expectation until something checks.

- **What it screens**: email addresses, phone numbers, payment card numbers, national identifiers,
  credentials and tokens, and public IP addresses. The patterns are deterministic, with no model
  involved.
- **Parks the record; does not redact it**: a record with a hit is left out of every prompt. Redacting
  one field and sending the rest only moves the miss to the next field.
- **Evidence**: records examined, records parked, and hit counts by kind (`pii:email`). A hit's value
  is never recorded.
- **Exact bytes**: the screen runs on the exact prompt bytes sent to the model, not on the source
  record before templating.
- **A screen that could not run refuses the run**. It never reports zero hits.
- **Content is data**: log messages and issue bodies are framed as data, never as instructions,
  because both are attacker-reachable.

### Loop A — logs to fixes (Stage 11 → Stage 1)

**Sources**: Sentry, and Azure through the Log Analytics workspace (workspace-based Application
Insights included). There are no other sources. The loop uses **Stage 11's source adapters and
read-only telemetry identity**; it does not ship its own clients. For that reason the Sentry and Log
Analytics adapters are designed once, together with the Stage 11 source contract, and serve both.

| Decision         | Value                                                                                          |
|------------------|------------------------------------------------------------------------------------------------|
| Primary function | `Triage(ctx, sources *dagger.File, rules *dagger.File, window string, previous *dagger.File, ...) (*dagger.File, error)`, where `previous` is the last run's evidence (optional) |
| Window           | Bounded per source by a persisted high-water mark; the evidence records the window queried     |
| Grouping         | Deterministic fingerprint: exception type + crash-site file + function, with the title only as a fallback. The model breaks ties and never invents a key |
| Classification   | `bug` / `noise` / `env` / `needs_info`, with confidence and blast radius. Consumer rules win over the model |
| Ownership        | A group whose stack never touches the consumer's own code is reported and never proposed        |
| Output           | One brief per qualifying `bug` group. Default is dry run: the evidence lists the proposals that would open. The issue is always the unit of record, and a draft PR is only ever attached to one. See *Issue or pull request* below |
| Limits           | A per-run cap on groups proposed; groups beyond the cap are counted, not dropped silently      |
| Writes           | None to Sentry or Azure: no resolve, no mute. The issue/PR token is a separate identity from the telemetry identity |
| Evidence         | Per source: window, records examined, groups, classifications, parked counts by kind, groups suppressed (by dismissal, by rule, by pre-gate reason), briefs, proposals opened and updated. An unreachable or unauthorised source goes in `errors[]` and never reads as "no errors" |

**Composite**: `src/composites/logs-to-fixes`, which runs Sanitize → Triage → propose → evidence →
notify. It is triggered by a schedule or an alert, never by a commit.

#### A false positive is decided once

The loop has to remember what a human already decided. Otherwise it re-proposes the same group on
every run.

- **The issue tracker is the record of decisions.** Each issue carries its group's fingerprint in a
  hidden marker. Before proposing, the loop reads the tracker (GitHub or Azure DevOps). If an issue
  for that fingerprint is open, it gets an updated comment, never a duplicate. If someone closed it
  as *not planned* / *won't fix*, the group is dismissed. cicd keeps no state of its own, because
  people already make these decisions in the tracker. If the tracker cannot be read, nothing is
  proposed, and that goes in `errors[]`, because an unread record of decisions looks the same as an
  empty one.
- **A dismissed group stays dismissed until something material changes.** It comes back only if:
  - it fires in a release newer than the dismissal **and** its rate has grown past the regrowth
    factor, or
  - it was closed as *fixed* and fires again in a release newer than the fix. That is reopened and
    labelled as a regression.

  Firing again on its own never brings it back.
- **Rules for whole classes of noise.** Consumer rules already win over the model. When several
  groups that share a pattern (origin, exception type, third-party frame) have been dismissed, the
  loop proposes a rule as a pull request to the consumer's rules file. Once a human merges it, that
  class is filtered before any model call.
- **A deterministic pre-gate before proposing.** It requires:
  - a frame in the consumer's own code, with a source-mapped path;
  - not seen only on old releases;
  - a minimum event or user volume;
  - persistence across more than one run, so a single spike is not proposed.

  Each refusal is counted in the evidence by reason.
- **A decided group is not triaged again.** cicd keeps no state, and a `noise` verdict never reaches
  the tracker, so the memory is the **previous run's evidence**, passed back in as an optional
  input (a workflow artifact or cache entry). A group already classified there is triaged again
  only in a newer release that also crosses the regrowth factor. Dismissed and already-proposed
  groups cost no model call, and the model gets no repeated chance to change its mind about the
  same noise. The pre-gate's persistence check reads the same input. When the input is missing or
  unreadable, the run still works: it re-triages everything, skips the persistence check (which
  only makes proposals stricter), and says both things in the evidence. A missing memory costs
  money, and the evidence shows that it cost money.
- **Regrowth is a rate, not a count.** It is measured as events per affected user, or per request
  where the source has request counts, against the rate when the group was decided. An absolute
  count trips whenever traffic grows, which would reopen harmless noise every time usage rises.
- **Precision is measured, and the loop cuts back automatically.** The evidence records every
  proposal and its outcome (merged, dismissed, still open), and precision is computed per
  classification and fix class. When precision for a class falls below the consumer's floor, that
  class drops one level, from PR to issue or from issue to dry run, and the evidence says so. Only a
  human raises it again.

#### Issue or pull request

The **issue is always the record**. A draft PR is optional, and it links to its issue. A PR is never
opened without an issue, because the issue is where dedupe, dismissal and discussion happen, and
learn-from-bugs takes it as input.

Confidence and blast radius decide the outcome, but neither is enough to open a PR. Model confidence
is reported by the model itself. The evidence for a PR is a reproducing test that cicd runs itself
through the witnessed BYO test of
[ADR-002](docs/decisions/ADR-002-witnessed-test-execution.md): it must fail on the current code and
pass with the proposed fix.

| Triage result | Outcome |
|---|---|
| `noise` / `env`, or matched by a rule | Nothing proposed; counted in the evidence |
| `noise` with its crash site in the consumer's own code, persisting past the reporting-noise threshold | Issue with fix class `reporting-noise` (see below). The same PR rules apply as for a bug |
| `needs_info`, or confidence below the issue floor | No issue; listed in the run summary, and looked at again if volume grows past the regrowth factor |
| `bug`, confidence at or above the issue floor, **or** high blast radius | Issue with the brief |
| `bug`, confidence at or above the PR floor, low or medium blast radius, allowlisted fix class, own code | Issue **plus** a draft PR from the consumer-supplied fix command, kept only if the reproducing test is witnessed red then green |
| The row above, but no test could be witnessed | Issue only; the proposed patch goes on the issue as text |

**Recurring noise in the consumer's own code is a reporting defect.** If an exception is expected
(a cancelled request, a client disconnect), the code should not report it as one. Because the loop
never mutes anything in Sentry or Azure, the lasting fix belongs in the code. The fix class
`reporting-noise` proposes that change: drop the event in the Sentry SDK's `beforeSend`, filter it
in an Application Insights telemetry processor, or lower the log level. Its witnessed test, when
there is one, asserts that the expected condition is no longer reported. Rules stay for noise from
code the consumer does not own, where no code change is possible. A rule hides a class for good,
while a `reporting-noise` fix removes it at the source.

**High blast radius never gets an automatic PR**, at any confidence. A human has to design that
fix. Every floor, the regrowth factor and the precision floor are consumer configuration. The
defaults are conservative, and the default mode is dry run. A consumer raises them once the
measured precision justifies it.

### Loop B — learn from bugs (fix merged → Stages 1–2)

**Input**: an issue (text, or a link) plus the exact fix (a commit, a `BASE..HEAD` range, or a
merged pull request).

**Triggers**:

- A fix landing on trunk at Stage 4.
- An on-demand run after a Stage 11 post-mortem; see
  [incident response](docs/explanation/continuous-delivery/deployment/incident-response.md).
- A merged logs-to-fixes proposal.

**Question**: which stage should have caught this, and what is the smallest change that would catch
the next one? The answer is one of: a regression test, a contract or schema check, a lint or static
rule, review guidance, a configuration check, or **no change**.

| Decision         | Value                                                                                           |
|------------------|-------------------------------------------------------------------------------------------------|
| Primary function | `Learn(ctx, src *dagger.Directory, proposal *dagger.File, report *dagger.File, fix string, testCmd string, ...) (*dagger.File, error)`. It grades a proposal the investigator already made; it never runs the investigator |
| Isolation        | The investigator runs **on the runner, not in Dagger**, under the agent CLI's own sandbox, on a copy of the checkout. It returns a diff plus a structured report and never edits the consumer's tree. See *Where the investigator runs* below |
| Witnessing       | cicd reruns the proposed regression test itself through the witnessed BYO test of [ADR-002](docs/decisions/ADR-002-witnessed-test-execution.md). The test must fail on the fix's parent and pass on the fix. Validation the agent reports is a claim, not evidence |
| Outcomes         | `applied`, `no_change`, `not_applied`, `apply_failed`, or did-not-run. `no_change` is valid but must give a reason; an agent timeout or an invalid report is never `no_change` |
| Stage mapping    | The earliest practical detection point is recorded as a CD Model stage number, so findings aggregate into the [defect-stages mapping](docs/explanation/continuous-delivery/quality-gates/defect-prevention/defect-stages-mapping.md) over time |
| Output           | A draft PR on its own branch, never trunk. The finding record travels as evidence and is not committed automatically |
| Evidence         | Issue reference or hash, fix base and head SHAs, diff hash, outcome, witnessed red/green results, stage mapping. No raw issue body, diff or transcript |

**Jobs**: the reusable workflow runs three jobs, in this order, and never runs two of them together:

1. **Investigate** (runner). Before it starts, `feedback.Sanitize` screens the issue text in
   Dagger. The agent CLI then runs under its own sandbox, and the job uploads the diff and the report.
   The job holds **only** a short-lived model credential (workload identity federation to an
   OpenAI-compatible Responses endpoint such as Azure AI Foundry, with a role that can only call
   models) and `contents: read`. It holds no write token and no other secret.
2. **Witness and evidence** (Dagger, no model credential). `src/composites/learn-from-bugs` runs
   `feedback.Learn`, which replays the proposed test red then green and writes the envelope, then
   evidence and notify.
3. **Propose** (runner). This job holds the token that opens the draft PR. It runs only after the
   witness, and never alongside the agent.

#### Where the investigator runs

This is the first cicd step that is not a Dagger module. The reason was measured:

- The agent CLI isolates each command it runs in Linux namespaces (bubblewrap). Inside a container
  this cannot start:
  - under the default container profiles, namespace creation is refused;
  - with seccomp and AppArmor unconfined, setting up the sandbox's network still fails.
- On a GitHub-hosted runner, which is a VM, the same sandbox starts. A measured spike confirmed
  that it denies network access and hides other processes' environments, and that it limits writes
  to the workspace.
- Running the agent in a container without its own sandbox would give model-chosen commands network
  access and read access to the credential. cicd has no way to restrict a Dagger container's egress
  today, so a container is a weaker boundary than the runner, not an equal one.

The sandbox limits writes, **not reads**. A command the agent runs can read files outside the
workspace, including the model token. The job design is the mitigation: the investigating job
holds nothing worth reading beyond a model token that expires within the hour and can only call
models. The PR token lives in a later job. Microsoft-hosted Azure DevOps agents are VMs too, but
this is unverified there.

Revisit the container shape only if cicd can deny a Dagger container all egress except a
credential-holding model proxy.

**Investigator tool**: TBD. It must be publicly installable and pinnable at an exact version. cicd
does not depend on a tool a consumer cannot fetch. The reusable workflow installs it with a pinned
version in a `run:` step, never as a third-party `uses:` action, because of the doctrine that our
own workflows use no third-party actions.

### Templates and sequencing

- Reusable workflows: `logs-to-fixes.yml` (schedule plus manual) and `learn-from-bugs.yml` (trunk
  push filtered to fixes, plus manual), with matching Azure DevOps starters.
- **Learn-from-bugs comes first**. It depends on nothing unbuilt, since the witnessed BYO test
  already ships.
- **Logs-to-fixes lands with the Stage 11 source contract**, because building it earlier would
  create a second set of Sentry and Log Analytics clients that Stage 11 would later have to replace.

---

## Conventions carried forward from Phase 1

All Phase 2 and Phase 3 modules follow the same conventions established in Phase 1:

- **Pull pattern**: every primary function returns `(*dagger.File, error)` with a JSON evidence envelope
- **VCS context**: every function accepts `commitSha string, branch string, repoUrl string`
- **Secrets**: always `*dagger.Secret`, never `string`
- **Identity first**: adapters accept an identity/connection reference and prefer federation or managed
  identity; a `*dagger.Secret` is the explicit fallback, not the default auth contract
- **`--fail-on`**: any scanning or verification function accepts a threshold (`CRITICAL HIGH MEDIUM LOW NONE`)
- **Evidence schema**: copy of `src/internal/evidence/schema.go` at module root, kept in sync
- **Composites**: call `src/cross-cutting/evidence` and `src/notify` at the end

---

## Open decisions

| Item                               | Status                          |
|------------------------------------|---------------------------------|
| Stage 5 PV tooling                 | TBD — k6 / Gatling / Locust     |
| Stage 6 perf-test tooling          | TBD                             |
| Stage 6 compliance tool            | TBD — OWASP ZAP or ASVS checker |
| Stage 9 Release Approval mechanism | TBD                             |
| Stage 5/10 target schema            | Shape decided; provider fields and dependency syntax TBD |
| CDN provider adapter               | TBD — target contract decided   |
| Stage 11 normalized signal schema  | Log Analytics hub + multi-source adapters decided; SLO/quorum details TBD |
| Auth role sets per provider        | WIF/managed-identity policy decided; exact least-privilege roles TBD |
| Stage 12 Release Toggling platform | TBD                             |
| Learn-from-bugs investigator tool  | TBD — must be public and pinnable |
| Claims-matching federated credentials (preview) | Decided to use. Unverified: one expression across several organisations (`or`), and which Entra identity types support it |
| Logs-to-fixes fix command for draft PRs | TBD — consumer-supplied; issue-only until decided |
| Sanitiser pattern set and parking policy | Shape decided; per-kind patterns TBD |
| Logs-to-fixes default floors (issue, PR, precision), regrowth factor, minimum volume | Shape decided; values TBD |
| Tracker fingerprint marker format (GitHub and Azure DevOps) | TBD |
| Previous-run evidence transport (artifact or cache) and retention | TBD |
| Rate denominator per source (users or requests) | TBD |
| Reporting-noise threshold | TBD |
