# Roadmap

**Nothing on this page is implemented.** This is a design record for the *remaining* stages of the
[CD Model](docs/explanation/continuous-delivery/cd-model/stages.md): every module, composite,
function signature and evidence field below is a decision captured ahead of implementation so the
work can proceed without re-interviewing. Names and signatures here are proposals and will change
when the code is written. TBD items are explicitly marked, and no phase has a delivery date.

For what is **actually shipped and released today** — the Stage 2 pre-commit source gate and the
Stage 4 commit stage with its `container|archive|none` artifact tail — see
[CHANGELOG.md](CHANGELOG.md#shipped). Do not pin, call, or wire anything named on this page: none of
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
