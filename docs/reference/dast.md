# Running-app DAST

Information-oriented reference for the DAST surface: the three shapes, every
parameter at each of the three layers (workflow → composite → module), the
`dast/1.0` evidence payload, and the disclosure lines. For the task-oriented
version — pick a shape, pick a cadence, read the output — see
[Scan a running app (DAST)](../how-to-guides/scan-a-running-app.md).

DAST has its own composite and is wired into no **other** composite. It is not
the commit/precommit merge gate: it runs on its own cadence and neither calls it.
Scan only explicitly authorized targets with traffic limits appropriate to the
environment; baseline generates requests too, and API/full modes send attack
traffic. Public modules support anonymous fetching; private copies require
read-only source access. Verify the referenced release and the platform's
workflow/action access policy; source access is separate from notification secrets.

## The three shapes

`--app` selects the source, always explicitly (ADR-005 — cicd never
auto-detects the shape). Two mechanisms, three shapes:

| Shape | Mechanism | Who starts the application | Provenance | Covers |
|-------|-----------|----------------------------|------------|--------|
| `url` | W1 | the consumer, somewhere the engine can route to | **not attested** — cicd cannot know what is behind the URL, and every run says so | any reachable environment |
| `service` | W1 | the consumer, on the CI runner (`docker compose up`, `dotnet run`) | **not attested**, same reason | a composed stack: several containers, a database, a sidecar |
| `container` | W2 | cicd, inside the engine, from this commit's Dockerfile | attestable — the image was built from this commit in this run | one container, one port, nothing beside it |

W2 is the only shape whose evidence can say the scanned code is the code this
commit produced. W1 is the only mechanism that covers an application cicd
cannot build and start on its own. A scan of a real running app with no
provenance line is worth more than no scan, which is why both ship.

`--app url` with a `localhost` address does not work and is not a bug: the
scan runs inside the Dagger engine, which has no route to the runner's
loopback. That is what `--app service` is for — the Dagger CLI maps a
`tcp://host:port` argument onto a host tunnel and cicd binds it under a fixed
alias, so the URL the scanner is given never contains a host the consumer
typed.

**The host Docker socket is refused, permanently.** Expressible in Dagger,
declined: it is root on the runner handed to the process being attacked. An
application that needs a stack around it uses `--app service`.

## Refused combinations

`validateApp` (`src/composites/dast/shape.go`) rejects these before any
container starts, and returns an error rather than an audit directory — an
audit directory is a thing a consumer reads as a verdict.

| Combination | Why it is refused |
|-------------|-------------------|
| `--app url` with no `--target` | there is no address to scan |
| `--app url` with `--service` or `--src` | the ignored input makes the run look like it scanned something it did not |
| `--app service` with no `--service` | nothing is bound |
| `--app service` with `--target` | a bound service is addressed by cicd, never by a URL the consumer typed |
| `--app container` with no `--src` | there is no Dockerfile to build |
| `--app container` with `--target` or `--service` | exactly one shape per run |
| an `--app` value outside the three | no default arm — an unrecognised shape must not resolve to the one needing least from the caller |
| `--mode ""` | see below |
| `--port 0` (bound shapes only) | see below |

The last two exist because of a Dagger mechanic rather than a taste call.
Dagger's generated Go client drops any optional argument holding its zero
value, so `--mode ""` and `--port 0` never reach `ScanWeb` at all — they are
replaced by its defaults, `baseline` and `8080`. A caller whose workflow
variable came out empty would silently get the weakest scan, or a scan of a
port they never named, with nothing in the evidence saying so. They are
refused in the composite because that is the last place they are still
visible. `--app url` carries its port inside `--target`, so no port is read or
checked there.

## Reusable workflow inputs

`context-and-oss/cicd/.github/workflows/dast.yml@v5.1.4`. Every input is a string
with an empty default unless stated otherwise, and empty means *keep the
module default* — the same contract `commit.yml` uses, for the zero-value
reason above.

| Input | Default | Notes |
|-------|---------|-------|
| `app` | `url` | `url` \| `service` \| `container` |
| `target` | — | `app=url` only: the full HTTP/S URL |
| `start-cmd` | — | `app=service` only: the command that starts your application on the runner. Runs from the repository root, must return once the app is starting. **Unwitnessed** — cicd did not build what this starts, which is the same fact `PROVENANCE NOT ATTESTED` states |
| `stop-cmd` | — | `app=service` only: teardown, run whatever the scan did |
| `dockerfile` | — | `app=container` only: path relative to the repository root |
| `platform` | — | `app=container` only: OCI platform |
| `port` | — | the port your app answers on. Both the runner tunnel and the port in the URL cicd composes |
| `scheme` | — | `http` \| `https` |
| `base-path` | — | path the application is served under |
| `health-path` | — | path the readiness probe requests; defaults to `base-path` |
| `ready-timeout-seconds` | — | how long the **scanner** waits for the target once cicd is running |
| `start-timeout-seconds` | `180` (number) | how long the **workflow** waits on the runner for `start-cmd`'s application |
| `mode` | `baseline` | `baseline` \| `api` \| `full` |
| `api-spec-path` | — | `mode=api`: path the *running application* serves its API document on; cicd fetches it from the target. Excludes `api-spec-file` |
| `api-spec-file` | — | `mode=api`: path to a document committed in this repository. Excludes `api-spec-path` |
| `api-format` | — | `openapi` \| `soap` \| `graphql` |
| `rule-config` | — | ZAP rule configuration (`-c`), committed in this repository |
| `max-duration-minutes` | — | ZAP `-T`. Empty means no cap |
| `profile` | — | the configuration the app ran under; recorded verbatim, never interpreted |
| `authenticated` | `false` (boolean) | `true` only when the scan exercised a real login |
| `fail-on` | `HIGH` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `NONE` |
| `job-timeout-minutes` | `90` (number) | hard ceiling on the whole job, including the image build and the engine pull |

The two timeouts are named apart on purpose. `start-timeout-seconds` failing
means *your app never started*; `ready-timeout-seconds` failing means *the
scanner could not reach it*. Those have different remedies and are otherwise
indistinguishable in the evidence.

Secrets: none are required; `TEAMS_WEBHOOK` is optional. A caller can only
pass secrets the reusable workflow *declares*, so an undeclared one resolves
empty inside it, always.

### Preflight the workflow runs that the module cannot

`start-cmd` and `stop-cmd` never reach the composite, so `validateApp` cannot
see them. The workflow checks the shape against its own inputs before
checking out anything: `app=service` needs both `start-cmd` and `port`, and
`start-cmd` / `stop-cmd` under any other shape is an error rather than a
no-op — under `app=url` or `app=container` such a command would start a
process nothing ever looks at while the run reports on a different
application.

## Reusable workflow outputs

The ADR-006 consumption seam: read `needs.<job>.outputs.*` instead of
reconstructing cicd's internals. A consumer job needs `if: always()`, because
a tripped gate fails the calling job.

| Output | Value | Notes |
|--------|-------|-------|
| `evidence-artifact` | `dast-evidence-<mode>-<sha>` | the uploaded artifact. **The mode is in the name**, so a weekly full scan does not overwrite a nightly baseline. 90-day retention |
| `passed` | `true` \| `false` | `false` also covers a scan that could not run |
| `findings-count` | integer | total alerts |
| `findings-by-severity` | compact JSON object | e.g. `{"HIGH":1,"MEDIUM":4}` |
| `gates` | compact JSON array | per-gate status from the envelope's `sources[]` |

The evidence artifact contains `combined-evidence.json`, `findings.sarif`,
`comment.md` and `sbom.cdx.json`. **`sbom.cdx.json` is present and empty**: a
DAST run produces no component inventory, and it is there because the evidence
aggregator writes the same set of documents for every pipeline. Do not read it
as an inventory of what was scanned.

When a DAST producer contributes source-located SARIF runs, they are uploaded
to Code Scanning under `category: cicd-dast-<mode>`. ZAP's findings identify
runtime URLs rather than repository files, so a ZAP-only bundle deliberately
skips that upload and keeps the findings in `combined-evidence.json`,
`comment.md`, and the native report under `parts/`. The workflow validates that
`runs` is an array before making that decision; malformed SARIF still fails the
job. The category is per mode deliberately — filed under one shared category,
a weekly full scan's HIGH alerts would be auto-closed by the next nightly
baseline, which structurally cannot find them.

## Composite: `src/composites/dast` → `scan`, then `package`

`scan` returns the scan evidence `File`. Export it immediately to the host.
`package` accepts that detached file in a fresh
Dagger call and returns the audit `Directory` (`combined-evidence.json`,
`findings.sarif`, `comment.md`, `sbom.cdx.json`). This two-call boundary keeps
a runner-backed Service out of the graph the CLI later exports.

Successful export is not gate enforcement. A CI caller must clean stale output,
fail on either export failure, and require `jq -e '.passed == true'` for both
the fresh scan envelope and `combined-evidence.json`. Missing/malformed evidence
is failure. See the [complete composite caller](../../src/composites/dast/README.md#usage).
Retain warnings, non-runs, rule settings and examined/provenance metadata even
on a pass; `passed` does not mean clean or full-scope analysis.

### `scan`

| Parameter | Default | Notes |
|-----------|---------|-------|
| `--commit-sha`, `--branch`, `--repo-url` | required | provenance, positional-first like every other composite |
| `--app` | `url` | `url` \| `service` \| `container` |
| `--src` | — | `Directory`; required for `container`, refused for the other two |
| `--dockerfile` | `Dockerfile` | relative to `--src` |
| `--platform` | `linux/amd64` | |
| `--target` | — | required for `url` |
| `--service` | — | `Service`, e.g. `--service=tcp://localhost:5000`; required for `service` |
| `--port` | `8080` | bound shapes only |
| `--scheme` | `http` | |
| `--base-path` | `/` | |
| `--health-path` | — | defaults to `--base-path` |
| `--ready-timeout-seconds` | `120` | |
| `--mode` | `baseline` | |
| `--api-spec` | — | `File`; excludes `--api-spec-path` |
| `--api-spec-path` | — | path on the running app; excludes `--api-spec` |
| `--api-format` | `openapi` | |
| `--rule-config` | — | `File`, ZAP `-c` |
| `--max-duration-minutes` | `0` | 0 = no cap |
| `--profile` | — | |
| `--authenticated` | `false` | only ever set to `true`; see below |
| `--fail-on` | `HIGH` | |

`--mode` is a string and not a `--full` bool because a bool cannot carry three
values, and because Dagger's client can only ever transmit an optional bool as
`true`. The same mechanic is why `--authenticated` is named positively: it is
only ever set in the direction that works.

### `package`

| Parameter | Default | Notes |
|-----------|---------|-------|
| `--evidence` | required | the host file exported from `scan` |
| `--commit-sha`, `--branch`, `--repo-url` | required | provenance |
| `--teams-webhook`, `--run-url` | — | notification |

## Module: `security.scan-web`

Same parameters as the composite minus the build and notification surface,
plus `--container` (a `*dagger.Container`, which is how the composite hands
over the image it built). Exactly one of `--target` / `--service` /
`--container`; zero or two is an error, not a default. Returns the evidence
`File`.

## The `dast/1.0` payload

`genericFormat` is `dast/1.0`, and `genericReport` is a document cicd owns.
Its `.zapReport` retains ZAP's alert topology but omits request bodies,
response bodies, headers, and per-instance evidence captures. Those values are
unbounded and duplicate the normalized findings; carrying them made completed
scans too large to export. Scope, rule, count, severity, method, parameter, and
URL data remain in the payload and envelope.

| Field | Type | Meaning |
|-------|------|---------|
| `mode` | string | `baseline` \| `api` \| `full` |
| `source` | string | `url` \| `service` \| `container` |
| `targetUrl` | string | the address the scanner was actually given |
| `profile` | string | omitted when unset |
| `authenticated` | bool | |
| `readiness` | object | `url`, `status`, `attempts`, `waitedSeconds`, `ok`, `error` |
| `urlsWithAlerts` | int | distinct `instances[].uri` values that produced **at least one alert** |
| `endpointsFromSpec` | int | `api` mode only; the operations the API document declares |
| `apiPaths` | string[] | `api` mode only |
| `ruleSettings` | object[] | `id`, `action`, `note`, `fired` — every rule the `-c` config names, including ones that raised no alert (`fired: false`). Wider than "suppressions" on purpose: a config can raise a rule as well as ignore one |
| `scanDurationSeconds` | int | |
| `zapExitCode` | int | `0` clean, `1` FAIL, `2` WARN, `3` other |
| `zapReport` | object | compact ZAP alert report; request/response captures omitted |

`urlsWithAlerts` is named for what it counts. ZAP's JSON report does not
enumerate the URLs it visited and found nothing on, so this is a floor and not
a crawl count; a number that overstates its own coverage is worse than no
number. `endpointsFromSpec` is the real denominator and exists only in `api`
mode.

`zapExitCode` is recorded because ZAP's exit codes carry information the alert
list does not — and because throwing it away is the defect this feature was
built to close.

## Readiness is a recorded fact, not a precondition

Before any scan, cicd requests `<scheme>://<host>:<port><healthPath>` until it
answers or `ready-timeout-seconds` expires, and records the result either way.
The probe runs in the pinned alpine image and **not** in ZAP's, for the reason
`vuln_source.go`'s probe already gives: the answer to "could the target be
reached" must not come from inside the tool whose silence is under suspicion.
A response is 2xx or 3xx; a TCP accept is not the same question as "the app is
serving", so Dagger's own port readiness is not trusted.

A probe that never got a served response is an `errors[]` entry and
`passed: false` at **every** threshold including `NONE` — it is a non-run, not
a finding. This closes the worst failure mode the feature has: an app that
never came up produces a ZAP report with zero alerts, which is otherwise
byte-identical to a clean scan.

## Disclosure lines

All `warnings[]`, never `errors[]` — nothing failed to run. They are rendered
into the PR comment and the Teams card verbatim, and the workflow's gate step
prints them **on the pass path too**, because most of them describe green runs
and each one narrows what green means.

| Prefix | When | What it says |
|--------|------|--------------|
| `dast: THRESHOLD UNREACHABLE` | `--fail-on CRITICAL` | ZAP's maximum risk is High, so no finding can fail this gate. A warning and not an error because `CRITICAL` is legal everywhere else in cicd — but never silent, because a gate that cannot fail and a gate that passed are otherwise the same envelope |
| `dast: PROVENANCE NOT ATTESTED` | `url`, `service` | cicd did not build what it scanned |
| `dast: NOT AUTHENTICATED` | `authenticated` false | every authorisation and access-control rule reports on the anonymous surface only |
| `dast: PROFILE <name>` | `profile` set | the app ran under a non-production configuration; transport security, headers and error verbosity are properties of the deployed ingress and were not tested |
| `dast: BASELINE ONLY` | `mode=baseline` | passive scan, no attack payload sent — injection, traversal and deserialisation rules did not run. Its **absence** on a `full` run is the informative half |
| `dast: API SCAN` | `mode=api` | only the operations the document declares were requested |
| `dast: NO ALERTED URL` | a clean run with zero alerted URLs | names the readiness status beside it, because that pair is what a reader must see together |
| `dast: UNKNOWN RISK CODE` | ZAP emitted a risk code outside 0–3 | the severity map has no default arm that guesses |

`PROFILE` and `NOT AUTHENTICATED` are opposite calls on the same question and
both are deliberate. An unset profile is a consumer who made no claim, so
inventing a caveat about it would be noise on every run; an unset
`authenticated` is a *choice* whose silence would carry no information, so it
is stated.

## Related

- [Scan a running app (DAST)](../how-to-guides/scan-a-running-app.md) — the
  how-to, with the template and both walkthroughs.
- [`templates/github-actions/dast.yml`](https://github.com/context-and-oss/cicd/blob/main/templates/github-actions/dast.yml)
  — the caller stub, with the cadence already wired.
- [DAST](../explanation/continuous-delivery/security/dast.md) — what dynamic
  analysis is and where it sits in the CD model.
- [Runtime tool images](./runtime-images.md) — the ZAP and alpine pins.
