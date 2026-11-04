# composites/dast

Running-app DAST: build the application or take an address for it, scan the
**running** thing with OWASP ZAP, aggregate the evidence, notify. One scan
entry point, shape as a parameter (ADR-005), and no auto-detection (ADR-001).

DAST is wired into **no** other pipeline. It runs on its own cadence — baseline
on mainline and nightly, full on demand and weekly — because an active scan is
minutes-to-hours of traffic against a live application, which is the wrong thing
to put in front of a merge.

## Entry functions

```go
func (m *Dast) Scan(
    ctx context.Context,
    commitSha, branch, repoUrl string,
    // --- shape ---
    app string,                 // default "url" — url|service|container
    src *dagger.Directory,      // required for --app container, refused otherwise
    dockerfile string,          // default "Dockerfile"
    platform string,            // default "linux/amd64"
    target string,              // required for --app url
    service *dagger.Service,    // required for --app service
    // --- address (service and container; url carries its own) ---
    port int,                   // default 8080
    scheme string,              // default "http"
    basePath string,            // default "/"
    healthPath string,          // defaults to basePath
    readyTimeoutSeconds int,    // default 120
    // --- scan (mirrors security.ScanWeb) ---
    mode string,                // default "baseline" — baseline|api|full
    apiSpec *dagger.File, apiSpecPath, apiFormat string,
    ruleConfig *dagger.File,
    maxDurationMinutes int,     // default 0 — no cap
    profile string,
    authenticated bool,
    failOn string,              // default HIGH
) (*dagger.File, error)

func (m *Dast) Package(
    ctx context.Context,
    evidence *dagger.File,
    commitSha, branch, repoUrl string,
    teamsWebhook *dagger.Secret,
    runUrl string,
) (*dagger.Directory, error)
```

`scan` is the single entry point for the three application shapes. The caller
immediately exports its File to the host.
`package` accepts that detached file in a fresh Dagger call and returns
`combined-evidence.json`, `findings.sarif`, `sbom.cdx.json` (empty — DAST
produces no components), `parts/`, `concerns/`, and `comment.md`.

## The three shapes

| `--app` | Who starts the app | What cicd does | Provenance |
|---------|--------------------|----------------|------------|
| `url` | the consumer, anywhere routable | scans `--target` as given | none |
| `service` | the consumer, on the CI runner | binds `--service` under a fixed alias and composes the address itself | none |
| `container` | cicd, inside the engine | `build.Build(src, dockerfile)` → `ScanWeb --container` | attested |

`url` and `service` are W1 ("you start it, we scan it"); `container` is W2 ("we
start it, we scan it"). W1 covers any shape, including a compose stack; W2 is
single-container only and is the only one whose evidence may say the scanned
code is this commit's code.

**Why `service` exists at all**, since `url` looks like it covers it: a Dagger
container has network egress but no route to the runner's loopback, so
`--target http://localhost:5000` against a compose stack on the runner does not
scan the wrong thing — it fails to connect. The Dagger CLI maps a
`tcp://host:port` argument for a `Service` parameter onto a host tunnel, and
`ScanWeb` binds that service under `app-under-test`, so the URL ZAP is given
never contains a host string a consumer typed.

**The host Docker socket is refused, permanently.** Mounting
`/var/run/docker.sock` is expressible in Dagger and is declined: it is root on
the runner, handed to the process being attacked. A repository whose application
needs a Docker socket (Testcontainers, an emulator) starts its own stack and
uses `--app service`.

## Why the validation lives in `shape.go`

`shape.go` is **untagged** and `main.go` is `//go:build !unit_test`, the pattern
`src/security/include.go` and `src/quality/include.go` already follow: logic
behind the Dagger build tag is logic no unit test can ask a question of, and
that is exactly how a `switch` with no `default:` arm survives.

`validateApp` refuses two classes of input, and the second is the one that is
easy to miss:

- **A selector that disagrees with its inputs** — `--app url` with a `--service`
  bound, `--app container` with no `--src`, a `--src` handed to a shape that
  builds nothing. Most of these would also be caught by `ScanWeb`'s "exactly one
  source" rule, but its message names three parameters the consumer did not
  think they were choosing between. A `--src` that is silently ignored is worse
  than a wrong flag: the run then reads as a scan of the code in this commit.
- **A value the generated client would drop.** Dagger's Go client omits any
  optional argument holding its zero value (`if !querybuilder.IsZeroValue(...)`)
  — the same mechanic that forces the intent gate's flag to be negative and
  DAST's mode to be a `string` rather than a `bool`. So `--mode ""` and
  `--port 0` never reach `ScanWeb` to be refused there; they arrive as its
  defaults instead, `baseline` and `8080`. An empty workflow variable would buy
  the weakest scan, or a scan of a port nobody named, with nothing in the
  evidence saying so. This composite is the last place those values are visible,
  so it is where they are refused.

The mode **set** is deliberately not copied here. `webmode.go` owns it and
rejects an unknown value; a second copy would be a second thing to keep in step,
and the drift would surface as a mode this composite rejects and the module
accepts. Only the empty string is checked here, because only the empty string
never arrives. `TestValidateAppPassesAnUnknownModeThrough` pins that boundary so
a future "helpful" addition of the set here is a deliberate act.

## The gate

The verdict is evidence, not command-exit enforcement: export the detached scan,
package it, then require `jq -e '.passed == true'` for both fresh scan and
combined envelopes. Clean stale outputs and fail immediately on either export
failure; see the [complete caller recipe](README.md#usage). Preserve warnings,
errors, provenance, rule settings and examined scope even on passes. Scan only
explicitly authorized targets; passive baseline also generates requests.

`ScanWeb`'s verdict rule is unchanged: findings at or above `--fail-on` fail the envelope, and a
readiness probe that never got a served response fails it at **every** threshold
including `NONE`, because a target that was never reached produces a report of
zero alerts that is otherwise byte-identical to a clean scan
(`gatedPassed(ran=false, …)`).

`--fail-on CRITICAL` is a threshold ZAP cannot reach — its maximum risk is High
— so it can never fail over findings, and the evidence warns rather than
reporting a green run that could not have been anything else.

## Delivery

`evidence.Wrap` → `notify.GithubBuildComment` → `comment.md` in the audit
bundle, plus an optional Teams card. `Package` hands this to `finishAudit` in
`audittail.go`, the tail the commit and precommit composites end in too; the
three copies are byte-identical apart from the SDK import (`synced_files` in `scripts/repo-inventory.json`). The reusable workflow first consumes the
scan File onto the runner, then invokes `package` in a fresh Dagger call. This
host-file boundary prevents the returned Directory from carrying a
runner-backed service graph, which can leave the CLI waiting after the module
function has completed. A notification that could not be delivered is a
non-fatal warned-pass delivery envelope, merged by a second `evidence.Wrap`
call so `warnings[]` survives in combined evidence and the PR comment; the
reason also goes to stderr. This is the same tail `composites/commit` uses.
`passed` alone is not notification delivery proof.

A DAST run produces no SBOM. `sbom.cdx.json` is still written by `evidence.Wrap` (it always
writes all three merged documents) and is empty of components; do not read it as
a component inventory of the scanned application.
