# Scan a running app (DAST)

Your repo ships a web app or an HTTP API. The source gate already reads your
code; this guide has something *attack* it while it runs. It wires the `dast`
composite into your repo: OWASP ZAP against a live target, the standard
evidence bundle, a PR comment, and a cadence that keeps an active scan off the
merge path.

Background on what dynamic analysis buys you and what it cannot see:
[DAST](../explanation/continuous-delivery/security/dast.md) and
[SAST](../explanation/continuous-delivery/security/sast.md). The one-entry-point
rule this composite follows is
[ADR-005](../decisions/ADR-005-commit-stage-code-and-artifact.md); the reason
cicd never deploys the thing it scans is
[ADR-001](../decisions/ADR-001-artifact-shapes.md).

## One question: who starts the app?

Everything else follows from the answer.

| | **W1 — you start it, we scan it** | **W2 — we start it, we scan it** |
|---|---|---|
| Who runs the app | your workflow, on the runner or anywhere routable | cicd, inside the Dagger engine |
| Works with | anything — compose stack, `dotnet run`, a deployed environment | a single container built from your Dockerfile |
| Needs a Dockerfile | no | yes |
| Databases, sidecars, seeded data | yours to arrange, so: yes | no — one container and nothing beside it |
| Provenance | none — cicd cannot prove what it scanned | attested — the image was built from this commit in this run |
| `--app` value | `service` (runner) or `url` (routable address) | `container` |

Neither is the "real" one. W2 is stronger evidence and fits a repo whose app is
one container that boots on its own. W1 fits everything else, and *everything
else* is most repos — anything that needs a database, mock data, a seeded
tenant, or three processes talking to each other.

If you can do both, do W2. If your app needs a stack around it, do W1 and stop
feeling bad about it: a scan of a real running app with no provenance line beats
no scan.

## Pick your shape

`--app` is always explicit. Nothing is auto-detected.

| `--app` | You provide | cicd does | Use it when |
|---------|-------------|-----------|-------------|
| `service` | `--service tcp://localhost:PORT` | binds the service under a fixed internal alias and composes the URL itself | your workflow started the app on the runner |
| `url` | `--target https://…` | scans exactly that address | the app runs somewhere else you own — a staging slot, a dev environment |
| `container` | `--src .` and a Dockerfile | builds the image, runs it, probes it, scans it | your app is one self-sufficient container |

**Why `service` exists when `url` looks like it covers it.** A Dagger container
has network egress but no route to the runner's loopback, so
`--target http://localhost:5000` against a stack on the runner does not scan the
wrong thing — it fails to connect, and you get a readiness error rather than a
green run. The Dagger CLI maps a `tcp://host:port` argument onto a host tunnel
for a `Service` parameter, so `--app service --service tcp://localhost:5000`
reaches the app your workflow started.

**`--target` must be an environment you are authorised to attack.** An active
scan sends real attack traffic. Point it at your own dev or staging environment,
never at production and never at somebody else's host.

## Pick your cadence

An active scan is minutes to hours of traffic. That is why `dast` is wired into
no other pipeline and has its own schedule.

| When | `--mode` | Why |
|------|----------|-----|
| Push to the mainline | `baseline` | passive only, a few minutes — a regression tripwire |
| Nightly | `baseline` | catches drift in the deployed environment, not just in the diff |
| Weekly | `full` | active attack traffic, spidering, the slow findings |
| On demand | your choice | reproduce a finding, or run `full` before a release |

`baseline` is passive: ZAP proxies and observes, it does not attack. `full` is
active. `api` sits between them — it drives an OpenAPI/SOAP/GraphQL document
instead of spidering HTML, which is the mode to pick for a headless API.

## The short way: copy the template

That whole cadence is already wired up. Copy
[`templates/github-actions/dast.yml`](https://github.com/context-and-oss/cicd/blob/main/templates/github-actions/dast.yml)
into your repository at `.github/workflows/dast.yml`, pick a shape, and you are
done — it calls the reusable workflow
[`context-and-oss/cicd/.github/workflows/dast.yml`](https://github.com/context-and-oss/cicd/blob/main/.github/workflows/dast.yml),
which handles the engine, the token, the SARIF upload, the evidence artifact
and the gate.

For W1 the reusable takes your start command: `app: service`, `start-cmd`, and
a `port` — it starts your app on the runner, waits for it on the same path the
scanner will probe, prints the start log on every run, and tears it down again
with `stop-cmd`. The two knobs people confuse are named apart on purpose:
`start-timeout-seconds` is how long the *workflow* waits for your app to come
up, `ready-timeout-seconds` is how long the *scanner* waits once cicd is
running. They exist to tell "my app never started" apart from "the scanner
could not reach it".

The rest of this guide is what the reusable does underneath, which is what you
need when your shape does not fit it — several apps in one repo, a matrix, a
scan job that has to run inside an existing workflow.

### On Azure DevOps

Copy
[`templates/azure-devops/dast.yml`](https://github.com/context-and-oss/cicd/blob/main/templates/azure-devops/dast.yml)
to `.pipelines/dast.yml` instead. Same three shapes, same cadence, same two
timeouts. The modules are public and need no credential; the optional
`TEAMS_WEBHOOK` is the one
[set-up-azure-devops-auth.md](set-up-azure-devops-auth.md) already describes.

Two differences worth knowing before you copy it. There is no reusable workflow
on this side — ADO has no `workflow_call`, so the template *is* the pipeline and
you own every line of it once copied. And **it does not gate**: the composites
exit 0 on a tripped gate, the verdict lives in `combined-evidence.json`, and the
step that reads it ships commented out under a `GATE GOES HERE` banner. Until
you uncomment it, the pipeline attacks your application and then goes green
whatever it finds. That is worse here than on the commit lane, because DAST's
`passed: false` also covers *a target that was never reached* — a scan that hit
nothing produces a report of zero alerts, byte-identical to a scan of a
genuinely clean app.

## Walkthrough — W1, an app your workflow starts

The shape for a repo whose app needs more than itself: a database, mock data,
several processes. Your job is to get it listening; cicd's job starts there.

```yaml
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Start the app in dev mode
        run: |
          docker compose -f docker-compose.dev.yml up -d
          # or: dotnet run --project src/Api & npm --prefix web start &

      - name: Wait for it to answer
        run: |
          for i in $(seq 1 60); do
            curl -fsS http://localhost:5000/health && exit 0
            sleep 2
          done
          echo "app never became ready" >&2
          exit 1

      - name: DAST
        run: |
          dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.3 call scan \
            --app=service --service=tcp://localhost:5000 \
            --port=5000 --health-path=/health \
            --mode=baseline --fail-on=HIGH \
            --commit-sha=$GITHUB_SHA --branch=${GITHUB_REF_NAME} \
            --repo-url=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY \
            export --path=./dast-scan.json
          dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.3 call package \
            --evidence=./dast-scan.json \
            --commit-sha=$GITHUB_SHA --branch=${GITHUB_REF_NAME} \
            --repo-url=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY \
            export --path ./dast-evidence
```

Two things people get wrong here.

`--port` is the port **the app listens on**, and it is also the port in the
`tcp://` argument. cicd composes the URL from `--scheme`, the internal alias and
`--port`; you never hand it a host string.

Your own readiness loop is not redundant with cicd's. Yours decides whether the
app started at all; cicd's `--ready-timeout-seconds` (default 120) decides
whether the *scanner* could reach it, and a probe that never got a served
response fails the run at **every** threshold, `--fail-on NONE` included.

For an API, swap the mode and hand it the document:

```bash
dagger -m ./src/composites/dast call scan \
  --app=service --service=tcp://localhost:5000 --port=5000 \
  --mode=api --api-spec-path=/swagger/v1/swagger.json \
  --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=./dast-scan.json
dagger -m ./src/composites/dast call package \
  --evidence=./dast-scan.json \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path ./dast-evidence
```

`--api-spec-path` is a path **on the running app** — cicd fetches it from the
target. Use `--api-spec` instead when the document is a file in your repo.

## Walkthrough — W2, a container cicd starts

One container, boots on its own, needs nothing beside it. This is the only shape
whose evidence may say the scanned code is this commit's code.

```bash
dagger -m ./src/composites/dast call scan \
  --app=container --src=. --dockerfile=Dockerfile \
  --port=8080 --health-path=/healthz \
  --mode=baseline --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=./dast-scan.json
dagger -m ./src/composites/dast call package \
  --evidence=./dast-scan.json \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path ./dast-evidence
```

cicd builds the image from your Dockerfile, runs it as a service, probes
`--health-path` until it answers or `--ready-timeout-seconds` expires, and
scans it.

It starts **one** container and nothing else. No database, no sidecar, and never
the host Docker socket — mounting `/var/run/docker.sock` is root on the runner
handed to the process being attacked, and it is refused permanently. If your app
needs a stack, that is not a limitation to work around: use `--app service`.

## What lands in the evidence

`export --path ./dast-evidence` writes the same bundle every cicd pipeline
writes:

| File | What it holds |
|------|---------------|
| `combined-evidence.json` | the envelope: `findings[]`, `findingsBySeverity`, `warnings[]`, `errors[]`, `passed` |
| `findings.sarif` | the same findings for GitHub code scanning |
| `comment.md` | the rendered PR comment |
| `sbom.cdx.json` | present but **empty** — a DAST run produces no components |

Read the warnings. The scan tells you what it did *not* cover: an unreachable
target, a scan cut short by `--max-duration-minutes`, rules you turned off with
`--rule-config`, and — for `--app url` and `--app service` — that cicd cannot
attest what was actually running at that address.

One threshold is a trap: **`--fail-on CRITICAL` can never fail over findings.**
ZAP's maximum risk is High, so there is no Critical tier to exceed. The evidence
warns rather than reporting a green run that could not have been anything else.
Use `HIGH`.

## What this is not

- **Not a deployment.** cicd scans; publishing and deploying stay in your repo
  ([ADR-001](../decisions/ADR-001-artifact-shapes.md)).
- **Not Operational Verification.** The readiness probe is a fact recorded in
  the DAST evidence, not a health attestation of its own.
- **Not a merge gate.** Nothing here belongs in `commit.yml`. Run it on the
  mainline, on a schedule, and on demand.

## Related

- [Use the complete pipeline](use-complete-pipeline.md) — the commit-stage gate that reads your code
- [Use individual modules](use-individual-modules.md) — calling `security` directly
- [DAST](../explanation/continuous-delivery/security/dast.md) — what dynamic analysis detects, and its limits
