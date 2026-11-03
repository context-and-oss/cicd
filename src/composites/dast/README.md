# composites/dast — Running-App DAST Pipeline

Scans a **running** application with OWASP ZAP and wraps the result in the
standard evidence bundle. Runs on its own cadence — baseline on mainline and
nightly, full on demand and weekly — and is wired into no other pipeline.

Composes: [build](../../build) + [security](../../security) +
[cross-cutting/evidence](../../cross-cutting/evidence) + [notify](../../notify)

## The three shapes

`--app` is always explicit (ADR-005). Nothing is auto-detected.

| `--app` | Who starts the application | Provenance |
|---------|----------------------------|------------|
| `url` | you, anywhere the Dagger engine can reach | none — the evidence says so |
| `service` | you, on the CI runner (`docker compose up`, `dotnet run`) | none — the evidence says so |
| `container` | cicd, from your Dockerfile, inside the engine | attested — the image was built from this commit in this run |

## Install

```
dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.3
```

## Usage

```bash
# W1 — you started it, we scan it (a compose stack on the runner)
dagger -m ./src/composites/dast call scan \
  --app=service --service=tcp://localhost:5000 \
  --mode=api --api-spec-path=/swagger/v1/swagger.json \
  --port=5000 --health-path=/health \
  --profile=Staging --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=dast-scan.json

# W2 — we start it, we scan it (single container, provenance attested)
dagger -m ./src/composites/dast call scan \
  --app=container --src=. --dockerfile=Dockerfile --port=8080 \
  --mode=baseline --fail-on=HIGH \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=dast-scan.json

# W1 — a deployed environment you own
dagger -m ./src/composites/dast call scan \
  --app=url --target=https://staging.example.com \
  --mode=full --max-duration-minutes=45 \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=dast-scan.json

# For any shape, package the detached scan file in a fresh Dagger call.
dagger -m ./src/composites/dast call package \
  --evidence=./dast-scan.json \
  --commit-sha=$SHA --branch=main --repo-url=$REPO_URL \
  export --path=./dast-evidence
```

The host file between `scan` and `package` is an intentional lifecycle
boundary. A service-shaped result is consumed while its runner tunnel is live;
the fresh packaging call has no Service in its graph and can export the audit
directory normally. The reusable workflow performs both calls and uploads the
directory.

## Functions

| Function | Description |
|----------|-------------|
| `scan` | Optional container build + ZAP scan; returns the scan evidence `File` |
| `package` | Wraps a detached scan file, adds the comment and optional notification, and returns the audit `Directory` |

## What it does not do

- It never deploys or publishes anything (ADR-001).
- It starts **one** container for `--app container` and nothing beside it: no
  database, no sidecar, and never the host Docker socket. An application that
  needs a stack around it uses `--app service`.
- It is not Operational Verification. The readiness probe is a fact recorded in
  the DAST evidence, not a health attestation of its own.

## Docs

→ [How to scan a running app](../../../docs/how-to-guides/scan-a-running-app.md)
→ Full documentation at [docs/](../../../docs/index.md)
