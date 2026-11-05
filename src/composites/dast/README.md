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

Scan only explicitly authorized targets. Baseline also generates requests;
API/full modes send attack traffic. Select traffic limits for the environment.

## Install

Remote references require authorized read access while the repository is private;
anonymous fetch is conditional on an explicitly approved public distribution.
An authorized read-only source checkout can instead use `-m ./src/composites/dast`
from its root. Source credentials are separate from notification secrets.

```
dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.4
```

## Usage

A complete container-shaped gate follows. Set `SHA` and `REPO_URL`, install
Dagger and `jq`, and run from the app source root with a Dockerfile serving
port 8080. Export success alone is not the verdict.

```bash
set -eu
rm -f ./dast-scan.json
rm -rf ./dast-evidence
dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.4 call scan \
  --app=container --src=. --dockerfile=Dockerfile --port=8080 \
  --mode=baseline --fail-on=HIGH \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./dast-scan.json || exit 1

# Package even a failed scan verdict, preserving evidence for inspection.
dagger -m github.com/context-and-oss/cicd/src/composites/dast@v5.1.4 call package \
  --evidence=./dast-scan.json \
  --commit-sha="$SHA" --branch=main --repo-url="$REPO_URL" \
  export --path=./dast-evidence || exit 1
jq -e '.passed == true' ./dast-scan.json >/dev/null || exit 1
jq -e '.passed == true' ./dast-evidence/combined-evidence.json >/dev/null || exit 1
```

For `service`, replace the container inputs with
`--app=service --service=tcp://localhost:5000 --port=5000 --health-path=/health`
after starting the authorized app yourself; own its teardown too. API mode
uses `--mode=api --api-spec-path=/swagger/v1/swagger.json` when the app serves
that document. For `url`, replace the container inputs with
`--app=url --target=https://staging.example.com`; full scans use
`--mode=full --max-duration-minutes=45`. These are alternative argument sets,
not additional scan commands to run sequentially. Keep the fresh-output,
export-failure and both verdict checks for every shape.

A pass covers configured checks, not clean/full-scope assurance. Preserve
warnings, errors, scope, rule settings, provenance and examined metadata.
DAST is not wired into the commit/precommit merge gate.

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
