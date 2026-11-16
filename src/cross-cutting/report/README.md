# cross-cutting/report

Extracts an embedded report payload from an evidence envelope and returns it as a
standalone file. A `genericReport` may be a cicd-owned wrapper rather than a native
tool document. No containers, no tool invocations — pure Go JSON parsing.

Works with evidence produced by any module (`security/`, `quality/`, `build/`) since all
share the same evidence envelope schema.

## Install

Public modules support anonymous fetching; private copies require read-only
source access. Verify the referenced release, or use `-m ./src/cross-cutting/report`
from a separate source checkout's root.

```
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.2.0
```

## Functions

| Function | Description |
|----------|-------------|
| `report` | Extract the native tool report from an evidence envelope |

## Usage

```bash
# Extract SARIF from a scan-source evidence file (e.g. for GitHub Advanced Security upload-sarif)
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.2.0 call report \
  --evidence ./evidence.json \
  export --path=./results.sarif

# Extract CycloneDX from a vuln scan or SBOM evidence file
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.2.0 call report \
  --evidence ./vuln-evidence.json \
  export --path=./vuln.cdx.json

# Extract the cicd-owned dast/1.0 payload from scan-web evidence
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.2.0 call report \
  --evidence ./web-evidence.json \
  export --path=./dast-report.json
```

For a compact ZAP alert document, explicitly extract the nested object:

```bash
set -eu
rm -f ./zap-report.json
jq -e '.zapReport | select(type == "object")' ./dast-report.json > ./zap-report.json || exit 1
```

This is report inspection, not verdict enforcement. The `dast/1.0` payload is
not raw ZAP output: `zapReport` omits request/response bodies, headers and
per-instance evidence captures. Keep the original envelope for verdict, scope,
warnings and non-run metadata. See the [DAST reference](../../../docs/reference/dast.md#the-dast10-payload).

## Output format

The output filename depends on which report field is populated in the envelope:

| Evidence field | Output filename | Format | Typical consumers |
|----------------|-----------------|--------|-------------------|
| `sarifReport` | `report.sarif` | SARIF 2.1.0 | GitHub Advanced Security `upload-sarif`, IDE integrations |
| `cyclonedxReport` | `report.cdx.json` | CycloneDX | Dependency tracking, SBOM consumers |
| `genericReport` | `report.json` | Producer-specific JSON (DAST: cicd-owned `dast/1.0`) | Payload-aware consumers |

Priority order: `sarifReport` → `cyclonedxReport` → `genericReport`. Returns an error if
none of the fields are populated.

## Parameters

| Param | Type | Description |
|-------|------|-------------|
| `evidence` | File | Evidence envelope produced by any module function |

## Development

- `main.go` — `Report()`: reads the envelope and writes the extracted file (`//go:build !unit_test`)
- `extract.go` — `extractFromJSON()`: the field priority and the output filename, untagged
- `extract_test.go` — one case per report field, a payload with none, and an envelope that is not JSON

```sh
(cd src/cross-cutting/report && GOWORK=off go test -tags unit_test ./...)
```
