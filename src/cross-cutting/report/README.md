# cross-cutting/report

Extracts the native tool report embedded in any evidence envelope and returns it as a
standalone file. No containers, no tool invocations — pure Go JSON parsing.

Works with evidence produced by any module (`security/`, `quality/`, `build/`) since all
share the same evidence envelope schema.

## Install

```
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.1.2
```

## Functions

| Function | Description |
|----------|-------------|
| `report` | Extract the native tool report from an evidence envelope |

## Usage

```bash
# Extract SARIF from a scan-source evidence file (e.g. for GitHub Advanced Security upload-sarif)
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.1.2 call report \
  --evidence ./evidence.json \
  export --path=./results.sarif

# Extract CycloneDX from a vuln scan or SBOM evidence file
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.1.2 call report \
  --evidence ./vuln-evidence.json \
  export --path=./vuln.cdx.json

# Extract ZAP JSON from a scan-web evidence file
dagger -m github.com/context-and-oss/cicd/src/cross-cutting/report@v5.1.2 call report \
  --evidence ./web-evidence.json \
  export --path=./zap-report.json
```

## Output format

The output filename depends on which report field is populated in the envelope:

| Evidence field | Output filename | Format | Typical consumers |
|----------------|-----------------|--------|-------------------|
| `sarifReport` | `report.sarif` | SARIF 2.1.0 | GitHub Advanced Security `upload-sarif`, IDE integrations |
| `cyclonedxReport` | `report.cdx.json` | CycloneDX | Dependency tracking, SBOM consumers |
| `genericReport` | `report.json` | Tool-specific JSON | ZAP, markdownlint, others |

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
cd src/cross-cutting/report && GOWORK=off go test -tags unit_test ./...
```
