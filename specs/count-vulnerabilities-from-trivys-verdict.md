# Intent: take vulnerability severity from Trivy's own verdict, and put the rows in the detail list

## Why

Two defects sat in the same code path, and the second one let a CRITICAL
vulnerability through a `--fail-on CRITICAL` gate.

The reporting defect first. `src/cross-cutting/evidence/main.go` built the
combined detail list from SARIF and from the two `genericReport` shapes it knows,
and never read `envelope.Findings`. The security module puts vulnerability detail
nowhere else, so Trivy rows reached no detail list at all: a run whose only
failure was a CVE rendered `**Findings** | 12` above an empty table, and
`src/notify/render.go` returns early on an empty slice, so the PR comment carried
a number nobody could act on.

The severity defect is the one with teeth. `parseCycloneDXSeverities` read
`vulnerabilities[].ratings[0].severity` with a literal `break // use first
rating`. CycloneDX ratings are a list of per-vendor opinions with no field marking
which one the scanner chose, so entry zero is whatever the vulnerability database
serialised first. Measured against trivy 0.70.0 on `debian:11.6`, 205
vulnerabilities:

- Trivy's own verdict: **9 CRITICAL**. Entry zero: **3**.
- Seven CRITICAL CVEs could not fail a `--fail-on CRITICAL` gate —
  CVE-2023-45853, CVE-2024-37371, CVE-2026-13221, CVE-2026-33845, CVE-2026-42010,
  CVE-2026-42496, CVE-2026-8376. One false CRITICAL was raised instead
  (CVE-2011-3389, which Trivy rates MEDIUM).
- Entry zero's vendor was `alma` for 117 of the 205 findings, on a Debian image.
- 34 findings were rated below Trivy's verdict overall.
- Seven vulnerabilities carried `UNKNOWN` or no rating, matched no case in the
  old switch, and reached neither the counts nor the total nor any list.

Trivy's verdict is not recoverable from the CycloneDX document. CVE-2023-45853
names `debian` as its severity source and has no `debian` entry in its ratings
array; `properties` is null throughout. `--format sarif` is no escape hatch
either, since SARIF has no level between `error` and `warning`, so critical and high both
arrive as `error` and `severityFromSARIFLevel` maps that to HIGH.

## What changed

Both scans now run `--format json` and then `trivy convert --format cyclonedx` on
that report, so the SBOM is a projection of the scan already performed rather
than a second scan. `src/security/trivyflags.go` splits into `trivyScanArgs` and
`trivyConvertArgs`, sharing one `trivySeverityPin` constant.

`src/security/trivyreport.go` is new and untagged, so `go test -tags unit_test`
reaches it. It parses the native report and derives three things from
`Severity`: the per-severity counts, the `Finding` rows, and a warning naming how
many vulnerabilities carry no vendor rating. `src/security/vuln_source.go`,
`src/security/vuln_image.go` and `src/security/archive.go` return one
`trivyResult` carrying all four outputs, and read the native report before
fetching the CycloneDX so an unreadable authority never yields a payload with no
findings beside it. `parseCycloneDXSeverities` is deleted from
`src/security/findings.go`.

`src/cross-cutting/evidence/main.go` reads `envelope.Findings`, then dedupes on
the whole struct so a module that both states a finding and ships a payload
describing it does not show the row twice.

`.github/workflows/ci.yml` asserts on the archive scan that trivy rows exist,
that their count equals `sum(len(affects))` across the SBOM's vulnerabilities,
that every severity is canonical, and that no row's severity is missing from
`findingsBySeverity`.

## Decisions

**Native JSON as the authority, CycloneDX as a rendering.** The alternative was
to keep reading ratings and pick a rule: `max` finds all 9 CRITICALs but
over-reports 93, and `source` then `nvd` then `max` still misses 5 and
over-reports 45. Every rule trades a missed gate against a false alarm, so the
choice was to stop guessing. `trivy convert` removes the trade because the two
documents cannot disagree — verified that the converted CycloneDX matches a direct
`--format cyclonedx` scan apart from `serialNumber`, `metadata.timestamp` and
generated `bom-ref` UUIDs, with the same 205 vulnerabilities and the same
component and dependency lists.

**`trivy convert` pins `--severity` as well.** It accepts the flag and its `-c`
still defaults to `trivy.yaml` in the working directory, so pinning only the scan
would leave a consumer's `severity: [CRITICAL]` free to filter the converted
report instead. A test asserts the two pins are identical, given that a drift
between them reopens the hole silently.

**`UNKNOWN` counts LOW rather than being dropped.** An unrated CVE is not a
low-risk one, so the count alone would misrepresent it — but dropping is what
happened before, and being counted at the bottom is strictly more honest than
being absent. A warning states how many rows this applies to.

**Counts are per package × CVE.** One CVE affecting three packages is three
places to change, therefore three rows and three counts. This is why the CI
cross-check compares against `sum(len(affects))` and not the vulnerability count.

**The envelope's `findings[]` carries vulnerabilities only.** Lint, SAST and
secrets detail is expressible in SARIF and the aggregator already reads it from
there, so stating those twice would only give the dedupe more work.

## Known residue

The `security-source` envelope's `tool.version` is still blank, which is a
separate reporting gap.

Because `findings[]` holds vulnerabilities and `findingsBySeverity` also counts
secrets and SAST, the two totals differ by design: the debian:11.6 run reports 364
rows against 373 counted, the difference being nine TruffleHog secrets that the
merged SARIF supplies.

`src/notify/render.go` prints at most a bounded slice of the detail table, so a
364-row image scan is truncated in the PR comment. The full list stays in
`combined-evidence.json`.

On npm lockfiles entry zero happened to be `ghsa`, which is the source Trivy uses
there, so the old parser mostly agreed on language dependencies — only
CVE-2025-13465 moved. The divergence is concentrated in OS packages, meaning the
gate this fixes is `ScanImage` and the stage-4 image check rather than
`ScanSource` on a lockfile.
