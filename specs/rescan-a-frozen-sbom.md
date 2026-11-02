# Rescan a frozen SBOM

The second of ADR-006's two work items in cicd, and the one that runs a tool.
The first — the publishing contract and the workflow outputs — shipped as
`expose-the-verdict-a-caller-can-read`; this one gives the mutable
`vuln-current.json` in that contract something to be regenerated *by*.

## The verdict that goes stale by standing still

A vulnerability verdict is a frozen SBOM crossed with moving CVE knowledge. The
CycloneDX document a commit-stage run freezes into its audit (`sbom.cdx.json`,
the envelope key `cyclonedxReport`) never changes again, but the database it was
graded against changes daily, so the verdict beside it is correct only about the
day it was produced. ADR-006 names the consequence for per-release customer
reports: four frozen files and one mutable `vuln-current.json`, regenerated on a
schedule the consumer owns.

Nothing in cicd could regenerate it. The security module's entry points took a
source tree (`ScanSource`), a container (`ScanImage`), a built directory
(`ScanArchive`) or a live URL (`ScanWeb`) — every one of them an input that has
to be *reconstructed* for a release that already shipped. Refreshing the verdict
meant checking the release tag out again and rescanning a rebuild of it, and a
rebuild is not the record: a floating version range restores differently today
than it did at release time, which is precisely the gap the frozen SBOM exists
to close. The exact input the question needs — the CycloneDX document the
release actually froze — was the one input no function accepted.

## The fix

`security.ScanSbom` (`src/security/sbomscan.go`): take a CycloneDX file, rescan
it against today's database with the same digest-pinned Trivy the pipelines
use, and return a standard evidence envelope.

The container run (`src/security/vuln_sbom.go`) is deliberately assembled from
parts that already existed, because the value of a rescan is comparability:

- the same `trivyImage` pin and `cicd-trivy-db` cache volume as the fs and
  image scans (`src/security/images.go`) — no new pin, no new update group;
- `trivyScanArgs("sbom", "/sbom/bom.json")` from `trivyflags.go`, which was
  already subcommand-generic, so the rescan carries the identical severity
  list, `--ignore-status` policy and `--pkg-types` selection as the scan that
  froze the SBOM. A difference between the frozen verdict and the rescan is
  therefore new CVE knowledge and nothing else — a third flag list would have
  reintroduced, one file over, the drift the shared builder exists to prevent;
- `trivyConvertArgs()` re-renders CycloneDX from this rescan's own native
  report, so the `cyclonedxReport` in the envelope describes the run that
  produced the verdict rather than restating the input;
- `readTrivyResult`/`parseTrivyNative` classify the outcome, so an empty
  report, malformed JSON or a missing `Results` array is a named non-run
  exactly as it is on the other two Trivy paths.

`ScanSbom` is wired into no composite. The pipelines scan the tree and the
image directly; rescanning their own minutes-old output could only restate the
verdict the run already holds. The function is the scheduled entry point the
consumer's workflow calls on its own cadence, with publishing and credentials
staying in the consumer repository (ADR-001, ADR-006).

### The input is refused locally, before any container runs

`sbomInputError` (`src/security/sbominput.go`) rejects a file that is empty, is
not valid JSON, declares no `bomFormat`, or declares one that is not
`CycloneDX`. Each rejection is one `errors[]` entry naming the caller's actual
defect, and `passed=false` at every threshold, `--fail-on NONE` included —
a rescan that never read its SBOM must never read as a rescan that found
nothing, which is the founding doctrine verbatim.

Local validation rather than letting Trivy trip, because Trivy's error for an
unreadable document describes Trivy's failure while the real defect is the
caller's: they handed cicd something that was never a CycloneDX document. The
error message for the no-`bomFormat` case also says where a real one comes from
(`cyclonedxReport` in any cicd envelope), because the likeliest way to hit it
is exporting the wrong key. The dependency-track upload refusing an empty SBOM
before posting it is the precedent.

The BOM is stripped once (the `\ufeff` prefix, then trim) before any parse,
because
`strings.TrimSpace` does not remove U+FEFF — the same measured trap
`read-the-document-a-leg-wrote` documents in the coverage sniffer — and a
document carrying two BOMs stays refused rather than being laundered into
validity.

### Where the logic lives, and why

`sbominput.go` is **untagged**; only `sbomscan.go` and `vuln_sbom.go` carry
`//go:build !unit_test`. Validating a string needs no Dagger, so every accept
and every rejection is driven by `sbominput_test.go` under the canonical
`-tags unit_test` runner — three accepted shapes (minimal document, leading
whitespace, UTF-8 BOM) and ten named rejections (empty, whitespace-only,
BOM-only, non-JSON, double BOM, JSON array, JSON scalar, no `bomFormat`, SPDX,
a SARIF document masquerading by key shape). `include.go` and `noartifact.go`
carry the same split for the same reason: logic that lives behind the Dagger
build tag is logic nothing can test.

`trivyflags_test.go` now iterates `sbom` through the same three assertions that
pin `fs` and `image` — vuln scanning explicitly enabled, native JSON asked for,
no package dropped from the SBOM — so a flag the subcommand stops accepting
fails the unit suite rather than the consumer's scheduled rescan.

The provenance trio stays required (`--commit-sha`, `--branch`, `--repo-url`)
and the parameter doc says what belongs there: the commit the SBOM was frozen
at, because that release is what the rescan grades. An envelope naming no
commit is a verdict about nothing in particular.

## What was proven

Measured on this branch, Dagger v0.20.8, Trivy 0.70.0 at the pinned digest,
darwin/arm64:

1. `scan-source` on `testdata/go-app` produced an envelope whose
   `cyclonedxReport` carries 3 components and 1 vulnerability. That document,
   extracted and handed to
   `dagger -m ./src/security call scan-sbom --sbom … --fail-on NONE …`, came
   back `passed: true`, `findingsCount: 1`, `findingsBySeverity: {"HIGH": 1}`,
   `errors: []`, `tool: {"name":"trivy","version":"0.70.0","args":["sbom"]}` —
   and the finding is byte-identical to the source scan's: CVE-2020-26160,
   `github.com/dgrijalva/jwt-go@v3.2.0+incompatible`, HIGH, artifact path
   `go.mod`. Same input, same flags, same database day, same verdict.
2. That green run is also the flag-acceptance proof the shared builder needed.
   `trivy` rejects an unknown flag with exit 2 and no report, which
   `readTrivyResult` classifies as a non-run — so if the `sbom` subcommand had
   refused any pinned flag, `errors[]` would be non-empty and step 1 red. It
   was green, so 0.70.0 accepts every flag `trivyScanArgs` pins, on the real
   digest, demonstrated rather than read off a help screen.
3. An empty file: `passed: false` at `--fail-on NONE`, one error —
   `sbom-input: the supplied SBOM file is empty, so there is nothing to
   rescan`.
4. `{"not":"an sbom"}`: `passed: false` at `--fail-on NONE`, one error naming
   the missing `bomFormat` and where a real document comes from.
5. The unit suites: `sbominput_test.go` (13 cases) and the widened
   `trivyflags_test.go`, both under `scripts/test-module-units.sh`, so a green
   `lint-repo` means they executed.
6. The `module-test` security arm in `.github/workflows/ci.yml` asserts both
   directions on every CI run: the archive scan's `cyclonedxReport` — already
   asserted to carry >0 vulnerabilities two cells earlier, so the positive
   control is free — rescans to `findingsCount > 0` with no errors, and a
   non-CycloneDX document lands in `errors[]` with `passed=false` at
   `--fail-on NONE`.

## What this does not do

**It does not schedule anything and it does not publish anything.** The cadence,
the CDN, and the credentials are the consumer's (ADR-001, ADR-006). cicd's
whole contribution to `vuln-current.json` is that regenerating it is now one
function call on a kept file instead of a checkout and a rebuild.

**It trusts the SBOM it is handed.** A document that omits components the
release actually shipped produces a verdict about the omission, not the
release. That is inherent to rescanning a frozen record, and it is why the
README points the caller at the commit audit's own `sbom.cdx.json` rather than
a hand-built inventory.

**An SBOM with no resolvable components is a non-run, not a pass.** Trivy
yields a report with no `Results` array for such a document, and
`parseTrivyNative` classifies that as a non-run. For a rescan this is the
honest answer — Trivy examined nothing — and the tree that produces such an
SBOM already fails the source scan's ecosystem reconciliation, so the rescan
agrees with the scan instead of inventing a cleaner verdict.

**It does not verify the provenance it records.** `--commit-sha` is the
caller's claim about which release the SBOM froze; nothing checks the document
against that commit. Verifying it would require the checkout this function
exists to avoid.
