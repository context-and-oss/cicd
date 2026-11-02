// Trivy invocation policy: the flags cicd pins on every scan so a repository's
// own trivy.yaml can narrow *scope* without ever narrowing *findings*.
//
// Deliberately untagged (no //go:build !unit_test): this is a flag list with no
// Dagger dependency, so trivyflags_test.go can pin it under
// `go test -tags unit_test ./...`.
package main

// trivyConfigDir is the working directory both Trivy scans run in. Trivy
// auto-loads `trivy.yaml` from its working directory, so mounting the source at
// /src and working there is what makes a consumer-owned `trivy.yaml` take
// effect — the same zero-configuration deal `.semgrepignore` gets. The scan
// target stays absolute (/src), which keeps `skip-dirs` patterns relative to
// the source root and leaves the report's root component name unchanged.
const trivyConfigDir = "/src"

// trivyPinnedFlags are passed on the command line of every Trivy scan, and the
// command line beats the config file.
//
// Honouring `trivy.yaml` (above) hands the consumer a file that can silently
// gut the scan: `severity: [CRITICAL]`, `ignore-unfixed: true`,
// `pkg.types: [os]`, `ignore-status: [affected]` and `db.skip-update: true` all
// remove findings from the report while the scan still "succeeds". Proven
// against trivy 0.70.0 on a fixture with ten known CVEs: a config setting
// severity + ignore-unfixed alone took the report from 10 vulnerabilities to 1,
// and pinning these flags took it back to 10.
//
// So the split is deliberate and load-bearing:
//   - scope (`skip-dirs`, `skip-files`, `.trivyignore`) stays the consumer's —
//     it is visible in their repository and reviewable in a pull request;
//   - anything that filters findings out of a scan cicd already gates on is
//     cicd's, and is pinned here.
//
// `.trivyignore` sits on the consumer's side of that split and is still
// honoured, but it is no longer the recommended way to accept a vulnerability:
// it drops rows *before* Trivy writes the report, so the acceptance and its
// reasoning are invisible in the evidence cicd produces. `--vuln-accept` does
// the same job with the identifier and the reason in `warnings[]`, and
// `trivyignore.go` discloses that a `.trivyignore` narrowed the report at all.
//
// --scanners vuln is in this list for a different reason: it used to be paired
// with "--format cyclonedx", and in that combination Trivy switches to pure SBOM
// generation and disables security scanning entirely, so its absence made every
// vulnerability scan report zero. The scan now asks for native JSON (see
// trivyScanArgs), where scanning is not silently disabled — the flag stays
// because pinning it costs nothing and `scan.scanners` in a consumer trivy.yaml
// can still switch vulnerability scanning off. See the CLAUDE.md in this
// directory.
//
// Maintenance risk worth naming: a future Trivy release can add a new
// finding-filtering key. Nothing here detects that automatically. When bumping
// trivyVersion, re-read the config reference for new keys under `severity`,
// `vulnerability` and `pkg` and add the matching flag.
var trivyPinnedFlags = []string{
	"--scanners", "vuln",
	"--severity", trivySeverityPin,
	"--ignore-unfixed=false",
	"--ignore-status", "",
	"--pkg-types", "os,library",
	"--skip-db-update=false",
}

// trivySeverityPin is shared by the scan and the conversion because `convert`
// accepts --severity too, and its -c/--config still defaults to `trivy.yaml` in
// the working directory. Pinning the scan alone would leave a consumer's
// `severity: [CRITICAL]` free to filter the *converted* report instead, which
// reopens exactly the hole trivyPinnedFlags exists to close.
const trivySeverityPin = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

// trivyScanArgs builds the scanning command line: the subcommand, the pinned
// flags, native-JSON report plumbing, and the caller's target arguments.
//
// The report format is Trivy's own JSON rather than CycloneDX because CycloneDX
// cannot express the severity Trivy resolved. A CycloneDX `vulnerability` holds
// a bag of per-vendor `ratings[]` and no verdict, and Trivy's chosen source is
// frequently absent from that bag entirely. Measured on 0.70.0 against
// debian:11.6 — 205 vulnerabilities, ground truth from the native report:
//
//	strategy                         exact   under-reported   uncounted
//	ratings[0] (what cicd did)         114               34           7
//	max across ratings                 105                0           7
//	source -> nvd -> max               148                5           7
//
// Nothing derived from `ratings[]` is both accurate and safe, and the first-entry
// pick found 3 of the 9 CRITICALs — the other 6 could not fail a
// `--fail-on CRITICAL` gate. Native JSON carries `Severity` per finding, so
// there is nothing to reconstruct.
//
// --list-all-pkgs is explicit rather than left to its default because the
// converted CycloneDX document is also the SBOM this repo uploads to Dependency
// Track; a default flip to false would quietly ship a components list holding
// only vulnerable packages.
//
// --exit-code 0 is safe here and is not a swallowed failure: findings are read
// out of the report, and a Trivy that could not run fails when the report file
// is absent, which surfaces as an error from the Dagger file read.
func trivyScanArgs(subcommand string, target ...string) []string {
	args := []string{"trivy", subcommand}
	args = append(args, trivyPinnedFlags...)
	args = append(args,
		"--format", "json",
		"--list-all-pkgs",
		"--output", trivyNativePath,
		"--exit-code", "0",
	)
	return append(args, target...)
}

// trivyConvertArgs renders the CycloneDX document from the scan Trivy already
// performed, so the SBOM and the severity counts cannot disagree — they are two
// projections of one scan.
//
// Verified on 0.70.0: converting the native report of a debian:11.6 image
// reproduces the directly-scanned CycloneDX document exactly, apart from the
// `serialNumber`, `metadata.timestamp` and generated `bom-ref` UUIDs. Same 205
// vulnerabilities, same component and dependency lists.
//
// `convert` does not take --scanners; it is not scanning. --severity and
// --list-all-pkgs it does take, and both are pinned for the reasons above.
func trivyConvertArgs() []string {
	return []string{
		"trivy", "convert",
		"--format", "cyclonedx",
		"--severity", trivySeverityPin,
		"--list-all-pkgs",
		"--output", trivyReportPath,
		trivyNativePath,
	}
}

// trivyFSArgs is the filesystem scan's command line: trivyScanArgs plus the
// one pin only `trivy fs` accepts. --include-dev-deps is not in
// trivyPinnedFlags because `image` and `sbom` reject it as an unknown flag
// (measured on 0.70.0, whose `fs --help` is the only one listing it).
//
// It is pinned false for the same reason as the rest: `include-dev-deps: true`
// in a consumer trivy.yaml would widen the gated set to development packages
// without the evidence saying so. Widening fails builds rather than hiding
// findings, but which packages a gate measures is cicd's, not the config's.
// Development-only lockfiles are cleared by a separate, ungated rescan — see
// devonly.go.
func trivyFSArgs(target string) []string {
	args := trivyScanArgs("fs", target)
	return append(args[:len(args)-1:len(args)-1], "--include-dev-deps=false", target)
}

// trivyDevRescanArgs is the development-inclusive rescan: the filesystem
// command line with the dev pin flipped and the report sent to its own path,
// so the gated report and the CycloneDX converted from it are untouched.
func trivyDevRescanArgs(target string) []string {
	args := trivyFSArgs(target)
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--include-dev-deps=false":
			out = append(out, "--include-dev-deps")
		case args[i] == "--output" && i+1 < len(args):
			out = append(out, "--output", trivyDevNativePath)
			i++
		default:
			out = append(out, args[i])
		}
	}
	return out
}

const (
	// trivyNativePath holds Trivy's own JSON report — the authority for severity.
	trivyNativePath = "/tmp/report.trivy.json"
	// trivyReportPath holds the CycloneDX document rendered from it.
	trivyReportPath = "/tmp/report.cdx.json"
)
