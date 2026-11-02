// Trivy invocation policy for the license scan: the flags cicd pins so a
// repository's own trivy.yaml can narrow *scope* without ever narrowing
// *findings*.
//
// This is the license-scan sibling of trivyflags.go, and it is a separate flag
// list rather than an extra value on trivyPinnedFlags for reasons that are
// load-bearing rather than stylistic:
//
//   - `--scanners vuln` in trivyPinnedFlags is a security pin, not a default.
//     It is there because `scan.scanners` in a consumer trivy.yaml can switch
//     vulnerability scanning off. Appending "license" to it would overload one
//     pin with a feature toggle, so a future change to the license feature
//     could not be made without editing the vulnerability pin.
//   - trivyflags.go records that `--scanners vuln` paired with
//     `--format cyclonedx` makes Trivy switch to pure SBOM generation and
//     disable security scanning entirely, reporting zero vulnerabilities from a
//     scan that "succeeded". Scanner mode and output format interact in Trivy in
//     ways that fail silently, and the license report is a third output shape.
//     Keeping the invocations apart keeps that interaction out of the vuln scan.
//   - The vulnerability pins are meaningless or wrong here: --ignore-unfixed and
//     --ignore-status describe vulnerability state, and trivySeverityPin is a
//     *vulnerability* severity scale. A license's severity is a projection of its
//     category (see licensereport.go), so sharing the vuln threshold would let a
//     license finding consume a vulnerability gate's budget.
//
// Deliberately untagged (no //go:build !unit_test): a flag list with no Dagger
// dependency, so licenseflags_test.go can pin it under
// `go test -tags unit_test ./...`. Same reason trivyflags.go is untagged.
package main

// trivyLicensePinnedFlags are passed on the command line of every license scan,
// and the command line beats the config file.
//
// --ignored-licenses is pinned EMPTY, and that pin is the whole reason this list
// exists. Honouring a consumer's trivy.yaml (see trivyConfigDir) hands them a
// file that can silently gut the license scan. Measured against the pinned
// Trivy 0.70.0 on testdata/node-app, whose package-lock.json declares one MIT
// dependency:
//
//	trivy.yaml                  CLI                        license findings
//	(none)                      (none)                                    1
//	license.ignored: [MIT]      (none)                                    0
//	license.ignored: [MIT]      --ignored-licenses ""                     1
//
// So a consumer can take the license report to zero from a file cicd honours,
// and pinning the flag takes it back. That is the same hole, with the same
// remedy, that trivyPinnedFlags closes for vulnerabilities.
//
// --license-confidence-level is pinned at Trivy's own default rather than left
// to the config for the same reason and not because it was measured to matter:
// it filters findings below a confidence score, so a consumer raising it hides
// findings while the scan still "succeeds". It has no observable effect on
// licenses read from package metadata, which report Confidence 1 — the pin is
// for the file-content mode, where scores are real.
//
// What is NOT pinned, and why: Trivy's license *classification* — which category
// a license falls in — is not settable from the command line on 0.70.0, only
// from config. An attempt to reclassify from a consumer trivy.yaml was measured
// and did not take effect: `license.forbidden: [MIT]` was loaded and MIT still
// reported Category "notice". So classification is taken from Trivy's report
// (licensereport.go) rather than reimplemented here, because a hand-maintained
// license-to-category table in cicd would be a far smaller and staler one than
// Trivy's.
//
// Maintenance risk worth naming: that measurement covers one config key on one
// version. If a future Trivy release makes classification consumer-settable, the
// categories this module gates on become consumer-controlled and the remedy is
// to pin the new key here, or to classify in Go if it cannot be pinned. When
// bumping trivyVersion, re-read the license section of the config reference.
var trivyLicensePinnedFlags = []string{
	"--scanners", "license",
	"--ignored-licenses", "",
	"--license-confidence-level", trivyLicenseConfidencePin,
}

// trivyLicenseConfidencePin is Trivy 0.70.0's own default. Named rather than
// inlined so a bump that changes the upstream default is a visible edit here.
const trivyLicenseConfidencePin = "0.9"

// trivyLicenseScanArgs builds the license scanning command line.
//
// full turns on --license-full, which reads licenses out of source headers and
// LICENSE files instead of only out of package metadata. It is a parameter and
// not a pin because it is the one license knob whose cost is a property of the
// consumer's tree rather than of the scan, and because metadata-only mode is
// worthless for some ecosystems. Measured on 0.70.0:
//
//	tree                        mode        license findings
//	cicd (16 Go manifests)      metadata                   0
//	cicd                        --license-full             1 (Apache-2.0)
//	testdata/node-app           metadata                   1 (MIT)
//	testdata/node-app           --license-full             1
//
// What full mode adds for a Go tree is the tree's own LICENSE, not its
// dependencies: Trivy reads a Go dependency's licence from the module cache in
// either mode, and with no cache it reads none in either. Measured later on a Go
// module with 36 dependencies: no cache, 0 of 36 in both modes; cache populated,
// 36 of 36 in both. The default stays on because the tree's own declarations are
// still worth judging, but it does not make a Go row a judged dependency graph —
// licencecoverage.go reports how many dependencies were read, and a graph with
// none read is SKIPPED, never CLEAN. Both trees above completed in about a second,
// so the slowdown usually attributed to full mode was NOT reproduced here;
// neither of them vendors dependencies into the scanned tree, which is the shape
// that would show it, and that is the case this flag exists to let a consumer
// opt out of.
//
// --exit-code 0 is safe and is not a swallowed failure, for the same reason
// trivyScanArgs gives: findings are read out of the report, and a Trivy that
// could not run leaves no report, which surfaces as an error from the file read.
func trivyLicenseScanArgs(full bool, target ...string) []string {
	args := []string{"trivy", "fs"}
	args = append(args, trivyLicensePinnedFlags...)
	if full {
		args = append(args, "--license-full")
	}
	args = append(args,
		"--format", "json",
		"--output", trivyLicensePath,
		"--exit-code", "0",
	)
	return append(args, target...)
}

// trivyLicensePath holds the license scan's native JSON report. A separate path
// from trivyNativePath so a license scan and a vulnerability scan can share a
// container without either overwriting the other's report.
const trivyLicensePath = "/tmp/report.license.json"
