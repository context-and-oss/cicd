package main

// Static scanner images this module selects on its own.
//
// Every scanner cicd runs is chosen here, by this repository, never by a
// consumer parameter or a consumer version file — so ADR-004's dynamic-toolchain
// carve-out does not apply and each one is immutable by digest (CWE-494). See
// src/quality/images.go for the full rationale and the shape contract; the same
// `// renovate-image:` + version + image triple is what renovate.json and
// scripts/check-runtime-image-pins.py both read.
//
// The version constants stay so the readable tag has one source of truth: the
// image reference is built from it, and where a module reports the tool version
// itself (zapVersion → toolInfo.Version in main.go) it reports the same value the
// image was pulled at. The rest of the scanners record their version inside the
// SARIF they produce; either way an auditor reads "gitleaks v8.30.1", never a
// bare digest.
//
// No build tag: the unit-test build (-tags unit_test) must see these constants.
const (
	// renovate-image: semgrep/semgrep
	semgrepVersion = "1.162.0"
	semgrepImage   = "semgrep/semgrep:" + semgrepVersion + "@sha256:9349edbadf90c3f3c0c3f55867625354e89680e6fa10d9034042af52fdb0e0d0"

	// renovate-image: zricethezav/gitleaks
	gitleaksVersion = "v8.30.1"
	gitleaksImage   = "zricethezav/gitleaks:" + gitleaksVersion + "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

	// renovate-image: aquasec/trivy
	trivyVersion = "0.70.0"
	trivyImage   = "aquasec/trivy:" + trivyVersion + "@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"

	// Trivy's vulnerability database is ~100 MB and is fetched on every scan
	// once --scanners vuln is on. A Dagger cache volume shares one copy across
	// the scans in a single pipeline (ScanSource + ScanImage both need it) and
	// across runs on a warm engine. Trivy still revalidates freshness itself,
	// so this trades no CVE currency for the saved download.
	trivyCachePath   = "/root/.cache/trivy"
	trivyCacheVolume = "cicd-trivy-db"

	// renovate-image: trufflesecurity/trufflehog
	trufflehogVersion = "3.78.0"
	trufflehogImage   = "trufflesecurity/trufflehog:" + trufflehogVersion + "@sha256:731515da41fae0bee29b08b68928cebfe67183f6cb13facbf791b32dfd2aeabf"

	// renovate-image: alpine
	//
	// Not a scanner: this runs the dependency-input probe (vuln_source.go), which
	// asks which dependency declarations and lockfiles the scanned tree actually
	// holds. That question is the exculpating half of "did Trivy have anything to
	// resolve", so it must not be answered from inside the Trivy image whose
	// silence is the thing under suspicion — and a `find` needs nothing else. Same
	// image and digest quality.Check uses for its own marker probe.
	alpineTag   = "3.19"
	alpineImage = "alpine:" + alpineTag + "@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"

	// The .NET SDK images the lockfile-free dependency-graph fallback restores
	// in (dotnetrestore.go). Same two bands, same digests, same reasoning as
	// src/quality/images.go: an SDK image carries its band in the tag, so a
	// single pin is not "cicd defaults to 8.0" but "cicd cannot restore any
	// consumer above 8.0", and a band must never be bumped across its own major.
	//
	// These are cicd's own choice — the consumer names no image — so ADR-004 does
	// not cover them and both are digest-pinned. They are duplicated from the
	// quality module rather than shared because Dagger modules are isolated; the
	// two copies disagreeing is a non-run, never a false pass (a band that cannot
	// build the tree fails the restore, which dotnetRestoreRunError classifies).
	//
	// renovate-image: mcr.microsoft.com/dotnet/sdk
	dotnetSDK80Band  = "8.0"
	dotnetSDK80Image = "mcr.microsoft.com/dotnet/sdk:" + dotnetSDK80Band + "@sha256:3c0edbfe1549dd93fb789dc96299a40df865ad7bffefcaf38e8c05940686d641"

	// renovate-image: mcr.microsoft.com/dotnet/sdk
	dotnetSDK100Band  = "10.0"
	dotnetSDK100Image = "mcr.microsoft.com/dotnet/sdk:" + dotnetSDK100Band + "@sha256:e1fc6e423f543119c406d24e2e687d67c569f18f04a37a8b0005d80ad0dcee80"

	// renovate-image: ghcr.io/zaproxy/zaproxy
	zapVersion = "2.17.0"
	zapImage   = "ghcr.io/zaproxy/zaproxy:" + zapVersion + "@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2"

	// The Go toolchain the licence scan downloads the module graph with
	// (goexec.go). Same pin as src/quality/images.go; it runs go mod edit and go
	// mod download only, never the consumer's code.
	// renovate-image: golang
	golangTag   = "1.26-alpine"
	golangImage = "golang:" + golangTag + "@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"
)
