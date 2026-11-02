package main

// Static container images this module selects on its own.
//
// Nothing a consumer passes and no version file in the consumer's repository
// chooses any of these, so ADR-004's dynamic-toolchain carve-out does not cover
// them: they are repository-controlled tool images and every one is immutable by
// digest (CWE-494 — a mutable tag can be repointed under us between the review
// that approved it and the run that executes it).
//
// Shape of each entry, and why it is uniform:
//
//	// renovate-image: <docker depName>
//	<tool>Version = "<readable tag>"
//	<tool>Image   = "<depName>:" + <tool>Version + "@sha256:<digest>"
//
// The tag stays readable so emitted tool metadata (toolInfo.Version), `docker
// pull` and code review all still name a human version — pinning by digest must
// not cost legibility. The version constant is the single source of truth for
// both the evidence envelope and the image reference, so the two cannot drift.
//
// Every digest is the multi-arch *image index* digest, so the same reference
// resolves on linux/amd64 (CI) and linux/arm64 (local development). Resolve a
// replacement with:
//
//	dagger core container from --address <repo>:<tag> image-ref
//
// scripts/check-runtime-image-pins.py discovers these references from source
// (not from an allowlist) and fails a mutable tag, a malformed digest, or a
// reference missing from scripts/runtime-images.json. renovate.json proposes
// version+digest bumps as reviewable PRs; nothing here is resolved at run time.
//
// This file carries no build tag on purpose: the unit-test build
// (-tags unit_test) must be able to see these constants.
const (
	// renovate-image: alpine
	alpineTag   = "3.19"
	alpineImage = "alpine:" + alpineTag + "@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"

	// golangci-lint v2.x is required, not merely preferred. v1 has no `sarif`
	// output format at all, so the Go lint leg could never emit the evidence this
	// module is built around — it failed on flag validation every time and the
	// fallback made that read as a clean tree. v1.57.2 is also built with go1.22.1
	// and cannot load export data from a modern toolchain, so it fails a second way
	// on this repository's own source.
	//
	// Keep in step with .github/workflows/ci.yml, which runs the same version via
	// `go run`, and with the `version: "2"` config schema in
	// src/internal/.golangci.yml.
	//
	// The renovate-image marker must stay immediately above the version constant:
	// renovate.json's custom manager matches comment, version line and digest line
	// as three consecutive lines, and prose wedged between them silently unpins the
	// image (caught by scripts/check-runtime-image-pins.py, which is why this
	// paragraph is up here rather than down there).
	//
	// renovate-image: golangci/golangci-lint
	golangciVersion = "v2.12.2"
	golangciImage   = "golangci/golangci-lint:" + golangciVersion + "@sha256:5cceeef04e53efe1470638d4b4b4f5ceefd574955ab3941b2d9a68a8c9ad5240"

	// renovate-image: node
	nodeTag   = "24-alpine"
	nodeImage = "node:" + nodeTag + "@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53"

	// renovate-image: python
	pythonTag   = "3.12-slim"
	pythonImage = "python:" + pythonTag + "@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"

	// renovate-image: golang
	golangTag   = "1.26-alpine"
	golangImage = "golang:" + golangTag + "@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"

	// The .NET SDK is pinned once per supported band rather than once, because
	// an SDK image carries exactly the band in its tag: a repository targeting
	// `net10.0` cannot restore in `sdk:8.0` at all, and the failure is a non-run
	// that no --fail-on threshold can forgive. A single pin therefore did not
	// mean "cicd defaults to 8.0", it meant "cicd cannot lint or test any
	// consumer above 8.0".
	//
	// Raising the one pin to 10.0 instead would have moved the same wall rather
	// than removing it, in the other direction: the 10.0 SDK does not ship the
	// 8.0 targeting pack, so every net8.0 consumer would acquire a new package
	// dependency on a currently offline lint leg, and `dotnet format`'s analyser
	// defaults would change under every .NET verdict this repo has ever
	// produced. Both bands pinned side by side keeps a net8.0 consumer on
	// byte-identical behaviour.
	//
	// dotnetSDKBands (dotnetreport.go) is the ordered list these constants are
	// selected from and dotnetSDKBase (dotnetexec.go) holds one literal From()
	// per band — deliberately not a map, see the comment there. Adding a band
	// means all four: a constant pair here, an entry in dotnetSDKBands, a case
	// in dotnetSDKBase, and a declaration in scripts/runtime-images.json.
	//
	// renovate-image: mcr.microsoft.com/dotnet/sdk
	dotnetSDK80Band  = "8.0"
	dotnetSDK80Image = "mcr.microsoft.com/dotnet/sdk:" + dotnetSDK80Band + "@sha256:3c0edbfe1549dd93fb789dc96299a40df865ad7bffefcaf38e8c05940686d641"

	// renovate.json keeps each band inside its own major (allowedVersions), so
	// this pin is never "updated" by being replaced with the newer band — that
	// would delete a supported band rather than bump a pin.
	//
	// renovate-image: mcr.microsoft.com/dotnet/sdk
	dotnetSDK100Band  = "10.0"
	dotnetSDK100Image = "mcr.microsoft.com/dotnet/sdk:" + dotnetSDK100Band + "@sha256:e1fc6e423f543119c406d24e2e687d67c569f18f04a37a8b0005d80ad0dcee80"
)

// Linter package versions installed inside a tool image (npm/pip), as opposed
// to the tool images above — these are not image references and carry no
// digest. They live here rather than in lint.go so the untagged report builders
// (eslintreport.go) can name them under `-tags unit_test`.
//
// ESLint is deliberately absent: the Node leg runs the consumer's own
// `node_modules/.bin/eslint`, so the version is theirs to pin and cicd reports
// whatever actually ran (`eslintVersionLabel`). A constant here would put a
// version cicd chose into evidence describing a run it did not control.
const (
	pylintVersion = "3.1.0"
)
