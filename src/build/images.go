package main

// Static tool images this module selects on its own: the SBOM scanner and the
// busybox-class helper used to probe the source tree for language markers. The
// toolchain container a consumer's own build command runs in is NOT here — that
// one is resolved per ADR-004 (explicit --toolchain-image, then .nvmrc /
// global.json, then a language default) and is deliberately not digest-pinned.
//
// See src/quality/images.go for the shape contract read by renovate.json and
// scripts/check-runtime-image-pins.py.
//
// trivyImage was previously pinned to sha256:4a092a85…, which is the *amd64
// platform manifest* for tag 0.50.4, not the image index — it resolves on CI and
// silently fails to offer an arm64 variant to local development. The digest below
// is the index that carries 4a092a85 as its amd64 child, so amd64 content is
// unchanged and arm64 now works.
//
// No build tag: the unit-test build (-tags unit_test) must see these constants.
const (
	// renovate-image: aquasec/trivy
	trivyVersion = "0.50.4"
	trivyImage   = "aquasec/trivy:" + trivyVersion + "@sha256:b7dc41ff0c3224dea024ee21bb9f6920a8af2fb343bba7139140d8fd0df1bac3"

	// renovate-image: alpine
	alpineTag   = "3.19"
	alpineImage = "alpine:" + alpineTag + "@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
)
