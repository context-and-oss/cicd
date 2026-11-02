package main

// Static tool images this module selects on its own — the OPA policy engine that
// runs the gate, the busybox-class helper used for timestamps, and the image
// risk.Scan's file collector runs in. None is consumer-selectable, so each is
// immutable by digest (CWE-494). See src/quality/images.go for the shape contract read by
// renovate.json and scripts/check-runtime-image-pins.py.
//
// conftestVersion is also what `make policy-test` runs: the Makefile pins the
// same version+digest, so a passing policy-test proves what the real gate will
// do at runtime rather than what some other conftest build would do.
//
// No build tag: the unit-test build (-tags unit_test) must see these constants.
const (
	// renovate-image: alpine
	alpineTag   = "3.21"
	alpineImage = "alpine:" + alpineTag + "@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"

	// collectorImage is the gitleaks image security.ScanSource already pins,
	// chosen because it ships git with busybox: the collector needs git to read
	// ignore rules (collect.go), and installing git at run time would fetch an
	// unpinned package on every scan.
	//
	// renovate-image: zricethezav/gitleaks
	collectorGitleaksVersion = "v8.30.1"
	collectorImage           = "zricethezav/gitleaks:" + collectorGitleaksVersion + "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

	// renovate-image: openpolicyagent/conftest
	conftestVersion = "v0.58.0"
	conftestImage   = "openpolicyagent/conftest:" + conftestVersion + "@sha256:bad948972156bf96d27d1f510db346ca4f7c5996e6ab298c43036505b60f8cc8"
)
