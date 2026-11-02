package main

import (
	"errors"
	"fmt"
	"strconv"
)

// validateWebInputs is everything ScanWeb can refuse before a container
// starts, in the order it refuses it: an unknown mode, both document inputs
// at once, api mode with no document, and a document handed to a mode that
// would silently ignore it.
//
// A failure here is a Go error and never an envelope. An envelope is a thing
// a consumer reads as a verdict, and a scan nobody could have run must not
// produce one. The messages are grepped by scripts/smoke/dast-shapes.sh, so
// they are byte-identical to the ones the entry used to hold inline.
//
// hasAPISpecPath is whether --api-spec-path carried anything but whitespace;
// the caller trims, so this function never has to.
func validateWebInputs(mode string, hasAPISpec, hasAPISpecPath bool) error {
	if _, err := zapScript(mode); err != nil {
		return err
	}
	if hasAPISpec && hasAPISpecPath {
		return errors.New("dast: --api-spec and --api-spec-path were both given; " +
			"exactly one may be supplied, because cicd cannot say which document the scan was driven from")
	}
	if mode == webModeAPI && !hasAPISpec && !hasAPISpecPath {
		return errors.New("dast: --mode api needs an API document: " +
			"pass --api-spec (a file) or --api-spec-path (a path the target serves it on)")
	}
	if mode != webModeAPI && (hasAPISpec || hasAPISpecPath) {
		return fmt.Errorf("dast: an API document was supplied but --mode is %s; "+
			"pass --mode api, or drop the document — a spec that is silently ignored is a scan narrower than the one that was asked for",
			strconv.Quote(mode))
	}
	return nil
}
