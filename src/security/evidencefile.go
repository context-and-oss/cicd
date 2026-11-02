//go:build !unit_test

package main

import (
	"dagger/security/internal/dagger"
	"fmt"
	"path/filepath"
)

// writeEvidenceFile writes an envelope into the module runtime's workdir and
// returns it by reference. WithNewFile embeds the complete envelope in the
// returned File ID; large scanner reports then make graph construction itself
// the bottleneck before the evidence aggregator can read or bound the payload.
func writeEvidenceFile(data []byte) (*dagger.File, error) {
	dir, err := writeEvidenceOutput(".", data)
	if err != nil {
		return nil, err
	}
	return dag.CurrentModule().Workdir(filepath.Clean(dir)).File(evidenceFileName), nil
}

// DAST reports are compacted before they reach this boundary. Embed that
// bounded envelope in a core Directory so the returned File no longer points
// back into the security module's workdir (and through it to the application
// service graph). Other scanners keep writeEvidenceFile: their reports can be
// much larger and must remain reference-backed.
const maxInlineDASTEvidenceBytes = 16 << 20

func writeInlineDASTEvidenceFile(data []byte) (*dagger.File, error) {
	if len(data) > maxInlineDASTEvidenceBytes {
		return nil, fmt.Errorf(
			"compacted DAST evidence is %d bytes, above the %d-byte inline transport limit",
			len(data), maxInlineDASTEvidenceBytes,
		)
	}
	return dag.Directory().WithNewFile(evidenceFileName, string(data)).File(evidenceFileName), nil
}
