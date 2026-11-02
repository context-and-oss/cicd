package main

import (
	"fmt"
	"strconv"
	"strings"
)

// readbackError words the errors[] entry for a file a leg's own script wrote
// and cicd could not read back out of the container.
//
// Every leg here runs its tool under `sh -c` with the output redirected to a
// file and the exit status echoed to a sentinel, so the tool's result exists
// only as those files. A read that fails after the sentinel came out is not
// the tool failing: it is cicd failing to collect what the tool said. The old
// `out, _ :=` turned that into an empty output, which for a test runner is
// zero tests and for a linter zero findings — the founding doctrine arriving
// through the read side. A tool whose output could not be read must never
// read as one that said nothing.
//
// The same two helpers exist in src/quality and src/security, because Dagger
// modules share no Go; keep them byte-identical (scripts/repo-inventory.json
// synced_files refuses a drift).
func readbackError(tool, path string, err error) string {
	return fmt.Sprintf("%s: could not read %s back from the container: %v", tool, path, err)
}

// readbackCount parses a count a leg's script wrote (`wc -l`, `echo $?`, a
// probe's attempt counter), or says why it could not. A read error and a
// non-numeric sentinel both come back as the sentence for errors[]; neither is
// ever a count of zero, because zero is the value that means "the tool wrote
// no result" or "the probe never answered", and the gate reads it.
func readbackCount(tool, path, raw string, readErr error) (int, string) {
	if readErr != nil {
		return 0, readbackError(tool, path, readErr)
	}
	trimmed := strings.TrimSpace(raw)
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Sprintf("%s: %s holds %q, which is not a count", tool, path, trimmed)
	}
	return n, ""
}
