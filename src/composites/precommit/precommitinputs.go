// The inputs precommit refuses before it calls stage-2.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session. The rule is one line
// and stage-2 checks the same thing again, but the composite refuses first so
// a bad value is named before any container is pulled.
package main

import "fmt"

// validatePrecommitInputs mirrors stage-2's own refusals for the two inputs
// the composite forwards as numbers, with the same messages.
func validatePrecommitInputs(parallelism, nodeProjectLimit int) error {
	if err := ValidateParallelism(parallelism); err != nil {
		return err
	}
	if nodeProjectLimit < 1 {
		return fmt.Errorf("node-project-limit must be positive")
	}
	return nil
}
