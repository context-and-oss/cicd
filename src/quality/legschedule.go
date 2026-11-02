package main

import (
	"context"
	"fmt"
	"time"
)

// runLegsBounded runs every leg under the --parallelism bound and returns the
// outcomes in declaration order, whatever order the legs finished in. The fold
// reads that slice front to back, so a concurrent run's evidence differs from a
// sequential one only in each leg's Duration.
//
// A leg the scheduler never started — the context ended first — has no outcome.
// An empty slot would fold as a leg that ran and said nothing, so that is an
// error naming the leg, and no envelope is written.
func runLegsBounded(ctx context.Context, labels []string, parallelism int, run func(int) legOutcome) ([]legOutcome, error) {
	outcomes := make([]legOutcome, len(labels))
	errs := RunBounded(ctx, len(labels), parallelism, func(i int) error {
		began := time.Now()
		outcomes[i] = run(i)
		outcomes[i].Duration = time.Since(began)
		return nil
	})
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("test-leg %s did not start: %w", labels[i], err)
		}
	}
	return outcomes, nil
}
