//go:build !unit_test

package main

import (
	"context"
	"dagger/notify/internal/dagger"
	"encoding/json"
	"fmt"
)

// Notify is the Dagger module that renders a pipeline's combined evidence as a
// Teams card, a GitHub pull-request comment or an Azure DevOps thread, and
// delivers it. Delivery is reported in an evidence envelope of its own and is
// never a gate: CLEAN delivered, SKIPPED not configured, ERROR attempted and
// lost, passed=true in all three.
type Notify struct{}

func parseEvidence(ctx context.Context, f *dagger.File) (*envelope, error) {
	contents, err := f.Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(contents), &env); err != nil {
		return nil, fmt.Errorf("parse evidence: %w", err)
	}
	return &env, nil
}
