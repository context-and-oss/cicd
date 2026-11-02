//go:build !unit_test

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"dagger/contract/internal/dagger"
	"dagger/contract/internal/source"
)

// Contract verifies Dagger module implementations against their declared step
// contracts and validates pipeline manifests against stage contracts.
type Contract struct{}

// VerifyPipeline checks that a pipeline manifest satisfies all stage contracts
// owned by this repository. Required steps missing from the manifest cause a failure.
//
// The manifest's `stage` field is a repo-relative path to the directory holding
// `stage-contract.json` — e.g. `"src/stage-2"` (paralleling the path-style
// `--step` argument of verify-signature). This keeps the verifier layout-agnostic.
//
// Example:
//
//	dagger -m ./src/cross-cutting/contract call verify-pipeline \
//	  --manifest ./pipeline.json \
//	  --repo .
func (m *Contract) VerifyPipeline(
	ctx context.Context,
	// Pipeline manifest file (pipeline.json).
	manifest *dagger.File,
	// Repository root containing <stage>/stage-contract.json files.
	// The manifest's `stage` field is treated as a path relative to this root.
	repo *dagger.Directory,
) (string, error) {
	data, err := manifest.Contents(ctx)
	if err != nil {
		return "", fmt.Errorf("read manifest: %w", err)
	}
	var pipeline pipelineManifest
	if err := json.Unmarshal([]byte(data), &pipeline); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}

	stages := make([]stageCheck, 0, len(pipeline.Stages))
	for _, ms := range pipeline.Stages {
		scData, err := repo.File(ms.Stage + "/stage-contract.json").Contents(ctx)
		if err != nil {
			return "", fmt.Errorf("read stage contract for %s: %w", ms.Stage, err)
		}
		var sc stageContract
		if err := json.Unmarshal([]byte(scData), &sc); err != nil {
			return "", fmt.Errorf("parse stage contract for %s: %w", ms.Stage, err)
		}
		stages = append(stages, stageCheck{Manifest: ms, Contract: sc})
	}

	report, pass := verifyPipeline(stages)
	if pass {
		return report, nil
	}
	return report, fmt.Errorf("pipeline contract verification failed\n%s", report)
}

// VerifySignature checks that a Go Dagger module exposes the function and all
// required parameters defined in the step contract.
//
// Note: only Go-based modules are supported. The verifier parses every
// non-generated, non-test *.go file at the module root and matches the first
// function or method named after the contract's `function` field.
//
// Example:
//
//	dagger -m ./src/cross-cutting/contract call verify-signature \
//	  --module ./src/my-custom-lint \
//	  --repo . \
//	  --step src/my-custom-lint
func (m *Contract) VerifySignature(
	ctx context.Context,
	// Source directory of the module to verify.
	module *dagger.Directory,
	// Repository root containing stage-N/<step>/contract.json files.
	repo *dagger.Directory,
	// Stage/step path identifying the contract, e.g. "stage-2/lint".
	step string,
) (string, error) {
	contractData, err := repo.File(step + "/contract.json").Contents(ctx)
	if err != nil {
		return "", fmt.Errorf("read contract for %s: %w", step, err)
	}
	contracts, err := parseModuleContracts(contractData)
	if err != nil {
		return "", err
	}

	entries, err := module.Entries(ctx)
	if err != nil {
		return "", fmt.Errorf("list module files: %w", err)
	}
	sources := map[string]string{}
	for _, name := range source.Select(entries) {
		src, err := module.File(name).Contents(ctx)
		if err != nil {
			return "", fmt.Errorf("read module file %s: %w", name, err)
		}
		sources[name] = src
	}
	if len(sources) == 0 {
		return "", fmt.Errorf("no Go source files found in module")
	}

	report, pass := verifySignatures(contracts, sources)
	if pass {
		return report, nil
	}
	return report, fmt.Errorf("signature verification failed\n%s", report)
}
