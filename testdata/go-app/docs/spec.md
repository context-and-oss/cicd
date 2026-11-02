# Go App — Feature Specification

## Overview

This document describes the design and acceptance criteria for the go-app
test fixture used in CD pipeline integration tests.

## Goals

- Provide a minimal Go application that exercises lint, unit-test, SAST,
  secrets-scan, and vulnerability-scan pipeline stages.
- Include intentional test artefacts (e.g. `secrets.go`) so that scanning
  modules can verify detection logic without affecting production code.

## Acceptance Criteria

- `go test ./...` passes with no failures.
- `golangci-lint run` produces no errors on `math.go` and `main.go`.
- Trivy reports no CRITICAL vulnerabilities in the module graph.
