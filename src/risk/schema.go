package main

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "1.6.0"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// Outcome is what a tool found, before any gate was applied to it. See
// internal/evidence/schema.go for the full argument; this file is a
// hand-maintained trim of it, so the type is restated rather than synced.
type Outcome string

const (
	OutcomeClean    Outcome = "CLEAN"
	OutcomeSkipped  Outcome = "SKIPPED"
	OutcomeFindings Outcome = "FINDINGS"
	OutcomeFailed   Outcome = "FAILED"
	OutcomeError    Outcome = "ERROR"
)

// Concern is the question a tool answers, as the reader of a report asks it.
// See internal/evidence/schema.go for the full argument; this file is a
// hand-maintained trim of it, so only the constants risk can produce are
// restated. Adding one here that risk never sets would invite a caller to use
// it and put the drift this file already risks somewhere harder to see.
type Concern string

const (
	// ConcernIaC: policy over infrastructure and pipeline definitions, which
	// is the whole of what this module does.
	ConcernIaC Concern = "iac"
)

// ValidSeverity returns true if s is a recognised severity level.
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
		return true
	}
	return false
}

type ToolInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Args    []string `json:"args,omitempty"`
}

type RepoContext struct {
	RepoURL     string   `json:"repoUrl"`
	CommitSHA   string   `json:"commitSha"`
	Branch      string   `json:"branch"`
	Tag         string   `json:"tag,omitempty"`
	AppID       string   `json:"appId,omitempty"`
	SourcePaths []string `json:"sourcePaths,omitempty"`
}

// Envelope is the top-level evidence artifact returned by every module function.
// Tool-specific payloads (SARIF, CycloneDX) are embedded as raw JSON so this
// struct does not need to know each format's internal schema.
type Envelope struct {
	SchemaVersion string `json:"schemaVersion"`

	ModuleName string      `json:"moduleName"`
	Stage      string      `json:"stage"`
	Tool       ToolInfo    `json:"tool"`
	Repo       RepoContext `json:"repo"`

	TimestampUTC time.Time `json:"timestampUtc"`
	DurationMS   int64     `json:"durationMs"`
	Languages    []string  `json:"languages,omitempty"`

	Passed bool `json:"passed"`
	// Outcome is the un-gated counterpart to Passed: what this module found,
	// before `fail-on` had a say. Empty means the producer did not state one,
	// which is not the same as CLEAN.
	Outcome Outcome `json:"outcome,omitempty"`
	// Concern is the question this module answers. See the canonical
	// definition in src/internal/evidence/schema.go.
	Concern Concern `json:"concern,omitempty"`
	// Examined is how much this module looked at. See the canonical
	// definition in src/internal/evidence/schema.go.
	Examined           *Examined        `json:"examined,omitempty"`
	FailOnSeverity     Severity         `json:"failOnSeverity,omitempty"`
	FindingsCount      int              `json:"findingsCount"`
	FindingsBySeverity map[Severity]int `json:"findingsBySeverity,omitempty"`

	// CoveragePercent is the line/statement coverage percentage (0–100).
	// Present only when the module measured coverage (quality module, test step).
	CoveragePercent *float64 `json:"coveragePercent,omitempty"`

	// CoverageByLanguage holds per-language coverage percentages (0–100).
	// Present on the combined quality envelope when multiple languages are detected.
	CoverageByLanguage map[string]float64 `json:"coverageByLanguage,omitempty"`

	// SARIFReport holds a SARIF 2.1.0 JSON document.
	// Validate uses it to publish deterministic policy findings to Code Scanning.
	SARIFReport json.RawMessage `json:"sarifReport,omitempty"`

	// CycloneDXReport holds a CycloneDX JSON document.
	// Present on: vuln-scan (both stages), sbom.
	CycloneDXReport json.RawMessage `json:"cyclonedxReport,omitempty"`

	// GenericReport holds arbitrary structured tool output for modules that do
	// not produce SARIF or CycloneDX (e.g. markdownlint, licence scanners).
	// GenericFormat identifies the payload schema (e.g. "markdownlint", "spdx-lite").
	GenericReport json.RawMessage `json:"genericReport,omitempty"`
	GenericFormat string          `json:"genericFormat,omitempty"`

	// RawOutputRef is a path to the verbose tool stdout+stderr file exported
	// from the Dagger pipeline.
	RawOutputRef string `json:"rawOutputRef,omitempty"`

	// Warnings carries non-fatal diagnostics — e.g. missing bootstrap files
	// or skipped optional steps. Pipelines should not fail because Warnings
	// is non-empty; rendering surfaces these under a "Warnings" heading so
	// they don't look like errors. Errors[] remains for hard failures.
	Warnings []string `json:"warnings,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

// Examined is how much a tool actually looked at, in whatever unit that tool
// counts in — the denominator a zero finding count needs. Restated here rather
// than synced: this module keeps a hand-trimmed schema.go. See
// src/internal/evidence/schema.go for the full reasoning.
type Examined struct {
	Unit  string `json:"unit"`
	Count int    `json:"count"`
	Total int    `json:"total,omitempty"`
}
