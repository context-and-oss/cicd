package main

import "encoding/json"

// trivyResult is what one Trivy scan contributes to an envelope: the CycloneDX
// document, severity counts, per-finding detail and non-fatal notes.
//
// It is untagged because the result's classification is pure evidence logic and
// must stay testable without loading Dagger. Only the code that produces it is
// in the !unit_test files.
type trivyResult struct {
	CycloneDX  json.RawMessage
	BySeverity map[Severity]int
	Findings   []Finding
	Warnings   []string
	// InventoryWarnings belongs to the SBOM row rather than the vulnerability
	// row. They share one Trivy execution, but each skipped concern must explain
	// its own missing assessment in the evidence.
	InventoryWarnings []string
	// Skipped means the independent input probe proved there was no supported
	// dependency scope. It is a passing N/A, not a clean scan and not an error.
	Skipped bool
	// ResolvedTypes names the ecosystems Trivy actually read a dependency graph
	// from. Zero findings is not evidence of a clean tree unless every ecosystem
	// the tree declares appears here; ecosystems.go does that reconciliation.
	ResolvedTypes []string
	// Accepted is how many rows --vuln-accept removed from the counts and the
	// findings. Zero on every scan that accepted nothing, which is the common
	// case; it exists so a caller can say "N accepted" in one sentence beside
	// the per-identifier warnings.
	Accepted int
	// Examined is how many packages Trivy resolved — the denominator a zero
	// finding count needs. See trivyExamined. Nil only when the report never
	// parsed or the dependency assessment was not applicable.
	Examined *Examined
}
