package main

import (
	"encoding/json"
	"fmt"
)

// The inventory row for a Trivy filesystem scan.
//
// runTrivyFS does two things under one tool name: it resolves the dependency
// graph into a CycloneDX inventory, and it looks the inventory up for known
// vulnerabilities. The envelope has carried both results since ScanSource
// existed — CycloneDXReport is the inventory, Findings the lookup — but only
// the lookup had a row, under `sca`. The inventory that cross-cutting/evidence
// merges into sbom.cdx.json was therefore claimed by nobody, and a commit run
// with `--artifact none` reported `sbom` as not answered while shipping a
// 26-component inventory in the same bundle. build.Sbom claims `sbom` for the
// image it inventories; nothing claimed it for the source tree.
//
// Not derived downstream from the presence of sbom.cdx.json, for the reason
// Concern's own doc gives: the aggregator only sees the document, and a
// DAST-cadence bundle ships an empty one. The producer knows whether the
// inventory is a scan result or a placeholder, so the producer declares it.

// inventoryUnit is the CycloneDX word for what the document lists. Trivy
// counts the lockfile itself as a component beside every package it names, so
// this is the document's own count, not a package count — Examined on the
// `sca` row is the package count, in Trivy's words.
const inventoryUnit = "components"

// inventoryResult is the `sbom` row for one Trivy filesystem scan and, when
// the scan itself succeeded but left no usable inventory, the error that says
// so.
//
// scanErr is the scan's own error and is carried on the row unchanged: a
// scan that did not run produced no inventory, and one ERROR row per fact is
// enough. The returned error is non-nil only when scanErr is nil, so the
// caller can add it to the envelope's errors[] without repeating the scan
// error, and so the envelope's Passed still ANDs with the rows — an ERROR row
// beside `passed: true` would be the rows and the envelope disagreeing about
// one run.
//
// Zero components in a usable document is not an error. A resultless scan over
// a tree whose independent probe found no supported dependency input is instead
// explicit SKIPPED: it produced no inventory and must not read as CLEAN over
// zero components. The ecosystem reconciliation on the `sca` row
// (ecosystems.go) is where "the tree declares dependencies Trivy did not read"
// remains an error.
func inventoryResult(scanErr error, scan trivyResult) (toolResult, error) {
	row := toolResult{
		Name:     "trivy",
		Concern:  ConcernSBOM,
		Err:      scanErr,
		Skipped:  scan.Skipped,
		Warnings: len(scan.InventoryWarnings),
	}
	if scanErr != nil {
		return row, nil
	}
	if scan.Skipped {
		return row, nil
	}
	n, err := inventoryComponents(scan.CycloneDX)
	if err != nil {
		row.Err = err
		return row, err
	}
	row.Examined = &Examined{Unit: inventoryUnit, Count: n}
	return row, nil
}

// inventoryComponents counts the components a CycloneDX document lists.
//
// The document must parse and must carry a components array — CycloneDX 1.4+
// makes it optional, but Trivy always writes one, so its absence from a Trivy
// document is a document Trivy did not write in full. An unparseable or
// truncated inventory is an error, not zero components: zero is a claim about
// the tree, and this layer cannot make it from a document it could not read.
func inventoryComponents(cdx json.RawMessage) (int, error) {
	if len(cdx) == 0 {
		return 0, fmt.Errorf("trivy produced no CycloneDX inventory")
	}
	var doc struct {
		Components *[]json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(cdx, &doc); err != nil {
		return 0, fmt.Errorf("trivy CycloneDX inventory is not valid JSON: %w", err)
	}
	if doc.Components == nil {
		return 0, fmt.Errorf("trivy CycloneDX inventory has no components array")
	}
	return len(*doc.Components), nil
}
