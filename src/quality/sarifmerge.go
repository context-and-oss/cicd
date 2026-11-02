package main

import "encoding/json"

// mergeSARIFReports combines per-language SARIF documents into a single
// document by concatenating their runs. Returns nil when no reports exist
// so the envelope field stays omitted rather than holding an empty document.
//
// Untagged: Check's aggregate and the three per-module lint legs all go
// through this, and it lived in main.go behind the Dagger build tag, where no
// unit test could reach it.
func mergeSARIFReports(reports []json.RawMessage) json.RawMessage {
	if len(reports) == 0 {
		return nil
	}
	if len(reports) == 1 {
		return reports[0]
	}
	type sarifDoc struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	// Runs starts non-nil: if every report failed to unmarshal, the merged
	// document must say "no runs" rather than marshal a null that reads as no
	// information at all.
	merged := sarifDoc{Runs: []json.RawMessage{}}
	for _, r := range reports {
		var doc sarifDoc
		if err := json.Unmarshal(r, &doc); err != nil {
			continue
		}
		if merged.Schema == "" {
			merged.Schema = doc.Schema
			merged.Version = doc.Version
		}
		merged.Runs = append(merged.Runs, doc.Runs...)
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return reports[0]
	}
	return out
}
