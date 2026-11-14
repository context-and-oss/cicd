package main

import "encoding/json"

// mergeSARIF merges raw SARIF JSON blobs by combining their runs arrays, in
// order. A nil document is skipped.
//
// The first document's $schema and version win. A side that is not a SARIF
// document leaves the merge as the first side alone — the caller has already
// recorded the tool that produced the unreadable half in errors[], and a
// merge that invented a run for it would be a second report of the same
// failure wearing a finding's face.
func mergeSARIF(docs ...json.RawMessage) json.RawMessage {
	var out json.RawMessage
	for _, d := range docs {
		out = mergeSARIFPair(out, d)
	}
	return out
}

// mergeSARIFPair is one step of mergeSARIF: b's runs appended to a's.
func mergeSARIFPair(a, b json.RawMessage) json.RawMessage {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	type sarifDoc struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	var docA, docB sarifDoc
	if err := json.Unmarshal(a, &docA); err != nil {
		return a
	}
	if err := json.Unmarshal(b, &docB); err != nil {
		return a
	}
	runs := append(docA.Runs, docB.Runs...)
	if runs == nil {
		// Both inputs carried a null runs array. Merging two nulls must produce
		// an empty array, not a third null: a consumer iterating runs faults on
		// null, and null cannot be told apart from "the producer never recorded
		// a run".
		runs = []json.RawMessage{}
	}
	merged := sarifDoc{
		Schema:  docA.Schema,
		Version: docA.Version,
		Runs:    runs,
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return a
	}
	return out
}
