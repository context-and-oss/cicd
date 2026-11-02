package main

import "encoding/json"

// singleRunSARIF builds the one-run SARIF 2.1.0 document shape that every
// report parser in this module emits: one driver, one results array, nothing
// else.
//
// It exists to hold one invariant in one place: **results is an array, never
// null.** Each parser used to declare `var results []map[string]any` and hand
// the nil slice straight to json.Marshal, so a clean run shipped
// `"results": null`. SARIF 2.1.0 §3.14.23 makes run.results optional, but when
// the property is present its value must be an array — null is schema-invalid,
// and any consumer iterating run.results faults on it instead of seeing an
// empty list.
//
// The semantic half matters more here than the schema half. This module's whole
// contract is that a tool which found nothing and a tool which never looked are
// different facts: `[]` says "ran, reported no problems", null says nothing at
// all. Emitting the ambiguous one on every clean lint gives away the
// distinction the run-error classification exists to preserve — in the evidence
// document, which is the part a consumer actually reads.
func singleRunSARIF(driver, version string, results []map[string]any) map[string]any {
	if results == nil {
		results = []map[string]any{}
	}
	return map[string]any{
		"version": "2.1.0",
		"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": driver, "version": version}},
			"results": results,
		}},
	}
}

// stampSARIFAutomationID writes `automationDetails.id` onto every run in the
// document, naming which project or module the run describes.
//
// Since 2025-07-22 GitHub Code Scanning identifies a SARIF run by the pair
// (tool driver name, category) and rejects an upload whose runs collide on it —
// it used to merge them silently. This module produces exactly that collision
// by design: a multi-project Node tree is one `eslint` run per project, a
// multi-module Go tree one `golangci-lint` run per module, a solution-less .NET
// tree one `dotnet-format` run per project. Concatenated into findings.sarif
// and uploaded under the pipeline's single `category:`, two such runs are the
// same identity, the whole upload is refused, and — because the upload step
// must tolerate repos without Advanced Security — refusal reads as a repo with
// nothing to report. The stamped id keeps each run distinct: upload-sarif's
// category input fills `automationDetails` only where it is absent (measured on
// codeql-action populateRunAutomationDetails), so a stamped run keeps its id as
// its category while single-run documents keep the workflow's.
//
// Callers stamp only when a leg produced more than one run. A single-project
// repo keeps the plain workflow category it has always had — restamping it
// would re-key every existing alert for no gain. The id is built from the
// project directory, not an ordinal, so adding a project does not shift the
// identity of the ones already there.
//
// Same tolerance contract as stampSARIFDriverVersion: any parse or marshal
// failure returns the original bytes untouched — run identity must never cost
// a finding.
func stampSARIFAutomationID(raw json.RawMessage, tool, dir string) json.RawMessage {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return raw
	}
	id := sarifAutomationID(tool, dir)
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			continue
		}
		details, ok := run["automationDetails"].(map[string]any)
		if !ok {
			details = map[string]any{}
		}
		details["id"] = id
		run["automationDetails"] = details
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// sarifAutomationID renders the per-run identity. "." is the mount root, which
// as a category segment would read as noise, so it gets a name.
func sarifAutomationID(tool, dir string) string {
	if dir == "" || dir == "." {
		dir = "root"
	}
	return "cicd/" + tool + "/" + dir
}
