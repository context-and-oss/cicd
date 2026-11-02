// Package sarif provides helpers for constructing SARIF 2.1.0 documents.
package sarif

import "encoding/json"

const sarifVersion = "2.1.0"
const sarifSchema = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"

type Document struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription *Message        `json:"shortDescription,omitempty"`
	Properties       json.RawMessage `json:"properties,omitempty"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"` // error, warning, note
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// NewDocument creates an empty SARIF document.
//
// Runs is initialised rather than left nil so an empty document marshals to
// `"runs": []`. A nil Go slice marshals to null, and a null tells a consumer
// nothing: it cannot be distinguished from a document whose producer never got
// as far as recording a run. An empty array says "no runs", which is a fact.
func NewDocument() *Document {
	return &Document{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs:    []Run{},
	}
}

// AddRun appends a run to the document.
//
// A nil results slice becomes an empty one for the same reason: SARIF 2.1.0
// §3.14.23 makes run.results optional, but when the property is present its
// value must be an array, so `"results": null` is schema-invalid and faults any
// consumer that iterates it. It is also the wrong fact — a tool that ran and
// reported no problems produced an empty list, not an absence of information,
// and keeping those two apart is the point of this repository.
func (d *Document) AddRun(toolName, toolVersion string, results []Result) {
	if results == nil {
		results = []Result{}
	}
	d.Runs = append(d.Runs, Run{
		Tool:    Tool{Driver: Driver{Name: toolName, Version: toolVersion}},
		Results: results,
	})
}

// Marshal serialises the document to JSON.
func (d *Document) Marshal() (json.RawMessage, error) {
	return json.Marshal(d)
}

// CountBySeverity tallies results by SARIF level mapped to evidence severity labels.
func CountBySeverity(results []Result) map[string]int {
	counts := map[string]int{}
	for _, r := range results {
		counts[sarifLevelToSeverity(r.Level)]++
	}
	return counts
}

func sarifLevelToSeverity(level string) string {
	switch level {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note":
		return "LOW"
	default:
		return "LOW"
	}
}
