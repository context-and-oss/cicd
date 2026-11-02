// Withholding who wrote a commit from gitleaks' report.
//
// Deliberately untagged (no //go:build !unit_test), so gitleaksidentity_test.go
// can drive it with `go test -tags unit_test ./...`.
//
// --redact keeps the secret out of the report, and nothing keeps the person
// out. A history-leg result carries the commit's identity in
// partialFingerprints, measured on v8.30.1 against a repository with one
// committed credential:
//
//	"partialFingerprints": {"commitSha": "<sha>", "email": "<author email>",
//	  "author": "<author name>", "date": "2026-10-24T19:29:01Z",
//	  "commitMessage": "<subject>"}
//
// The envelope is a build artifact anyone with read access downloads, it is
// posted to code scanning, and it outlives the access of the people it names.
// So partialFingerprints keeps an allowlist, not a denylist: commitSha, which
// is how a triager finds the commit (and its author, with the access to see
// it), and date, which says how old the leak is. Everything else goes,
// commitMessage included: it is free text a person wrote, and "rotate the key
// <value>" is a commit message too. A key a later gitleaks adds goes with it
// until someone reads it and decides, which is the direction to fail in.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
)

// gitleaksKeptFingerprints is every partialFingerprints key that reaches the
// envelope.
var gitleaksKeptFingerprints = map[string]bool{
	"commitSha": true,
	"date":      true,
}

// withholdGitleaksCommitIdentity returns raw with every partialFingerprints
// key outside gitleaksKeptFingerprints removed from every result, and an error
// when raw cannot be walked: a report cicd cannot read is one it cannot prove
// it withheld anything from.
func withholdGitleaksCommitIdentity(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps lines and columns exactly as gitleaks wrote them.
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("gitleaks: could not read the report to withhold commit authorship, so it is not passed on: " + err.Error())
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return nil, errors.New("gitleaks: the report has no runs array, so cicd cannot prove it withheld commit authorship, and it is not passed on")
	}
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			return nil, errors.New("gitleaks: a run in the report is not an object, so its commit authorship cannot be withheld")
		}
		rawResults, present := run["results"]
		if !present || rawResults == nil {
			continue
		}
		results, ok := rawResults.([]any)
		if !ok {
			return nil, errors.New("gitleaks: a run's results are not an array, so their commit authorship cannot be withheld")
		}
		for _, res := range results {
			result, ok := res.(map[string]any)
			if !ok {
				return nil, errors.New("gitleaks: a result in the report is not an object, so its commit authorship cannot be withheld")
			}
			rawFP, present := result["partialFingerprints"]
			if !present || rawFP == nil {
				continue
			}
			fp, ok := rawFP.(map[string]any)
			if !ok {
				return nil, errors.New("gitleaks: a result's partialFingerprints is not an object, so its commit authorship cannot be withheld")
			}
			for k := range fp {
				if !gitleaksKeptFingerprints[k] {
					delete(fp, k)
				}
			}
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("gitleaks: could not re-encode the report after withholding commit authorship: " + err.Error())
	}
	return out, nil
}
