//go:build unit_test

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// gitleaksHistorySARIF is the shape a v8.30.1 history leg wrote for one
// committed credential (measured), with the identity replaced by probes. The
// second result is the tree leg's shape: the same keys, empty.
const gitleaksHistorySARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"generic-api-key"}]}},"results":[` +
	`{"message":{"text":"generic-api-key has detected secret for file cfg.env at commit ce842e5c6d91bf2c0ef64b6d77ea5fc9663daaaa."},"ruleId":"generic-api-key",` +
	`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"cfg.env"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":45,"snippet":{"text":"REDACTED"}}}}],` +
	`"partialFingerprints":{"commitSha":"ce842e5c6d91bf2c0ef64b6d77ea5fc9663daaaa","email":"probe.author@example.invalid","author":"Probe Author","date":"2026-10-24T19:29:01Z","commitMessage":"rotate PROBECOMMITMSG","committerEmail":"probe.committer@example.invalid"},` +
	`"properties":{"tags":[]}},` +
	`{"message":{"text":"generic-api-key has detected secret for file b.env"},"ruleId":"generic-api-key",` +
	`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.env"},"region":{"startLine":2}}}],` +
	`"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}]}]}`

func TestWithholdGitleaksCommitIdentity(t *testing.T) {
	out, err := withholdGitleaksCommitIdentity(json.RawMessage(gitleaksHistorySARIF))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// committerEmail is not a key v8.30.1 writes: it stands for the one a
	// later gitleaks adds, which the allowlist must drop unread.
	for _, gone := range []string{"Probe Author", "probe.author@", "probe.committer@", "PROBECOMMITMSG",
		`"email"`, `"author"`, `"commitMessage"`, `"committerEmail"`} {
		if strings.Contains(s, gone) {
			t.Errorf("%s survived into the report: %s", gone, s)
		}
	}
	for _, kept := range []string{`"commitSha":"ce842e5c6d91bf2c0ef64b6d77ea5fc9663daaaa"`, `"date":"2026-10-24T19:29:01Z"`,
		`"startLine":1`, `"endColumn":45`, `"uri":"cfg.env"`, "at commit ce842e5c6d91bf2c0ef64b6d77ea5fc9663daaaa"} {
		if !strings.Contains(s, kept) {
			t.Errorf("%s was lost: %s", kept, s)
		}
	}
	// What the envelope counts is unchanged.
	if got, want := len(gitleaksFindings(out)), len(gitleaksFindings(json.RawMessage(gitleaksHistorySARIF))); got != want || got != 2 {
		t.Errorf("findings = %d, want %d (2)", got, want)
	}
}

func TestWithholdGitleaksCommitIdentityPassesAReportWithNothingToWithhold(t *testing.T) {
	for name, raw := range map[string]string{
		"clean scan":               cleanSARIF,
		"results absent":           `{"runs":[{"tool":{"driver":{"name":"gitleaks"}}}]}`,
		"results null":             `{"runs":[{"results":null}]}`,
		"no partialFingerprints":   `{"runs":[{"results":[{"ruleId":"x"}]}]}`,
		"null partialFingerprints": `{"runs":[{"results":[{"ruleId":"x","partialFingerprints":null}]}]}`,
	} {
		if _, err := withholdGitleaksCommitIdentity(json.RawMessage(raw)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestWithholdGitleaksCommitIdentityRefusesWhatItCannotWalk(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":                       `{"runs":[{"results":[{"partialFingerprints":{"author":"Probe Author"`,
		"runs not an array":              `{"runs":{"author":"Probe Author"}}`,
		"run not an object":              `{"runs":["Probe Author"]}`,
		"results not an array":           `{"runs":[{"results":{"author":"Probe Author"}}]}`,
		"result not an object":           `{"runs":[{"results":["Probe Author"]}]}`,
		"partialFingerprints not object": `{"runs":[{"results":[{"partialFingerprints":["Probe Author"]}]}]}`,
	} {
		out, err := withholdGitleaksCommitIdentity(json.RawMessage(raw))
		if err == nil {
			t.Errorf("%s: passed through: %s", name, out)
			continue
		}
		if strings.Contains(err.Error(), "Probe Author") {
			t.Errorf("%s: the error quotes the report: %v", name, err)
		}
	}
}
