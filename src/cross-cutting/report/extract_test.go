package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractFromJSON_eachFormat(t *testing.T) {
	cases := []struct {
		name     string
		envelope string
		wantFile string
		wantBody string
	}{
		{"sarif", `{"sarifReport":{"version":"2.1.0","runs":[]}}`, "report.sarif", `{"version":"2.1.0","runs":[]}`},
		{"cyclonedx", `{"cyclonedxReport":{"bomFormat":"CycloneDX"}}`, "report.cdx.json", `{"bomFormat":"CycloneDX"}`},
		{"generic", `{"genericReport":{"site":[]}}`, "report.json", `{"site":[]}`},
		{"sarif outranks cyclonedx and generic", `{"genericReport":{"g":1},"cyclonedxReport":{"c":1},"sarifReport":{"s":1}}`, "report.sarif", `{"s":1}`},
		{"cyclonedx outranks generic", `{"genericReport":{"g":1},"cyclonedxReport":{"c":1}}`, "report.cdx.json", `{"c":1}`},
		{"null sarif falls through to cyclonedx", `{"sarifReport":null,"cyclonedxReport":{"c":1}}`, "report.cdx.json", `{"c":1}`},
		{"null sarif and cyclonedx fall through to generic", `{"sarifReport":null,"cyclonedxReport":null,"genericReport":{"g":1}}`, "report.json", `{"g":1}`},
		{"other envelope fields are ignored", `{"passed":true,"findingsCount":3,"sarifReport":{"s":1}}`, "report.sarif", `{"s":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, file, err := extractFromJSON(tc.envelope)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if file != tc.wantFile {
				t.Errorf("filename = %q, want %q", file, tc.wantFile)
			}
			if string(data) != tc.wantBody {
				t.Errorf("body = %s, want %s", data, tc.wantBody)
			}
			if !json.Valid(data) {
				t.Errorf("extracted body is not valid JSON: %s", data)
			}
		})
	}
}

func TestExtractFromJSON_noReportIsAnErrorNotAnEmptyFile(t *testing.T) {
	cases := map[string]string{
		"empty object":       `{}`,
		"all three null":     `{"sarifReport":null,"cyclonedxReport":null,"genericReport":null}`,
		"unrelated fields":   `{"passed":true,"errors":["semgrep: did not run"]}`,
		"empty envelope row": `{"schemaVersion":"1.0.0","findingsCount":0}`,
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			data, file, err := extractFromJSON(envelope)
			if err == nil {
				t.Fatalf("expected an error, got file %q body %s", file, data)
			}
			if !strings.Contains(err.Error(), "contains no embedded report") {
				t.Errorf("error does not say what is missing: %v", err)
			}
			if data != nil || file != "" {
				t.Errorf("error path leaked a result: file %q body %s", file, data)
			}
		})
	}
}

func TestExtractFromJSON_malformedEnvelopeIsAnError(t *testing.T) {
	for name, content := range map[string]string{
		"truncated":  `{"sarifReport":{"s":1}`,
		"not json":   `semgrep: did not run`,
		"empty":      ``,
		"json array": `[{"sarifReport":{"s":1}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := extractFromJSON(content)
			if err == nil {
				t.Fatal("expected a parse error")
			}
			if !strings.HasPrefix(err.Error(), "parse evidence JSON:") {
				t.Errorf("error is not classified as a parse failure: %v", err)
			}
		})
	}
}
