// TruffleHog argument shape, output parsing and SARIF construction.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger,
// so the unit_test-tagged suite compiles against it and `make
// test-module-units` — the only canonical module-unit runner — actually
// executes these tests. They previously sat behind the Dagger tag, where a
// green `lint-repo` said nothing about them. The container call itself stays in
// secrets_image.go.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// trufflehogMountRoot is where runTrufflehog mounts the image rootfs. It is our
// own scaffolding, so it is stripped from reported paths: a consumer reading
// `/etc/app/config.yaml` can find that file in their image, while
// `/target/etc/app/config.yaml` sends them looking for a directory that only
// ever existed inside a Dagger container.
const trufflehogMountRoot = "/target"

// trufflehogArgs assembles the TruffleHog command line for a filesystem scan of
// the mounted image root. It is a pure function (no container/network) so the
// argument shape can be unit-tested in isolation. When verifySecrets is true it
// appends --only-verified, the "heavier secrets" knob from ADR-005, which makes
// TruffleHog live-verify each candidate against its provider before reporting.
func trufflehogArgs(verifySecrets bool) []string {
	args := []string{
		"trufflehog", "filesystem",
		trufflehogMountRoot,
		"--json",
		"--no-update",
	}
	if verifySecrets {
		args = append(args, "--only-verified")
	}
	return args
}

// trufflehogResult is one line of `trufflehog --json` output.
//
// SourceName is *not* a path — for a filesystem scan it is the literal string
// "trufflehog - filesystem", identical for every result in the run. Reporting
// it as the finding's file gave every secret in an image the same location, so
// the evidence aggregator's dedupe (which keys on the whole finding) merged
// distinct secrets sharing a detector into a single row. The real path and line
// live in SourceMetadata, which is where they are read from now.
// TruffleHog's `Raw` field — the secret itself — is deliberately not mirrored
// here. Nothing needs it, and a field that exists is a field someone renders
// into a message: gitleaks had to be given `--redact` precisely because a
// scanner that copies the credential into its report copies it into a
// downloadable build artifact. The detector name and location are what triage
// uses; the value is in the developer's own file at that line.
type trufflehogResult struct {
	DetectorName   string `json:"DetectorName"`
	SourceName     string `json:"SourceName"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				// A pointer, because absent and 0 are different questions —
				// see trufflehogLocation.
				Line *int `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// trufflehogLocation extracts the path and 1-based line for one result.
//
// `line` is a **0-based offset**, and it is serialised with omitempty. Measured
// against the pinned trufflehog 3.78.0, three secrets on known lines:
//
//	secret on file line 3  ->  "line": 2
//	secret on file line 7  ->  "line": 6
//	secret on file line 1  ->  no "line" key at all
//
// So the value is incremented — an evidence field named `line` that is
// systematically one row high is worse than none, because a reader clicks it.
// And a missing key is reported as no line rather than as line 1: omitempty
// makes offset 0 indistinguishable from a source that reports no offset, and
// inventing the more precise of two readings is how a fabricated location gets
// into evidence. A first-line secret therefore arrives with its path and no
// line, which is honest and still locates the file.
//
// This is version-coupled by construction. `trufflehogImage` is digest-pinned
// and Renovate-grouped for exactly this reason: when the version moves,
// re-measure the base before trusting the numbers (see src/security/CLAUDE.md).
func trufflehogLocation(r trufflehogResult) (string, int) {
	fs := r.SourceMetadata.Data.Filesystem
	path := strings.TrimPrefix(fs.File, trufflehogMountRoot)
	if fs.Line == nil || *fs.Line < 0 {
		return path, 0
	}
	return path, *fs.Line + 1
}

// parseTrufflehogOutput turns TruffleHog's JSON-lines stdout into findings.
//
// A line that will not decode ends the parse and is reported as a run error,
// rather than being skipped. Two reasons, and neither is tidiness: output this
// cannot read is a scan whose result is unknown, and "unknown" must never
// arrive as a shorter findings list that reads like a cleaner image. And
// json.Decoder does not advance past a syntax error, so the `continue` this
// replaces left More() true and Decode failing on the same bytes forever — a
// hang, not a degradation.
func parseTrufflehogOutput(output string, runErr error) ([]finding, []string) {
	var errs []string
	if runErr != nil {
		errs = append(errs, fmt.Sprintf("trufflehog: %v", runErr))
		return nil, errs
	}

	// TruffleHog outputs one JSON object per line.
	var results []trufflehogResult
	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var r trufflehogResult
		if err := decoder.Decode(&r); err != nil {
			errs = append(errs, fmt.Sprintf(
				"trufflehog: could not read result %d of its own output (%v), so "+
					"the findings it reported cannot be trusted to be all of them",
				len(results)+1, err))
			return nil, errs
		}
		results = append(results, r)
	}

	findings := make([]finding, 0, len(results))
	for _, r := range results {
		path, line := trufflehogLocation(r)
		findings = append(findings, finding{
			RuleID:      r.DetectorName,
			Description: fmt.Sprintf("Secret detected by %s", r.DetectorName),
			File:        path,
			Line:        line,
		})
	}
	return findings, nil
}

// buildTrufflehogSARIF creates a minimal SARIF 2.1.0 document from TruffleHog
// findings.
//
// The locations array is the point: without it the evidence aggregator has no
// path and no line to extract, so every secret from one detector collapsed into
// a single row in the PR comment — the count said three, the table said one, and
// the table is what a reviewer reads. A finding with no path emits no location
// (SARIF 2.1.0 §3.27.12 makes locations optional) rather than an entry naming
// nothing.
func buildTrufflehogSARIF(findings []finding) json.RawMessage {
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *sarifRegion `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifRoot struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		r := sarifResult{
			RuleID: f.RuleID,
			Level:  "error",
		}
		r.Message.Text = f.Description
		if f.File != "" {
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = f.File
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			r.Locations = []sarifLocation{loc}
		}
		results = append(results, r)
	}

	run := sarifRun{}
	run.Tool.Driver.Name = "trufflehog"
	run.Results = results

	doc := sarifRoot{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return data
}
