// The Check envelope's genericReport: one place for the diagnostic payloads the
// per-language legs produce. Untagged so `go test -tags unit_test` reaches it.
package main

import (
	"encoding/json"
	"fmt"
)

// qualityDiagnosticsFormat is quality.Check's genericFormat when at least one leg
// produced a diagnostic payload. The payload is an object keyed by each leg's
// own genericFormat — `{"dotnet-test-output/1.0": [...]}` — so a leg's record
// keeps the name that describes its shape, and a new leg (a Go test tail, say)
// adds a key without changing this one's meaning.
//
// This is genericReport and not a new envelope field because the envelope has
// exactly one free-form slot for "structured tool output a module keeps beside
// its verdict", and that is what this is. A typed field would be a schema MINOR
// bump replicated into every module's schema.go for a payload only quality
// writes and only a human reads; quality.Test already uses the same slot for its
// legs report. The aggregator ignores a genericFormat it does not know, and the
// report module prefers sarifReport, which Check also carries, so nothing
// downstream changes its reading of a quality envelope.
const qualityDiagnosticsFormat = "quality-diagnostics/1.0"

// qualityDiagnosticsReport wraps the legs' payloads. encoding/json writes map
// keys sorted, so the envelope is byte-stable across runs. Nil and "" when there
// is nothing to wrap, so a green run's envelope carries no genericReport at all
// — the field is evidence of a problem, and its absence must keep meaning
// "there was none".
//
// The error is for a payload that is not JSON. Unreachable while every part is
// produced by json.Marshal in this module, and returned rather than swallowed
// because a diagnostic record that vanished on the way into the envelope is the
// exact failure the record exists to prevent.
func qualityDiagnosticsReport(parts map[string]json.RawMessage) (json.RawMessage, string, error) {
	present := make(map[string]json.RawMessage, len(parts))
	for k, v := range parts {
		if len(v) == 0 || string(v) == "null" {
			continue
		}
		present[k] = v
	}
	if len(present) == 0 {
		return nil, "", nil
	}
	raw, err := json.Marshal(present)
	if err != nil {
		return nil, "", fmt.Errorf("quality: a leg's diagnostic payload could not be written into genericReport: %w", err)
	}
	return json.RawMessage(raw), qualityDiagnosticsFormat, nil
}
