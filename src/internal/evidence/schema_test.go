package evidence_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/context-and-oss/cicd/internal/evidence"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	env := &evidence.Envelope{
		SchemaVersion: evidence.SchemaVersion,
		ModuleName:    "stage-2/lint",
		Stage:         "stage-2",
		Tool:          evidence.ToolInfo{Name: "golangci-lint", Version: "1.57.0"},
		Repo: evidence.RepoContext{
			RepoURL:   "https://github.com/example/repo",
			CommitSHA: "abc123",
			Branch:    "main",
		},
		TimestampUTC:   time.Now().UTC().Truncate(time.Second),
		DurationMS:     4200,
		Languages:      []string{"go"},
		Passed:         true,
		FailOnSeverity: evidence.SeverityHigh,
		FindingsCount:  0,
	}

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got evidence.Envelope
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.SchemaVersion != env.SchemaVersion {
		t.Errorf("SchemaVersion: got %q, want %q", got.SchemaVersion, env.SchemaVersion)
	}
	if got.ModuleName != env.ModuleName {
		t.Errorf("ModuleName: got %q, want %q", got.ModuleName, env.ModuleName)
	}
	if got.Passed != env.Passed {
		t.Errorf("Passed: got %v, want %v", got.Passed, env.Passed)
	}
}

func TestEnvelopeCoverageRatchet(t *testing.T) {
	t.Run("round-trip with both fields set", func(t *testing.T) {
		env := &evidence.Envelope{
			SchemaVersion: evidence.SchemaVersion,
			ModuleName:    "quality/test",
			Stage:         "stage-2",
			Tool:          evidence.ToolInfo{Name: "vitest", Version: "3.0.0"},
			Repo: evidence.RepoContext{
				RepoURL:   "https://github.com/example/repo",
				CommitSHA: "abc123",
				Branch:    "main",
			},
			TimestampUTC: time.Now().UTC().Truncate(time.Second),
			Passed:       true,
			CoverageBaselineByLanguage: map[string]float64{
				"node": 82.5,
				"go":   91.0,
			},
			CoverageRatchet: "pass",
		}

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var got evidence.Envelope
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if got.CoverageRatchet != env.CoverageRatchet {
			t.Errorf("CoverageRatchet: got %q, want %q", got.CoverageRatchet, env.CoverageRatchet)
		}
		if len(got.CoverageBaselineByLanguage) != len(env.CoverageBaselineByLanguage) {
			t.Fatalf("CoverageBaselineByLanguage: got %d entries, want %d",
				len(got.CoverageBaselineByLanguage), len(env.CoverageBaselineByLanguage))
		}
		for lang, want := range env.CoverageBaselineByLanguage {
			if got.CoverageBaselineByLanguage[lang] != want {
				t.Errorf("CoverageBaselineByLanguage[%q]: got %v, want %v",
					lang, got.CoverageBaselineByLanguage[lang], want)
			}
		}
	})

	t.Run("keys omitted when fields are empty", func(t *testing.T) {
		env := &evidence.Envelope{
			SchemaVersion: evidence.SchemaVersion,
			ModuleName:    "quality/test",
			Stage:         "stage-2",
			Passed:        true,
		}

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("unmarshal to map: %v", err)
		}

		if _, ok := raw["coverageBaselineByLanguage"]; ok {
			t.Error("coverageBaselineByLanguage key present in serialized output, want omitted")
		}
		if _, ok := raw["coverageRatchet"]; ok {
			t.Error("coverageRatchet key present in serialized output, want omitted")
		}
	})
}

func TestValidSeverity(t *testing.T) {
	valid := []evidence.Severity{
		evidence.SeverityCritical,
		evidence.SeverityHigh,
		evidence.SeverityMedium,
		evidence.SeverityLow,
		evidence.SeverityNone,
	}
	for _, s := range valid {
		if !evidence.ValidSeverity(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}
	if evidence.ValidSeverity("UNKNOWN") {
		t.Error("expected UNKNOWN to be invalid")
	}
}
