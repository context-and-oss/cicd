package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestByoTestRequested(t *testing.T) {
	cases := []struct {
		cmd, legs string
		want      bool
	}{
		{"", "", false},
		{"npm test", "", true},
		{"", `[{"language":"go","cmd":"go test ./..."}]`, true},
		{"npm test", `[{"language":"go"}]`, true},
	}
	for _, tc := range cases {
		if got := byoTestRequested(tc.cmd, tc.legs); got != tc.want {
			t.Errorf("byoTestRequested(%q, %q) = %v, want %v", tc.cmd, tc.legs, got, tc.want)
		}
	}
}

func TestValidateStage2Inputs(t *testing.T) {
	cases := []struct {
		name                          string
		parallelism, nodeProjectLimit int
		hasPrepared, byoTest          bool
		wantErr                       string
	}{
		{"defaults", 1, 4, false, false, ""},
		{"prepared with byo test", 4, 1, true, true, ""},
		{"parallelism zero", 0, 4, false, false, "parallelism must be an integer from 1 to 4, got 0"},
		{"parallelism five", 5, 4, false, false, "parallelism must be an integer from 1 to 4, got 5"},
		{"node project limit zero", 1, 0, false, false, "node-project-limit must be positive"},
		{"node project limit negative", 1, -3, false, false, "node-project-limit must be positive"},
		{"prepared without byo test", 1, 4, true, false, "prepared execution requires witnessed BYO tests"},
		// Parallelism is checked first, so the message names the first refusal
		// in the order Run always used, not whichever input happens to be worst.
		{"every input wrong names parallelism", 0, 0, true, false, "parallelism must be an integer from 1 to 4, got 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStage2Inputs(tc.parallelism, tc.nodeProjectLimit, tc.hasPrepared, tc.byoTest)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("expected %q, got nil", tc.wantErr)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestStage2LegsPairEachValueWithItsName(t *testing.T) {
	pairs := func(legs []stage2Leg[string]) [][2]string {
		out := make([][2]string, len(legs))
		for i, l := range legs {
			out[i] = [2]string{l.name, l.value}
		}
		return out
	}

	got := pairs(stage2Legs(false, "Q", "T", "S", "L", "R", "I"))
	want := [][2]string{
		{"quality", "Q"}, {"source security", "S"}, {"source licences", "L"},
		{"risk", "R"}, {"intent", "I"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("without BYO tests: %v, want %v", got, want)
	}
	for _, p := range got {
		if p[1] == "T" {
			t.Error("a tests value passed without byoTest must be dropped, not slotted under another leg's name")
		}
	}

	got = pairs(stage2Legs(true, "Q", "T", "S", "L", "R", "I"))
	want = [][2]string{
		{"quality", "Q"}, {"witnessed tests", "T"}, {"source security", "S"},
		{"source licences", "L"}, {"risk", "R"}, {"intent", "I"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with BYO tests: %v, want %v", got, want)
	}
	// The count is 5 or 6 and downstream must never assume either; the
	// witnessed-tests leg is the only one that comes and goes.
	if len(stage2Legs(true, "", "", "", "", "", ""))-len(stage2Legs(false, "", "", "", "", "", "")) != 1 {
		t.Error("exactly one leg is conditional")
	}
}

func TestUnusableEvidenceIsAFailedErrorEnvelopeNamingTheLeg(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	repo := repoContext{RepoURL: "https://example.com/r", CommitSHA: "abc123", Branch: "main"}
	e := unusableEvidence("source security", repo, now)
	if e.Passed {
		t.Error("a leg that produced nothing must not pass")
	}
	if e.Outcome != OutcomeError {
		t.Errorf("outcome = %q, want %q", e.Outcome, OutcomeError)
	}
	if e.SchemaVersion != evidenceSchemaVersion || e.ModuleName != "stage-2" || e.Stage != "stage-2" {
		t.Errorf("identity = %q/%q/%q", e.SchemaVersion, e.ModuleName, e.Stage)
	}
	if e.Tool.Name != "source security" || !e.TimestampUTC.Equal(now) {
		t.Errorf("tool/time = %+v", e)
	}
	if e.Repo.RepoURL != repo.RepoURL || e.Repo.CommitSHA != repo.CommitSHA || e.Repo.Branch != repo.Branch {
		t.Errorf("repo = %+v, want %+v", e.Repo, repo)
	}
	if len(e.Errors) != 1 || !strings.HasPrefix(e.Errors[0], "source security: execution did not produce usable evidence") {
		t.Errorf("errors = %q", e.Errors)
	}
	if e.FindingsCount != 0 || len(e.Findings) != 0 {
		t.Error("an unusable leg must not invent findings")
	}
	// The envelope is what cross-cutting/evidence reads; it must survive the
	// wire with the verdict intact.
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back envelope
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Passed || back.Outcome != OutcomeError || back.Errors[0] != e.Errors[0] {
		t.Errorf("round trip changed the verdict: %s", data)
	}
}
