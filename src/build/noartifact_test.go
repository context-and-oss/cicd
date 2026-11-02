//go:build unit_test

// What a none-shape run must say, asserted on the shipping envelope rather than
// on a hand-built copy of it. Run with:
//
//	cd src/build && go test -tags unit_test ./...
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNoArtifactEnvelopeIsAWarnedPass(t *testing.T) {
	env, err := noArtifactEnvelope("abc123", "main", "https://example.com/repo", time.Now())
	if err != nil {
		t.Fatalf("noArtifactEnvelope: %v", err)
	}

	// Disclosure, not gating. A repository that ships nothing deployable is
	// legitimate, and --fail-on NONE cannot clear a non-run, so failing here
	// would be a permanent red with no remedy.
	if !env.Passed {
		t.Error("passed = false; the absence of an artifact must be disclosed, not gated")
	}
	if env.FindingsCount != 0 {
		t.Errorf("findingsCount = %d, want 0", env.FindingsCount)
	}
	if env.FailOnSeverity != "" {
		t.Errorf("failOnSeverity = %q; this envelope gates nothing and must claim no threshold", env.FailOnSeverity)
	}
	if len(env.Errors) != 0 {
		t.Errorf("errors = %v, want none", env.Errors)
	}

	// cross-cutting/evidence rejects an envelope whose moduleName is empty
	// ("unrecognised format"), so the identity is load-bearing, not decoration.
	if env.ModuleName != "build" || env.Stage != "domain" {
		t.Errorf("identity = %q/%q, want build/domain", env.ModuleName, env.Stage)
	}
	if env.Repo.CommitSHA != "abc123" || env.Repo.Branch != "main" {
		t.Errorf("provenance not carried through: %+v", env.Repo)
	}
}

func TestNoArtifactEnvelopeStatesTheAbsenceForHumansAndMachines(t *testing.T) {
	env, err := noArtifactEnvelope("abc123", "main", "https://example.com/repo", time.Now())
	if err != nil {
		t.Fatalf("noArtifactEnvelope: %v", err)
	}

	// The human half: notify renders envelope.Warnings verbatim into the PR
	// comment and the Teams card. Exactly one, so a none-shape audit cannot be
	// read as noise.
	if len(env.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", env.Warnings)
	}
	if !strings.Contains(env.Warnings[0], "NOT ATTESTED") {
		t.Errorf("warning does not announce the state: %q", env.Warnings[0])
	}

	// The machine half, mirroring intent's genericReport.required: false. False
	// rather than absent — an absent key is indistinguishable from an envelope
	// produced before the key existed.
	if env.GenericFormat != "artifact-attestation" {
		t.Errorf("genericFormat = %q, want artifact-attestation", env.GenericFormat)
	}
	var report map[string]any
	if err := json.Unmarshal(env.GenericReport, &report); err != nil {
		t.Fatalf("genericReport is not JSON: %v", err)
	}
	attested, ok := report["artifactAttested"]
	if !ok {
		t.Fatalf("genericReport has no artifactAttested key: %v", report)
	}
	if attested != false {
		t.Errorf("artifactAttested = %v, want false", attested)
	}
	if report["sbomDescribes"] != "source-lockfiles" {
		t.Errorf("sbomDescribes = %v, want source-lockfiles — the SBOM in a none-shape audit is not an artifact SBOM", report["sbomDescribes"])
	}
}

func TestNoArtifactWarningQuotesFactsAndRemedies(t *testing.T) {
	w := noArtifactWarning()

	// Concrete facts, not a bare claim: the selector value that produced the
	// run, the steps that therefore did not run, and what the sbom.cdx.json
	// sitting in the same audit directory actually describes.
	for _, want := range []string{
		"--artifact none",
		"sbom.cdx.json",
		"source lockfiles",
		"build.Sbom",
		"security.ScanImage",
		"security.ScanArchive",
		"--artifact container",
		"--artifact archive",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warning does not mention %q: %s", want, w)
		}
	}

	// notify/render.go writes each warning as "- `%s`", so a backtick in the
	// text closes the code span and a newline breaks the list item.
	if strings.ContainsAny(w, "`\n\r") {
		t.Errorf("warning contains a backtick or newline, which breaks the rendered PR comment: %q", w)
	}
}

func TestNoArtifactEvidenceSurvivesTheWire(t *testing.T) {
	data, err := noArtifactEvidence("abc123", "main", "https://example.com/repo", time.Now())
	if err != nil {
		t.Fatalf("noArtifactEvidence: %v", err)
	}

	// Warnings is `omitempty`: a nil or empty slice marshals away entirely, and
	// the disclosure would vanish between this module and the aggregator without
	// anything erroring. Parse it back the way cross-cutting/evidence does.
	var round envelope
	if err := json.Unmarshal([]byte(data), &round); err != nil {
		t.Fatalf("evidence is not a parseable envelope: %v", err)
	}
	if len(round.Warnings) != 1 || !strings.Contains(round.Warnings[0], "NOT ATTESTED") {
		t.Fatalf("the disclosure did not survive marshalling: %v", round.Warnings)
	}
	if round.ModuleName == "" {
		t.Error("moduleName empty after round trip; evidence.Wrap would reject this envelope")
	}
	if !round.Passed {
		t.Error("passed = false after round trip")
	}
	if round.SchemaVersion != evidenceSchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", round.SchemaVersion, evidenceSchemaVersion)
	}
}

// The false green this envelope shipped with its first Outcome. `--artifact
// none` builds nothing, SBOMs nothing and scans nothing, so passed=true and
// zero findings arrive at CLEAN — a green tick for a check that never ran,
// against this file's own stated doctrine that "a tool that could not run must
// never read as clean".
func TestTheNoArtifactEnvelopeSaysItSkipped(t *testing.T) {
	env, err := noArtifactEnvelope("abc123", "main", "https://example.com/repo", time.Now())
	if err != nil {
		t.Fatalf("noArtifactEnvelope: %v", err)
	}

	if env.Outcome != OutcomeSkipped {
		t.Errorf("outcome = %q, want %q — nothing was attested, so nothing is clean", env.Outcome, OutcomeSkipped)
	}
	if env.Outcome == OutcomeError {
		t.Error("SKIPPED, not ERROR: the caller asked for no artifact and got exactly that")
	}
	if !env.Passed {
		t.Error("passed must stay true: a repository that ships no deployable is legitimate and this is not a gate change")
	}
}
