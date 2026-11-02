// Saying that no artifact was attested.
//
// Deliberately untagged (no //go:build !unit_test): assembling an envelope that
// records the absence of an artifact needs no Dagger — no container, no source
// tree, no tool exit status to classify. The Dagger entry point in main.go is a
// three-line wrapper around noArtifactEvidence, so everything a reader has to
// trust here (the warning text, the machine-readable statement, and the fact
// that the envelope passes) is driven by tests. include.go in the quality
// module carries the same split for the same reason.
//
// This file exists because `--artifact none` recorded nothing at all. The
// commit composite's none branch was a bare comment, so the audit of a
// repository that ships multiple deployables and the audit of a repository that
// ships zero were byte-identical: same combined-evidence.json shape, same
// passed=true, same sbom.cdx.json, and nothing anywhere saying that no artifact
// had been built, SBOM'd or scanned. That is this repository's founding
// doctrine — a tool that could not run must never read as clean — on the
// artifact side, arriving through a selector value rather than a crashed
// scanner, and it is the same shape as the opt-in intent gate: an artifact tail
// that did not run produces exactly what an artifact tail that found nothing
// produces.
//
// So it is stated, once, in the one place a reviewer reads. notify renders
// envelope.Warnings verbatim into the PR comment and the Teams card, which is
// why the disclosure is a warning and not a comment in a log — and why the
// string carries no backticks: render.go wraps each warning in a backtick pair.
package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// Module identity. Declared here rather than in main.go (where it used to live)
// so the unit-testable envelope builder below can use the real values: main.go
// is //go:build !unit_test, so anything declared there is invisible to the
// -tags unit_test suite, and an envelope test asserting a module name it had
// supplied itself would prove nothing about what ships.
const (
	moduleName  = "build"
	moduleStage = "domain"
)

// artifactAttestationTool names the producer of the no-artifact record. It is
// not a tool that ran — nothing ran — it is the name under which this
// repository states that nothing did, and it is what an auditor greps for in
// combined-evidence.json.
const (
	artifactAttestationTool    = "artifact-attestation"
	artifactAttestationVersion = "1.0.0"
	artifactAttestationFormat  = "artifact-attestation"
)

// noArtifactWarning is the record a commit-stage run leaves behind when it was
// asked to build no artifact.
//
// It quotes facts rather than making a claim a reader has to take on trust
// (`quality: NOT SCANNED — node detected (web/package.json) …` is the
// precedent): which selector value produced this run, which five build and
// scan functions therefore did not run, and — the fact most likely to be missed
// — what the sbom.cdx.json sitting in the same audit directory actually
// describes. That file is present in a none-shape audit exactly as it is in a
// container-shape audit, and it is a source-lockfile SBOM either way; without
// this line the only thing distinguishing the two audits is the absence of the
// image SBOM merged into one of them, which is not something a human reads.
//
// A warning, not an error, and not a failed gate. A repository that genuinely
// ships no deployable artifact — a library, an infra/config repo, the "none"
// shape ADR-005 added for exactly that case — is legitimate, and failing it
// would be a permanent red with no remedy available to the consumer: --fail-on
// NONE deliberately does not suppress a non-run, so the one knob they would
// reach for could not clear it either. Same reasoning as quality's
// NO LANGUAGE DETECTED, same shape as intent-gate's NOT REQUIRED.
//
// The remedy names --artifact, which is the commit composite's flag and not
// this module's: the consumer types it, and a message naming this module's own
// parameters would send them looking in the wrong place. intent.Check does the
// same with --require-intent, a flag owned by stage-2 and precommit.
func noArtifactWarning() string {
	return "artifact: NOT ATTESTED — --artifact none was selected, so no artifact was built and " +
		"neither an artifact SBOM nor an artifact scan ran (build.Build, build.Sbom, " +
		"security.ScanImage, build.BuildArchive and security.ScanArchive were all skipped). " +
		"sbom.cdx.json in this audit describes source lockfiles (stage-2 scan-source, Trivy-FS), " +
		"not a deployable. Select --artifact container or --artifact archive to attest one, or " +
		"read this as confirmation that this repository ships no deployable artifact."
}

// noArtifactReport is the machine-readable half of the same statement.
// ArtifactAttested is the field a policy engine or a later pipeline reads, and
// it is false rather than absent for the same reason intent's genericReport
// carries `required: false` instead of omitting the key: an absent field is
// indistinguishable from an envelope produced before the field existed.
type noArtifactReport struct {
	Tool             string `json:"tool"`
	Version          string `json:"version"`
	ArtifactAttested bool   `json:"artifactAttested"`
	ArtifactShape    string `json:"artifactShape"`
	SbomDescribes    string `json:"sbomDescribes"`
}

// noArtifactEnvelope builds the evidence envelope for a run that attested no
// artifact.
//
// Passed is true and FailOnSeverity is left unset, deliberately: this envelope
// gates nothing, and stamping a threshold onto a record of work that did not
// happen would claim a severity decision was made. FindingsCount is 0 because
// there were none — the disclosure lives in Warnings, which notify renders and
// no gate reads.
func noArtifactEnvelope(commitSha, branch, repoUrl string, at time.Time) (*envelope, error) {
	payload, err := json.Marshal(noArtifactReport{
		Tool:             artifactAttestationTool,
		Version:          artifactAttestationVersion,
		ArtifactAttested: false,
		ArtifactShape:    "none",
		SbomDescribes:    "source-lockfiles",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal no-artifact report: %w", err)
	}

	return &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool: toolInfo{
			Name:    artifactAttestationTool,
			Version: artifactAttestationVersion,
		},
		Repo: repoContext{
			RepoURL:   repoUrl,
			CommitSHA: commitSha,
			Branch:    branch,
		},
		TimestampUTC: at.UTC(),
		DurationMS:   0,
		Passed:       true,
		// SKIPPED, not CLEAN. This file's own doctrine, stated at the top: "a
		// tool that could not run must never read as clean". Nothing was built,
		// SBOM'd or scanned, because `--artifact none` asked for nothing to be —
		// which is legitimate, and is why this is not ERROR either. The
		// envelope succeeded at recording an absence; the absence is what it
		// records.
		Outcome:       OutcomeSkipped,
		FindingsCount: 0,
		GenericReport: json.RawMessage(payload),
		GenericFormat: artifactAttestationFormat,
		Warnings:      []string{noArtifactWarning()},
	}, nil
}

// noArtifactEvidence renders the envelope as the JSON the Dagger entry point
// writes to evidence.json.
func noArtifactEvidence(commitSha, branch, repoUrl string, at time.Time) (string, error) {
	env, err := noArtifactEnvelope(commitSha, branch, repoUrl, at)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal no-artifact evidence: %w", err)
	}
	return string(data), nil
}
