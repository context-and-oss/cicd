//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"fmt"
	"time"
)

// ScanSbom rescans an existing CycloneDX SBOM against today's vulnerability
// database. A vulnerability verdict is a frozen SBOM crossed with moving CVE
// knowledge, so the verdict a release shipped with goes stale the day a new
// advisory lands — this is the scheduled-rescan entry point ADR-006 names: the
// consumer feeds back the sbom.cdx.json a commit run froze and gets a fresh
// evidence envelope. Deliberately wired into no composite; the pipelines scan
// the tree and the image directly.
func (m *Security) ScanSbom(
	ctx context.Context,
	// CycloneDX SBOM document to rescan. cicd's own envelopes carry one under
	// the key cyclonedxReport; the commit audit directory ships it as
	// sbom.cdx.json.
	sbom *dagger.File,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance — the commit the SBOM was frozen
	// at, so the rescan's envelope names the release it grades.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Refuse a non-empty application inventory that Trivy resolved to no packages.
	// +optional
	applicationInventory bool,
	// Vulnerability findings to accept, ONE PER LINE, each as "<id>=<reason>"
	// — e.g. "CVE-2026-81871=the exporter only reaches the Dagger engine's own
	// telemetry endpoint on the runner". An accepted identifier is removed from
	// the severity counts, from findings[] and from the gate, and is disclosed
	// in warnings[] with the reason given; the row stays in the CycloneDX
	// report, so the vulnerability is still in the evidence. A reason is
	// mandatory, patterns are refused, and an acceptance matching nothing warns
	// so a stale one is visible rather than a standing permission. The
	// separator is a newline and never a comma, because a reason is prose that
	// contains commas — see splitVulnAcceptances in vulnallow.go for what the
	// CLI does to a []string here.
	// +optional
	vulnAccept string,
) (*dagger.File, error) {
	start := time.Now()
	threshold := Severity(failOn)
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch}

	// Validate the input before any scan container is built: a document that
	// was never CycloneDX is the caller's defect, and letting Trivy trip over
	// it would put Trivy's error in errors[] instead of the real cause. The
	// rejection is a non-run — passed=false at every threshold, NONE included —
	// because a rescan that never read its SBOM must never read as a rescan
	// that found nothing.
	accepted, acceptErr := newVulnAccepter(vulnAccept)
	if acceptErr != nil {
		return nil, acceptErr
	}

	var errs []string
	var vuln trivyResult
	contents, err := sbom.Contents(ctx)
	if err != nil {
		errs = append(errs, fmt.Sprintf("sbom-input: could not read the supplied SBOM file: %v", err))
	} else if msg := sbomInputError(contents); msg != "" {
		errs = append(errs, msg)
	} else if vuln, err = runTrivySbom(ctx, sbom, accepted); err != nil {
		errs = append(errs, err.Error())
	}
	if applicationInventory && len(errs) == 0 {
		var inventory struct {
			Components []json.RawMessage `json:"components"`
		}
		if err := json.Unmarshal([]byte(contents), &inventory); err != nil {
			return nil, err
		}
		if len(inventory.Components) > 0 && (vuln.Examined == nil || vuln.Examined.Count == 0) {
			errs = append(errs, "Trivy resolved no packages from a non-empty application inventory; dependency scanning is incomplete")
		}
	}

	total := 0
	for _, c := range vuln.BySeverity {
		total += c
	}
	ran := len(errs) == 0
	severityOK := !shouldFail(vuln.BySeverity, threshold)

	env := &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: "trivy", Version: trivyVersion, Args: []string{"sbom"}},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(ran, severityOK, threshold),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: vuln.BySeverity,
		// A rescan of a frozen SBOM asks the same question a source scan asks
		// — known vulnerabilities in resolved dependencies — so it is the same
		// concern. The frozen input is the scope, not a different subject.
		Concern: ConcernSCA,
		// One tool under this envelope, so the denominator sits on the envelope
		// rather than in a Sources row — the shape ScanLicenses already uses.
		// Nil on every error path above, because a rescan that never read its
		// SBOM did not examine zero packages, it did not say.
		Examined: vuln.Examined,
		// The CycloneDX here is re-rendered from this rescan's native report —
		// the input document restated with today's vulnerability knowledge.
		CycloneDXReport: vuln.CycloneDX,
		// Vulnerability detail only — see the note in ScanSource.
		Findings: vuln.Findings,
		Warnings: vuln.Warnings,
		Errors:   errs,
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}
