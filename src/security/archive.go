//go:build !unit_test

package main

import (
	"context"
	"dagger/security/internal/dagger"
	"encoding/json"
	"fmt"
	"time"
)

// ScanArchive scans the "archive" artifact shape (a built directory/zip
// rather than an OCI image — see ADR-001):
//
//   - dependency vulnerabilities + CycloneDX SBOM come from the SOURCE
//     (Trivy filesystem scan over lockfiles — bundled/published artifacts
//     yield garbage dependency data);
//   - secrets detection (Gitleaks) targets the built OUTPUT — the
//     bundled-.env class of leak only exists in the artifact.
//
// Returns an aggregated evidence envelope shaped like ScanImage's
// (FindingsBySeverity, CycloneDXReport, SARIFReport).
func (m *Security) ScanArchive(
	ctx context.Context,
	// Source directory the archive was built from (lockfile SBOM + dependency vuln scan).
	src *dagger.Directory,
	// Built archive output directory to secrets-scan (e.g. a vite dist/, dotnet publish output).
	// Named outputDir, not output: the dagger CLI reserves -o/--output on
	// `dagger call`, so a param literally named "output" can never be passed.
	outputDir *dagger.Directory,
	// Minimum severity that fails the pipeline: CRITICAL|HIGH|MEDIUM|LOW|NONE
	// +default="HIGH"
	failOn string,
	// Git commit SHA for evidence provenance.
	commitSha string,
	// Git branch name for evidence provenance.
	branch string,
	// Repository URL for evidence provenance.
	repoUrl string,
	// Private NuGet feed index URL, used only by the lockfile-free dependency
	// graph fallback — see ScanSource.
	// +optional
	nugetFeedUrl string,
	// Token for nugetFeedUrl. Handed to NuGet as a secret and never written to
	// the evidence envelope.
	// +optional
	nugetToken *dagger.Secret,
	// Only scan built-output secrets. The orchestrator separately declares
	// whether dependency assessment ran or was intentionally deferred.
	// +optional
	artifactOnly bool,
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

	// Same preflight as ScanSource, and for the same reason: refuse to put a
	// feed token on a cleartext transport before any container exists.
	if nugetToken != nil {
		if err := feedTransportOK("nuget-feed-url", nugetFeedUrl, schemeRequired); err != nil {
			return nil, err
		}
	}

	// Parsed before any container is built — see ScanSource.
	accepted, err := newVulnAccepter(vulnAccept)
	if err != nil {
		return nil, err
	}

	var vuln trivyResult
	var err1, err3 error
	var inventory toolResult
	if !artifactOnly {
		vuln, err1 = runTrivyFS(ctx, src, nugetFeedUrl, nugetToken, accepted)
		// The same scan's second answer: the inventory it resolved. See
		// inventory.go and the note in ScanSource.
		inventory, err3 = inventoryResult(err1, vuln)
	}
	sarifSecrets, findingsSecrets, secretsScan, err2 := runGitleaksDir(ctx, outputDir)

	var errs []string
	for _, e := range []error{err1, err2, err3} {
		if e != nil {
			errs = append(errs, e.Error())
		}
	}

	combined := mergeSeverity(vuln.BySeverity, bySeverityFromFindings(findingsSecrets))
	total := 0
	for _, c := range combined {
		total += c
	}
	ran := len(errs) == 0
	severityOK := !shouldFail(combined, threshold)

	// The verdicts behind the single Passed below — see the note in
	// ScanSource and perToolSources. Gitleaks appears here AND on the
	// security-source envelope; the Scope field is what tells the two
	// apart, and without it one scanner over two scopes reads as two
	// scanners. The dependency rows are left out, not sliced off, when the
	// scan did not run; see ScanSource.
	var tools []toolResult
	if !artifactOnly {
		tools = append(tools,
			toolResult{
				Name:       "trivy",
				BySeverity: vuln.BySeverity,
				Examined:   vuln.Examined,
				Err:        err1,
				Warnings:   len(vuln.Warnings),
				Skipped:    vuln.Skipped,
				Concern:    ConcernSCA,
			},
		)
	}
	tools = append(tools,
		// Warnings name the archives in the output gitleaks did not open —
		// a jar, a nupkg, a .tgz — which is the bundled-.env leak this scan
		// exists for. See gitleaksarchives.go.
		toolResult{
			Name:       "gitleaks",
			BySeverity: bySeverityFromFindings(findingsSecrets),
			Examined:   secretsScan.Examined,
			Err:        err2,
			Warnings:   len(secretsScan.Warnings),
			Concern:    ConcernSecrets,
		},
	)
	if !artifactOnly {
		tools = append(tools, inventory)
	}

	env := &envelope{
		SchemaVersion:      evidenceSchemaVersion,
		ModuleName:         moduleName,
		Stage:              moduleStage,
		Tool:               toolInfo{Name: scopeArchive},
		Repo:               repo,
		TimestampUTC:       start.UTC(),
		DurationMS:         time.Since(start).Milliseconds(),
		Passed:             gatedPassed(ran, severityOK, threshold),
		FailOnSeverity:     threshold,
		FindingsCount:      total,
		FindingsBySeverity: combined,
		// The two verdicts behind the single Passed above — see the note in
		// ScanSource and perToolSources. Gitleaks appears here AND on the
		// security-source envelope; the Scope field is what tells the two
		// apart, and without it one scanner over two scopes reads as two
		// scanners.
		Sources: perToolSources(scopeArchive, threshold, tools...),
		// Secrets are counted HIGH; stamp the same level into gitleaks' SARIF
		// so the detail rows agree with the counts (see stampSARIFLevel).
		SARIFReport:     stampSARIFLevel(sarifSecrets, "error"),
		CycloneDXReport: vuln.CycloneDX,
		// Vulnerability detail only — see the note in ScanSource.
		Findings: vuln.Findings,
		Warnings: concatWarnings(vuln.Warnings, secretsScan.Warnings, vuln.InventoryWarnings),
		Errors:   errs,
	}
	// The envelope reports what its tools found, folded from the rows above.
	// Derived from the rows that actually ship rather than recomputed from the
	// same inputs, so the two cannot disagree.
	if artifactOnly {
		env.Warnings = append(env.Warnings, "Archive output secrets scan only; dependency assessment is not part of this scan.")
	}
	env.Outcome = sourcesOutcome(env.Sources)

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return writeEvidenceFile(data)
}
